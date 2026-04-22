using System.Buffers.Binary;
using System.Text;

namespace PostQuantum.FileFormat.Cbor;

internal sealed class CborValidationException : Exception
{
    public CborValidationException(string message) : base(message)
    {
    }
}

internal static class DeterministicCborValidator
{
    /// <summary>
    /// Parse CBOR bytes and verify the encoding is deterministic per RFC 8949 section 4.2.2.
    /// Throws CborValidationException on any non-determinism.
    /// </summary>
    public static CborValue ParseStrict(ReadOnlyMemory<byte> cbor)
    {
        var bytes = cbor.ToArray();
        var offset = 0;
        var value = ParseValue(bytes, ref offset);

        if (offset != bytes.Length)
        {
            throw new CborValidationException("Trailing bytes are not allowed after the top-level CBOR item.");
        }

        return value;
    }

    private static CborValue ParseValue(byte[] bytes, ref int offset)
    {
        EnsureAvailable(bytes, offset, 1);
        var initialByte = bytes[offset++];
        var majorType = initialByte >> 5;
        var additional = (byte)(initialByte & 0x1F);

        return majorType switch
        {
            0 => CborValue.Uint(ReadLengthAndValidateShortest(bytes, ref offset, additional, "unsigned integer")),
            1 => ParseNegativeInteger(bytes, ref offset, additional),
            2 => ParseByteString(bytes, ref offset, additional),
            3 => ParseTextString(bytes, ref offset, additional),
            4 => ParseArray(bytes, ref offset, additional),
            5 => ParseMap(bytes, ref offset, additional),
            6 => ParseTag(bytes, ref offset, additional),
            7 => ParseSimple(bytes, ref offset, additional),
            _ => throw new CborValidationException($"Unsupported major type {majorType}.")
        };
    }

    private static CborValue ParseNegativeInteger(byte[] bytes, ref int offset, byte additional)
    {
        var value = ReadLengthAndValidateShortest(bytes, ref offset, additional, "negative integer");
        if (value > long.MaxValue)
        {
            throw new CborValidationException("Negative integer value is out of supported range.");
        }

        return CborValue.NegInt((long)value);
    }

    private static CborValue ParseByteString(byte[] bytes, ref int offset, byte additional)
    {
        var length = ReadLengthAndValidateShortest(bytes, ref offset, additional, "byte string");
        var len = ToInt32Checked(length, "byte string length");
        EnsureAvailable(bytes, offset, len);

        var content = new byte[len];
        Array.Copy(bytes, offset, content, 0, len);
        offset += len;

        return CborValue.Bytes(content);
    }

    private static CborValue ParseTextString(byte[] bytes, ref int offset, byte additional)
    {
        var length = ReadLengthAndValidateShortest(bytes, ref offset, additional, "text string");
        var len = ToInt32Checked(length, "text string length");
        EnsureAvailable(bytes, offset, len);

        var content = new byte[len];
        Array.Copy(bytes, offset, content, 0, len);
        offset += len;

        string text;
        try
        {
            text = CborCanonicity.StrictUtf8.GetString(content);
        }
        catch (DecoderFallbackException ex)
        {
            throw new CborValidationException($"Text string contains invalid UTF-8: {ex.Message}");
        }

        return CborValue.Text(text);
    }

    private static CborValue ParseArray(byte[] bytes, ref int offset, byte additional)
    {
        var length = ReadLengthAndValidateShortest(bytes, ref offset, additional, "array");
        var len = ToInt32Checked(length, "array length");
        var items = new List<CborValue>(len);

        for (var i = 0; i < len; i++)
        {
            items.Add(ParseValue(bytes, ref offset));
        }

        return CborValue.Array(items);
    }

    private static CborValue ParseMap(byte[] bytes, ref int offset, byte additional)
    {
        var length = ReadLengthAndValidateShortest(bytes, ref offset, additional, "map");
        var len = ToInt32Checked(length, "map length");
        var entries = new List<KeyValuePair<CborValue, CborValue>>(len);
        byte[]? previousKeyEncoding = null;

        for (var i = 0; i < len; i++)
        {
            var keyStart = offset;
            var key = ParseValue(bytes, ref offset);
            var keyLength = offset - keyStart;
            var currentKeyEncoding = new byte[keyLength];
            Array.Copy(bytes, keyStart, currentKeyEncoding, 0, keyLength);

            if (previousKeyEncoding is not null)
            {
                var cmp = CborCanonicity.CompareEncodedMapKeys(previousKeyEncoding, currentKeyEncoding);
                if (cmp == 0)
                {
                    throw new CborValidationException("Map contains duplicate keys.");
                }

                if (cmp > 0)
                {
                    throw new CborValidationException("Map keys are not in deterministic order.");
                }
            }

            previousKeyEncoding = currentKeyEncoding;
            var value = ParseValue(bytes, ref offset);
            entries.Add(new KeyValuePair<CborValue, CborValue>(key, value));
        }

        return CborValue.Map(entries);
    }

    private static CborValue ParseTag(byte[] bytes, ref int offset, byte additional)
    {
        var tag = ReadLengthAndValidateShortest(bytes, ref offset, additional, "tag");
        if (tag != 0)
        {
            throw new CborValidationException("Only tag 0 is allowed in PQF v1 headers.");
        }

        var taggedValue = ParseValue(bytes, ref offset);
        return CborValue.Tag(tag, taggedValue);
    }

    private static CborValue ParseSimple(byte[] bytes, ref int offset, byte additional)
    {
        return additional switch
        {
            20 => CborValue.Bool(false),
            21 => CborValue.Bool(true),
            22 => CborValue.Null,
            24 => throw new CborValidationException("Unused simple values are not allowed."),
            25 or 26 or 27 => throw new CborValidationException("Floating-point values are not allowed."),
            31 => throw new CborValidationException("Indefinite-length items are not allowed."),
            _ => throw new CborValidationException("Unused simple values are not allowed.")
        };
    }

    private static ulong ReadLengthAndValidateShortest(byte[] bytes, ref int offset, byte additional, string context)
    {
        if (additional <= 23)
        {
            return additional;
        }

        if (additional == 31)
        {
            throw new CborValidationException($"Indefinite-length {context} is not allowed.");
        }

        ulong value;
        switch (additional)
        {
            case 24:
                EnsureAvailable(bytes, offset, 1);
                value = bytes[offset];
                offset += 1;
                if (value <= 23)
                {
                    throw new CborValidationException($"Non-shortest integer encoding detected for {context}.");
                }

                return value;

            case 25:
                EnsureAvailable(bytes, offset, 2);
                value = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset, 2));
                offset += 2;
                if (value <= byte.MaxValue)
                {
                    throw new CborValidationException($"Non-shortest integer encoding detected for {context}.");
                }

                return value;

            case 26:
                EnsureAvailable(bytes, offset, 4);
                value = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(offset, 4));
                offset += 4;
                if (value <= ushort.MaxValue)
                {
                    throw new CborValidationException($"Non-shortest integer encoding detected for {context}.");
                }

                return value;

            case 27:
                EnsureAvailable(bytes, offset, 8);
                value = BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(offset, 8));
                offset += 8;
                if (value <= uint.MaxValue)
                {
                    throw new CborValidationException($"Non-shortest integer encoding detected for {context}.");
                }

                return value;

            default:
                throw new CborValidationException($"Unsupported additional information value {additional}.");
        }
    }

    private static int ToInt32Checked(ulong value, string context)
    {
        if (value > int.MaxValue)
        {
            throw new CborValidationException($"{context} exceeds implementation limits.");
        }

        return (int)value;
    }

    private static void EnsureAvailable(byte[] bytes, int offset, int required)
    {
        if (offset < 0 || required < 0 || offset + required > bytes.Length)
        {
            throw new CborValidationException("Unexpected end of CBOR payload.");
        }
    }
}