using System.Buffers;
using System.Buffers.Binary;

namespace PostQuantum.FileFormat.Cbor;

internal static class DeterministicCborEncoder
{
    /// <summary>
    /// Encode a structured value as deterministic CBOR per RFC 8949 section 4.2.2.
    /// </summary>
    public static byte[] Encode(CborValue value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var writer = new ArrayBufferWriter<byte>();
        WriteValue(writer, value);
        return writer.WrittenSpan.ToArray();
    }

    private static void WriteValue(IBufferWriter<byte> writer, CborValue value)
    {
        switch (value)
        {
            case CborValue.UIntValue u:
                WriteTypeAndLength(writer, majorType: 0, u.Value);
                return;

            case CborValue.NegIntValue n:
                if (n.Value < 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), "Negative integer canonical value must be non-negative.");
                }

                WriteTypeAndLength(writer, majorType: 1, (ulong)n.Value);
                return;

            case CborValue.BytesValue b:
                WriteTypeAndLength(writer, majorType: 2, (ulong)b.Value.Length);
                writer.Write(b.Value.Span);
                return;

            case CborValue.TextValue t:
                var utf8 = CborCanonicity.StrictUtf8.GetBytes(t.Value);
                WriteTypeAndLength(writer, majorType: 3, (ulong)utf8.Length);
                writer.Write(utf8);
                return;

            case CborValue.ArrayValue a:
                WriteTypeAndLength(writer, majorType: 4, (ulong)a.Items.Count);
                foreach (var item in a.Items)
                {
                    WriteValue(writer, item);
                }

                return;

            case CborValue.MapValue m:
                WriteTypeAndLength(writer, majorType: 5, (ulong)m.Entries.Count);
                foreach (var pair in m.Entries
                             .Select(entry => new KeyValuePair<byte[], CborValue>(Encode(entry.Key), entry.Value))
                             .OrderBy(entry => entry.Key, ByteArrayKeyComparer.Instance))
                {
                    writer.Write(pair.Key);
                    WriteValue(writer, pair.Value);
                }

                return;

            case CborValue.TagValue tag:
                if (tag.TagNumber != 0)
                {
                    throw new NotSupportedException("Only CBOR tag 0 is supported by PQF v1.");
                }

                WriteTypeAndLength(writer, majorType: 6, tag.TagNumber);
                WriteValue(writer, tag.Value);
                return;

            case CborValue.BoolValue b:
                WriteSingleByte(writer, b.Value ? (byte)0xF5 : (byte)0xF4);
                return;

            case CborValue.NullValue:
                WriteSingleByte(writer, 0xF6);
                return;

            default:
                throw new NotSupportedException($"Unsupported CBOR value type: {value.GetType().Name}");
        }
    }

    private static void WriteTypeAndLength(IBufferWriter<byte> writer, int majorType, ulong value)
    {
        var initial = (byte)(majorType << 5);

        if (value <= 23)
        {
            WriteSingleByte(writer, (byte)(initial | (byte)value));
            return;
        }

        if (value <= byte.MaxValue)
        {
            var span = writer.GetSpan(2);
            span[0] = (byte)(initial | 24);
            span[1] = (byte)value;
            writer.Advance(2);
            return;
        }

        if (value <= ushort.MaxValue)
        {
            var span = writer.GetSpan(3);
            span[0] = (byte)(initial | 25);
            BinaryPrimitives.WriteUInt16BigEndian(span[1..3], (ushort)value);
            writer.Advance(3);
            return;
        }

        if (value <= uint.MaxValue)
        {
            var span = writer.GetSpan(5);
            span[0] = (byte)(initial | 26);
            BinaryPrimitives.WriteUInt32BigEndian(span[1..5], (uint)value);
            writer.Advance(5);
            return;
        }

        {
            var span = writer.GetSpan(9);
            span[0] = (byte)(initial | 27);
            BinaryPrimitives.WriteUInt64BigEndian(span[1..9], value);
            writer.Advance(9);
        }
    }

    private static void WriteSingleByte(IBufferWriter<byte> writer, byte value)
    {
        var span = writer.GetSpan(1);
        span[0] = value;
        writer.Advance(1);
    }

    private sealed class ByteArrayKeyComparer : IComparer<byte[]>
    {
        public static readonly ByteArrayKeyComparer Instance = new();

        public int Compare(byte[]? x, byte[]? y)
        {
            if (ReferenceEquals(x, y))
            {
                return 0;
            }

            if (x is null)
            {
                return -1;
            }

            if (y is null)
            {
                return 1;
            }

            return CborCanonicity.CompareEncodedMapKeys(x, y);
        }
    }
}