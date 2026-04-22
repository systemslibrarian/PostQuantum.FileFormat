using System.Text;

namespace PostQuantum.FileFormat.Cbor;

internal static class CborCanonicity
{
    public static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static int CompareEncodedMapKeys(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
        {
            return left.Length.CompareTo(right.Length);
        }

        for (var i = 0; i < left.Length; i++)
        {
            var cmp = left[i].CompareTo(right[i]);
            if (cmp != 0)
            {
                return cmp;
            }
        }

        return 0;
    }
}

internal abstract record CborValue
{
    public sealed record UIntValue(ulong Value) : CborValue;
    public sealed record NegIntValue(long Value) : CborValue;
    public sealed record BytesValue(ReadOnlyMemory<byte> Value) : CborValue;
    public sealed record TextValue(string Value) : CborValue;
    public sealed record ArrayValue(IReadOnlyList<CborValue> Items) : CborValue;
    public sealed record MapValue(IReadOnlyList<KeyValuePair<CborValue, CborValue>> Entries) : CborValue;
    public sealed record TagValue(ulong TagNumber, CborValue Value) : CborValue;
    public sealed record BoolValue(bool Value) : CborValue;
    public sealed record NullValue : CborValue;

    private static readonly NullValue NullSingleton = new();

    public static CborValue Uint(ulong value) => new UIntValue(value);

    public static CborValue NegInt(long value) => new NegIntValue(value);

    public static CborValue Bytes(ReadOnlyMemory<byte> value) => new BytesValue(value);

    public static CborValue Text(string value) => new TextValue(value);

    public static CborValue Array(IReadOnlyList<CborValue> items) => new ArrayValue(items);

    public static CborValue Map(IReadOnlyList<KeyValuePair<CborValue, CborValue>> entries) => new MapValue(entries);

    public static CborValue Tag(ulong tag, CborValue value) => new TagValue(tag, value);

    public static CborValue Bool(bool value) => new BoolValue(value);

    public static CborValue Null => NullSingleton;
}