using PostQuantum.FileFormat.Cbor;

namespace PostQuantum.FileFormat.Tests.Cbor;

public sealed class DeterministicCborValidatorTests
{
    [Fact]
    public void ParseStrict_rejects_non_shortest_uint()
    {
        Assert.Throws<CborValidationException>(() => DeterministicCborValidator.ParseStrict(new byte[] { 0x18, 0x00 }));
    }

    [Fact]
    public void ParseStrict_rejects_indefinite_length_array()
    {
        Assert.Throws<CborValidationException>(() => DeterministicCborValidator.ParseStrict(new byte[] { 0x9F, 0x01, 0x02, 0xFF }));
    }

    [Fact]
    public void ParseStrict_rejects_indefinite_length_map()
    {
        Assert.Throws<CborValidationException>(() => DeterministicCborValidator.ParseStrict(new byte[] { 0xBF, 0x61, 0x61, 0x01, 0xFF }));
    }

    [Fact]
    public void ParseStrict_rejects_out_of_order_map_keys()
    {
        Assert.Throws<CborValidationException>(() => DeterministicCborValidator.ParseStrict(FromHex("A2616201616102")));
    }

    [Fact]
    public void ParseStrict_rejects_duplicate_map_keys()
    {
        Assert.Throws<CborValidationException>(() => DeterministicCborValidator.ParseStrict(FromHex("A2616101616102")));
    }

    [Fact]
    public void ParseStrict_rejects_floats()
    {
        Assert.Throws<CborValidationException>(() => DeterministicCborValidator.ParseStrict(new byte[] { 0xF9, 0x3C, 0x00 }));
    }

    [Fact]
    public void ParseStrict_rejects_trailing_bytes()
    {
        Assert.Throws<CborValidationException>(() => DeterministicCborValidator.ParseStrict(new byte[] { 0x00, 0x00 }));
    }

    [Fact]
    public void ParseStrict_roundtrip_through_encoder_matches_input()
    {
        var random = new Random(0x51D4E6);

        for (var i = 0; i < 100; i++)
        {
            var value = RandomValue(random, depth: 0);
            var encoded = DeterministicCborEncoder.Encode(value);
            var parsed = DeterministicCborValidator.ParseStrict(encoded);
            var reencoded = DeterministicCborEncoder.Encode(parsed);

            Assert.Equal(encoded, reencoded);
        }
    }

    private static CborValue RandomValue(Random random, int depth)
    {
        if (depth > 3)
        {
            return CborValue.Uint((ulong)random.Next(0, 1000));
        }

        var kind = random.Next(0, 9);
        return kind switch
        {
            0 => CborValue.Uint((ulong)random.NextInt64(0, long.MaxValue)),
            1 => CborValue.NegInt(random.Next(0, 10_000)),
            2 => RandomBytes(random),
            3 => CborValue.Text(RandomText(random)),
            4 => RandomArray(random, depth + 1),
            5 => RandomMap(random, depth + 1),
            6 => CborValue.Tag(0, CborValue.Text("2026-04-21T14:30:00Z")),
            7 => CborValue.Bool(random.Next(0, 2) == 1),
            _ => CborValue.Null
        };
    }

    private static CborValue RandomBytes(Random random)
    {
        var length = random.Next(0, 33);
        var bytes = new byte[length];
        random.NextBytes(bytes);
        return CborValue.Bytes(bytes);
    }

    private static CborValue RandomArray(Random random, int depth)
    {
        var count = random.Next(0, 5);
        var items = new List<CborValue>(count);
        for (var i = 0; i < count; i++)
        {
            items.Add(RandomValue(random, depth));
        }

        return CborValue.Array(items);
    }

    private static CborValue RandomMap(Random random, int depth)
    {
        var count = random.Next(0, 5);
        var entries = new List<KeyValuePair<CborValue, CborValue>>(count);
        var keys = new List<CborValue>(count);

        for (var i = 0; i < count; i++)
        {
            keys.Add(CborValue.Text($"k{i}_{RandomText(random)}"));
        }

        foreach (var key in keys.OrderBy(k => DeterministicCborEncoder.Encode(k), ByteArrayComparer.Instance))
        {
            entries.Add(new KeyValuePair<CborValue, CborValue>(key, RandomValue(random, depth)));
        }

        return CborValue.Map(entries);
    }

    private static string RandomText(Random random)
    {
        var length = random.Next(1, 16);
        var chars = new char[length];
        for (var i = 0; i < chars.Length; i++)
        {
            chars[i] = (char)random.Next(0x61, 0x7A);
        }

        return new string(chars);
    }

    private static byte[] FromHex(string hex) => Convert.FromHexString(hex);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();

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

            if (x.Length != y.Length)
            {
                return x.Length.CompareTo(y.Length);
            }

            return x.AsSpan().SequenceCompareTo(y);
        }
    }
}