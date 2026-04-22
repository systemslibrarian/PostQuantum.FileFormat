using PostQuantum.FileFormat.Cbor;
using System.Text;

namespace PostQuantum.FileFormat.Tests.Cbor;

public sealed class DeterministicCborEncoderTests
{
    [Fact]
    public void EmptyMap_encodes_to_single_byte_0xA0()
    {
        var encoded = DeterministicCborEncoder.Encode(CborValue.Map(Array.Empty<KeyValuePair<CborValue, CborValue>>()));
        Assert.Equal("A0", ToHex(encoded));
    }

    [Fact]
    public void Map_with_two_keys_sorts_shorter_key_first()
    {
        var map = CborValue.Map(
        [
            new(CborValue.Text("aa"), CborValue.Uint(2)),
            new(CborValue.Text("a"), CborValue.Uint(1))
        ]);

        var encoded = DeterministicCborEncoder.Encode(map);
        Assert.Equal("A261610162616102", ToHex(encoded));
    }

    [Fact]
    public void Map_with_equal_length_keys_sorts_lexicographically()
    {
        var map = CborValue.Map(
        [
            new(CborValue.Text("b"), CborValue.Uint(2)),
            new(CborValue.Text("a"), CborValue.Uint(1))
        ]);

        var encoded = DeterministicCborEncoder.Encode(map);
        Assert.Equal("A2616101616202", ToHex(encoded));
    }

    [Fact]
    public void Uint_0_encodes_as_0x00_not_0x1800()
    {
        var encoded = DeterministicCborEncoder.Encode(CborValue.Uint(0));
        Assert.Equal("00", ToHex(encoded));
    }

    [Fact]
    public void Uint_23_encodes_in_one_byte()
    {
        var encoded = DeterministicCborEncoder.Encode(CborValue.Uint(23));
        Assert.Equal("17", ToHex(encoded));
    }

    [Fact]
    public void Uint_24_encodes_in_two_bytes_0x1818()
    {
        var encoded = DeterministicCborEncoder.Encode(CborValue.Uint(24));
        Assert.Equal("1818", ToHex(encoded));
    }

    [Fact]
    public void Uint_256_encodes_in_three_bytes_0x190100()
    {
        var encoded = DeterministicCborEncoder.Encode(CborValue.Uint(256));
        Assert.Equal("190100", ToHex(encoded));
    }

    [Fact]
    public void Uint_65536_encodes_in_five_bytes_0x1A00010000()
    {
        var encoded = DeterministicCborEncoder.Encode(CborValue.Uint(65536));
        Assert.Equal("1A00010000", ToHex(encoded));
    }

    [Fact]
    public void Bytes_32_encodes_with_major_type_2_length_prefix()
    {
        var data = Enumerable.Repeat((byte)0x42, 32).ToArray();
        var encoded = DeterministicCborEncoder.Encode(CborValue.Bytes(data));

        Assert.Equal(34, encoded.Length);
        Assert.Equal((byte)0x58, encoded[0]);
        Assert.Equal((byte)0x20, encoded[1]);
    }

    [Fact]
    public void Text_utf8_encodes_with_major_type_3_length_prefix()
    {
        var encoded = DeterministicCborEncoder.Encode(CborValue.Text("pqf"));
        Assert.Equal("63707166", ToHex(encoded));
    }

    [Fact]
    public void Text_invalid_utf8_throws()
    {
        var invalid = "\uD800";
        Assert.Throws<EncoderFallbackException>(() => DeterministicCborEncoder.Encode(CborValue.Text(invalid)));
    }

    [Fact]
    public void Array_empty_encodes_as_0x80()
    {
        var encoded = DeterministicCborEncoder.Encode(CborValue.Array(Array.Empty<CborValue>()));
        Assert.Equal("80", ToHex(encoded));
    }

    [Fact]
    public void Array_three_uints_encodes_correctly()
    {
        var encoded = DeterministicCborEncoder.Encode(CborValue.Array([CborValue.Uint(1), CborValue.Uint(2), CborValue.Uint(3)]));
        Assert.Equal("83010203", ToHex(encoded));
    }

    [Fact]
    public void Tag0_datetime_encodes_with_tag_prefix_0xC0()
    {
        var encoded = DeterministicCborEncoder.Encode(CborValue.Tag(0, CborValue.Text("2026-04-21T14:30:00Z")));
        Assert.Equal((byte)0xC0, encoded[0]);
    }

    [Fact]
    public void Bool_true_encodes_as_0xF5()
    {
        var encoded = DeterministicCborEncoder.Encode(CborValue.Bool(true));
        Assert.Equal("F5", ToHex(encoded));
    }

    [Fact]
    public void Bool_false_encodes_as_0xF4()
    {
        var encoded = DeterministicCborEncoder.Encode(CborValue.Bool(false));
        Assert.Equal("F4", ToHex(encoded));
    }

    [Fact]
    public void Null_encodes_as_0xF6()
    {
        var encoded = DeterministicCborEncoder.Encode(CborValue.Null);
        Assert.Equal("F6", ToHex(encoded));
    }

    private static string ToHex(byte[] data) => Convert.ToHexString(data);
}