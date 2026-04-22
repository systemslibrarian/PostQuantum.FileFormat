using PostQuantum.FileFormat.Crypto;

namespace PostQuantum.FileFormat.Tests.Crypto;

public sealed class HkdfCombinerTests
{
    [Fact]
    public void DeriveKek_is_deterministic_for_identical_inputs()
    {
        var x = Enumerable.Repeat((byte)0x11, 32).ToArray();
        var m = Enumerable.Repeat((byte)0x22, 32).ToArray();
        var fileId = Enumerable.Repeat((byte)0x33, 16).ToArray();

        var k1 = HkdfCombiner.DeriveKek(x, m, fileId, 7);
        var k2 = HkdfCombiner.DeriveKek(x, m, fileId, 7);

        Assert.Equal(32, k1.Length);
        Assert.Equal(k1, k2);
    }

    [Fact]
    public void DeriveKek_changes_when_inputs_change()
    {
        var x = Enumerable.Repeat((byte)0x11, 32).ToArray();
        var m = Enumerable.Repeat((byte)0x22, 32).ToArray();
        var fileId = Enumerable.Repeat((byte)0x33, 16).ToArray();

        var baseline = HkdfCombiner.DeriveKek(x, m, fileId, 1);
        var changedX = HkdfCombiner.DeriveKek(Enumerable.Repeat((byte)0x12, 32).ToArray(), m, fileId, 1);
        var changedM = HkdfCombiner.DeriveKek(x, Enumerable.Repeat((byte)0x23, 32).ToArray(), fileId, 1);
        var changedFile = HkdfCombiner.DeriveKek(x, m, Enumerable.Repeat((byte)0x34, 16).ToArray(), 1);
        var changedIndex = HkdfCombiner.DeriveKek(x, m, fileId, 2);

        Assert.NotEqual(baseline, changedX);
        Assert.NotEqual(baseline, changedM);
        Assert.NotEqual(baseline, changedFile);
        Assert.NotEqual(baseline, changedIndex);
    }

    [Fact]
    public void DeriveChunkKey_is_deterministic_and_index_bound()
    {
        var dek = Enumerable.Repeat((byte)0x44, 32).ToArray();
        var k0a = HkdfCombiner.DeriveChunkKey(dek, 0);
        var k0b = HkdfCombiner.DeriveChunkKey(dek, 0);
        var k1 = HkdfCombiner.DeriveChunkKey(dek, 1);

        Assert.Equal(k0a, k0b);
        Assert.NotEqual(k0a, k1);
        Assert.Equal(32, k0a.Length);
    }
}
