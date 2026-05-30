using PostQuantum.FileFormat.Crypto;

namespace PostQuantum.FileFormat.Tests.Crypto;

public sealed class HkdfCombinerTests
{
    // KEM-level KEK derivation moved to X-Wing (see XWingKemTests). The
    // remaining surface here is the per-chunk HKDF expansion used by
    // ChunkCipher, which is unrelated to F2's KEM-combiner concern.

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
