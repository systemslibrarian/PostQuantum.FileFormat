using PostQuantum.FileFormat.Crypto;

namespace PostQuantum.FileFormat.Tests.Crypto;

// Pinned known-answer vectors for HkdfCombiner.DeriveChunkKey (spec §5.2).
//
// Construction under test:
//   chunk_key = HKDF-Expand(SHA-256,
//                           PRK  = DEK,
//                           info = "PQF1-chunk-v1" || uint64BE(chunkIndex),
//                           L    = 32)
//
// Vectors are committed verbatim after dual independent computation:
//   1. The .NET BCL System.Security.Cryptography.HKDF.Expand
//      (the primitive the production HkdfCombiner calls into).
//   2. RFC 5869 §2.3 reduced single-block form, T(1) = HMAC-SHA256(PRK, info || 0x01),
//      computed from raw HMAC-SHA256.
// Both implementations agree byte-exact on every vector below. The same five
// pairs are mirrored into the independent Rust impl at
// impl/rust/pqf-writer/tests/hkdf_chunk_key_kat.rs so the two implementations
// cannot drift on this primitive.
public sealed class HkdfCombinerKatTests
{
    public static IEnumerable<object[]> Vectors() => new[]
    {
        // Representative DEK = repeat(0x44, 32), edge chunk indices.
        new object[] { (byte)0x44, 0UL,
            "B9954575C12134A01D7DE7B2482230D68AFAF3D2222985B59C5F436FACF0286A" },
        new object[] { (byte)0x44, 1UL,
            "8AE81F7EA2402D261921E8415493C7159FB80E80F5C1A46C1D1513EF71022721" },
        new object[] { (byte)0x44, ulong.MaxValue,
            "5F9E16CDCA00F4AF17FF5E990D1D274F12A095793FD48493A0C0A08840A86286" },
        // Boundary DEKs at chunkIndex = 0.
        new object[] { (byte)0x00, 0UL,
            "E0E05D84A15D93FF9B66A9325367871169B1EAC2ECD983A217BC0556CFF8D4A7" },
        new object[] { (byte)0xFF, 0UL,
            "765AB31275F7ACBF7AAF3500651B9528037427B55C8670C07F74503473D06DE8" },
    };

    [Theory]
    [MemberData(nameof(Vectors))]
    public void DeriveChunkKey_matches_pinned_vector(byte dekByte, ulong chunkIndex, string expectedHex)
    {
        var dek = Enumerable.Repeat(dekByte, 32).ToArray();
        var actual = HkdfCombiner.DeriveChunkKey(dek, chunkIndex);
        Assert.Equal(expectedHex, Convert.ToHexString(actual));
    }
}
