using System.Security.Cryptography;
using System.Text.Json;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;
using PostQuantum.FileFormat.TestSupport;

var root = ResolveRepoRoot();
var outDir = Path.Combine(root, "test-vectors", "v1");
var casesDir = Path.Combine(outDir, "cases");
Directory.CreateDirectory(casesDir);

var provider = new BouncyCastleCryptoProvider();

var idA = GenerateIdentity("id-a", provider, "identity-a-seed");
var idB = GenerateIdentity("id-b", provider, "identity-b-seed");
var signer = GenerateSigner(provider, "signer-seed");

var vectors = new List<VectorManifestEntry>();

for (var i = 1; i <= 14; i++)
{
    var signed = i % 2 == 0;
    var chunkSizes = new[] { 4096, 8192, 16384 };
    var chunkSize = chunkSizes[(i - 1) % chunkSizes.Length];

    var plaintext = DeterministicBytes(500 + i * 3791, $"tv-pos-{i}-plaintext");
    var recipients = i % 4 == 0 ? new[] { idA.PublicKey, idB.PublicKey } : new[] { idA.PublicKey };

    var path = $"cases/TV-{i:000}.pqf";
    var bytes = await BuildEncryptedAsync(
        plaintext,
        recipients,
        signed ? signer : null,
        chunkSize,
        provider,
        $"tv-pos-{i}-rng");

    await File.WriteAllBytesAsync(Path.Combine(outDir, path), bytes);

    vectors.Add(new VectorManifestEntry(
        Id: $"TV-{i:000}",
        File: path,
        Expect: "success",
        Identity: "id-a",
        Reason: null,
        StreamingPostHocFailure: false,
        PlaintextSha256: Convert.ToHexString(SHA256.HashData(plaintext))));
}

var baseSigned = await File.ReadAllBytesAsync(Path.Combine(outDir, "cases/TV-002.pqf"));
var baseUnsigned = await File.ReadAllBytesAsync(Path.Combine(outDir, "cases/TV-001.pqf"));

var negatives = new List<(string id, byte[] bytes, string reason, bool postHoc, string identity)>
{
    ("TV-NEG-001", Mutate(baseUnsigned, b => b[0] ^= 0xFF), nameof(PqfRefusalReason.MagicMismatch), false, "id-a"),
    ("TV-NEG-002", Mutate(baseUnsigned, b => b[5] ^= 0x01), nameof(PqfRefusalReason.VersionMismatch), false, "id-a"),
    ("TV-NEG-003", baseUnsigned[..^1], nameof(PqfRefusalReason.ChunkLengthExceedsRemainingBytes), false, "id-a"),
    ("TV-NEG-004", Append(baseUnsigned, 0xAA), nameof(PqfRefusalReason.TrailingDataAfterExpectedEof), false, "id-a"),
    ("TV-NEG-005", MutateFooterMagic(baseUnsigned), nameof(PqfRefusalReason.FooterMagicInvalid), false, "id-a"),
    ("TV-NEG-006", MutateFirstChunkFlags(baseUnsigned, 0x80), nameof(PqfRefusalReason.ReservedChunkFlagBitsSet), false, "id-a"),
    ("TV-NEG-007", MutateFirstChunkLength(baseUnsigned, uint.MaxValue), nameof(PqfRefusalReason.TruncationDetected), false, "id-a"),
    ("TV-NEG-008", MutateFirstCiphertextByte(baseUnsigned), nameof(PqfRefusalReason.AeadTagFailure), false, "id-a"),
    ("TV-NEG-009", Mutate(baseSigned, b => b[^1] ^= 0x01), nameof(PqfRefusalReason.SignatureVerificationFailure), true, "id-a"),
    ("TV-NEG-010", Mutate(baseSigned, b => b[10] ^= 0x01), nameof(PqfRefusalReason.NonDeterministicCborEncoding), false, "id-a"),
    ("TV-NEG-011", Mutate(baseSigned, b => b[^500] ^= 0x01), nameof(PqfRefusalReason.SignatureVerificationFailure), true, "id-a"),
    ("TV-NEG-012", Mutate(baseUnsigned, b => { b[6] = 0xFF; b[7] = 0xFF; b[8] = 0xFF; b[9] = 0xFF; }), nameof(PqfRefusalReason.HeaderLengthExceedsLimit), false, "id-a"),
    ("TV-NEG-013", Mutate(baseUnsigned, b => { b[6] = 0x00; b[7] = 0x00; b[8] = 0x00; b[9] = 0x00; }), nameof(PqfRefusalReason.HeaderLengthExceedsLimit), false, "id-a"),
    ("TV-NEG-014", Mutate(baseUnsigned, b => b[10] ^= 0x20), nameof(PqfRefusalReason.TrailingDataAfterExpectedEof), false, "id-a"),
    ("TV-NEG-015", Mutate(baseUnsigned, b => b[^30] ^= 0x10), nameof(PqfRefusalReason.AeadTagFailure), false, "id-a"),
    ("TV-NEG-016", Mutate(baseUnsigned, b => b[^40] ^= 0x20), nameof(PqfRefusalReason.AeadTagFailure), false, "id-a"),
    ("TV-NEG-017", Mutate(baseUnsigned, b => b[^50] ^= 0x40), nameof(PqfRefusalReason.AeadTagFailure), false, "id-a"),
    ("TV-NEG-018", MutateFirstChunkFlags(baseUnsigned, 0x02), nameof(PqfRefusalReason.ReservedChunkFlagBitsSet), false, "id-a"),
    ("TV-NEG-019", MutateFooterCount(baseUnsigned, 9_999), nameof(PqfRefusalReason.FooterChunkCountMismatch), false, "id-a"),
    ("TV-NEG-020", MutateFooterPlaintextBytes(baseUnsigned, 123), nameof(PqfRefusalReason.FooterPlaintextBytesMismatch), false, "id-a"),
    ("TV-NEG-021", baseUnsigned, nameof(PqfRefusalReason.IdentityMatchesNoRecipient), false, "id-b"),
    ("TV-NEG-022", Mutate(baseUnsigned, b => b[^2] ^= 0x11), nameof(PqfRefusalReason.FooterPlaintextBytesMismatch), false, "id-a"),
};

foreach (var neg in negatives)
{
    var path = $"cases/{neg.id}.pqf";
    await File.WriteAllBytesAsync(Path.Combine(outDir, path), neg.bytes);
    vectors.Add(new VectorManifestEntry(
        Id: neg.id,
        File: path,
        Expect: "failure",
        Identity: neg.identity,
        Reason: neg.reason,
        StreamingPostHocFailure: neg.postHoc,
        PlaintextSha256: null));
}

var manifest = new VectorManifest(
    Version: "v1",
    Identities:
    [
        new IdentityManifest("id-a", Convert.ToBase64String(idA.PublicKey.ToCanonicalBinary()), Convert.ToBase64String(idA.X25519PrivateKey.ToArray()), Convert.ToBase64String(idA.MlKem1024PrivateKey.ToArray())),
        new IdentityManifest("id-b", Convert.ToBase64String(idB.PublicKey.ToCanonicalBinary()), Convert.ToBase64String(idB.X25519PrivateKey.ToArray()), Convert.ToBase64String(idB.MlKem1024PrivateKey.ToArray())),
    ],
    Vectors: vectors);

var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
await File.WriteAllTextAsync(Path.Combine(outDir, "manifest.json"), json + Environment.NewLine);

Console.WriteLine($"Generated {vectors.Count(v => v.Expect == "success")} positive and {vectors.Count(v => v.Expect == "failure")} negative vectors in {outDir}");

static string ResolveRepoRoot()
{
    var current = new DirectoryInfo(AppContext.BaseDirectory);
    while (current is not null)
    {
        var candidate = Path.Combine(current.FullName, "PostQuantum.FileFormat.sln");
        if (File.Exists(candidate))
        {
            return current.FullName;
        }

        current = current.Parent;
    }

    throw new InvalidOperationException("Could not locate repository root.");
}

static PqfIdentity GenerateIdentity(string name, ICryptoProvider provider, string seed)
{
    var rng = new InjectableRandomness(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(seed)));
    switch (provider)
    {
        case BouncyCastleCryptoProvider bc:
            bc.SetInjectableRandomness(rng);
            break;
        case BclCryptoProvider bcl:
            bcl.SetInjectableRandomness(rng);
            break;
    }

    return PqfIdentity.Generate(provider);
}

static PqfSigningIdentity GenerateSigner(ICryptoProvider provider, string seed)
{
    var rng = new InjectableRandomness(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(seed)));
    switch (provider)
    {
        case BouncyCastleCryptoProvider bc:
            bc.SetInjectableRandomness(rng);
            break;
        case BclCryptoProvider bcl:
            bcl.SetInjectableRandomness(rng);
            break;
    }

    return PqfSigningIdentity.Generate(provider);
}

static async Task<byte[]> BuildEncryptedAsync(
    byte[] plaintext,
    IReadOnlyList<PqfPublicKey> recipients,
    PqfSigningIdentity? signer,
    int chunkSize,
    ICryptoProvider provider,
    string seed)
{
    var rng = new InjectableRandomness(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(seed)));
    using var source = new MemoryStream(plaintext);
    using var destination = new MemoryStream();

    await PqfFileWriter.EncryptAsync(
        source,
        destination,
        recipients,
        signer,
        chunkSize,
        provider,
        rng,
        createdUtc: new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
        cancellationToken: default);

    return destination.ToArray();
}

static byte[] DeterministicBytes(int length, string label)
{
    var seed = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(label));
    var rng = new InjectableRandomness(seed);
    var bytes = new byte[length];
    rng.Fill(bytes);
    return bytes;
}

static byte[] Append(byte[] source, byte b)
{
    var copy = new byte[source.Length + 1];
    Buffer.BlockCopy(source, 0, copy, 0, source.Length);
    copy[^1] = b;
    return copy;
}

static byte[] Mutate(byte[] source, Action<byte[]> mutator)
{
    var copy = source.ToArray();
    mutator(copy);
    return copy;
}

static byte[] MutateFooterMagic(byte[] source)
{
    var copy = source.ToArray();
    var footerOffset = FindFooterOffset(copy);
    copy[footerOffset] ^= 0x01;
    return copy;
}

static byte[] MutateFooterCount(byte[] source, long count)
{
    var copy = source.ToArray();
    var footerOffset = FindFooterOffset(copy);
    System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(copy.AsSpan(footerOffset + 4, 8), count);
    return copy;
}

static byte[] MutateFooterPlaintextBytes(byte[] source, long bytes)
{
    var copy = source.ToArray();
    var footerOffset = FindFooterOffset(copy);
    System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(copy.AsSpan(footerOffset + 12, 8), bytes);
    return copy;
}

static byte[] MutateFirstChunkFlags(byte[] source, byte flagMask)
{
    var copy = source.ToArray();
    var reader = PqfFileReader.OpenForValidation(copy);
    var offset = reader.Chunks[0].HeaderOffset + 4;
    copy[offset] |= flagMask;
    return copy;
}

static byte[] MutateFirstChunkLength(byte[] source, uint length)
{
    var copy = source.ToArray();
    var reader = PqfFileReader.OpenForValidation(copy);
    var offset = reader.Chunks[0].HeaderOffset;
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(copy.AsSpan(offset, 4), length);
    return copy;
}

static byte[] MutateFirstCiphertextByte(byte[] source)
{
    var copy = source.ToArray();
    var reader = PqfFileReader.OpenForValidation(copy);
    var offset = reader.Chunks[0].DataOffset;
    copy[offset] ^= 0x40;
    return copy;
}

static int FindFooterOffset(byte[] source)
{
    var reader = PqfFileReader.OpenForValidation(source);
    return reader.FileBytes.Length - 20 - (reader.Header.Signer is not null ? HybridSigner.HybridSignatureLength : 0);
}

internal sealed record VectorManifest(
    string Version,
    IReadOnlyList<IdentityManifest> Identities,
    IReadOnlyList<VectorManifestEntry> Vectors);

internal sealed record IdentityManifest(
    string Id,
    string PublicKey,
    string X25519PrivateKey,
    string MlKem1024PrivateKey);

internal sealed record VectorManifestEntry(
    string Id,
    string File,
    string Expect,
    string Identity,
    string? Reason,
    bool StreamingPostHocFailure,
    string? PlaintextSha256);
