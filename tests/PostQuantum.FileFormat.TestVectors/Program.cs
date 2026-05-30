using System.Security.Cryptography;
using System.Text.Json;
using PostQuantum.FileFormat.Cbor;
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
    // TV-NEG-003: trailing-byte truncation. The streaming reader exhausts the
    // input while reading the 20-byte footer; the legacy in-memory reader saw
    // the same byte deficit one frame earlier as a chunk-length overrun. Both
    // are equally fail-closed; TruncationDetected is the more accurate
    // explanation for "file is one byte short".
    ("TV-NEG-003", baseUnsigned[..^1], nameof(PqfRefusalReason.TruncationDetected), true, "id-a"),
    // TV-NEG-004: appended trailing byte. The streaming reader emits plaintext
    // and reads the footer normally, then detects the extra byte during the
    // post-trailer EOF probe — so this is a post-hoc failure in streaming mode.
    ("TV-NEG-004", Append(baseUnsigned, 0xAA), nameof(PqfRefusalReason.TrailingDataAfterExpectedEof), true, "id-a"),
    // TV-NEG-005: footer magic corruption is detected after the chunk stream
    // has been drained, so streaming mode has already emitted plaintext.
    ("TV-NEG-005", MutateFooterMagic(baseUnsigned), nameof(PqfRefusalReason.FooterMagicInvalid), true, "id-a"),
    ("TV-NEG-006", MutateFirstChunkFlags(baseUnsigned, 0x80), nameof(PqfRefusalReason.ReservedChunkFlagBitsSet), false, "id-a"),
    // TV-NEG-007: forged chunk_length = uint.MaxValue. The streaming reader
    // bounds chunk frames at chunk_size+16 (≤ 16 MiB + 16) and refuses
    // immediately at the per-chunk bound rather than waiting until the read
    // of the bogus payload exhausts the stream. The new reason is strictly
    // more precise about the defect.
    ("TV-NEG-007", MutateFirstChunkLength(baseUnsigned, uint.MaxValue), nameof(PqfRefusalReason.ChunkLengthExceedsRemainingBytes), false, "id-a"),
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
    // TV-NEG-019/020: footer count/byte-tally mismatches are detected only
    // after every chunk has been drained, so streaming mode has emitted the
    // (cryptographically authentic) plaintext before refusing.
    ("TV-NEG-019", MutateFooterCount(baseUnsigned, 9_999), nameof(PqfRefusalReason.FooterChunkCountMismatch), true, "id-a"),
    ("TV-NEG-020", MutateFooterPlaintextBytes(baseUnsigned, 123), nameof(PqfRefusalReason.FooterPlaintextBytesMismatch), true, "id-a"),
    ("TV-NEG-021", baseUnsigned, nameof(PqfRefusalReason.IdentityMatchesNoRecipient), false, "id-b"),
    ("TV-NEG-022", Mutate(baseUnsigned, b => b[^2] ^= 0x11), nameof(PqfRefusalReason.FooterPlaintextBytesMismatch), true, "id-a"),
    // TV-NEG-023..033: header-schema malformations. Each is produced by parsing
    // the deterministic CBOR header of an unsigned (or signed, for the signer
    // case) base vector, mutating the structured value, re-encoding it
    // deterministically, and splicing it back with a corrected length prefix.
    // Header-schema validation runs before chunk/signature processing, so the
    // (now-stale) tail bytes are irrelevant to the refusal.
    // Unknown header field at the top level (spec §4.3).
    ("TV-NEG-023", MutateHeader(baseUnsigned, e => e.Add(new(CborValue.Text("x_unknown_field"), CborValue.Uint(1)))), nameof(PqfRefusalReason.UnknownHeaderField), false, "id-a"),
    // Unknown field inside the 'alg' map (spec §4.3 / §4.2.1).
    ("TV-NEG-024", MutateHeader(baseUnsigned, e => AddNestedMapField(e, "alg", "x_unknown_alg", CborValue.Text("x"))), nameof(PqfRefusalReason.UnknownHeaderField), false, "id-a"),
    // Unknown field inside the first recipient map (spec §4.3 / §8.4).
    ("TV-NEG-025", MutateHeader(baseUnsigned, e => AddFirstRecipientField(e, "x_unknown_recipient", CborValue.Bytes(new byte[1]))), nameof(PqfRefusalReason.UnknownHeaderField), false, "id-a"),
    // Unknown field inside the 'signer' map (spec §4.3) — requires a signed base.
    ("TV-NEG-026", MutateHeader(baseSigned, e => AddNestedMapField(e, "signer", "x_unknown_signer", CborValue.Bytes(new byte[1]))), nameof(PqfRefusalReason.UnknownHeaderField), false, "id-a"),
    // Algorithm identifier mismatch: a non-conformant KEM value (spec §4.2.1).
    ("TV-NEG-027", MutateHeader(baseUnsigned, e => SetNestedMapField(e, "alg", "kem", CborValue.Text("x25519+ml-kem-1024"))), nameof(PqfRefusalReason.AlgorithmIdentifierMismatch), false, "id-a"),
    // Missing required field: drop 'chunk_size' (spec §6.3 step 4).
    ("TV-NEG-028", MutateHeader(baseUnsigned, e => RemoveKey(e, "chunk_size")), nameof(PqfRefusalReason.MissingRequiredField), false, "id-a"),
    // Empty recipients array (spec §8.4).
    ("TV-NEG-029", MutateHeader(baseUnsigned, e => SetKey(e, "recipients", CborValue.Array([]))), nameof(PqfRefusalReason.RecipientsEmpty), false, "id-a"),
    // Malformed 'created' timestamp: offset form instead of UTC 'Z' (spec §8.4).
    ("TV-NEG-030", MutateHeader(baseUnsigned, e => SetKey(e, "created", CborValue.Tag(0, CborValue.Text("2025-01-01T00:00:00+00:00")))), nameof(PqfRefusalReason.CreatedTimestampInvalid), false, "id-a"),
    // Invalid 'chunk_size': in range but not a power of two (spec §6.3 step 6).
    ("TV-NEG-031", MutateHeader(baseUnsigned, e => SetKey(e, "chunk_size", CborValue.Uint(5000))), nameof(PqfRefusalReason.ChunkSizeInvalid), false, "id-a"),
    // Binary field with wrong length: 'file_id' truncated to 15 bytes (spec §4.2.2).
    ("TV-NEG-032", MutateHeader(baseUnsigned, e => SetKey(e, "file_id", CborValue.Bytes(new byte[15]))), nameof(PqfRefusalReason.BinaryFieldLengthMismatch), false, "id-a"),
    // Duplicate CBOR map key at the top level (spec §4.3 / deterministic-CBOR).
    ("TV-NEG-033", MutateHeader(baseUnsigned, DuplicateChunkSizeKey), nameof(PqfRefusalReason.DuplicateCborKey), false, "id-a"),
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
        new IdentityManifest("id-a", Convert.ToBase64String(idA.PublicKey.ToCanonicalBinary()), Convert.ToBase64String(idA.X25519PrivateKey.ToArray()), Convert.ToBase64String(idA.MlKem768PrivateKey.ToArray())),
        new IdentityManifest("id-b", Convert.ToBase64String(idB.PublicKey.ToCanonicalBinary()), Convert.ToBase64String(idB.X25519PrivateKey.ToArray()), Convert.ToBase64String(idB.MlKem768PrivateKey.ToArray())),
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
        deterministicSigning: true,
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

// --- Header-schema mutation helpers (TV-NEG-023..033) ---------------------
// These parse the deterministic CBOR header out of a base vector, apply a
// structured transform, re-encode deterministically, and splice the result
// back into the container with a corrected 4-byte header-length prefix.

static byte[] MutateHeader(byte[] source, Action<List<KeyValuePair<CborValue, CborValue>>> transform)
{
    var oldLen = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(source.AsSpan(6, 4));
    var headerValue = (CborValue.MapValue)DeterministicCborValidator.ParseStrict(source.AsMemory(10, oldLen));

    var entries = headerValue.Entries.ToList();
    transform(entries);
    var newHeaderBytes = DeterministicCborEncoder.Encode(CborValue.Map(entries));

    var tail = source.AsSpan(10 + oldLen).ToArray();
    var result = new byte[10 + newHeaderBytes.Length + tail.Length];
    Buffer.BlockCopy(source, 0, result, 0, 10);
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(6, 4), (uint)newHeaderBytes.Length);
    Buffer.BlockCopy(newHeaderBytes, 0, result, 10, newHeaderBytes.Length);
    Buffer.BlockCopy(tail, 0, result, 10 + newHeaderBytes.Length, tail.Length);
    return result;
}

static int IndexOfKey(List<KeyValuePair<CborValue, CborValue>> entries, string key)
    => entries.FindIndex(e => e.Key is CborValue.TextValue t && t.Value == key);

static void SetKey(List<KeyValuePair<CborValue, CborValue>> entries, string key, CborValue value)
{
    var i = IndexOfKey(entries, key);
    if (i < 0)
    {
        throw new InvalidOperationException($"Header field '{key}' not found.");
    }

    entries[i] = new KeyValuePair<CborValue, CborValue>(entries[i].Key, value);
}

static void RemoveKey(List<KeyValuePair<CborValue, CborValue>> entries, string key)
{
    var i = IndexOfKey(entries, key);
    if (i < 0)
    {
        throw new InvalidOperationException($"Header field '{key}' not found.");
    }

    entries.RemoveAt(i);
}

static void AddNestedMapField(List<KeyValuePair<CborValue, CborValue>> entries, string mapKey, string fieldKey, CborValue fieldValue)
{
    var i = IndexOfKey(entries, mapKey);
    if (i < 0 || entries[i].Value is not CborValue.MapValue map)
    {
        throw new InvalidOperationException($"Header field '{mapKey}' is not a map.");
    }

    var inner = map.Entries.ToList();
    inner.Add(new KeyValuePair<CborValue, CborValue>(CborValue.Text(fieldKey), fieldValue));
    entries[i] = new KeyValuePair<CborValue, CborValue>(entries[i].Key, CborValue.Map(inner));
}

static void SetNestedMapField(List<KeyValuePair<CborValue, CborValue>> entries, string mapKey, string fieldKey, CborValue fieldValue)
{
    var i = IndexOfKey(entries, mapKey);
    if (i < 0 || entries[i].Value is not CborValue.MapValue map)
    {
        throw new InvalidOperationException($"Header field '{mapKey}' is not a map.");
    }

    var inner = map.Entries.ToList();
    var j = inner.FindIndex(e => e.Key is CborValue.TextValue t && t.Value == fieldKey);
    if (j < 0)
    {
        throw new InvalidOperationException($"Field '{fieldKey}' not found in '{mapKey}'.");
    }

    inner[j] = new KeyValuePair<CborValue, CborValue>(inner[j].Key, fieldValue);
    entries[i] = new KeyValuePair<CborValue, CborValue>(entries[i].Key, CborValue.Map(inner));
}

static void AddFirstRecipientField(List<KeyValuePair<CborValue, CborValue>> entries, string fieldKey, CborValue fieldValue)
{
    var i = IndexOfKey(entries, "recipients");
    if (i < 0 || entries[i].Value is not CborValue.ArrayValue array || array.Items.Count == 0
        || array.Items[0] is not CborValue.MapValue recipient)
    {
        throw new InvalidOperationException("Header field 'recipients' is not a non-empty array of maps.");
    }

    var inner = recipient.Entries.ToList();
    inner.Add(new KeyValuePair<CborValue, CborValue>(CborValue.Text(fieldKey), fieldValue));

    var items = array.Items.ToList();
    items[0] = CborValue.Map(inner);
    entries[i] = new KeyValuePair<CborValue, CborValue>(entries[i].Key, CborValue.Array(items));
}

static void DuplicateChunkSizeKey(List<KeyValuePair<CborValue, CborValue>> entries)
{
    var i = IndexOfKey(entries, "chunk_size");
    if (i < 0)
    {
        throw new InvalidOperationException("Header field 'chunk_size' not found.");
    }

    // Append a second 'chunk_size' entry. The deterministic encoder emits both
    // (the map length includes the duplicate and the equal keys sort adjacent),
    // which a conforming reader must reject as a duplicate CBOR map key.
    entries.Add(new KeyValuePair<CborValue, CborValue>(entries[i].Key, entries[i].Value));
}

internal sealed record VectorManifest(
    string Version,
    IReadOnlyList<IdentityManifest> Identities,
    IReadOnlyList<VectorManifestEntry> Vectors);

internal sealed record IdentityManifest(
    string Id,
    string PublicKey,
    string X25519PrivateKey,
    string MlKem768PrivateKey);

internal sealed record VectorManifestEntry(
    string Id,
    string File,
    string Expect,
    string Identity,
    string? Reason,
    bool StreamingPostHocFailure,
    string? PlaintextSha256);
