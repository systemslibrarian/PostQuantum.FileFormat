using System.Security.Cryptography;
using System.Text.Json;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;
using PostQuantum.FileFormat.TestSupport;

namespace PostQuantum.FileFormat.Differential;

/// <summary>
/// Generates N pseudo-random but structurally-valid PQF containers and
/// writes them under the output directory, plus a manifest.json the
/// Rust conformance binary can consume.
///
/// Each container is:
///   - signed iff the index is even
///   - has 1..4 recipients
///   - uses one of {4096, 8192, 16384, 65536} as chunk_size
///   - has a plaintext length drawn from a small set of edge sizes
///
/// All randomness is seeded by --seed so a CI run is reproducible.
/// Exit code is the number of self-roundtrip failures (sanity check
/// that the .NET writer/reader pair agrees with itself before the
/// Rust reader is invoked separately).
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        var seed = 1;
        var count = 12;
        var outDir = Path.Combine(Path.GetTempPath(), "pqf-differential");

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                // Parse as long then wrap into int range: CI passes
                // --seed $GITHUB_RUN_ID, an 11-digit value that overflows Int32.
                case "--seed": seed = unchecked((int)long.Parse(args[++i])); break;
                case "--count": count = int.Parse(args[++i]); break;
                case "--out": outDir = args[++i]; break;
                default:
                    Console.Error.WriteLine($"unknown flag: {args[i]}");
                    return 2;
            }
        }

        Directory.CreateDirectory(outDir);
        var casesDir = Path.Combine(outDir, "cases");
        Directory.CreateDirectory(casesDir);

        var provider = new BouncyCastleCryptoProvider();
        var rng = new Random(seed);

        var chunkSizes = new[] { 4096, 8192, 16384, 65536 };
        var plaintextSizes = new[] { 1, 64, 4095, 4096, 4097, 65535, 65536, 100_000 };

        var identities = Enumerable.Range(0, 4)
            .Select(i => GenerateIdentity($"id-{(char)('a' + i)}", provider, $"diff-seed-{seed}-{i}"))
            .ToArray();

        var signer = GenerateSigner(provider, $"diff-signer-seed-{seed}");

        var manifestIdentities = identities.Select(id => new
        {
            Id = id.Name,
            PublicKey = Convert.ToBase64String(id.Identity.PublicKey.ToCanonicalBinary()),
            X25519PrivateKey = Convert.ToBase64String(id.Identity.X25519PrivateKey.ToArray()),
            MlKem1024PrivateKey = Convert.ToBase64String(id.Identity.MlKem1024PrivateKey.ToArray()),
        }).ToList();

        var vectors = new List<object>();
        var selfRoundtripFailures = 0;

        for (var i = 1; i <= count; i++)
        {
            var signed = i % 2 == 0;
            var chunkSize = chunkSizes[rng.Next(chunkSizes.Length)];
            var ptSize = plaintextSizes[rng.Next(plaintextSizes.Length)];
            var nRecipients = 1 + rng.Next(4);

            var plaintext = new byte[ptSize];
            rng.NextBytes(plaintext);

            var chosen = Enumerable.Range(0, identities.Length).OrderBy(_ => rng.Next()).Take(nRecipients).ToArray();
            var pubs = chosen.Select(idx => identities[idx].Identity.PublicKey).ToArray();

            byte[] container;
            using (var src = new MemoryStream(plaintext))
            using (var enc = new MemoryStream())
            {
                PqfFileWriter.EncryptAsync(
                    src, enc, pubs, signed ? signer : null,
                    chunkSize, provider, randomness: null, createdUtc: null,
                    deterministicSigning: signed,
                    cancellationToken: default).GetAwaiter().GetResult();
                container = enc.ToArray();
            }

            var name = $"RAND-{i:000}.pqf";
            System.IO.File.WriteAllBytes(Path.Combine(casesDir, name), container);

            // Self-roundtrip: .NET writer -> .NET reader should be exact.
            try
            {
                using var ctIn = new MemoryStream(container);
                using var ptOut = new MemoryStream();
                PqfDecryptor.DecryptAsync(ctIn, ptOut, identities[chosen[0]].Identity).GetAwaiter().GetResult();
                if (!ptOut.ToArray().SequenceEqual(plaintext))
                {
                    Console.Error.WriteLine($"  {name}: self-roundtrip mismatch");
                    selfRoundtripFailures++;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  {name}: self-roundtrip threw {ex.GetType().Name}: {ex.Message}");
                selfRoundtripFailures++;
            }

            vectors.Add(new
            {
                Id = $"RAND-{i:000}",
                File = $"cases/{name}",
                Expect = "success",
                Identity = identities[chosen[0]].Name,
                Reason = (string?)null,
                StreamingPostHocFailure = false,
                PlaintextSha256 = Convert.ToHexString(SHA256.HashData(plaintext)),
            });
        }

        var manifest = new
        {
            Version = "v1-differential",
            Identities = manifestIdentities,
            Vectors = vectors,
        };
        var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        System.IO.File.WriteAllText(Path.Combine(outDir, "manifest.json"), json);

        Console.WriteLine($"Wrote {count} random containers to {outDir} (seed={seed}). Self-roundtrip failures: {selfRoundtripFailures}.");
        return selfRoundtripFailures == 0 ? 0 : 1;
    }

    private record IdentityWithName(string Name, PqfIdentity Identity);

    private static IdentityWithName GenerateIdentity(string name, ICryptoProvider provider, string seed)
    {
        var rng = new InjectableRandomness(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(seed)));
        if (provider is BouncyCastleCryptoProvider bc) bc.SetInjectableRandomness(rng);
        try { return new IdentityWithName(name, PqfIdentity.Generate(provider)); }
        finally { if (provider is BouncyCastleCryptoProvider bc2) bc2.SetInjectableRandomness(null); }
    }

    private static PqfSigningIdentity GenerateSigner(ICryptoProvider provider, string seed)
    {
        var rng = new InjectableRandomness(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(seed)));
        if (provider is BouncyCastleCryptoProvider bc) bc.SetInjectableRandomness(rng);
        try { return PqfSigningIdentity.Generate(provider); }
        finally { if (provider is BouncyCastleCryptoProvider bc2) bc2.SetInjectableRandomness(null); }
    }
}
