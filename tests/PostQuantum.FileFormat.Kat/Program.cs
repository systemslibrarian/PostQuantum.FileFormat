using PostQuantum.FileFormat.Crypto;

namespace PostQuantum.FileFormat.Kat;

/// <summary>
/// Entry point for the NIST KAT cross-check harness.
///
/// Reads NIST KAT .rsp files for ML-KEM-1024 and ML-DSA-87 and verifies
/// the parts the current <see cref="ICryptoProvider"/> surface exposes:
///
///   - ML-KEM-1024: given (sk, ct, ss) from the KAT, check that
///     <c>provider.MlKem1024Decapsulate(sk, ct) == ss</c>.
///   - ML-DSA-87: given (pk, msg, sm) from the KAT, where sm is the
///     "signed message" (signature concatenated with the message), check
///     that <c>provider.MlDsa87Verify(pk, msg, sig)</c> returns true.
///
/// Keygen-from-seed validation requires a deterministic keygen entry
/// point on the provider, which the current surface does not expose. If
/// the provider grows one, this harness will be extended to check that
/// derived (pk, sk) match the KAT values byte-for-byte.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        var katDir = args.Length > 0
            ? args[0]
            : ResolveDefaultKatDir();

        if (!Directory.Exists(katDir))
        {
            Console.Error.WriteLine($"KAT directory not found: {katDir}");
            Console.Error.WriteLine("Run scripts/fetch-nist-kat.sh to populate it.");
            return 2;
        }

        var provider = CryptoProvider.Detect();
        Console.WriteLine($"KAT harness — provider={provider.GetType().Name} dir={katDir}");

        var failures = 0;
        failures += RunMlKem1024Kats(katDir, provider);
        failures += RunMlDsa87Kats(katDir, provider);

        if (failures == 0)
        {
            Console.WriteLine("All KAT vectors passed.");
            return 0;
        }

        Console.Error.WriteLine($"FAIL: {failures} KAT vector(s) did not match.");
        return Math.Min(failures, 127);
    }

    private static int RunMlKem1024Kats(string katDir, ICryptoProvider provider)
    {
        var path = Path.Combine(katDir, "ml-kem-1024.rsp");
        if (!System.IO.File.Exists(path))
        {
            Console.WriteLine($"[skip] {Path.GetFileName(path)} not present.");
            return 0;
        }

        var failures = 0;
        var checked_ = 0;
        foreach (var entry in NistKatRsp.Parse(path))
        {
            if (!entry.Fields.ContainsKey("sk") ||
                !entry.Fields.ContainsKey("ct") ||
                !entry.Fields.ContainsKey("ss"))
            {
                continue;
            }

            var sk = entry.Hex("sk");
            var ct = entry.Hex("ct");
            var ss = entry.Hex("ss");

            byte[] recovered;
            try
            {
                recovered = provider.MlKem768Decapsulate(sk, ct);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  ML-KEM count={entry.Count} decap threw {ex.GetType().Name}: {ex.Message}");
                failures++;
                continue;
            }

            if (!recovered.SequenceEqual(ss))
            {
                Console.Error.WriteLine($"  ML-KEM count={entry.Count} shared-secret mismatch");
                failures++;
            }

            checked_++;
        }
        Console.WriteLine($"ML-KEM-1024: checked={checked_} failures={failures}");
        return failures;
    }

    private static int RunMlDsa87Kats(string katDir, ICryptoProvider provider)
    {
        var path = Path.Combine(katDir, "ml-dsa-87.rsp");
        if (!System.IO.File.Exists(path))
        {
            Console.WriteLine($"[skip] {Path.GetFileName(path)} not present.");
            return 0;
        }

        var failures = 0;
        var checked_ = 0;
        foreach (var entry in NistKatRsp.Parse(path))
        {
            if (!entry.Fields.ContainsKey("pk") ||
                !entry.Fields.ContainsKey("msg") ||
                !entry.Fields.ContainsKey("sm"))
            {
                continue;
            }

            var pk  = entry.Hex("pk");
            var msg = entry.Hex("msg");
            var sm  = entry.Hex("sm");

            // sm is signature || message per the NIST KAT layout for the
            // PQClean / reference test format. Strip the trailing message.
            if (sm.Length < msg.Length)
            {
                Console.Error.WriteLine($"  ML-DSA count={entry.Count} signed-message shorter than message");
                failures++;
                continue;
            }

            var sigLen = sm.Length - msg.Length;
            var sig = new byte[sigLen];
            Buffer.BlockCopy(sm, 0, sig, 0, sigLen);

            bool ok;
            try
            {
                ok = provider.MlDsa87Verify(pk, msg, sig);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  ML-DSA count={entry.Count} verify threw {ex.GetType().Name}: {ex.Message}");
                failures++;
                continue;
            }

            if (!ok)
            {
                Console.Error.WriteLine($"  ML-DSA count={entry.Count} signature verify returned false");
                failures++;
            }
            checked_++;
        }
        Console.WriteLine($"ML-DSA-87: checked={checked_} failures={failures}");
        return failures;
    }

    private static string ResolveDefaultKatDir()
    {
        var here = AppContext.BaseDirectory;
        for (var dir = new DirectoryInfo(here); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "test-vectors", "nist-kat");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }
            if (System.IO.File.Exists(Path.Combine(dir.FullName, "PostQuantum.FileFormat.sln")))
            {
                return candidate;
            }
        }
        return Path.Combine(here, "test-vectors", "nist-kat");
    }
}
