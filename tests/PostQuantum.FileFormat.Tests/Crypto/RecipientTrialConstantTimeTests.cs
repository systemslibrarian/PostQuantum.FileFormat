using System.Diagnostics;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;
using Xunit.Abstractions;

namespace PostQuantum.FileFormat.Tests.Crypto;

/// <summary>
/// dudect-style scaffold for measuring the recipient-trial loop in
/// <see cref="AuthenticatedModeDecryptor.ResolveDek"/>.
///
/// The recipient-trial loop iterates over every recipient block and
/// attempts to unwrap the DEK with each. The leakage we worry about is
/// the loop terminating early or branching on which recipient matched,
/// which would let an attacker learn — by timing alone — which recipient
/// holds the file's DEK beyond what the unencrypted recipient list
/// already reveals.
///
/// This test is currently **measurement-only**: it gathers timing samples
/// for "identity is the first recipient" vs "identity is the last
/// recipient" and computes a Welch's t-statistic. It writes the result to
/// the test output so it shows up in CI logs, but does not gate. Once we
/// trust the measurement setup (warmup, sample count, baseline noise), a
/// future version of this test can fail when |t| exceeds a threshold,
/// turning this into a real CT regression gate.
///
/// References:
///   - Reparaz, Balasch, Verbauwhede. "Dude, is my code constant time?"
///     (DATE 2017).
///   - https://github.com/oreparaz/dudect
///
/// We do NOT claim a single-machine, single-run measurement is sound
/// evidence of constant time. It is a *necessary, not sufficient* sanity
/// check on top of the structural arguments in
/// docs/SIDE-CHANNEL-POSTURE.md.
/// </summary>
[Trait("Category", "ConstantTime")]
public sealed class RecipientTrialConstantTimeTests
{
    private readonly ITestOutputHelper _out;

    public RecipientTrialConstantTimeTests(ITestOutputHelper output)
    {
        _out = output;
    }

    [Fact(Skip = "Measurement-only — run explicitly. Will be promoted to a gate once baseline noise is characterized.")]
    public void Recipient_trial_timing_does_not_depend_on_which_recipient_matches()
    {
        const int numRecipients = 4;
        const int warmupIterations = 200;
        const int measuredIterations = 2_000;

        var provider = CryptoProvider.Detect();
        var hybridKem = new HybridKem(provider);

        var identities = new PqfIdentity[numRecipients];
        try
        {
            for (var i = 0; i < numRecipients; i++)
            {
                identities[i] = PqfIdentity.Generate(provider);
            }

            var header = BuildHeaderWith(identities, provider);

            // Warmup: JIT, branch predictors, caches.
            for (var i = 0; i < warmupIterations; i++)
            {
                _ = AuthenticatedModeDecryptor.ResolveDek(header, identities[0], hybridKem);
                _ = AuthenticatedModeDecryptor.ResolveDek(header, identities[^1], hybridKem);
            }

            var firstWins = new double[measuredIterations];
            var lastWins  = new double[measuredIterations];

            // Interleave the two classes so any drift in machine load
            // affects both samples equally.
            for (var i = 0; i < measuredIterations; i++)
            {
                firstWins[i] = TimeOne(() => AuthenticatedModeDecryptor.ResolveDek(header, identities[0], hybridKem));
                lastWins[i]  = TimeOne(() => AuthenticatedModeDecryptor.ResolveDek(header, identities[^1], hybridKem));
            }

            var t = WelchTStatistic(firstWins, lastWins);
            var meanFirst = Mean(firstWins);
            var meanLast  = Mean(lastWins);

            _out.WriteLine($"recipient-trial CT: N={measuredIterations} recipients={numRecipients}");
            _out.WriteLine($"  mean(first-recipient wins) = {meanFirst:F2} ns/op");
            _out.WriteLine($"  mean(last-recipient wins)  = {meanLast:F2} ns/op");
            _out.WriteLine($"  Welch's t = {t:F3}");
            _out.WriteLine($"  (|t| > 4.5 would be alarming; |t| > 10 is clear evidence of timing dependence)");
        }
        finally
        {
            foreach (var id in identities)
            {
                id?.Dispose();
            }
        }
    }

    private static PqfFileHeader BuildHeaderWith(PqfIdentity[] identities, ICryptoProvider provider)
    {
        var fileId = new byte[16];
        System.Security.Cryptography.RandomNumberGenerator.Fill(fileId);

        var kem = new HybridKem(provider);
        var dek = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(dek);

        var header = new PqfFileHeader
        {
            FileId = fileId,
        };

        for (var i = 0; i < identities.Length; i++)
        {
            var (epk, ct, kek) = kem.Encapsulate(identities[i].PublicKey, fileId, (uint)i);
            var (nonce, wrapped) = DekWrapper.Wrap(kek, dek, fileId);
            SecureZero.Clear(kek);

            header.Recipients.Add(new PqfRecipientBlock
            {
                ClassicalEpk = epk,
                PqcCt = ct,
                WrappedDekNonce = nonce,
                WrappedDek = wrapped,
            });
        }

        SecureZero.Clear(dek);
        return header;
    }

    private static double TimeOne(Action body)
    {
        var sw = Stopwatch.StartNew();
        body();
        sw.Stop();
        // Convert to nanoseconds; Stopwatch ticks vary by platform.
        return sw.Elapsed.TotalNanoseconds;
    }

    private static double Mean(double[] xs)
    {
        var sum = 0.0;
        for (var i = 0; i < xs.Length; i++) sum += xs[i];
        return sum / xs.Length;
    }

    private static double Variance(double[] xs, double mean)
    {
        var sum = 0.0;
        for (var i = 0; i < xs.Length; i++)
        {
            var d = xs[i] - mean;
            sum += d * d;
        }
        return sum / (xs.Length - 1);
    }

    private static double WelchTStatistic(double[] a, double[] b)
    {
        var ma = Mean(a);
        var mb = Mean(b);
        var va = Variance(a, ma);
        var vb = Variance(b, mb);
        var se = Math.Sqrt(va / a.Length + vb / b.Length);
        if (se == 0.0) return 0.0;
        return (ma - mb) / se;
    }
}
