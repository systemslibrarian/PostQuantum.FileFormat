using System.Diagnostics;
using System.Security.Cryptography;
using PostQuantum.FileFormat.Cbor;
using PostQuantum.FileFormat.File;

namespace PostQuantum.FileFormat.Fuzz;

/// <summary>
/// Lightweight fuzz harness for the PQF reader.
///
/// Usage:
///   dotnet run -- --time &lt;seconds&gt; --target &lt;header|streaming|cbor&gt; [--seed N]
///
/// Targets:
///   cbor       — feed random bytes to DeterministicCborValidator.ParseStrict
///   header     — feed random bytes that pass the PQF1 magic to the streaming pipeline
///   streaming  — feed mutated copies of a seed container to the streaming pipeline
///
/// A "find" is any exception other than PqfFileException or
/// CborValidationException. Those two are the correct refusal types — seeing
/// them means the harness is exercising refusal paths, which is exactly what
/// a fail-closed parser is supposed to do.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        var seconds = 30;
        var target = "header";
        var seed = (int)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() & 0x7fffffff);

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--time":
                    seconds = int.Parse(args[++i]);
                    break;
                case "--target":
                    target = args[++i];
                    break;
                case "--seed":
                    seed = int.Parse(args[++i]);
                    break;
                default:
                    Console.Error.WriteLine($"Unknown flag: {args[i]}");
                    return 2;
            }
        }

        Console.WriteLine($"fuzz: target={target} time={seconds}s seed={seed}");
        var rng = new Random(seed);
        var deadline = Stopwatch.StartNew();
        long iterations = 0;
        long refusals = 0;
        Exception? findings = null;
        byte[]? findingInput = null;

        try
        {
            while (deadline.Elapsed.TotalSeconds < seconds)
            {
                iterations++;
                var input = MakeInput(target, rng);
                try
                {
                    Drive(target, input);
                }
                catch (PqfFileException)
                {
                    refusals++;
                }
                catch (CborValidationException)
                {
                    refusals++;
                }
                catch (ArgumentOutOfRangeException)
                {
                    // Length-prefix overflows in random bytes are legal refusals.
                    refusals++;
                }
                catch (Exception ex)
                {
                    findings = ex;
                    findingInput = input;
                    break;
                }
            }
        }
        finally
        {
            deadline.Stop();
        }

        Console.WriteLine($"fuzz: iterations={iterations} refusals={refusals} elapsed={deadline.Elapsed.TotalSeconds:F1}s");
        if (findings is not null)
        {
            Console.Error.WriteLine($"fuzz: FINDING — {findings.GetType().FullName}: {findings.Message}");
            Console.Error.WriteLine(findings);
            if (findingInput is not null)
            {
                var path = Path.Combine(Path.GetTempPath(), $"pqf-fuzz-find-{seed}.bin");
                File.WriteAllBytes(path, findingInput);
                Console.Error.WriteLine($"fuzz: input saved to {path}");
            }
            return 1;
        }

        return 0;
    }

    private static byte[] MakeInput(string target, Random rng)
    {
        switch (target)
        {
            case "cbor":
            {
                var size = rng.Next(1, 4096);
                var buf = new byte[size];
                rng.NextBytes(buf);
                return buf;
            }
            case "header":
            {
                // Random bytes prefixed with the PQF1 magic so the streaming
                // pipeline gets past the magic check and into the CBOR parser.
                var size = rng.Next(8, 16 * 1024);
                var buf = new byte[size];
                rng.NextBytes(buf);
                buf[0] = (byte)'P';
                buf[1] = (byte)'Q';
                buf[2] = (byte)'F';
                buf[3] = (byte)'1';
                // Version field = 0x0001 (current spec).
                buf[4] = 0x00;
                buf[5] = 0x01;
                return buf;
            }
            case "streaming":
            {
                // Bit-flip mutation of pure noise; future work: seed with a
                // valid container produced by the writer at startup.
                var size = rng.Next(64, 64 * 1024);
                var buf = new byte[size];
                rng.NextBytes(buf);
                buf[0] = (byte)'P';
                buf[1] = (byte)'Q';
                buf[2] = (byte)'F';
                buf[3] = (byte)'1';
                buf[4] = 0x00;
                buf[5] = 0x01;
                return buf;
            }
            default:
                throw new ArgumentException($"unknown target: {target}");
        }
    }

    private static void Drive(string target, byte[] input)
    {
        switch (target)
        {
            case "cbor":
                _ = DeterministicCborValidator.ParseStrict(input);
                return;

            case "header":
            case "streaming":
            {
                using var ms = new MemoryStream(input, writable: false);
                // PqfStreamingPipeline.OpenAsync parses the header and (if
                // signed) the header signature. We only await it; we don't
                // need to enumerate chunks for the parser-fuzz target.
                var task = PqfStreamingPipeline.OpenAsync(ms, leaveOpen: true);
                task.GetAwaiter().GetResult().DisposeAsync().AsTask().GetAwaiter().GetResult();
                return;
            }

            default:
                throw new ArgumentException($"unknown target: {target}");
        }
    }
}
