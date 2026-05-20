using BenchmarkDotNet.Running;

namespace PostQuantum.FileFormat.Bench;

/// <summary>
/// Benchmark entry point. Run a specific benchmark class with
///   dotnet run -c Release -- --filter "*Roundtrip*"
/// or all of them with
///   dotnet run -c Release -- --filter "*"
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        var switcher = BenchmarkSwitcher.FromTypes(new[]
        {
            typeof(EncryptDecryptBenchmarks),
            typeof(HeaderParseBenchmarks),
            typeof(MultiRecipientBenchmarks),
        });
        switcher.Run(args);
        return 0;
    }
}
