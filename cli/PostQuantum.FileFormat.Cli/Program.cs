namespace PostQuantum.FileFormat.Cli;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        return await CliApp.RunAsync(args, Console.Out, Console.Error).ConfigureAwait(false);
    }
}