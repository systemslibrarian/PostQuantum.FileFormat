namespace PostQuantum.FileFormat.Crypto;

public static class CryptoProvider
{
    private static readonly Lazy<ICryptoProvider> Cached = new(DetectInternal);
    private static int _logged;

    public static ICryptoProvider Detect() => Cached.Value;

    private static ICryptoProvider DetectInternal()
    {
        ICryptoProvider provider = BclCryptoProvider.IsSupported
            ? new BclCryptoProvider()
            : new BouncyCastleCryptoProvider();

        if (Interlocked.Exchange(ref _logged, 1) == 0)
        {
            Console.Error.WriteLine($"[PQF] Crypto provider: {provider.GetType().Name}");
        }

        return provider;
    }
}
