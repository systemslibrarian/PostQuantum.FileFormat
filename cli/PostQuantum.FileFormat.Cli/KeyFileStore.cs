using System.Text.Json;
using PostQuantum.FileFormat.Armor;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Cli;

internal static class KeyFileStore
{
    public static async Task WriteEncryptionIdentityAsync(PqfIdentity identity, string publicKeyPath, string privateKeyPath)
    {
        var publicPem = PemArmor.ArmorPublicKey(identity.PublicKey);
        var privateFile = new EncryptionIdentityFile(
            Type: "pqf-encryption-identity-v1",
            PublicKeyPem: publicPem,
            X25519PrivateKey: Convert.ToBase64String(identity.X25519PrivateKey.Span),
            MlKem1024PrivateKey: Convert.ToBase64String(identity.MlKem1024PrivateKey.Span));

        await System.IO.File.WriteAllTextAsync(publicKeyPath, publicPem).ConfigureAwait(false);
        await WriteJsonAsync(privateKeyPath, privateFile).ConfigureAwait(false);
    }

    public static async Task WriteSigningIdentityAsync(PqfSigningIdentity identity, string publicKeyPath, string privateKeyPath)
    {
        var publicPem = PemArmor.ArmorSigningPublicKey(identity.PublicKey);
        var privateFile = new SigningIdentityFile(
            Type: "pqf-signing-identity-v1",
            PublicKeyPem: publicPem,
            Ed25519PrivateKey: Convert.ToBase64String(identity.Ed25519PrivateKey.Span),
            MlDsa87PrivateKey: Convert.ToBase64String(identity.MlDsa87PrivateKey.Span));

        await System.IO.File.WriteAllTextAsync(publicKeyPath, publicPem).ConfigureAwait(false);
        await WriteJsonAsync(privateKeyPath, privateFile).ConfigureAwait(false);
    }

    public static async Task<PqfPublicKey> ReadRecipientPublicKeyAsync(string path)
    {
        var pem = await System.IO.File.ReadAllTextAsync(path).ConfigureAwait(false);
        return PemArmor.DearmorPublicKey(pem);
    }

    public static async Task<PqfIdentity> ReadEncryptionIdentityAsync(string path)
    {
        var file = await ReadJsonAsync<EncryptionIdentityFile>(path).ConfigureAwait(false)
            ?? throw new FormatException("Identity file is missing required fields.");

        if (!string.Equals(file.Type, "pqf-encryption-identity-v1", StringComparison.Ordinal))
        {
            throw new FormatException("Unsupported encryption identity type.");
        }

        var publicKey = PemArmor.DearmorPublicKey(file.PublicKeyPem);
        return new PqfIdentity(
            publicKey,
            Convert.FromBase64String(file.X25519PrivateKey),
            Convert.FromBase64String(file.MlKem1024PrivateKey));
    }

    public static async Task<PqfSigningIdentity> ReadSigningIdentityAsync(string path)
    {
        var file = await ReadJsonAsync<SigningIdentityFile>(path).ConfigureAwait(false)
            ?? throw new FormatException("Signing identity file is missing required fields.");

        if (!string.Equals(file.Type, "pqf-signing-identity-v1", StringComparison.Ordinal))
        {
            throw new FormatException("Unsupported signing identity type.");
        }

        var publicKey = PemArmor.DearmorSigningPublicKey(file.PublicKeyPem);
        return new PqfSigningIdentity(
            publicKey,
            Convert.FromBase64String(file.Ed25519PrivateKey),
            Convert.FromBase64String(file.MlDsa87PrivateKey));
    }

    private static async Task WriteJsonAsync<T>(string path, T value)
    {
        var json = JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true });
        await System.IO.File.WriteAllTextAsync(path, json + Environment.NewLine).ConfigureAwait(false);
    }

    private static async Task<T?> ReadJsonAsync<T>(string path)
    {
        var json = await System.IO.File.ReadAllTextAsync(path).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        });
    }

    private sealed record EncryptionIdentityFile(
        string Type,
        string PublicKeyPem,
        string X25519PrivateKey,
        string MlKem1024PrivateKey);

    private sealed record SigningIdentityFile(
        string Type,
        string PublicKeyPem,
        string Ed25519PrivateKey,
        string MlDsa87PrivateKey);
}