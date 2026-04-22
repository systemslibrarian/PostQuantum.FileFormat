using System.Text.Json;
using System.Text.Json.Serialization;
using PostQuantum.FileFormat.Armor;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Cli;

internal static class KeyFileStore
{
    // Strict JSON: case-sensitive, reject unknown fields. The CLI is the only
    // consumer of these files and the format is fully specified, so silently
    // accepting "x25519PrivateKey" / "X25519privateKey" / extra fields would
    // mask malformed identity files instead of refusing them.
    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        WriteIndented = true,
    };

    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        PropertyNameCaseInsensitive = false,
    };

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
        var json = JsonSerializer.Serialize(value, WriteOptions) + Environment.NewLine;
        var bytes = System.Text.Encoding.UTF8.GetBytes(json);

        // Private-key files must not be world-readable on Unix. On Windows the
        // default ACL inheritance is acceptable for a per-user CLI tool; if the
        // user wants stricter ACLs they can set them on the parent directory.
        var options = new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            Share = FileShare.None,
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        await using var stream = new FileStream(path, options);
        await stream.WriteAsync(bytes).ConfigureAwait(false);
    }

    private static async Task<T?> ReadJsonAsync<T>(string path)
    {
        var json = await System.IO.File.ReadAllTextAsync(path).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(json, ReadOptions);
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