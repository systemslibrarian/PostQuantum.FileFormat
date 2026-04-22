using System.Text.Json;
using PostQuantum.FileFormat.Cli;

namespace PostQuantum.FileFormat.Cli.Tests;

public sealed class CliAppTests
{
    [Fact]
    public async Task Keygen_encrypt_and_authenticated_decrypt_roundtrip()
    {
        using var temp = new TempDir();
        var plaintextPath = Path.Combine(temp.Path, "plain.bin");
        var encryptedPath = Path.Combine(temp.Path, "cipher.pqf");
        var decryptedPath = Path.Combine(temp.Path, "plain.out.bin");
        var recipientPubPath = Path.Combine(temp.Path, "recipient.pub.pem");
        var recipientIdentityPath = Path.Combine(temp.Path, "recipient.identity.json");

        var plaintext = RandomBytes(120_000);
        await System.IO.File.WriteAllBytesAsync(plaintextPath, plaintext);

        var keygen = await RunAsync("keygen", "--type", "encrypt", "--public-out", recipientPubPath, "--private-out", recipientIdentityPath);
        Assert.Equal(CliApp.ExitCodes.Success, keygen.ExitCode);

        var encrypt = await RunAsync("encrypt", "--in", plaintextPath, "--out", encryptedPath, "--recipient", recipientPubPath);
        Assert.Equal(CliApp.ExitCodes.Success, encrypt.ExitCode);

        var decrypt = await RunAsync("decrypt", "--in", encryptedPath, "--out", decryptedPath, "--identity", recipientIdentityPath);
        Assert.Equal(CliApp.ExitCodes.Success, decrypt.ExitCode);

        var decrypted = await System.IO.File.ReadAllBytesAsync(decryptedPath);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task Inspect_json_reports_recipient_count()
    {
        using var temp = new TempDir();
        var plaintextPath = Path.Combine(temp.Path, "plain.bin");
        var encryptedPath = Path.Combine(temp.Path, "cipher.pqf");
        var recipientPubPath = Path.Combine(temp.Path, "recipient.pub.pem");
        var recipientIdentityPath = Path.Combine(temp.Path, "recipient.identity.json");

        await System.IO.File.WriteAllBytesAsync(plaintextPath, RandomBytes(4096));
        _ = await RunAsync("keygen", "--type", "encrypt", "--public-out", recipientPubPath, "--private-out", recipientIdentityPath);
        _ = await RunAsync("encrypt", "--in", plaintextPath, "--out", encryptedPath, "--recipient", recipientPubPath);

        var inspect = await RunAsync("inspect", "--in", encryptedPath, "--json");
        Assert.Equal(CliApp.ExitCodes.Success, inspect.ExitCode);

        using var document = JsonDocument.Parse(inspect.Stdout);
        Assert.Equal(1, document.RootElement.GetProperty("recipients").GetInt32());
    }

    [Fact]
    public async Task Fingerprint_outputs_prefixed_form()
    {
        using var temp = new TempDir();
        var recipientPubPath = Path.Combine(temp.Path, "recipient.pub.pem");
        var recipientIdentityPath = Path.Combine(temp.Path, "recipient.identity.json");

        _ = await RunAsync("keygen", "--type", "encrypt", "--public-out", recipientPubPath, "--private-out", recipientIdentityPath);

        var fp = await RunAsync("fingerprint", "--public-key", recipientPubPath);
        Assert.Equal(CliApp.ExitCodes.Success, fp.ExitCode);
        Assert.Contains("pqf1fp:", fp.Stdout);
    }

    [Fact]
    public async Task Streaming_decrypt_returns_refused_on_posthoc_signature_failure()
    {
        using var temp = new TempDir();
        var plaintextPath = Path.Combine(temp.Path, "plain.bin");
        var encryptedPath = Path.Combine(temp.Path, "cipher.pqf");
        var tamperedPath = Path.Combine(temp.Path, "cipher.tampered.pqf");
        var outPath = Path.Combine(temp.Path, "out.bin");

        var recipientPubPath = Path.Combine(temp.Path, "recipient.pub.pem");
        var recipientIdentityPath = Path.Combine(temp.Path, "recipient.identity.json");
        var signerPubPath = Path.Combine(temp.Path, "signer.pub.pem");
        var signerIdentityPath = Path.Combine(temp.Path, "signer.identity.json");

        await System.IO.File.WriteAllBytesAsync(plaintextPath, RandomBytes(96_000));

        _ = await RunAsync("keygen", "--type", "encrypt", "--public-out", recipientPubPath, "--private-out", recipientIdentityPath);
        _ = await RunAsync("keygen", "--type", "sign", "--public-out", signerPubPath, "--private-out", signerIdentityPath);

        var encrypt = await RunAsync(
            "encrypt",
            "--in", plaintextPath,
            "--out", encryptedPath,
            "--recipient", recipientPubPath,
            "--signing-key", signerIdentityPath);
        Assert.Equal(CliApp.ExitCodes.Success, encrypt.ExitCode);

        var tampered = await System.IO.File.ReadAllBytesAsync(encryptedPath);
        tampered[^1] ^= 0x01;
        await System.IO.File.WriteAllBytesAsync(tamperedPath, tampered);

        var decrypt = await RunAsync(
            "decrypt",
            "--in", tamperedPath,
            "--out", outPath,
            "--identity", recipientIdentityPath,
            "--mode", "streaming");

        Assert.Equal(CliApp.ExitCodes.Refused, decrypt.ExitCode);
        Assert.Contains("post-hoc-auth=true", decrypt.Stderr);
        Assert.True(new FileInfo(outPath).Length > 0);
    }

    private static async Task<RunResult> RunAsync(params string[] args)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var exitCode = await CliApp.RunAsync(args, stdout, stderr);
        return new RunResult(exitCode, stdout.ToString(), stderr.ToString());
    }

    private static byte[] RandomBytes(int n)
    {
        var bytes = new byte[n];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    private sealed record RunResult(int ExitCode, string Stdout, string Stderr);

    private sealed class TempDir : IDisposable
    {
        public TempDir()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"pqf-cli-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch
            {
                // Best effort cleanup.
            }
        }
    }
}