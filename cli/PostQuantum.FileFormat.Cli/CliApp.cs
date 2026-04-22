using System.Text.Json;
using PostQuantum.FileFormat.Armor;
using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Fingerprint;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Cli;

public static class CliApp
{
    public static async Task<int> RunAsync(string[] args, TextWriter stdout, TextWriter stderr)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintHelp(stdout);
            return ExitCodes.Success;
        }

        try
        {
            return args[0] switch
            {
                "keygen" => await RunKeygenAsync(args[1..], stdout, stderr).ConfigureAwait(false),
                "encrypt" => await RunEncryptAsync(args[1..], stdout, stderr).ConfigureAwait(false),
                "decrypt" => await RunDecryptAsync(args[1..], stdout, stderr).ConfigureAwait(false),
                "inspect" => await RunInspectAsync(args[1..], stdout, stderr).ConfigureAwait(false),
                "fingerprint" => await RunFingerprintAsync(args[1..], stdout, stderr).ConfigureAwait(false),
                _ => FailUsage(stderr, $"Unknown command '{args[0]}'.")
            };
        }
        catch (IOException ex)
        {
            await stderr.WriteLineAsync($"I/O error: {ex.Message}").ConfigureAwait(false);
            return ExitCodes.IoError;
        }
        catch (UnauthorizedAccessException ex)
        {
            await stderr.WriteLineAsync($"Permission error: {ex.Message}").ConfigureAwait(false);
            return ExitCodes.IoError;
        }
        catch (JsonException ex)
        {
            await stderr.WriteLineAsync($"Invalid key file JSON: {ex.Message}").ConfigureAwait(false);
            return ExitCodes.KeyError;
        }
        catch (FormatException ex)
        {
            await stderr.WriteLineAsync($"Invalid key format: {ex.Message}").ConfigureAwait(false);
            return ExitCodes.KeyError;
        }
        catch (KeyFormatException ex)
        {
            await stderr.WriteLineAsync($"Invalid key material: {ex.Message}").ConfigureAwait(false);
            return ExitCodes.KeyError;
        }
        catch (Exception ex)
        {
            await stderr.WriteLineAsync($"Internal error: {ex.Message}").ConfigureAwait(false);
            return ExitCodes.InternalError;
        }
    }

    private static async Task<int> RunKeygenAsync(string[] args, TextWriter stdout, TextWriter stderr)
    {
        if (!TryParseOptions(args, out var options, out var error))
        {
            return FailUsage(stderr, error);
        }

        if (!TryGetSingle(options, "type", out var keyType) ||
            !TryGetSingle(options, "public-out", out var publicOut) ||
            !TryGetSingle(options, "private-out", out var privateOut))
        {
            return FailUsage(stderr, "keygen requires --type, --public-out, and --private-out.");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(publicOut)) ?? ".");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(privateOut)) ?? ".");

        if (string.Equals(keyType, "encrypt", StringComparison.OrdinalIgnoreCase))
        {
            using var identity = PqfIdentity.Generate();
            await KeyFileStore.WriteEncryptionIdentityAsync(identity, publicOut, privateOut).ConfigureAwait(false);
            await stdout.WriteLineAsync($"Generated encryption identity: {privateOut}").ConfigureAwait(false);
            await stdout.WriteLineAsync($"Generated encryption public key: {publicOut}").ConfigureAwait(false);
            return ExitCodes.Success;
        }

        if (string.Equals(keyType, "sign", StringComparison.OrdinalIgnoreCase))
        {
            using var identity = PqfSigningIdentity.Generate();
            await KeyFileStore.WriteSigningIdentityAsync(identity, publicOut, privateOut).ConfigureAwait(false);
            await stdout.WriteLineAsync($"Generated signing identity: {privateOut}").ConfigureAwait(false);
            await stdout.WriteLineAsync($"Generated signing public key: {publicOut}").ConfigureAwait(false);
            return ExitCodes.Success;
        }

        return FailUsage(stderr, "--type must be either 'encrypt' or 'sign'.");
    }

    private static async Task<int> RunEncryptAsync(string[] args, TextWriter stdout, TextWriter stderr)
    {
        if (!TryParseOptions(args, out var options, out var error))
        {
            return FailUsage(stderr, error);
        }

        if (!TryGetSingle(options, "in", out var inputPath) || !TryGetSingle(options, "out", out var outputPath))
        {
            return FailUsage(stderr, "encrypt requires --in and --out.");
        }

        if (!options.TryGetValue("recipient", out var recipientPaths) || recipientPaths.Count == 0)
        {
            return FailUsage(stderr, "encrypt requires at least one --recipient file.");
        }

        var recipients = new List<PqfPublicKey>(recipientPaths.Count);
        foreach (var recipientPath in recipientPaths)
        {
            recipients.Add(await KeyFileStore.ReadRecipientPublicKeyAsync(recipientPath).ConfigureAwait(false));
        }

        PqfSigningIdentity? signer = null;
        if (TryGetSingle(options, "signing-key", out var signingKeyPath))
        {
            signer = await KeyFileStore.ReadSigningIdentityAsync(signingKeyPath).ConfigureAwait(false);
        }

        var chunkSize = 65536;
        if (TryGetSingle(options, "chunk-size", out var chunkSizeRaw) && !int.TryParse(chunkSizeRaw, out chunkSize))
        {
            signer?.Dispose();
            return FailUsage(stderr, "--chunk-size must be an integer.");
        }

        await using var input = System.IO.File.OpenRead(inputPath);
        await using var output = System.IO.File.Create(outputPath);

        try
        {
            await PqfFile.EncryptAsync(input, output, recipients, signer, chunkSize).ConfigureAwait(false);
        }
        finally
        {
            signer?.Dispose();
        }

        await stdout.WriteLineAsync($"Encrypted {inputPath} -> {outputPath}").ConfigureAwait(false);
        return ExitCodes.Success;
    }

    private static async Task<int> RunDecryptAsync(string[] args, TextWriter stdout, TextWriter stderr)
    {
        if (!TryParseOptions(args, out var options, out var error))
        {
            return FailUsage(stderr, error);
        }

        if (!TryGetSingle(options, "in", out var inputPath) ||
            !TryGetSingle(options, "out", out var outputPath) ||
            !TryGetSingle(options, "identity", out var identityPath))
        {
            return FailUsage(stderr, "decrypt requires --in, --out, and --identity.");
        }

        var mode = "authenticated";
        if (TryGetSingle(options, "mode", out var explicitMode))
        {
            mode = explicitMode;
        }

        using var identity = await KeyFileStore.ReadEncryptionIdentityAsync(identityPath).ConfigureAwait(false);
        await using var input = System.IO.File.OpenRead(inputPath);
        await using var output = System.IO.File.Create(outputPath);

        if (string.Equals(mode, "authenticated", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                await PqfDecryptor.DecryptAsync(input, output, identity).ConfigureAwait(false);
                await stdout.WriteLineAsync($"Decrypted {inputPath} -> {outputPath}").ConfigureAwait(false);
                return ExitCodes.Success;
            }
            catch (PqfFileException ex)
            {
                await stderr.WriteLineAsync($"Decryption refused ({ex.Reason}): {ex.Message}").ConfigureAwait(false);
                return ExitCodes.Refused;
            }
        }

        if (string.Equals(mode, "streaming", StringComparison.OrdinalIgnoreCase))
        {
            var result = await PqfDecryptor.DecryptStreamingAsync(input, output, identity).ConfigureAwait(false);
            if (result.Success)
            {
                await stdout.WriteLineAsync($"Decrypted {inputPath} -> {outputPath} ({result.PlaintextBytesEmitted} bytes)").ConfigureAwait(false);
                return ExitCodes.Success;
            }

            var postHoc = result.PostHocAuthenticationFailed ? " post-hoc-auth=true" : string.Empty;
            await stderr.WriteLineAsync($"Decryption refused ({result.FailureReason}) emitted={result.PlaintextBytesEmitted}{postHoc}").ConfigureAwait(false);
            return ExitCodes.Refused;
        }

        return FailUsage(stderr, "--mode must be either 'authenticated' or 'streaming'.");
    }

    private static async Task<int> RunInspectAsync(string[] args, TextWriter stdout, TextWriter stderr)
    {
        if (!TryParseOptions(args, out var options, out var error))
        {
            return FailUsage(stderr, error);
        }

        if (!TryGetSingle(options, "in", out var inputPath))
        {
            return FailUsage(stderr, "inspect requires --in.");
        }

        var emitJson = options.ContainsKey("json");
        var bytes = await System.IO.File.ReadAllBytesAsync(inputPath).ConfigureAwait(false);

        try
        {
            var reader = PqfFileReader.OpenForValidation(bytes);
            var payload = new
            {
                chunkSize = reader.Header.ChunkSize,
                createdUtc = reader.Header.CreatedUtc,
                fileId = Convert.ToHexString(reader.Header.FileId).ToLowerInvariant(),
                recipients = reader.Header.Recipients.Count,
                signed = reader.Header.Signer is not null,
                chunkCount = reader.TotalChunkCount,
                plaintextBytes = reader.ReportedPlaintextBytes,
            };

            if (emitJson)
            {
                await stdout.WriteLineAsync(JsonSerializer.Serialize(payload, new JsonSerializerOptions
                {
                    WriteIndented = true,
                })).ConfigureAwait(false);
            }
            else
            {
                await stdout.WriteLineAsync($"chunk_size: {payload.chunkSize}").ConfigureAwait(false);
                await stdout.WriteLineAsync($"created_utc: {payload.createdUtc:O}").ConfigureAwait(false);
                await stdout.WriteLineAsync($"file_id: {payload.fileId}").ConfigureAwait(false);
                await stdout.WriteLineAsync($"recipients: {payload.recipients}").ConfigureAwait(false);
                await stdout.WriteLineAsync($"signed: {payload.signed}").ConfigureAwait(false);
                await stdout.WriteLineAsync($"chunk_count: {payload.chunkCount}").ConfigureAwait(false);
                await stdout.WriteLineAsync($"plaintext_bytes: {payload.plaintextBytes}").ConfigureAwait(false);
            }

            return ExitCodes.Success;
        }
        catch (PqfFileException ex)
        {
            await stderr.WriteLineAsync($"Inspect refused ({ex.Reason}): {ex.Message}").ConfigureAwait(false);
            return ExitCodes.Refused;
        }
    }

    private static async Task<int> RunFingerprintAsync(string[] args, TextWriter stdout, TextWriter stderr)
    {
        if (!TryParseOptions(args, out var options, out var error))
        {
            return FailUsage(stderr, error);
        }

        if (!TryGetSingle(options, "public-key", out var keyPath))
        {
            return FailUsage(stderr, "fingerprint requires --public-key.");
        }

        var pem = await System.IO.File.ReadAllTextAsync(keyPath).ConfigureAwait(false);

        try
        {
            var key = PemArmor.DearmorPublicKey(pem);
            var fp = PqfFingerprint.Compute(key);
            await stdout.WriteLineAsync($"{PqfFingerprint.ToPrefixedHex(fp)} (enc, short={PqfFingerprint.ToShortHex(fp)})").ConfigureAwait(false);
            return ExitCodes.Success;
        }
        catch (FormatException)
        {
            var key = PemArmor.DearmorSigningPublicKey(pem);
            var fp = PqfFingerprint.Compute(key);
            await stdout.WriteLineAsync($"{PqfFingerprint.ToPrefixedHex(fp)} (sig, short={PqfFingerprint.ToShortHex(fp)})").ConfigureAwait(false);
            return ExitCodes.Success;
        }
    }

    private static bool IsHelp(string arg)
    {
        return string.Equals(arg, "-h", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(arg, "--help", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(arg, "help", StringComparison.OrdinalIgnoreCase);
    }

    private static int FailUsage(TextWriter stderr, string message)
    {
        stderr.WriteLine($"Usage error: {message}");
        return ExitCodes.Usage;
    }

    private static bool TryParseOptions(
        IReadOnlyList<string> args,
        out Dictionary<string, List<string>> options,
        out string error)
    {
        options = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        error = string.Empty;

        for (var i = 0; i < args.Count; i++)
        {
            var token = args[i];
            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                error = $"Unexpected argument '{token}'. Use --name value options.";
                return false;
            }

            var name = token[2..];
            if (string.IsNullOrWhiteSpace(name))
            {
                error = "Encountered empty option name.";
                return false;
            }

            if (!options.TryGetValue(name, out var values))
            {
                values = new List<string>();
                options[name] = values;
            }

            if (i + 1 >= args.Count || args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                values.Add("true");
                continue;
            }

            values.Add(args[++i]);
        }

        return true;
    }

    private static bool TryGetSingle(Dictionary<string, List<string>> options, string name, out string value)
    {
        value = string.Empty;
        if (!options.TryGetValue(name, out var values) || values.Count == 0)
        {
            return false;
        }

        value = values[^1];
        return true;
    }

    private static void PrintHelp(TextWriter stdout)
    {
        stdout.WriteLine("pqf - PostQuantum.FileFormat CLI");
        stdout.WriteLine();
        stdout.WriteLine("Commands:");
        stdout.WriteLine("  keygen --type encrypt|sign --public-out <path> --private-out <path>");
        stdout.WriteLine("  encrypt --in <path> --out <path> --recipient <pub.pem> [--recipient <pub.pem>] [--signing-key <signing.key.json>] [--chunk-size <n>]");
        stdout.WriteLine("  decrypt --in <path> --out <path> --identity <identity.key.json> [--mode authenticated|streaming]");
        stdout.WriteLine("  inspect --in <path> [--json]");
        stdout.WriteLine("  fingerprint --public-key <pub.pem>");
    }

    public static class ExitCodes
    {
        public const int Success = 0;
        public const int Usage = 2;
        public const int IoError = 3;
        public const int KeyError = 4;
        public const int Refused = 5;
        public const int InternalError = 10;
    }
}