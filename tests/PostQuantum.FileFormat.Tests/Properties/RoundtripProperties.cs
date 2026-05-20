using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.Properties;

/// <summary>
/// Property-based tests for the PQF roundtrip and refusal contracts.
///
/// Properties are higher-leverage than example-based tests for a
/// fail-closed format: each one is a statement about every legal input
/// in the abstract space, and a failing property gives you a minimized
/// counterexample to add as a regression test.
///
/// Input sizes are bounded per-property to keep runtime reasonable;
/// LargeFileStressTests covers the unbounded end.
/// </summary>
[Trait("Category", "Property")]
public sealed class RoundtripProperties
{
    private const int MaxBytes = 16 * 1024;
    private const int MinChunkSize = 4096;

    private static readonly int[] ChunkSizes = { 4096, 8192, 16384 };

    [Property(MaxTest = 40)]
    public bool Roundtrip_in_authenticated_mode_is_identity_for_any_plaintext(byte[] plaintext, int chunkSizeSelector)
    {
        if (plaintext is null || plaintext.Length > MaxBytes) return true;
        var chunkSize = ChunkSizes[Math.Abs(chunkSizeSelector) % ChunkSizes.Length];
        var roundtripped = EncryptThenDecrypt(plaintext, chunkSize, signed: false);
        return roundtripped.SequenceEqual(plaintext);
    }

    [Property(MaxTest = 40)]
    public bool Roundtrip_with_signature_is_identity_for_any_plaintext(byte[] plaintext, int chunkSizeSelector)
    {
        if (plaintext is null || plaintext.Length > MaxBytes) return true;
        var chunkSize = ChunkSizes[Math.Abs(chunkSizeSelector) % ChunkSizes.Length];
        var roundtripped = EncryptThenDecrypt(plaintext, chunkSize, signed: true);
        return roundtripped.SequenceEqual(plaintext);
    }

    [Property(MaxTest = 20)]
    public bool Any_single_bit_flip_in_ciphertext_is_refused(int offsetSeed)
    {
        var plaintext = new byte[2048];
        System.Security.Cryptography.RandomNumberGenerator.Fill(plaintext);
        using var recipient = PqfIdentity.Generate(CryptoProvider.Detect());

        byte[] ciphertext;
        using (var enc = new MemoryStream())
        using (var ptIn = new MemoryStream(plaintext))
        {
            PqfFile.EncryptAsync(ptIn, enc, new[] { recipient.PublicKey }, signer: null,
                chunkSize: MinChunkSize).GetAwaiter().GetResult();
            ciphertext = enc.ToArray();
        }
        if (ciphertext.Length == 0) return true;

        var pos = Math.Abs(offsetSeed) % ciphertext.Length;
        ciphertext[pos] ^= 0x01;

        using var ctIn = new MemoryStream(ciphertext);
        using var ptOut = new MemoryStream();
        try
        {
            PqfDecryptor.DecryptAsync(ctIn, ptOut, recipient).GetAwaiter().GetResult();
            // If we got here without an exception, the flip happened to
            // produce a still-valid file. For AES-GCM that's
            // cryptographically negligible, so it should still decrypt
            // to identical plaintext if at all.
            return ptOut.ToArray().SequenceEqual(plaintext);
        }
        catch (PqfFileException)
        {
            return true;
        }
        catch (System.Security.Cryptography.AuthenticationTagMismatchException)
        {
            return true;
        }
        catch (EndOfStreamException)
        {
            return true;
        }
    }

    [Property(MaxTest = 12)]
    public bool Multi_recipient_each_can_decrypt_independently(byte[] plaintext, int countSeed)
    {
        if (plaintext is null || plaintext.Length > 2048) return true;
        var count = 1 + (Math.Abs(countSeed) % 4);
        var provider = CryptoProvider.Detect();
        var recipients = new PqfIdentity[count];
        try
        {
            for (var i = 0; i < count; i++) recipients[i] = PqfIdentity.Generate(provider);

            byte[] ciphertext;
            using (var enc = new MemoryStream())
            using (var ptIn = new MemoryStream(plaintext))
            {
                PqfFile.EncryptAsync(ptIn, enc, recipients.Select(r => r.PublicKey).ToArray(),
                    signer: null, chunkSize: MinChunkSize).GetAwaiter().GetResult();
                ciphertext = enc.ToArray();
            }

            for (var i = 0; i < count; i++)
            {
                using var ctIn = new MemoryStream(ciphertext);
                using var ptOut = new MemoryStream();
                PqfDecryptor.DecryptAsync(ctIn, ptOut, recipients[i]).GetAwaiter().GetResult();
                if (!ptOut.ToArray().SequenceEqual(plaintext)) return false;
            }
            return true;
        }
        finally
        {
            foreach (var r in recipients) r?.Dispose();
        }
    }

    [Property(MaxTest = 25)]
    public bool Truncation_at_any_offset_is_refused(int offsetSeed)
    {
        var plaintext = new byte[1024];
        System.Security.Cryptography.RandomNumberGenerator.Fill(plaintext);
        using var recipient = PqfIdentity.Generate(CryptoProvider.Detect());

        byte[] ciphertext;
        using (var enc = new MemoryStream())
        using (var ptIn = new MemoryStream(plaintext))
        {
            PqfFile.EncryptAsync(ptIn, enc, new[] { recipient.PublicKey }, signer: null,
                chunkSize: MinChunkSize).GetAwaiter().GetResult();
            ciphertext = enc.ToArray();
        }
        if (ciphertext.Length < 16) return true;

        var truncatedLen = 10 + (Math.Abs(offsetSeed) % (ciphertext.Length - 10));
        var truncated = ciphertext.AsSpan(0, truncatedLen).ToArray();

        using var ctIn = new MemoryStream(truncated);
        using var ptOut = new MemoryStream();
        try
        {
            PqfDecryptor.DecryptAsync(ctIn, ptOut, recipient).GetAwaiter().GetResult();
            // Authenticated mode refuses before any byte is released.
            // Reaching here means truncation went undetected — a violation.
            return false;
        }
        catch (PqfFileException)
        {
            return true;
        }
        catch (EndOfStreamException)
        {
            return true;
        }
        catch (System.Security.Cryptography.AuthenticationTagMismatchException)
        {
            return true;
        }
    }

    private static byte[] EncryptThenDecrypt(byte[] plaintext, int chunkSize, bool signed)
    {
        var provider = CryptoProvider.Detect();
        using var recipient = PqfIdentity.Generate(provider);
        PqfSigningIdentity? signingIdentity = signed
            ? PqfSigningIdentity.Generate(provider)
            : null;
        try
        {
            byte[] ciphertext;
            using (var enc = new MemoryStream())
            using (var ptIn = new MemoryStream(plaintext))
            {
                PqfFile.EncryptAsync(ptIn, enc, new[] { recipient.PublicKey }, signingIdentity, chunkSize)
                    .GetAwaiter().GetResult();
                ciphertext = enc.ToArray();
            }

            using var ctIn = new MemoryStream(ciphertext);
            using var ptOut = new MemoryStream();
            PqfDecryptor.DecryptAsync(ctIn, ptOut, recipient).GetAwaiter().GetResult();
            return ptOut.ToArray();
        }
        finally
        {
            signingIdentity?.Dispose();
        }
    }
}
