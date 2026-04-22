using System.Security.Cryptography;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.File;

internal sealed class AuthenticatedModeDecryptor
{
    internal const long BufferToDiskThresholdBytes = 100L * 1024 * 1024;

    public async Task DecryptAsync(
        Stream source,
        Stream destination,
        PqfIdentity identity,
        ICryptoProvider provider,
        CancellationToken ct)
    {
        using var input = new MemoryStream();
        await source.CopyToAsync(input, ct).ConfigureAwait(false);
        var fileBytes = input.ToArray();
        var reader = PqfFileReader.OpenForValidation(fileBytes);

        var hybridKem = new HybridKem(provider);
        var signer = new HybridSigner(provider);

        if (reader.Header.Signer is not null)
        {
            var signingPublic = PqfSigningPublicKey.FromParts(reader.Header.Signer.ClassicalPub, reader.Header.Signer.PqcPub);
            if (!signer.Verify(signingPublic, reader.HeaderBytes.Span, reader.HeaderSignatureBytes.Span))
            {
                throw new PqfFileException(PqfRefusalReason.SignatureVerificationFailure, "Header signature verification failed");
            }
        }

        var selectedDek = ResolveDek(reader, identity, hybridKem);

        Stream? buffer = null;
        string? tempFilePath = null;
        long observedPlaintext = 0;
        using var chunkHasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        try
        {
            if (reader.ReportedPlaintextBytes > BufferToDiskThresholdBytes)
            {
                tempFilePath = Path.Combine(Path.GetTempPath(), $"pqf-auth-{Guid.NewGuid():N}.tmp");
                buffer = new FileStream(tempFilePath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.SequentialScan);
            }
            else
            {
                buffer = new MemoryStream((int)Math.Min(int.MaxValue, Math.Max(0, reader.ReportedPlaintextBytes)));
            }

            for (var i = 0; i < reader.Chunks.Count; i++)
            {
                var chunk = reader.Chunks[i];
                chunkHasher.AppendData(reader.FileBytes.Slice(chunk.HeaderOffset, 5 + chunk.CiphertextLength).Span);

                var plaintextBuffer = new byte[chunk.PlaintextLength];
                var written = ChunkCipher.DecryptChunk(
                    selectedDek,
                    (ulong)i,
                    chunk.IsFinal,
                    reader.Header.FileId,
                    reader.FileBytes.Slice(chunk.DataOffset, chunk.CiphertextLength).Span,
                    plaintextBuffer);

                if (written < 0)
                {
                    throw new PqfFileException(PqfRefusalReason.AeadTagFailure, $"Chunk {i} failed AEAD authentication");
                }

                await buffer.WriteAsync(plaintextBuffer.AsMemory(0, written), ct).ConfigureAwait(false);
                observedPlaintext += written;
                SecureZero.Clear(plaintextBuffer);
            }

            if (observedPlaintext != reader.ReportedPlaintextBytes)
            {
                throw new PqfFileException(PqfRefusalReason.FooterPlaintextBytesMismatch, "Footer plaintext bytes mismatch");
            }

            if (reader.Header.Signer is not null)
            {
                var digest = chunkHasher.GetHashAndReset();
                var message = new byte[16 + 32 + 20];
                reader.Header.FileId.CopyTo(message, 0);
                digest.CopyTo(message, 16);
                reader.FooterBytes.CopyTo(message.AsMemory(48));

                var signingPublic = PqfSigningPublicKey.FromParts(reader.Header.Signer.ClassicalPub, reader.Header.Signer.PqcPub);
                if (!signer.Verify(signingPublic, message, reader.FileSignatureBytes.Span))
                {
                    throw new PqfFileException(PqfRefusalReason.SignatureVerificationFailure, "File signature verification failed");
                }

                SecureZero.Clear(digest);
                SecureZero.Clear(message);
            }

            buffer.Position = 0;
            await buffer.CopyToAsync(destination, ct).ConfigureAwait(false);
        }
        finally
        {
            SecureZero.Clear(selectedDek);
            if (buffer is not null)
            {
                await buffer.DisposeAsync().ConfigureAwait(false);
            }

            if (tempFilePath is not null)
            {
                try
                {
                    System.IO.File.Delete(tempFilePath);
                }
                catch
                {
                    // Best effort cleanup.
                }
            }
        }
    }

    private static byte[] ResolveDek(PqfFileReader reader, PqfIdentity identity, HybridKem hybridKem)
    {
        byte[]? selectedDek = null;

        for (var i = 0; i < reader.Header.Recipients.Count; i++)
        {
            var recipient = reader.Header.Recipients[i];
            var kek = hybridKem.Decapsulate(identity, recipient.ClassicalEpk, recipient.PqcCt, reader.Header.FileId, (uint)i);
            var dek = DekWrapper.Unwrap(kek, recipient.WrappedDekNonce, recipient.WrappedDek, reader.Header.FileId);
            SecureZero.Clear(kek);

            if (dek is null)
            {
                continue;
            }

            if (selectedDek is null)
            {
                selectedDek = dek;
            }
            else
            {
                SecureZero.Clear(dek);
            }
        }

        if (selectedDek is null)
        {
            throw new PqfFileException(PqfRefusalReason.IdentityMatchesNoRecipient, "Identity does not match any recipient");
        }

        return selectedDek;
    }
}
