using System.Security.Cryptography;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.File;

/// <summary>
/// Authenticated decryption: NO plaintext is released to the destination
/// until the full file signature (when present) is verified. To preserve
/// that property without buffering the entire ciphertext stream, we drive
/// a streaming pipeline that surfaces chunks one at a time, decrypt each
/// chunk, and write the resulting plaintext to a private staging buffer
/// (memory for small files, an mode-0600 DeleteOnClose tempfile above the
/// threshold). After the file signature verifies, we drain the staging
/// buffer to the caller-supplied destination.
/// </summary>
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
        await using var pipeline = await PqfStreamingPipeline.OpenAsync(source, leaveOpen: true, ct).ConfigureAwait(false);

        var hybridKem = new HybridKem(provider);
        var hybridSigner = new HybridSigner(provider);

        if (pipeline.Header.Signer is not null)
        {
            var signingPublic = PqfSigningPublicKey.FromParts(pipeline.Header.Signer.ClassicalPub, pipeline.Header.Signer.PqcPub);
            if (!hybridSigner.Verify(signingPublic, HybridSigner.HeaderSignatureDomain, pipeline.HeaderBytes.Span, pipeline.HeaderSignatureBytes.Span))
            {
                throw new PqfFileException(PqfRefusalReason.SignatureVerificationFailure, "Header signature verification failed");
            }
        }

        var selectedDek = ResolveDek(pipeline.Header, identity, hybridKem);
        SpillToDiskStream? buffer = null;
        ulong observedPlaintext = 0;
        using var chunkHasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        try
        {
            // We do not know the plaintext size up-front in true streaming
            // mode (the footer has not been read yet). SpillToDiskStream
            // starts in memory and spills to a 0600 DeleteOnClose tempfile
            // once the threshold is exceeded.
            buffer = new SpillToDiskStream(BufferToDiskThresholdBytes);

            await foreach (var chunk in pipeline.EnumerateChunksAsync(chunkHasher, ct).ConfigureAwait(false))
            {
                var plaintextLength = chunk.Ciphertext.Length - 16;
                var plaintextBuffer = new byte[plaintextLength];
                var written = ChunkCipher.DecryptChunk(
                    selectedDek,
                    chunk.Index,
                    chunk.IsFinal,
                    pipeline.Header.FileId,
                    chunk.Ciphertext,
                    plaintextBuffer);

                SecureZero.Clear(chunk.Ciphertext);

                if (written < 0)
                {
                    throw new PqfFileException(PqfRefusalReason.AeadTagFailure, $"Chunk {chunk.Index} failed AEAD authentication");
                }

                await buffer.WriteAsync(plaintextBuffer.AsMemory(0, written), ct).ConfigureAwait(false);
                observedPlaintext += (ulong)written;
                SecureZero.Clear(plaintextBuffer);
            }

            await pipeline.ReadTrailerAsync(ct).ConfigureAwait(false);

            if (observedPlaintext != pipeline.ReportedPlaintextBytes)
            {
                throw new PqfFileException(PqfRefusalReason.FooterPlaintextBytesMismatch, "Footer plaintext bytes mismatch");
            }

            if (pipeline.Header.Signer is not null)
            {
                var digest = chunkHasher.GetHashAndReset();
                var message = new byte[16 + 32 + 20];
                pipeline.Header.FileId.CopyTo(message, 0);
                digest.CopyTo(message, 16);
                pipeline.FooterBytes.CopyTo(message.AsMemory(48));

                var signingPublic = PqfSigningPublicKey.FromParts(pipeline.Header.Signer.ClassicalPub, pipeline.Header.Signer.PqcPub);
                if (!hybridSigner.Verify(signingPublic, HybridSigner.FileSignatureDomain, message, pipeline.FileSignatureBytes.Span))
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
        }
    }

    internal static byte[] ResolveDek(PqfFileHeader header, PqfIdentity identity, HybridKem hybridKem)
    {
        byte[]? selectedDek = null;

        for (var i = 0; i < header.Recipients.Count; i++)
        {
            var recipient = header.Recipients[i];
            var kek = hybridKem.Decapsulate(identity, recipient.ClassicalEpk, recipient.PqcCt);
            var dek = DekWrapper.Unwrap(kek, recipient.WrappedDekNonce, recipient.WrappedDek, header.FileId, (uint)i);
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
