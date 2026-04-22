using System.Security.Cryptography;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.File;

/// <summary>
/// Streaming decryption: plaintext is emitted to the destination as each
/// chunk is decrypted, with no full-file buffering. This is post-hoc
/// authenticated — the file signature is still verified at the end and
/// failure is reported via <see cref="PqfDecryptResult"/>, but bytes
/// already emitted to the destination cannot be unwritten. Callers who
/// require pre-disclosure authentication MUST use
/// <see cref="AuthenticatedModeDecryptor"/> instead.
/// </summary>
internal sealed class StreamingModeDecryptor
{
    [MustUseReturnValue]
    public async Task<PqfDecryptResult> DecryptAsync(
        Stream source,
        Stream destination,
        PqfIdentity identity,
        ICryptoProvider provider,
        CancellationToken ct)
    {
        long emitted = 0;
        try
        {
            await using var pipeline = await PqfStreamingPipeline.OpenAsync(source, leaveOpen: true, ct).ConfigureAwait(false);

            var hybridKem = new HybridKem(provider);
            var hybridSigner = new HybridSigner(provider);

            if (pipeline.Header.Signer is not null)
            {
                var signingPublic = PqfSigningPublicKey.FromParts(pipeline.Header.Signer.ClassicalPub, pipeline.Header.Signer.PqcPub);
                if (!hybridSigner.Verify(signingPublic, pipeline.HeaderBytes.Span, pipeline.HeaderSignatureBytes.Span))
                {
                    return new PqfDecryptResult(false, PqfRefusalReason.SignatureVerificationFailure, 0, false);
                }
            }

            var selectedDek = AuthenticatedModeDecryptor.ResolveDek(pipeline.Header, identity, hybridKem);
            using var chunkHasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            try
            {
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
                        return new PqfDecryptResult(false, PqfRefusalReason.AeadTagFailure, emitted, false);
                    }

                    await destination.WriteAsync(plaintextBuffer.AsMemory(0, written), ct).ConfigureAwait(false);
                    emitted += written;
                    SecureZero.Clear(plaintextBuffer);
                }

                await pipeline.ReadTrailerAsync(ct).ConfigureAwait(false);

                if ((ulong)emitted != pipeline.ReportedPlaintextBytes)
                {
                    return new PqfDecryptResult(false, PqfRefusalReason.FooterPlaintextBytesMismatch, emitted, true);
                }

                if (pipeline.Header.Signer is not null)
                {
                    var digest = chunkHasher.GetHashAndReset();
                    var message = new byte[16 + 32 + 20];
                    pipeline.Header.FileId.CopyTo(message, 0);
                    digest.CopyTo(message, 16);
                    pipeline.FooterBytes.CopyTo(message.AsMemory(48));

                    var signingPublic = PqfSigningPublicKey.FromParts(pipeline.Header.Signer.ClassicalPub, pipeline.Header.Signer.PqcPub);
                    if (!hybridSigner.Verify(signingPublic, message, pipeline.FileSignatureBytes.Span))
                    {
                        return new PqfDecryptResult(false, PqfRefusalReason.SignatureVerificationFailure, emitted, true);
                    }

                    SecureZero.Clear(message);
                    SecureZero.Clear(digest);
                }

                return new PqfDecryptResult(true, null, emitted, false);
            }
            finally
            {
                SecureZero.Clear(selectedDek);
            }
        }
        catch (PqfFileException ex)
        {
            return new PqfDecryptResult(false, ex.Reason, emitted, emitted > 0);
        }
    }
}
