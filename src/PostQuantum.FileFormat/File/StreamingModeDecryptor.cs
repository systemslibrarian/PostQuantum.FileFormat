using System.Security.Cryptography;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.File;

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
        try
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
                    return new PqfDecryptResult(false, PqfRefusalReason.SignatureVerificationFailure, 0, false);
                }
            }

            var selectedDek = ResolveDek(reader, identity, hybridKem);
            long emitted = 0;
            using var chunkHasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            try
            {
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
                        return new PqfDecryptResult(false, PqfRefusalReason.AeadTagFailure, emitted, false);
                    }

                    await destination.WriteAsync(plaintextBuffer.AsMemory(0, written), ct).ConfigureAwait(false);
                    emitted += written;
                    SecureZero.Clear(plaintextBuffer);
                }

                if (emitted != reader.ReportedPlaintextBytes)
                {
                    return new PqfDecryptResult(false, PqfRefusalReason.FooterPlaintextBytesMismatch, emitted, true);
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
            return new PqfDecryptResult(false, ex.Reason, 0, false);
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
