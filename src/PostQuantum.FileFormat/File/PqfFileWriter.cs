using System.Buffers.Binary;
using System.Security.Cryptography;
using PostQuantum.FileFormat.Cbor;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.Keys;
using PostQuantum.FileFormat.TestSupport;

namespace PostQuantum.FileFormat.File;

public static class PqfFileWriter
{
    private sealed record RecipientMaterial(byte[] ClassicalEpk, byte[] PqcCt, byte[] WrappedDek, byte[] WrappedDekNonce);

    public static async Task EncryptAsync(
        Stream plaintext,
        Stream destination,
        IReadOnlyList<PqfPublicKey> recipients,
        PqfSigningIdentity? signer,
        int chunkSize = 65536,
        ICryptoProvider? provider = null,
        CancellationToken cancellationToken = default)
    {
        await EncryptAsync(
            plaintext,
            destination,
            recipients,
            signer,
            chunkSize,
            provider,
            randomness: null,
            createdUtc: null,
            cancellationToken).ConfigureAwait(false);
    }

    internal static async Task EncryptAsync(
        Stream plaintext,
        Stream destination,
        IReadOnlyList<PqfPublicKey> recipients,
        PqfSigningIdentity? signer,
        int chunkSize,
        ICryptoProvider? provider,
        InjectableRandomness? randomness,
        DateTimeOffset? createdUtc,
        CancellationToken cancellationToken)
    {
        if (recipients is null || recipients.Count == 0)
        {
            throw new ArgumentException("At least one recipient is required", nameof(recipients));
        }

        if (chunkSize < 4096 || chunkSize > 16_777_216 || (chunkSize & (chunkSize - 1)) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkSize), "Chunk size must be power-of-two in [4096, 16777216]");
        }

        var crypto = provider ?? CryptoProvider.Detect();

        if (randomness is not null)
        {
            if (crypto is BouncyCastleCryptoProvider bc)
            {
                bc.SetInjectableRandomness(randomness);
            }
            else if (crypto is BclCryptoProvider bcl)
            {
                bcl.SetInjectableRandomness(randomness);
            }
        }

        var hybridKem = new HybridKem(crypto);
        var hybridSigner = new HybridSigner(crypto);

        var dek = new byte[32];
        var fileId = new byte[16];
        if (randomness is null)
        {
            RandomNumberGenerator.Fill(dek);
            RandomNumberGenerator.Fill(fileId);
        }
        else
        {
            randomness.Fill(dek);
            randomness.Fill(fileId);
        }
        var recipientMaterials = new List<RecipientMaterial>(recipients.Count);

        try
        {
            for (var i = 0; i < recipients.Count; i++)
            {
                var (classicalEpk, pqcCiphertext, kek) = hybridKem.Encapsulate(recipients[i], fileId, (uint)i);
                var (nonce, wrappedDek) = randomness is null
                    ? DekWrapper.Wrap(kek, dek, fileId)
                    : WrapDeterministic(kek, dek, fileId, randomness);
                SecureZero.Clear(kek);

                recipientMaterials.Add(new RecipientMaterial(classicalEpk, pqcCiphertext, wrappedDek, nonce));
            }

            var header = BuildHeader(fileId, chunkSize, recipientMaterials, signer?.PublicKey, createdUtc);
            var headerBytes = DeterministicCborEncoder.Encode(header).ToArray();

            byte[]? headerSignature = null;
            if (signer is not null)
            {
                headerSignature = hybridSigner.Sign(signer, headerBytes);
            }

            // magic + version + header length
            var prefix = new byte[10];
            BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(0, 4), 0x50514631);
            BinaryPrimitives.WriteUInt16BigEndian(prefix.AsSpan(4, 2), 0x0001);
            BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(6, 4), (uint)headerBytes.Length);

            await destination.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
            await destination.WriteAsync(headerBytes, cancellationToken).ConfigureAwait(false);
            if (headerSignature is not null)
            {
                await destination.WriteAsync(headerSignature, cancellationToken).ConfigureAwait(false);
            }

            using var chunkHasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            ulong chunkCount = 0;
            ulong plaintextBytes = 0;

            var current = new byte[chunkSize];
            var next = new byte[chunkSize];

            var currentRead = await plaintext.ReadAsync(current.AsMemory(0, chunkSize), cancellationToken).ConfigureAwait(false);
            while (currentRead > 0)
            {
                var nextRead = await plaintext.ReadAsync(next.AsMemory(0, chunkSize), cancellationToken).ConfigureAwait(false);
                var isFinal = nextRead == 0;

                var encrypted = new byte[currentRead + 16];
                var encryptedLen = ChunkCipher.EncryptChunk(dek, chunkCount, isFinal, fileId, current.AsSpan(0, currentRead), encrypted);

                var chunkPrefix = new byte[5];
                BinaryPrimitives.WriteUInt32BigEndian(chunkPrefix.AsSpan(0, 4), (uint)encryptedLen);
                chunkPrefix[4] = isFinal ? (byte)0x01 : (byte)0x00;

                await destination.WriteAsync(chunkPrefix, cancellationToken).ConfigureAwait(false);
                await destination.WriteAsync(encrypted.AsMemory(0, encryptedLen), cancellationToken).ConfigureAwait(false);

                chunkHasher.AppendData(chunkPrefix);
                chunkHasher.AppendData(encrypted.AsSpan(0, encryptedLen));

                chunkCount++;
                plaintextBytes += (ulong)currentRead;

                SecureZero.Clear(encrypted);
                SecureZero.Clear(current.AsSpan(0, currentRead));

                var temp = current;
                current = next;
                next = temp;
                currentRead = nextRead;
            }

            // Footer
            var footer = new byte[20];
            BinaryPrimitives.WriteUInt32BigEndian(footer.AsSpan(0, 4), 0x50514645);
            BinaryPrimitives.WriteUInt64BigEndian(footer.AsSpan(4, 8), chunkCount);
            BinaryPrimitives.WriteUInt64BigEndian(footer.AsSpan(12, 8), plaintextBytes);
            await destination.WriteAsync(footer, cancellationToken).ConfigureAwait(false);

            if (signer is not null)
            {
                var chunksHash = chunkHasher.GetHashAndReset();
                var signatureMessage = new byte[16 + 32 + 20];
                fileId.CopyTo(signatureMessage, 0);
                chunksHash.CopyTo(signatureMessage, 16);
                footer.CopyTo(signatureMessage, 48);

                var fileSignature = hybridSigner.Sign(signer, signatureMessage);
                await destination.WriteAsync(fileSignature, cancellationToken).ConfigureAwait(false);

                SecureZero.Clear(chunksHash);
                SecureZero.Clear(signatureMessage);
                SecureZero.Clear(fileSignature);
            }

            SecureZero.Clear(prefix);
            SecureZero.Clear(footer);
            SecureZero.Clear(headerBytes);
            SecureZero.Clear(headerSignature);
        }
        finally
        {
            SecureZero.Clear(dek);
            SecureZero.Clear(fileId);
            foreach (var recipient in recipientMaterials)
            {
                SecureZero.Clear(recipient.ClassicalEpk);
                SecureZero.Clear(recipient.PqcCt);
                SecureZero.Clear(recipient.WrappedDek);
                SecureZero.Clear(recipient.WrappedDekNonce);
            }
        }
    }

    private static (byte[] nonce, byte[] wrappedDek) WrapDeterministic(
        ReadOnlySpan<byte> kek,
        ReadOnlySpan<byte> dek,
        ReadOnlySpan<byte> fileId,
        InjectableRandomness randomness)
    {
        var nonce = new byte[DekWrapper.WrapNonceLength];
        randomness.Fill(nonce);
        return DekWrapper.Wrap(kek, dek, fileId, nonce);
    }

    private static CborValue BuildHeader(
        ReadOnlySpan<byte> fileId,
        int chunkSize,
        IReadOnlyList<RecipientMaterial> recipients,
        PqfSigningPublicKey? signer,
        DateTimeOffset? createdUtc)
    {
        var algMap = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("aead"), CborValue.Text("aes-256-gcm-chunked")),
            new(CborValue.Text("combiner"), CborValue.Text("pqf1-concat-extract-v1")),
            new(CborValue.Text("kdf"), CborValue.Text("hkdf-sha256")),
            new(CborValue.Text("kem"), CborValue.Text("x25519+ml-kem-1024")),
            new(CborValue.Text("sig"), CborValue.Text("ed25519+ml-dsa-87")),
        });

        var recipientItems = new CborValue[recipients.Count];
        for (var i = 0; i < recipients.Count; i++)
        {
            var recipient = recipients[i];
            recipientItems[i] = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
            {
                new(CborValue.Text("classical_epk"), CborValue.Bytes(recipient.ClassicalEpk)),
                new(CborValue.Text("pqc_ct"), CborValue.Bytes(recipient.PqcCt)),
                new(CborValue.Text("wrapped_dek"), CborValue.Bytes(recipient.WrappedDek)),
                new(CborValue.Text("wrapped_dek_nonce"), CborValue.Bytes(recipient.WrappedDekNonce)),
            });
        }

        var entries = new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("alg"), algMap),
            new(CborValue.Text("chunk_size"), CborValue.Uint((ulong)chunkSize)),
            new(CborValue.Text("created"), CborValue.Tag(0, CborValue.Text((createdUtc ?? DateTimeOffset.UtcNow).ToString("yyyy-MM-ddTHH:mm:ssZ")))),
            new(CborValue.Text("file_id"), CborValue.Bytes(fileId.ToArray())),
            new(CborValue.Text("recipients"), CborValue.Array(recipientItems)),
        };

        if (signer is not null)
        {
            entries.Add(new(
                CborValue.Text("signer"),
                CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
                {
                    new(CborValue.Text("classical_pub"), CborValue.Bytes(signer.Ed25519PublicKey.ToArray())),
                    new(CborValue.Text("pqc_pub"), CborValue.Bytes(signer.MlDsa87PublicKey.ToArray())),
                })));
        }

        return CborValue.Map(entries);
    }
}
