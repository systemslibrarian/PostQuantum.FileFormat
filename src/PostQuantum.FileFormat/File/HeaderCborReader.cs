using PostQuantum.FileFormat.Cbor;

namespace PostQuantum.FileFormat.File;

/// <summary>
/// Parses and validates a deterministic CBOR header according to spec §4.
/// All schema constraints are enforced with precise refusal reasons.
/// </summary>
internal static class HeaderCborReader
{
    public static PqfFileHeader Parse(CborValue headerValue)
    {
        if (headerValue is not CborValue.MapValue mapValue)
        {
            throw new PqfFileException(
                PqfRefusalReason.NonDeterministicCborEncoding,
                "Header CBOR is not a map");
        }

        var entries = mapValue.Entries;
        var header = new PqfFileHeader();
        var seenFields = new HashSet<string>();

        foreach (var entry in entries)
        {
            // Extract field name
            if (entry.Key is not CborValue.TextValue textKey)
            {
                throw new PqfFileException(
                    PqfRefusalReason.NonDeterministicCborEncoding,
                    "Header map key is not a text string");
            }

            var fieldName = textKey.Value;
            if (!seenFields.Add(fieldName))
            {
                throw new PqfFileException(
                    PqfRefusalReason.DuplicateCborKey,
                    $"Duplicate field in header: {fieldName}");
            }

            switch (fieldName)
            {
                case "alg":
                    ParseAlg(entry.Value, header);
                    break;
                case "chunk_size":
                    ParseChunkSize(entry.Value, header);
                    break;
                case "created":
                    ParseCreated(entry.Value, header);
                    break;
                case "file_id":
                    ParseFileId(entry.Value, header);
                    break;
                case "recipients":
                    ParseRecipients(entry.Value, header);
                    break;
                case "signer":
                    ParseSigner(entry.Value, header);
                    break;
                default:
                    throw new PqfFileException(
                        PqfRefusalReason.UnknownHeaderField,
                        $"Unknown header field: {fieldName}");
            }
        }

        // Verify all required fields present
        if (header.SignatureAlgorithm == null)
            throw new PqfFileException(PqfRefusalReason.MissingRequiredField, "Missing required field: alg");
        if (header.ChunkSize == 0)
            throw new PqfFileException(PqfRefusalReason.MissingRequiredField, "Missing required field: chunk_size");
        if (header.CreatedUtc == default)
            throw new PqfFileException(PqfRefusalReason.MissingRequiredField, "Missing required field: created");
        if (header.FileId.Length == 0)
            throw new PqfFileException(PqfRefusalReason.MissingRequiredField, "Missing required field: file_id");
        if (header.Recipients.Count == 0)
            throw new PqfFileException(PqfRefusalReason.RecipientsEmpty, "Recipients array is empty");

        return header;
    }

    private static void ParseAlg(CborValue value, PqfFileHeader header)
    {
        if (value is not CborValue.MapValue mapValue)
        {
            throw new PqfFileException(
                PqfRefusalReason.AlgorithmIdentifierMismatch,
                "Field 'alg' must be a map");
        }

        var algFields = new HashSet<string>();
        var requiredAlgValues = new Dictionary<string, string>
        {
            ["aead"] = "aes-256-gcm-chunked",
            ["combiner"] = "x-wing",
            ["kdf"] = "hkdf-sha256",
            ["kem"] = "x25519+ml-kem-768",
            ["sig"] = "ed25519+ml-dsa-87",
        };

        foreach (var entry in mapValue.Entries)
        {
            if (entry.Key is not CborValue.TextValue textKey)
            {
                throw new PqfFileException(
                    PqfRefusalReason.AlgorithmIdentifierMismatch,
                    "Algorithm map key is not a text string");
            }

            var fieldName = textKey.Value;
            if (!algFields.Add(fieldName))
            {
                throw new PqfFileException(
                    PqfRefusalReason.DuplicateCborKey,
                    $"Duplicate field in alg: {fieldName}");
            }

            if (entry.Value is not CborValue.TextValue textValue)
            {
                throw new PqfFileException(
                    PqfRefusalReason.AlgorithmIdentifierMismatch,
                    $"Algorithm field '{fieldName}' must be a text string");
            }

            if (!requiredAlgValues.TryGetValue(fieldName, out var expectedValue))
            {
                throw new PqfFileException(
                    PqfRefusalReason.UnknownHeaderField,
                    $"Unknown algorithm field: {fieldName}");
            }

            if (textValue.Value != expectedValue)
            {
                throw new PqfFileException(
                    PqfRefusalReason.AlgorithmIdentifierMismatch,
                    $"Algorithm '{fieldName}' has wrong value: expected '{expectedValue}', got '{textValue.Value}'");
            }
        }

        // Verify all required algorithm fields are present
        foreach (var requiredField in requiredAlgValues.Keys)
        {
            if (!algFields.Contains(requiredField))
            {
                throw new PqfFileException(
                    PqfRefusalReason.MissingRequiredField,
                    $"Missing required algorithm field: {requiredField}");
            }
        }

        header.SignatureAlgorithm = "v1";
    }

    private static void ParseChunkSize(CborValue value, PqfFileHeader header)
    {
        if (value is not CborValue.UIntValue uintValue)
        {
            throw new PqfFileException(
                PqfRefusalReason.ChunkSizeInvalid,
                "Field 'chunk_size' must be an unsigned integer");
        }

        var chunkSize = (long)uintValue.Value;

        // Check range [4096, 16777216]
        if (chunkSize < 4096 || chunkSize > 16_777_216)
        {
            throw new PqfFileException(
                PqfRefusalReason.ChunkSizeInvalid,
                $"Chunk size out of range: {chunkSize} (must be 4096-16777216)");
        }

        // Check power of 2
        if ((chunkSize & (chunkSize - 1)) != 0)
        {
            throw new PqfFileException(
                PqfRefusalReason.ChunkSizeInvalid,
                $"Chunk size must be a power of 2: {chunkSize}");
        }

        header.ChunkSize = (uint)chunkSize;
    }

    private static void ParseCreated(CborValue value, PqfFileHeader header)
    {
        if (value is not CborValue.TagValue tagValue || tagValue.TagNumber != 0)
        {
            throw new PqfFileException(
                PqfRefusalReason.CreatedTimestampInvalid,
                "Field 'created' must be CBOR tag 0 (RFC 3339 datetime)");
        }

        if (tagValue.Value is not CborValue.TextValue textValue)
        {
            throw new PqfFileException(
                PqfRefusalReason.CreatedTimestampInvalid,
                "CBOR tag 0 must contain a text string");
        }

        var dateStr = textValue.Value;

        // Validate RFC 3339 UTC format: must end with 'Z' and parse correctly
        if (!dateStr.EndsWith("Z"))
        {
            throw new PqfFileException(
                PqfRefusalReason.CreatedTimestampInvalid,
                "Timestamp must use UTC (Z suffix), not offset");
        }

        if (!System.DateTime.TryParseExact(dateStr, "yyyy-MM-ddTHH:mm:ssZ", null, System.Globalization.DateTimeStyles.AssumeUniversal, out var dt))
        {
            throw new PqfFileException(
                PqfRefusalReason.CreatedTimestampInvalid,
                $"Timestamp is not valid RFC 3339 format: {dateStr}");
        }

        header.CreatedUtc = dt;
    }

    private static void ParseFileId(CborValue value, PqfFileHeader header)
    {
        if (value is not CborValue.BytesValue bytesValue)
        {
            throw new PqfFileException(
                PqfRefusalReason.BinaryFieldLengthMismatch,
                "Field 'file_id' must be a byte string");
        }

        if (bytesValue.Value.Length != 16)
        {
            throw new PqfFileException(
                PqfRefusalReason.BinaryFieldLengthMismatch,
                $"Field 'file_id' must be exactly 16 bytes, got {bytesValue.Value.Length}");
        }

        header.FileId = bytesValue.Value.ToArray();
    }

    private static void ParseRecipients(CborValue value, PqfFileHeader header)
    {
        if (value is not CborValue.ArrayValue arrayValue)
        {
            throw new PqfFileException(
                PqfRefusalReason.RecipientsEmpty,
                "Field 'recipients' must be an array");
        }

        if (arrayValue.Items.Count == 0)
        {
            throw new PqfFileException(
                PqfRefusalReason.RecipientsEmpty,
                "Recipients array is empty");
        }

        foreach (var item in arrayValue.Items)
        {
            header.Recipients.Add(ParseRecipient(item));
        }
    }

    private static PqfRecipientBlock ParseRecipient(CborValue value)
    {
        if (value is not CborValue.MapValue mapValue)
        {
            throw new PqfFileException(
                PqfRefusalReason.BinaryFieldLengthMismatch,
                "Recipient must be a map");
        }

        var recipient = new PqfRecipientBlock();
        var seenFields = new HashSet<string>();
        var requiredFields = new HashSet<string> { "classical_epk", "pqc_ct", "wrapped_dek", "wrapped_dek_nonce" };

        foreach (var entry in mapValue.Entries)
        {
            if (entry.Key is not CborValue.TextValue textKey)
            {
                throw new PqfFileException(
                    PqfRefusalReason.UnknownHeaderField,
                    "Recipient map key is not a text string");
            }

            var fieldName = textKey.Value;
            if (!seenFields.Add(fieldName))
            {
                throw new PqfFileException(
                    PqfRefusalReason.DuplicateCborKey,
                    $"Duplicate field in recipient: {fieldName}");
            }

            if (entry.Value is not CborValue.BytesValue bytesValue)
            {
                throw new PqfFileException(
                    PqfRefusalReason.BinaryFieldLengthMismatch,
                    $"Recipient field '{fieldName}' must be a byte string");
            }

            switch (fieldName)
            {
                case "classical_epk":
                    if (bytesValue.Value.Length != 32)
                        throw new PqfFileException(
                            PqfRefusalReason.BinaryFieldLengthMismatch,
                            $"Field 'classical_epk' must be 32 bytes, got {bytesValue.Value.Length}");
                    recipient.ClassicalEpk = bytesValue.Value.ToArray();
                    break;
                case "pqc_ct":
                    if (bytesValue.Value.Length != 1088)
                        throw new PqfFileException(
                            PqfRefusalReason.BinaryFieldLengthMismatch,
                            $"Field 'pqc_ct' must be 1088 bytes, got {bytesValue.Value.Length}");
                    recipient.PqcCt = bytesValue.Value.ToArray();
                    break;
                case "wrapped_dek":
                    if (bytesValue.Value.Length != 48)
                        throw new PqfFileException(
                            PqfRefusalReason.BinaryFieldLengthMismatch,
                            $"Field 'wrapped_dek' must be 48 bytes, got {bytesValue.Value.Length}");
                    recipient.WrappedDek = bytesValue.Value.ToArray();
                    break;
                case "wrapped_dek_nonce":
                    if (bytesValue.Value.Length != 12)
                        throw new PqfFileException(
                            PqfRefusalReason.BinaryFieldLengthMismatch,
                            $"Field 'wrapped_dek_nonce' must be 12 bytes, got {bytesValue.Value.Length}");
                    recipient.WrappedDekNonce = bytesValue.Value.ToArray();
                    break;
                default:
                    throw new PqfFileException(
                        PqfRefusalReason.UnknownHeaderField,
                        $"Unknown recipient field: {fieldName}");
            }
        }

        // Verify all required fields present
        foreach (var required in requiredFields)
        {
            if (!seenFields.Contains(required))
            {
                throw new PqfFileException(
                    PqfRefusalReason.MissingRequiredField,
                    $"Missing required recipient field: {required}");
            }
        }

        return recipient;
    }

    private static void ParseSigner(CborValue value, PqfFileHeader header)
    {
        // Signer can be null (unsigned file) or a map
        if (value is CborValue.NullValue)
        {
            header.Signer = null;
            return;
        }

        if (value is not CborValue.MapValue mapValue)
        {
            throw new PqfFileException(
                PqfRefusalReason.AlgorithmIdentifierMismatch,
                "Field 'signer' must be a map or null");
        }

        var signer = new PqfSignerBlock();
        var seenFields = new HashSet<string>();
        var requiredFields = new HashSet<string> { "classical_pub", "pqc_pub" };

        foreach (var entry in mapValue.Entries)
        {
            if (entry.Key is not CborValue.TextValue textKey)
            {
                throw new PqfFileException(
                    PqfRefusalReason.UnknownHeaderField,
                    "Signer map key is not a text string");
            }

            var fieldName = textKey.Value;
            if (!seenFields.Add(fieldName))
            {
                throw new PqfFileException(
                    PqfRefusalReason.DuplicateCborKey,
                    $"Duplicate field in signer: {fieldName}");
            }

            if (entry.Value is not CborValue.BytesValue bytesValue)
            {
                throw new PqfFileException(
                    PqfRefusalReason.BinaryFieldLengthMismatch,
                    $"Signer field '{fieldName}' must be a byte string");
            }

            switch (fieldName)
            {
                case "classical_pub":
                    if (bytesValue.Value.Length != 32)
                        throw new PqfFileException(
                            PqfRefusalReason.BinaryFieldLengthMismatch,
                            $"Field 'classical_pub' must be 32 bytes, got {bytesValue.Value.Length}");
                    signer.ClassicalPub = bytesValue.Value.ToArray();
                    break;
                case "pqc_pub":
                    if (bytesValue.Value.Length != 2592)
                        throw new PqfFileException(
                            PqfRefusalReason.BinaryFieldLengthMismatch,
                            $"Field 'pqc_pub' must be 2592 bytes, got {bytesValue.Value.Length}");
                    signer.PqcPub = bytesValue.Value.ToArray();
                    break;
                default:
                    throw new PqfFileException(
                        PqfRefusalReason.UnknownHeaderField,
                        $"Unknown signer field: {fieldName}");
            }
        }

        // Verify all required fields present
        foreach (var required in requiredFields)
        {
            if (!seenFields.Contains(required))
            {
                throw new PqfFileException(
                    PqfRefusalReason.MissingRequiredField,
                    $"Missing required signer field: {required}");
            }
        }

        header.Signer = signer;
    }
}
