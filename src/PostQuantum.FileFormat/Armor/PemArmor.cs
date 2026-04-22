using System.Text;
using System.Text.RegularExpressions;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Armor;

public static class PemArmor
{
    public const string PublicKeyLabel = "PQF PUBLIC KEY";
    public const string SigningPublicKeyLabel = "PQF SIGNING PUBLIC KEY";

    private static readonly Regex PemRegex = new(
        "^\\s*-----BEGIN (?<begin>[A-Z0-9 ]+)-----\\s*(?<body>[A-Za-z0-9+/=\\s]+?)\\s*-----END (?<end>[A-Z0-9 ]+)-----\\s*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.Singleline);

    public static string ArmorPublicKey(PqfPublicKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Armor(PublicKeyLabel, key.ToCanonicalBinary());
    }

    public static string ArmorSigningPublicKey(PqfSigningPublicKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Armor(SigningPublicKeyLabel, key.ToCanonicalBinary());
    }

    public static PqfPublicKey DearmorPublicKey(string pem)
    {
        var bytes = Dearmor(PublicKeyLabel, pem);
        return PqfPublicKey.FromCanonicalBinary(bytes);
    }

    public static PqfSigningPublicKey DearmorSigningPublicKey(string pem)
    {
        var bytes = Dearmor(SigningPublicKeyLabel, pem);
        return PqfSigningPublicKey.FromCanonicalBinary(bytes);
    }

    private static string Armor(string label, byte[] canonicalBytes)
    {
        var base64 = Convert.ToBase64String(canonicalBytes);
        var wrapped = WrapAt64(base64);

        return $"-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n";
    }

    private static byte[] Dearmor(string expectedLabel, string pem)
    {
        if (pem is null)
        {
            throw new ArgumentNullException(nameof(pem));
        }

        var match = PemRegex.Match(pem);
        if (!match.Success)
        {
            throw new FormatException("Input is not valid PEM.");
        }

        var beginLabel = match.Groups["begin"].Value;
        var endLabel = match.Groups["end"].Value;
        if (!string.Equals(beginLabel, endLabel, StringComparison.Ordinal))
        {
            throw new FormatException("PEM begin/end labels do not match.");
        }

        if (!string.Equals(beginLabel, expectedLabel, StringComparison.Ordinal))
        {
            throw new FormatException($"PEM label mismatch. Expected '{expectedLabel}', found '{beginLabel}'.");
        }

        var body = match.Groups["body"].Value;
        var compactBody = RemoveAsciiWhitespace(body);

        try
        {
            return Convert.FromBase64String(compactBody);
        }
        catch (FormatException ex)
        {
            throw new FormatException("PEM body is not valid base64.", ex);
        }
    }

    private static string RemoveAsciiWhitespace(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (var ch in text)
        {
            if (ch is ' ' or '\t' or '\n' or '\r' or '\f' or '\v')
            {
                continue;
            }

            sb.Append(ch);
        }

        return sb.ToString();
    }

    private static string WrapAt64(string base64)
    {
        if (base64.Length <= 64)
        {
            return base64;
        }

        var sb = new StringBuilder(base64.Length + (base64.Length / 64));
        for (var i = 0; i < base64.Length; i += 64)
        {
            var remaining = Math.Min(64, base64.Length - i);
            sb.Append(base64, i, remaining);
            if (i + remaining < base64.Length)
            {
                sb.Append('\n');
            }
        }

        return sb.ToString();
    }
}