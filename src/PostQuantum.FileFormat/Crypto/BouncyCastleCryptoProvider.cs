using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using PostQuantum.FileFormat.TestSupport;

namespace PostQuantum.FileFormat.Crypto;

public sealed class BouncyCastleCryptoProvider : ICryptoProvider
{
    private sealed class InjectableRandomGenerator : IRandomGenerator
    {
        private readonly InjectableRandomness _randomness;

        public InjectableRandomGenerator(InjectableRandomness randomness)
        {
            _randomness = randomness;
        }

        public void AddSeedMaterial(byte[] seed) { }

        public void AddSeedMaterial(ReadOnlySpan<byte> seed) { }

        public void AddSeedMaterial(long seed) { }

        public void NextBytes(byte[] bytes)
        {
            _randomness.Fill(bytes);
        }

        public void NextBytes(Span<byte> bytes)
        {
            _randomness.Fill(bytes);
        }

        public void NextBytes(byte[] bytes, int start, int len)
        {
            _randomness.Fill(bytes.AsSpan(start, len));
        }
    }

    private InjectableRandomness? _injectableRandomness;

    internal void SetInjectableRandomness(InjectableRandomness? randomness)
    {
        _injectableRandomness = randomness;
    }

    private SecureRandom CurrentRandom => _injectableRandomness is null
        ? new SecureRandom()
        : new SecureRandom(new InjectableRandomGenerator(_injectableRandomness));

    public (byte[] sk, byte[] pk) X25519GenerateKeyPair()
    {
        var sk = new X25519PrivateKeyParameters(CurrentRandom);
        var pk = sk.GeneratePublicKey();
        return (sk.GetEncoded(), pk.GetEncoded());
    }

    public byte[] X25519DeriveSharedSecret(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> peerPk)
    {
        // sk arrives as a span over the caller's identity buffer. BouncyCastle's
        // X25519PrivateKeyParameters constructor takes byte[]+offset and copies
        // into its own internal buffer. We must materialize a managed array to
        // call it; we zero that intermediate copy in finally so the GC heap does
        // not retain a plaintext private key past this method's return.
        var skCopy = new byte[sk.Length];
        try
        {
            sk.CopyTo(skCopy);
            var privateKey = new X25519PrivateKeyParameters(skCopy, 0);
            var publicKey = new X25519PublicKeyParameters(peerPk.ToArray(), 0);
            var agreement = new X25519Agreement();
            agreement.Init(privateKey);
            var output = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(publicKey, output, 0);
            return output;
        }
        finally
        {
            SecureZero.Clear(skCopy);
        }
    }

    public (byte[] sk, byte[] pk) MlKem1024GenerateKeyPair()
    {
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(CurrentRandom, MLKemParameters.ml_kem_1024));
        AsymmetricCipherKeyPair kp = generator.GenerateKeyPair();
        var sk = (MLKemPrivateKeyParameters)kp.Private;
        var pk = (MLKemPublicKeyParameters)kp.Public;
        return (sk.GetEncoded(), pk.GetEncoded());
    }

    public (byte[] sharedSecret, byte[] ciphertext) MlKem1024Encapsulate(ReadOnlySpan<byte> peerPk)
    {
        var publicKey = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_1024, peerPk.ToArray());
        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_1024);
        encapsulator.Init(new ParametersWithRandom(publicKey, CurrentRandom));

        var sharedSecret = new byte[encapsulator.SecretLength];
        var ciphertext = new byte[encapsulator.EncapsulationLength];
        encapsulator.Encapsulate(ciphertext, sharedSecret);
        return (sharedSecret, ciphertext);
    }

    public byte[] MlKem1024Decapsulate(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> ciphertext)
    {
        // See note on X25519DeriveSharedSecret: same pattern, zero the
        // intermediate managed copy of the private key in finally.
        var skCopy = new byte[sk.Length];
        try
        {
            sk.CopyTo(skCopy);
            var privateKey = MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_1024, skCopy);
            var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_1024);
            decapsulator.Init(privateKey);

            var sharedSecret = new byte[decapsulator.SecretLength];
            decapsulator.Decapsulate(ciphertext, sharedSecret);
            return sharedSecret;
        }
        finally
        {
            SecureZero.Clear(skCopy);
        }
    }

    public (byte[] sk, byte[] pk) Ed25519GenerateKeyPair()
    {
        var sk = new Ed25519PrivateKeyParameters(CurrentRandom);
        var pk = sk.GeneratePublicKey();
        return (sk.GetEncoded(), pk.GetEncoded());
    }

    public byte[] Ed25519Sign(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message)
    {
        // See note on X25519DeriveSharedSecret.
        var skCopy = new byte[sk.Length];
        try
        {
            sk.CopyTo(skCopy);
            var signer = new Ed25519Signer();
            signer.Init(true, new Ed25519PrivateKeyParameters(skCopy, 0));
            signer.BlockUpdate(message);
            return signer.GenerateSignature();
        }
        finally
        {
            SecureZero.Clear(skCopy);
        }
    }

    public bool Ed25519Verify(ReadOnlySpan<byte> pk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        var signer = new Ed25519Signer();
        signer.Init(false, new Ed25519PublicKeyParameters(pk.ToArray(), 0));
        signer.BlockUpdate(message);
        return signer.VerifySignature(signature.ToArray());
    }

    public (byte[] sk, byte[] pk) MlDsa87GenerateKeyPair()
    {
        var generator = new MLDsaKeyPairGenerator();
        generator.Init(new MLDsaKeyGenerationParameters(CurrentRandom, MLDsaParameters.ml_dsa_87));
        AsymmetricCipherKeyPair kp = generator.GenerateKeyPair();
        var sk = (MLDsaPrivateKeyParameters)kp.Private;
        var pk = (MLDsaPublicKeyParameters)kp.Public;
        return (sk.GetEncoded(), pk.GetEncoded());
    }

    public byte[] MlDsa87Sign(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message)
        => MlDsa87SignCore(sk, message, deterministic: false);

    public byte[] MlDsa87SignDeterministic(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message)
        => MlDsa87SignCore(sk, message, deterministic: true);

    private byte[] MlDsa87SignCore(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message, bool deterministic)
    {
        // See note on X25519DeriveSharedSecret. The second MLDsaSigner ctor
        // arg is the FIPS 204 deterministic flag: true => rnd is zero,
        // signatures over the same (sk, message) are byte-identical.
        var skCopy = new byte[sk.Length];
        try
        {
            sk.CopyTo(skCopy);
            var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_87, deterministic);
            var privateKey = MLDsaPrivateKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_87, skCopy);
            signer.Init(true, privateKey);
            signer.BlockUpdate(message);
            return signer.GenerateSignature();
        }
        finally
        {
            SecureZero.Clear(skCopy);
        }
    }

    public bool MlDsa87Verify(ReadOnlySpan<byte> pk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_87, false);
        var publicKey = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_87, pk.ToArray());
        signer.Init(false, publicKey);
        signer.BlockUpdate(message);
        return signer.VerifySignature(signature.ToArray());
    }
}
