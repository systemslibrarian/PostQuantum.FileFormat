using System.Security.Cryptography;
using System.Text.Json;
using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.File;

public sealed class TestVectorConformanceTests
{
    [Fact]
    public async Task Manifest_vectors_conform_in_authenticated_and_streaming_modes()
    {
        var root = ResolveRepoRoot();
        var vectorRoot = Path.Combine(root, "test-vectors", "v1");
        var manifestPath = Path.Combine(vectorRoot, "manifest.json");

        Assert.True(System.IO.File.Exists(manifestPath), "Run PostQuantum.FileFormat.TestVectors first to generate manifest.json.");

        var manifestJson = await System.IO.File.ReadAllTextAsync(manifestPath);
        var manifest = JsonSerializer.Deserialize<VectorManifest>(manifestJson, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        });

        Assert.NotNull(manifest);
        Assert.Equal("v1", manifest!.Version);
        Assert.Equal(47, manifest.Vectors.Count);

        var identities = manifest.Identities.ToDictionary(
            i => i.Id,
            i => new PqfIdentity(
                PqfPublicKey.FromCanonicalBinary(Convert.FromBase64String(i.PublicKey)),
                Convert.FromBase64String(i.X25519PrivateKey),
                Convert.FromBase64String(i.MlKem1024PrivateKey)));

        foreach (var vector in manifest.Vectors)
        {
            var filePath = Path.Combine(vectorRoot, vector.File.Replace('/', Path.DirectorySeparatorChar));
            var bytes = await System.IO.File.ReadAllBytesAsync(filePath);
            var identity = identities[vector.Identity];

            if (string.Equals(vector.Expect, "success", StringComparison.Ordinal))
            {
                await AssertSuccessInBothModes(bytes, vector, identity);
            }
            else
            {
                await AssertFailureInBothModes(bytes, vector, identity);
            }
        }
    }

    private static async Task AssertSuccessInBothModes(byte[] bytes, VectorManifestEntry vector, PqfIdentity identity)
    {
        using var authInput = new MemoryStream(bytes);
        using var authOutput = new MemoryStream();
        await PqfDecryptor.DecryptAsync(authInput, authOutput, identity);

        var authPlaintext = authOutput.ToArray();
        Assert.Equal(vector.PlaintextSha256, Convert.ToHexString(SHA256.HashData(authPlaintext)));

        using var streamInput = new MemoryStream(bytes);
        using var streamOutput = new MemoryStream();
        var result = await PqfDecryptor.DecryptStreamingAsync(streamInput, streamOutput, identity);

        Assert.True(result.Success);
        Assert.False(result.PostHocAuthenticationFailed);

        var streamPlaintext = streamOutput.ToArray();
        Assert.Equal(vector.PlaintextSha256, Convert.ToHexString(SHA256.HashData(streamPlaintext)));
    }

    private static async Task AssertFailureInBothModes(byte[] bytes, VectorManifestEntry vector, PqfIdentity identity)
    {
        var expectedReason = Enum.Parse<PqfRefusalReason>(vector.Reason!, ignoreCase: false);

        using var authInput = new MemoryStream(bytes);
        using var authOutput = new MemoryStream();
        PqfFileException? authEx = null;
        try
        {
            await PqfDecryptor.DecryptAsync(authInput, authOutput, identity);
        }
        catch (PqfFileException ex)
        {
            authEx = ex;
        }

        Assert.True(authEx is not null, $"{vector.Id}: authenticated mode unexpectedly succeeded");
        Assert.True(authEx!.Reason == expectedReason, $"{vector.Id}: authenticated expected {expectedReason}, got {authEx.Reason}");
        Assert.Equal(0, authOutput.Length);

        using var streamInput = new MemoryStream(bytes);
        using var streamOutput = new MemoryStream();
        var result = await PqfDecryptor.DecryptStreamingAsync(streamInput, streamOutput, identity);

        Assert.False(result.Success);
        Assert.True(result.FailureReason == expectedReason, $"{vector.Id}: streaming expected {expectedReason}, got {result.FailureReason}");
        Assert.True(result.PostHocAuthenticationFailed == vector.StreamingPostHocFailure, $"{vector.Id}: streaming post-hoc expected {vector.StreamingPostHocFailure}, got {result.PostHocAuthenticationFailed}");
    }

    private static string ResolveRepoRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (System.IO.File.Exists(Path.Combine(current.FullName, "PostQuantum.FileFormat.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Could not locate repository root.");
    }

    private sealed record VectorManifest(string Version, IReadOnlyList<IdentityManifest> Identities, IReadOnlyList<VectorManifestEntry> Vectors);

    private sealed record IdentityManifest(string Id, string PublicKey, string X25519PrivateKey, string MlKem1024PrivateKey);

    private sealed record VectorManifestEntry(string Id, string File, string Expect, string Identity, string? Reason, bool StreamingPostHocFailure, string? PlaintextSha256);
}
