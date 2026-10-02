using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2MessagingMutationBoundsTests
{
    [Theory]
    [InlineData(0, 0)]
    [InlineData(4, 2)]
    [InlineData(5, 0)]
    [InlineData(5, 5)]
    [InlineData(6, 3)]
    [InlineData(7, 3)]
    [InlineData(588, 255)]
    [InlineData(604, 255)]
    public void ProtectedCommitmentDoesNotMakeHostileMutationCanonical(int offset, byte value)
    {
        var scope = MetadataScope(); var empty = Did2MessagingFloor.Empty(scope);
        var bytes = new byte[Did2MessagingFloor.MetadataBytes]; "MSP2"u8.CopyTo(bytes);
        bytes[4] = 1; bytes[5] = 1; empty.Exact.Span.CopyTo(bytes.AsSpan(8)); bytes[offset] = value;
        var pending = Did2MessagingFloor.Pending(scope, empty, 0, 1, Hash(1), Hash(2), bytes, bytes);
        Assert.Throws<InvalidDataException>(() => OwnedDid2MessagingMutation.RecoverProtectedPending(scope, pending, bytes));
        // A rejected constructor/finalizer must never dereference an unowned buffer.
        GC.Collect(); GC.WaitForPendingFinalizers();
    }

    [Fact]
    public void MutationHasNoPublicConstructorAndNoPublicSecretExport()
    {
        var type = typeof(OwnedDid2MessagingMutation);
        Assert.Empty(type.GetConstructors()); Assert.Empty(type.GetProperties());
    }

    [Fact]
    public void SqlConnectionPolicyIsRestoredOnEveryReopenWithoutPQProvisioning()
    {
        var directory = Path.Combine(Path.GetTempPath(), "did2-connection-policy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); var path = Path.Combine(directory, "policy.db"); var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            for (var index = 0; index < 3; index++)
            {
                var policy = SqliteDeepIdV2AccountGeneration.ReadConnectionPolicyForTests(path, key, create: index == 0);
                Assert.Equal(2, policy.Synchronous); Assert.Equal(1, policy.SecureDelete); Assert.Equal("delete", policy.JournalMode);
            }
            Assert.False(File.ReadAllBytes(path).AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            foreach (var file in Directory.EnumerateFiles(directory)) File.Delete(file);
            Directory.Delete(directory);
        }
    }
    private static byte[] Hash(byte value) => Enumerable.Repeat(value, 32).ToArray();
    private static Did2MessagingSessionScope MetadataScope()
    {
        var bytes = new byte[404]; bytes[0] = 1; bytes[1] = 1; bytes.AsSpan(4, 16).Fill(1);
        foreach (var offset in new[] { 20, 52, 92, 132, 172, 212, 244, 276, 308, 340, 372 }) bytes.AsSpan(offset, 32).Fill(checked((byte)(offset % 251 + 1)));
        foreach (var offset in new[] { 84, 124, 164, 204 }) BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), 1);
        return Did2MessagingSessionScope.RestoreMetadata(bytes);
    }
}
