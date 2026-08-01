using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class ScopedMailboxCredentialRepositoryTests
{
    [Fact]
    public void SelectorsAreAccountSubjectIssuerAndKindSeparated()
    {
        var account = OutboxAccountScope.FromBytes(Bytes(32, 1));
        var self = new MailboxCredentialSelector(
            account, MailboxCredentialScopeKind.Self, Bytes(32, 2), Bytes(32, 3));
        var peer = new MailboxCredentialSelector(
            account, MailboxCredentialScopeKind.Peer, Bytes(32, 2), Bytes(32, 3));
        var otherSubject = new MailboxCredentialSelector(
            account, MailboxCredentialScopeKind.Peer, Bytes(32, 4), Bytes(32, 3));
        Assert.NotEqual(self.ScopeId.ToArray(), peer.ScopeId.ToArray());
        Assert.NotEqual(peer.ScopeId.ToArray(), otherSubject.ScopeId.ToArray());
        Assert.DoesNotContain(Convert.ToHexString(Bytes(32, 2)), peer.ToString());
    }

    [Fact]
    public void GroupSelectorRequiresVerifiedMembershipCommitment()
    {
        var account = OutboxAccountScope.FromBytes(Bytes(32, 1));
        Assert.Throws<ArgumentException>(() => new MailboxCredentialSelector(
            account, MailboxCredentialScopeKind.Group, Bytes(32, 2), Bytes(32, 3)));
        Assert.Throws<ArgumentException>(() => new MailboxCredentialSelector(
            account, MailboxCredentialScopeKind.Peer, Bytes(32, 2), Bytes(32, 3),
            Bytes(32, 4)));
        var first = new MailboxCredentialSelector(
            account, MailboxCredentialScopeKind.Group, Bytes(32, 2), Bytes(32, 3),
            Bytes(32, 4));
        var second = new MailboxCredentialSelector(
            account, MailboxCredentialScopeKind.Group, Bytes(32, 2), Bytes(32, 3),
            Bytes(32, 5));
        Assert.NotEqual(first.ScopeId.ToArray(), second.ScopeId.ToArray());
    }

    [Fact]
    public void DirectP2pCannotCarryCloudAuthority()
    {
        new MailboxDeliveryDecision(
            MailboxTransportProtocol.DirectP2p,
            MailboxInfrastructureOwnership.DirectP2p,
            null).Validate();
        Assert.Throws<InvalidOperationException>(() =>
            new MailboxDeliveryDecision(
                MailboxTransportProtocol.DirectP2p,
                MailboxInfrastructureOwnership.DirectP2p,
                Authority()).Validate());
        Assert.Throws<InvalidOperationException>(() =>
            new MailboxDeliveryDecision(
                MailboxTransportProtocol.AuthenticatedMau2,
                MailboxInfrastructureOwnership.OfficialManaged,
                null).Validate());
    }

    [Fact]
    public async Task TargetOverflowFailsBeforeSignerOrDatabaseMutation()
    {
        var path = Path.Combine(
            Path.GetTempPath(), $"deep-scoped-overflow-{Guid.NewGuid():N}.db");
        try
        {
            using var store = new SqliteSessionStore(path);
            var account = OutboxAccountScope.FromBytes(Bytes(32, 1));
            var selector = new MailboxCredentialSelector(
                account, MailboxCredentialScopeKind.Self,
                Bytes(32, 2), Bytes(32, 3));
            var binding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
                1, Bytes(16, 4), new BlindedMailboxId(Bytes(32, 5)),
                new BlindedPlacementId(Bytes(32, 6)), 0, 1, []);
            var target = new ScopedMailboxBatchTarget(selector, binding);
            var request = new ScopedMailboxPrepareBatchRequest(
                account, Bytes(16, 7),
                Enumerable.Repeat(
                    target,
                    SqliteSessionStore.MaximumScopedMailboxBatchTargets + 1)
                    .ToArray(),
                DateTimeOffset.FromUnixTimeMilliseconds(1000));

            await Assert.ThrowsAsync<ArgumentException>(() =>
                store.PrepareScopedMailboxBatchAsync(
                    request, new ThrowingSigner(), Authority()));

            using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
            connection.Open();
            using var count = connection.CreateCommand();
            count.CommandText =
                "SELECT count(*) FROM mailbox_prepared_batches;";
            Assert.Equal(0L, (long)count.ExecuteScalar()!);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
            {
                if (File.Exists(candidate))
                {
                    File.Delete(candidate);
                }
            }
        }
    }

    private static VerifiedOfficialMailboxAuthority Authority() =>
        new(Bytes(16, 8), 1, [Issuer(Bytes(32, 9))], true,
            static () => true,
            new NoRevocations(),
            TimeProvider.System);

    private static MailboxCapabilityIssuerAuthority Issuer(byte[] key) => new()
    {
        PublicKey = key,
        Domain = MailboxCapabilityDomain.Deposit,
        AllowedLifecycle = MailboxCapabilityLifecycle.Active,
        MinimumGeneration = 1,
        MaximumGeneration = 1,
        ValidFromUnixSeconds = 1,
        ValidUntilUnixSeconds = ulong.MaxValue
    };

    private static byte[] Bytes(int count, byte value) =>
        Enumerable.Repeat(value, count).ToArray();

    private sealed class NoRevocations : IFreshMailboxCapabilityRevocationSource
    {
        public void ValidateFreshness() { }
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => false;
    }

    private sealed class ThrowingSigner : IMailboxOperationSigner
    {
        public Deep.Client.Shared.Domain.SessionId SessionId =>
            throw new InvalidOperationException("Signer must not be called.");
        public byte[] GetEd25519PublicKey() =>
            throw new InvalidOperationException("Signer must not be called.");
        public byte[] SignMailboxPresentation(
            MailboxAuthenticatedOperation operation,
            ReadOnlySpan<byte> canonicalPresentationSigningBytes) =>
            throw new InvalidOperationException("Signer must not be called.");
    }
}
