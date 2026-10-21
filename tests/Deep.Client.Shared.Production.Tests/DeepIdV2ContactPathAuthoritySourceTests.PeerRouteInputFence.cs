using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PeerRouteInputFence_ChangedOrMissingConsentRootDuringIssuanceRefusesStore(bool responder)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var scope = await fixture.PreparePeerFenceScope(responder);
        using var command = await fixture.CreateOwnedText(scope, "held route fence test");
        byte[] ciphertext;
        using (var sent = await fixture.SendOwnedMessage(scope, command.OperationId,
            ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span))) ciphertext = sent.ExactEnvelope.ToArray();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: !responder);
        var terminal = new OwnedStoreFixture(fixture, scope, command.OperationId.ToArray(), ciphertext);
        var changed = false;
        grants.BeforeReturn = async () => { await fixture.ChangeOrRemoveConsentRoot(scope); changed = true; };
        if (responder)
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.DeliverNativeMessage(scope, command.OperationId.ToArray(), grants, terminal));
        else
            await Assert.ThrowsAsync<InvalidDataException>(() => fixture.DeliverNativeMessage(scope, command.OperationId.ToArray(), grants, terminal));
        Assert.True(changed); Assert.Equal(1, grants.Calls); Assert.Equal(0, terminal.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PeerRouteInputFence_UnchangedInputsDeliverAndColdReplayWithoutSecondStore(bool responder)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var scope = await fixture.PreparePeerFenceScope(responder);
        using var command = await fixture.CreateOwnedText(scope, "unchanged held route test");
        byte[] ciphertext;
        using (var sent = await fixture.SendOwnedMessage(scope, command.OperationId,
            ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span))) ciphertext = sent.ExactEnvelope.ToArray();
        var terminal = new OwnedStoreFixture(fixture, scope, command.OperationId.ToArray(), ciphertext);
        _ = await fixture.DeliverNativeMessage(scope, command.OperationId.ToArray(),
            new OwnedGrantTransport(fixture, ownerOnPrimary: !responder), terminal);
        Assert.Equal(1, terminal.Calls);
        if (responder) fixture.ColdReopenReceiverStoreStorage(); else fixture.ColdReopenCompactionStorage();
        var replay = new OwnedStoreFixture(fixture, scope, command.OperationId.ToArray(), ciphertext);
        _ = await fixture.DeliverNativeMessage(scope, command.OperationId.ToArray(),
            new OwnedGrantTransport(fixture, ownerOnPrimary: !responder), replay);
        Assert.Equal(0, replay.Calls);
    }

    private sealed partial class Fixture
    {
        internal async Task<Did2MessagingSessionScope> PreparePeerFenceScope(bool responder)
        {
            if (!responder) return (await PrepareRouteFaultPair(this)).Sender;
            var accept = await PrepareCompletedContactSendCase(false);
            accept.Grants.MaximumFixtureGrantLifetimeSeconds = 120;
            _ = await accept.Deliver();
            Assert.Equal(1, accept.Transport.Calls);
            using var grants = await ReadPeerGrantsAsync(own: false);
            var winner = Assert.Single(grants.Entries.Values, value => ProtectedDid2MailboxGrantJournal.HasWinner(value));
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2",
                ProtectedDid2MailboxGrantJournal.Response(winner).Span).Field(8).Span);
            AdvanceStoreSettlementClock(grant.ExpiresAtUnixSeconds + 6);
            return accept.Scope;
        }

        internal async Task ChangeOrRemoveConsentRoot(Did2MessagingSessionScope scope)
        {
            // Disposable owned corruption fixture only: no owner lease is
            // reacquired inside the held issuer callback and no private state
            // is copied between real profiles. A canonical root still changes
            // the exact verified input and must refuse before ingress.
            var secure = scope.IsInitiator ? innerStorage : peerStorage;
            // A canonical empty root has revision1 exactly. Do not invent a
            // noncanonical revision to stand in for a valid-root substitution.
            if (scope.IsInitiator) { await secure.DeleteBatchAsync([ProtectedDid2ContactAcceptJournal.Slot]); return; }
            using var root = await secure.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot) ?? throw new InvalidDataException();
            var old = root.Use(bytes => bytes.ToArray()); byte[] next = [];
            try
            {
                using var state = ProtectedDid2ContactAcceptJournal.Decode(old, scope.Network, scope.LocalAccount, scope.Instance);
                state.Revision++;
                next = ProtectedDid2ContactAcceptJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
                Assert.True(await secure.CompareExchangeAsync(ProtectedDid2ContactAcceptJournal.Slot, old, next));
            }
            finally { CryptographicOperations.ZeroMemory(old); CryptographicOperations.ZeroMemory(next); }
        }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PeerRouteInputFence_FirstAcceptanceCompletesConsentAndColdExactReplay()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var accept = await fixture.PrepareCompletedContactSendCase(false);
        var result = await accept.Deliver();
        Assert.Equal(1, accept.Transport.Calls);
        fixture.ColdReopenReceiverStoreStorage();
        var repeated = await accept.Deliver();
        Assert.Equal(result.Cursor, repeated.Cursor); Assert.Equal(1, accept.Transport.Calls);
    }
}
