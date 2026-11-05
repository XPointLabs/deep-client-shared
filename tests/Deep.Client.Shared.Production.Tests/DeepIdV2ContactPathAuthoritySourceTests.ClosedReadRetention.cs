using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2ClosedReadRetention_ActualPressureSealsHistoricalUnknownWithoutReplayingAndColdReads()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 5_000);
        await fixture.CheckClosedReadRetentionAsync("pressure");
    }

    [Theory]
    [InlineData("missing")] [InlineData("tampered")] [InlineData("foreign-instance")] [InlineData("callback")]
    [InlineData("restored-reference")]
    public async Task Did2ClosedReadRetention_ExactSealedOriginalRemainsMandatoryBeforeNewWork(string defect)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 5_000);
        await fixture.CheckClosedReadRetentionAsync(defect);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckClosedReadRetentionAsync(string defect)
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            TrackMailboxDispatchClock();
            var first = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true)
                { MaximumFixtureGrantLifetimeSeconds = 34 };
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true)
                { ReturnEmptyPage = true, LoseRetrieveReply = true };
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => SynchronizeNativeSender(first, terminal));
            var originalMau = Assert.Single(terminal.ExactRetrieveRequests).ToArray();
            var acquisition = Convert.ToHexString(SHA256.HashData(first.OriginalRequest.Span));
            var originalGrant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2", first.OriginalResponse.Span).Field(8).Span);
            var originalHash = SHA256.HashData(MailboxAuthenticatedCapabilityCodec.EncodeGrant(originalGrant));
            byte[] original;
            using (var state = await ReadPeerGrantsAsync(own: true)) original = state.Entries[acquisition].ToArray();
            void Past(ulong expiry)
            {
                var target = Math.Max(checked(expiry + 31), checked(CurrentProofTime + 1));
                var delta = target - CurrentProofTime; ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
            }
            try
            {
                Past(originalGrant.ExpiresAtUnixSeconds); terminal.LoseRetrieveReply = false;
                var successor = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true)
                    { MaximumFixtureGrantLifetimeSeconds = 34 };
                Assert.Equal(0, (await SynchronizeNativeSender(successor, terminal)).ProcessedEnvelopes);
                Assert.Equal(1, successor.Calls);
                using (var read = await ReadPeerMailboxReads(own: true))
                { Assert.Equal(originalMau, Assert.Single(read.Closed).Value.ExactMau); Assert.Equal(0, read.Phase); }
                var slot = ProtectedDid2MailboxGrantJournal.RetainedSlot(Convert.FromHexString(acquisition));
                if (defect == "pressure")
                {
                    var expiry = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2", successor.OriginalResponse.Span).Field(8).Span).ExpiresAtUnixSeconds;
                    for (var index = 2; index < 20; index++)
                    {
                        Past(expiry);
                        var issuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true)
                            { MaximumFixtureGrantLifetimeSeconds = 34 };
                        Assert.Equal(0, (await SynchronizeNativeSender(issuer, terminal)).ProcessedEnvelopes);
                        Assert.Equal(1, issuer.Calls);
                        expiry = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2", issuer.OriginalResponse.Span).Field(8).Span).ExpiresAtUnixSeconds;
                    }
                    using (var state = await ReadPeerGrantsAsync(own: true))
                    {
                        Assert.False(state.Entries.ContainsKey(acquisition));
                        Assert.Equal(1, state.Retained[acquisition].Phase);
                        using var raw = await storage.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                        using var exact = raw.Use(bytes => ProtectedDid2MailboxGrantJournal.DecodeRetained(state, acquisition,
                            bytes, Network, bytes.Slice(28, 32), bytes.Slice(60, 32)));
                        Assert.Equal(original, exact.Entries[acquisition]);
                    }
                    ColdReopenCompactionStorage();
                    var noNewIssuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
                    Assert.Equal(0, (await SynchronizeNativeSender(noNewIssuer, terminal)).ProcessedEnvelopes);
                    Assert.Equal(0, noNewIssuer.Calls);
                    using var after = await ReadPeerMailboxReads(own: true);
                    Assert.Equal(originalMau, Assert.Single(after.Closed).Value.ExactMau);
                    Assert.Equal(MailboxAuthenticatedClientRequestCodec.Decode(originalMau).Presentation.ReplayCounter,
                        after.Counters[Convert.ToHexString(originalHash)]);
                    Assert.Single(terminal.ExactRetrieveRequests, value => value.AsSpan().SequenceEqual(originalMau));
                    return;
                }
                // Two real signed acquisitions + a real closed unknown query.
                // This explicit codec/storage move sets up hostile reader inputs;
                // the pressure Fact above separately proves producer eligibility.
                using (var before = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException())
                {
                    var root = before.Use(bytes => bytes.ToArray());
                    using var state = before.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, Network, bytes.Slice(28, 32), bytes.Slice(60, 32)));
                    var account = root.AsSpan(28, 32).ToArray(); var instance = root.AsSpan(60, 32).ToArray();
                    var moved = ProtectedDid2MailboxGrantJournal.SealOldest(state, Convert.FromHexString(acquisition), Network, account, instance);
                    try { Assert.True(await storage.CompareExchangeAndInsertAsync(ProtectedDid2MailboxGrantJournal.Slot, root, moved.Working, [new(slot, moved.Retained)])); }
                    finally { foreach (var bytes in new[] { root, account, instance, moved.Working, moved.Retained }) CryptographicOperations.ZeroMemory(bytes); }
                }
                if (defect == "restored-reference")
                {
                    using var before = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                    var root = before.Use(bytes => bytes.ToArray());
                    using var state = before.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, Network, bytes.Slice(28, 32), bytes.Slice(60, 32)));
                    var restored = ProtectedDid2MailboxGrantJournal.RestoreRetainedOldest(state, acquisition, original,
                        Network, root.AsSpan(28, 32), root.AsSpan(60, 32));
                    try { Assert.True(await storage.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, root, restored)); }
                    finally { CryptographicOperations.ZeroMemory(root); CryptographicOperations.ZeroMemory(restored); }
                }
                ColdReopenCompactionStorage();
                using var grantRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                using var readRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
                using var sealedRoot = await storage.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                var working = grantRoot.Use(bytes => bytes.ToArray()); var sealedBytes = sealedRoot.Use(bytes => bytes.ToArray());
                var hit = false;
                async Task Damage()
                {
                    if (defect is "missing" or "callback")
                        Assert.True(await innerStorage.CompareAndDeleteAsync(ProtectedDid2MailboxGrantJournal.Slot, working, [slot]));
                    else
                    {
                        var damaged = sealedBytes.ToArray();
                        try
                        {
                            if (defect == "tampered") damaged[^1] ^= 1; else damaged[60] ^= 1;
                            Assert.True(await innerStorage.CompareExchangeAsync(slot, sealedBytes, damaged));
                        }
                        finally { CryptographicOperations.ZeroMemory(damaged); }
                    }
                }
                if (defect is not ("callback" or "restored-reference")) await Damage();
                var calls = terminal.RetrieveCalls;
                var blockedIssuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
                using var hook = Did2AcquisitionRetentionTestHooks.Push(point =>
                {
                    if (defect == "callback" && point == Did2AcquisitionRetentionFailpoint.AfterClosedSourceCapture)
                    { hit = true; Damage().GetAwaiter().GetResult(); }
                });
                var error = await Record.ExceptionAsync(() => SynchronizeNativeSender(blockedIssuer, terminal));
                Assert.True(error is CryptographicException or InvalidDataException or FormatException);
                Assert.Equal(defect == "callback", hit); Assert.Equal(0, blockedIssuer.Calls); Assert.Equal(calls, terminal.RetrieveCalls);
                using var afterGrant = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                using var afterRead = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
                Assert.Equal(working, afterGrant.Use(bytes => bytes.ToArray()));
                Assert.Equal(readRoot.Use(bytes => bytes.ToArray()), afterRead.Use(bytes => bytes.ToArray()));
                CryptographicOperations.ZeroMemory(working); CryptographicOperations.ZeroMemory(sealedBytes);
            }
            finally { foreach (var bytes in new[] { original, originalMau, originalHash }) CryptographicOperations.ZeroMemory(bytes); }
        }
    }
}
