using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2SustainedRetrieve_Crosses128DistinctGrantsWithoutResetAndColdResumesRead()
    {
        // Actual signed requests/results, protected roots and SQLCipher. The
        // issuer/read terminal is in-process; this is not physical delivery.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 1_200);
        await fixture.CheckSustainedRetrieveGrantsAsync(rollover: true);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2SustainedRetrieve_128ActualGrantsKeepFloorsAndBackpressureBeforePolicyCeiling()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 1_200);
        await fixture.CheckSustainedRetrieveGrantsAsync(rollover: false);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckExpiredRetrieveReplacementAsync()
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            TrackMailboxDispatchClock();
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            var first = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
            Assert.Equal(0, (await SynchronizeNativeSender(first, terminal)).ProcessedEnvelopes);
            byte[] original;
            using (var grants = await ReadPeerGrantsAsync(own: true)) original = Assert.Single(grants.Entries).Value.ToArray();
            var originalGrant = ContactCodec.Decode("XMC2", first.OriginalResponse.Span).Field(8);
            var originalHash = Convert.ToHexString(SHA256.HashData(originalGrant.Span));
            try
            {
                await AdvanceOriginalStoreEpochForTestAsync(1_206);
                var second = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true)
                    { MaximumFixtureGrantLifetimeSeconds = 34 };
                Assert.Equal(0, (await SynchronizeNativeSender(second, terminal)).ProcessedEnvelopes);
                Assert.Equal(1, second.Calls);
                using (var grants = await ReadPeerGrantsAsync(own: true)) Assert.Equal(2, grants.Entries.Count);
                var expires = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2", second.OriginalResponse.Span).Field(8).Span).ExpiresAtUnixSeconds;
                var delta = checked(expires + 6 - CurrentProofTime);
                ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
                ColdReopenCompactionStorage();
                var third = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true)
                    { MaximumFixtureGrantLifetimeSeconds = 34 };
                Assert.Equal(0, (await SynchronizeNativeSender(third, terminal)).ProcessedEnvelopes);
                Assert.Equal(1, third.Calls); Assert.Equal(3, terminal.RetrieveCalls);
                using (var grants = await ReadPeerGrantsAsync(own: true))
                {
                    Assert.Equal(3, grants.Entries.Count);
                    Assert.True(CryptographicOperations.FixedTimeEquals(original,
                        grants.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(original)]));
                    Assert.Equal(Convert.ToHexString(SHA256.HashData(third.OriginalRequest.Span)), Assert.Single(grants.Selections).Value.Current);
                }
                using var reads = await ReadPeerMailboxReads(own: true);
                Assert.Equal(0, reads.Phase); Assert.Null(reads.Active);
                Assert.True(reads.Counters.ContainsKey(originalHash)); // No floor/holder retirement on this hint.
            }
            finally { CryptographicOperations.ZeroMemory(original); }
        }

        internal async Task CheckRetainedNamespaceMetadataAsync()
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            await AdvanceOriginalStoreEpochForTestAsync(1_206);
            TrackMailboxDispatchClock();
            var issuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            Assert.Equal(0, (await SynchronizeNativeSender(issuer, terminal)).ProcessedEnvelopes);
            byte[] policy, projection;
            using (var grants = await ReadPeerGrantsAsync(own: true))
            {
                var entry = Assert.Single(grants.Entries).Value;
                policy = ProtectedDid2MailboxGrantJournal.OriginalPolicy(entry).ToArray();
                projection = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span).Projection.CanonicalBytes.ToArray();
            }
            await AdvanceCurrentRoutingAuthorityAsync(3_500);
            var delta = checked(6_006UL - CurrentProofTime);
            ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
            var account = ReopenAccount(); var source = Source(account);
            var own = await source.VerifyForOwnPreKeyAuthoringAsync(account, default);
            var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(own.Network, own.Authority,
                own.MailboxAuthority.ExactPma2, source.RendezvousTrustedTime);
            var original = ContactCodec.Decode("PMT2", projection);
            using var before = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            var protectedBefore = before.Use(bytes => bytes.ToArray());
            try
            {
                await Assert.ThrowsAsync<CryptographicException>(() => host.RequireOriginalNamespaceAsync(policy, projection).AsTask());
                await own.RequireOriginalMailboxNamespacesAsync(host, policy, original, MailboxCapabilityDomain.Retrieve, default);
                await Assert.ThrowsAsync<CryptographicException>(() => own.RequireOriginalMailboxNamespacesAsync(host,
                    policy, original, MailboxCapabilityDomain.Deposit, default).AsTask());
                await Assert.ThrowsAsync<CryptographicException>(() => own.RequireOriginalMailboxNamespacesAsync(host,
                    policy, original, (MailboxCapabilityDomain)255, default).AsTask());
                var badPolicy = policy.ToArray(); badPolicy[^1] ^= 1;
                await Assert.ThrowsAsync<CryptographicException>(() => own.RequireOriginalMailboxNamespacesAsync(host,
                    badPolicy, original, MailboxCapabilityDomain.Retrieve, default).AsTask());
                var issuanceCore = ContactCodec.Decode("PMA2", policy).CoreHash.ToArray();
                foreach (var defect in new[] { "missing-issuance-projection", "missing-route-policy", "changed-projection" })
                {
                    var metadata = own.NamespaceRecords;
                    var pmts = metadata.ExactOrderedPmt2Chain.Select(bytes => bytes.ToArray()).ToList();
                    var pmas = metadata.ExactOrderedPma2Chain.Select(bytes => bytes.ToArray()).ToList();
                    if (defect == "missing-route-policy")
                        pmas.RemoveAll(bytes => CryptographicOperations.FixedTimeEquals(
                            ContactCodec.Decode("PMA2", bytes).CoreHash.Span, original.Field(4).Span[6..]));
                    else
                    {
                        var at = pmts.FindIndex(bytes => CryptographicOperations.FixedTimeEquals(ContactCodec.Decode("PMT2", bytes).Field(4).Span[6..], issuanceCore));
                        Assert.True(at >= 0);
                        if (defect == "missing-issuance-projection") pmts.RemoveAt(at);
                        else pmts[at][^1] ^= 1;
                    }
                    var changed = own with { NamespaceRecords = new DeepIdV2NetworkClosureArtifacts(
                        metadata.ExactXna1AuthorityChain, metadata.ExactDts1PolicyChain, metadata.ExactOrderedXvp1Chain,
                        metadata.ExactOrderedXnv1Chain, metadata.ExactOrderedXnh1Chain, metadata.ExactActiveXnd1,
                        pmts.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray(), pmas.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray()) };
                    await Assert.ThrowsAsync<CryptographicException>(() => changed.RequireOriginalMailboxNamespacesAsync(host,
                        policy, original, MailboxCapabilityDomain.Retrieve, default).AsTask());
                }
                using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => own.RequireOriginalMailboxNamespacesAsync(host,
                    policy, original, MailboxCapabilityDomain.Retrieve, cancelled.Token).AsTask());
                using var after = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                Assert.True(after.Use(bytes => CryptographicOperations.FixedTimeEquals(bytes, protectedBefore)));
                Assert.Equal(1, issuer.Calls); Assert.Equal(1, terminal.RetrieveCalls);
            }
            finally { CryptographicOperations.ZeroMemory(protectedBefore); }
        }

        internal async Task CheckSustainedRetrieveGrantsAsync(bool rollover)
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            await AdvanceOriginalStoreEpochForTestAsync(1_206);
            TrackMailboxDispatchClock();
            var count = ProtectedDid2MailboxGrantJournal.MaximumEntries + (rollover ? 1 : 0);
            var issued = new HashSet<string>(StringComparer.Ordinal);
            var requests = new HashSet<string>(StringComparer.Ordinal);
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            ulong priorExpiry = 0;
            var issuerCalls = 0;
            for (var ordinal = 0; ordinal < count; ordinal++)
            {
                if (priorExpiry != 0)
                {
                    // Short grant expiry triggers renewal, NOT retirement.
                    // The original signed possible-issuance ceiling must also
                    // close. Keep the actual replacement valid across it.
                    var next = rollover && ordinal == 127 ? 6_006UL : checked(priorExpiry + 6);
                    var delta = checked(next - CurrentProofTime);
                    ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
                }
                var issuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true)
                    // Retrieve's actual timeout+retry margin and both signed
                    // uncertainty bounds must fit;20s cannot authorize a read.
                    { MaximumFixtureGrantLifetimeSeconds = rollover && ordinal == 126
                        ? checked((uint)(6_060UL - checked(CurrentProofTime - 5)))
                        : rollover && ordinal >= 127 ? 120U : 34U };
                var interrupted = ordinal == 64;
                if (interrupted)
                {
                    using (ClientMailboxRetrieveTestHooks.Push(point =>
                        { if (point == ClientMailboxRetrieveFailpoint.AfterPageCommit) throw new IOException("Interrupted sustained read after durable page."); }))
                        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => SynchronizeNativeSender(issuer, terminal));
                    using (var pending = await ReadPeerMailboxReads(own: true))
                    { Assert.Equal(3, pending.Phase); Assert.NotNull(pending.Active); }
                    ColdReopenCompactionStorage();
                    var calls = terminal.RetrieveCalls;
                    Assert.Equal(0, (await SynchronizeNativeSender(issuer, terminal)).ProcessedEnvelopes);
                    Assert.Equal(calls, terminal.RetrieveCalls); // Resume the committed page, never reissue it.
                }
                else Assert.Equal(0, (await SynchronizeNativeSender(issuer, terminal)).ProcessedEnvelopes);

                Assert.Equal(1, issuer.Calls); Assert.True(issuer.BuiltHeldFrame); Assert.True(issuer.ExactRetry);
                issuerCalls += issuer.Calls;
                Assert.True(requests.Add(Convert.ToHexString(SHA256.HashData(issuer.OriginalRequest.Span))));
                var grantBytes = ContactCodec.Decode("XMC2", issuer.OriginalResponse.Span).Field(8);
                var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(grantBytes.Span);
                var hash = Convert.ToHexString(SHA256.HashData(grantBytes.Span));
                Assert.True(issued.Add(hash)); priorExpiry = grant.ExpiresAtUnixSeconds;
                Assert.True(checked(CurrentProofTime + 5) < priorExpiry);
                using (var grants = await ReadPeerGrantsAsync(own: true))
                {
                    Assert.InRange(grants.Entries.Count, 1, ProtectedDid2MailboxGrantJournal.MaximumEntries);
                    var selection = Assert.Single(grants.Selections).Value;
                    Assert.Null(selection.Pending);
                    Assert.Equal(Convert.ToHexString(SHA256.HashData(issuer.OriginalRequest.Span)), selection.Current);
                    Assert.Equal(issuer.OriginalResponse.ToArray(), ProtectedDid2MailboxGrantJournal.Response(grants.Entries[selection.Current!]).ToArray());
                }
                using (var reads = await ReadPeerMailboxReads(own: true))
                {
                    Assert.Equal(0, reads.Phase); Assert.Null(reads.Active);
                    Assert.InRange(reads.Counters.Count, 1, ProtectedDid2MailboxReadJournal.MaximumFloors);
                    Assert.True(reads.Counters[hash] > 0);
                    Assert.Single(reads.Traversals); // Same original retained path, not 129 invented routes.
                }
                // A real disk reopen and a second public poll must reuse the
                // selected grant, with no extra issuance or account reset.
                if (ordinal % 16 == 0 || ordinal == count - 1) ColdReopenCompactionStorage();
                var unused = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
                Assert.Equal(0, (await SynchronizeNativeSender(unused, terminal)).ProcessedEnvelopes);
                Assert.Equal(0, unused.Calls);
                if (rollover && ordinal == 64)
                    await AdvanceCurrentRoutingAuthorityAsync(checked(CurrentProofTime + 30));
            }
            Assert.Equal(count, issued.Count); Assert.Equal(count, requests.Count); Assert.Equal(count, issuerCalls);
            Assert.Equal(count * 2, terminal.RetrieveCalls); // Two completed public polls per real grant.
            await SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
            using var final = await ReadPeerMailboxReads(own: true);
            Assert.Equal(0, final.Phase); Assert.Null(final.Active);
            if (!rollover)
            {
                Assert.Equal(ProtectedDid2MailboxReadJournal.MaximumFloors, final.Counters.Count);
                using var beforeRead = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
                using var beforeGrant = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                var delta = checked(priorExpiry + 6 - CurrentProofTime);
                ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
                var unused = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
                var readsBefore = terminal.RetrieveCalls;
                await Assert.ThrowsAsync<IOException>(() => SynchronizeNativeSender(unused, terminal));
                Assert.Equal(0, unused.Calls); Assert.Equal(readsBefore, terminal.RetrieveCalls);
                using var afterRead = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
                using var afterGrant = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                var readHash = beforeRead.Use(bytes => SHA256.HashData(bytes));
                var grantHash = beforeGrant.Use(bytes => SHA256.HashData(bytes));
                Assert.True(afterRead.Use(bytes => CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), readHash)));
                Assert.True(afterGrant.Use(bytes => CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), grantHash)));
            }
        }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2SustainedRetrieve_ExpiredReplacementDefersRetirementAndNewReadRenews()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 1_200);
        await fixture.CheckExpiredRetrieveReplacementAsync();
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RetainedNamespaceMetadata_DistinctIssuanceAndRouteJoinsRejectSubstitutionWithoutMutation()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 1_200);
        await fixture.CheckRetainedNamespaceMetadataAsync();
    }
}
