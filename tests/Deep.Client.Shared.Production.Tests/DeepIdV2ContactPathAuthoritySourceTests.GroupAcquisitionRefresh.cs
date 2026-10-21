using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2Groups_AcquisitionRefresh_UncachedThirdMemberAdvancesFloorAndNewScopeReacquires()
    {
        await using var f = await Fixture.CreateAsync(withPeer: true);
        await f.CheckGroupAcquisitionRefreshAsync();
    }

    [Theory]
    [InlineData("network")]
    [InlineData("clock")]
    [InlineData("corrupt-floor")]
    public async Task Did2Groups_AcquisitionRefresh_OtherChangedCustodyIsTerminal(string fault)
    {
        await using var f = await Fixture.CreateAsync(withPeer: true);
        await f.CheckGroupAcquisitionRefreshAsync(fault);
    }

    [Fact]
    public async Task Did2Groups_AcquisitionRefresh_UnavailableMemberDoesNotBecomeRefreshSignal()
    {
        await using var f = await Fixture.CreateAsync(withPeer: true);
        await f.CheckUnavailableGroupMemberAsync();
    }

    [Fact]
    public async Task Did2Groups_AcquisitionRefresh_InvalidNonceIsTerminalAndCannotAdvanceFloor()
    {
        await using var f = await Fixture.CreateAsync(withPeer: true);
        await f.CheckInvalidGroupMemberAsync();
    }

    private sealed partial class Fixture
    {
        private VerifiedAdc1V2? groupAcquisitionExtraCheckpoint;
        private bool corruptGroupAcquisitionNonce;

        // The normal fixture is unchanged. Only this regression adds a third
        // independently created account to genuinely signed proof material.
        private VerifiedAdc1V2[] GroupAcquisitionProofCheckpoints() =>
            groupAcquisitionExtraCheckpoint is { } third
                ? [checkpoint, peerCheckpoint!, third]
                : peerCheckpoint is null ? [checkpoint] : [checkpoint, peerCheckpoint];

        private async Task PrepareUncachedThirdGroupMemberAsync()
        {
            using var thirdStorage = new InMemoryDeepSecureStorage();
            var path = Path.Combine(directory, "third-group-member"); Directory.CreateDirectory(path);
            var third = new DeepIdV2AccountService(thirdStorage, path, Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            await third.CreateAsync("Independent third group member");
            var admission = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(await third.PrepareGenesisAdmissionAsync()).Admission;
            groupAcquisitionExtraCheckpoint = DeepIdV2GenesisAdmissionVerifier.Verify(admission, 1_000, 1, 2, pq);
            retainedIssuanceHistory = new()
            {
                [genesis.ProtectedHead.LogGeneration] = genesis.ProtectedHead,
                [head.ProtectedHead.LogGeneration] = head.ProtectedHead
            };
            head = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(bootstrap.Authority, head.ProtectedHead,
                new(head.ExactAllTransitions, [checkpoint, peerCheckpoint!], [groupAcquisitionExtraCheckpoint!], 990, 1_500, 2), witnesses);
            retainedIssuanceHistory[head.ProtectedHead.LogGeneration] = head.ProtectedHead;
        }

        internal async Task CheckGroupAcquisitionRefreshAsync(string? fault = null)
        {
            // Authenticate the genuine first head before adding another leaf.
            // Issuance may advance its actual protected floor one successor at
            // a time; a fixture must not skip that root-authorized boundary.
            _ = await Source().VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            await PrepareUncachedThirdGroupMemberAsync();
            using var outer = Source().OpenCommandReadScope(); var source = outer.Source;
            var captured = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var third = groupAcquisitionExtraCheckpoint!;
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            // Cache a different, genuine member at the captured view. The third
            // member remains absent from the explicit command's memo.
            using (var held = await lease.AcquireAsync(default))
                _ = await source.VerifyGroupDirectoryAsync(peerCheckpoint!.Binding.DeepId.CanonicalBytes,
                    peerCheckpoint.Binding.Record.DeepAccountId, captured, held, default);
            var oldHead = head;
            var next = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(bootstrap.Authority, head.ProtectedHead,
                new(head.ExactAllTransitions, GroupAcquisitionProofCheckpoints(), [], 990, 1_500, 2), witnesses);
            OnNextDirectoryProof = () =>
            {
                head = next;
                retainedIssuanceHistory![oldHead.ProtectedHead.LogGeneration] = oldHead.ProtectedHead;
                retainedIssuanceHistory[head.ProtectedHead.LogGeneration] = head.ProtectedHead;
            };
            var before = ProofRequests;
            byte[]? beforeGroupHash;
            using (var root = await innerStorage.ReadOwnedAsync(ProtectedDid2GroupJournal.Slot))
                beforeGroupHash = root?.Use(bytes => SHA256.HashData(bytes));
            using (var held = await lease.AcquireAsync(default))
            {
                await Assert.ThrowsAsync<DeepIdV2GroupDirectoryViewAdvancedException>(async () =>
                    await source.VerifyGroupDirectoryAsync(third.Binding.DeepId.CanonicalBytes,
                        third.Binding.Record.DeepAccountId, captured, held, default));
            }
            Assert.Equal(before + 1, ProofRequests);
            // Normal account setup may own an empty journal. A refused member
            // acquisition must preserve its EXACT authenticated prior bytes.
            using (var root = await innerStorage.ReadOwnedAsync(ProtectedDid2GroupJournal.Slot))
                Assert.Equal(beforeGroupHash, root?.Use(bytes => SHA256.HashData(bytes)));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default));

            if (fault == "network")
            {
                await AdvanceNetworkAsync();
                _ = await Source().VerifyCurrentNetworkAsync(Network);
            }
            else if (fault == "clock") Sample = captured.Proof.MonotonicSample - 1;
            else if (fault == "corrupt-floor") await DamageHistoryAnchorAsync(corrupt: true);
            if (fault is not null)
            {
                using var held = await lease.AcquireAsync(default);
                // Use the actual newer verified directory floor, but an old
                // captured pair. No other custody failure may be reclassified.
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await source.RecheckEndpointPairUnderLeaseAsync(captured, captured.Proof, held, default,
                        groupAcquisition: true));
                return;
            }

            // Match the publisher's restart boundary: release actual owner
            // first, reset only scheduling memo, then acquire an INDEPENDENT
            // command even though an outer explicit command is still active.
            await source.DiscardUncapturedAuthorityAsync(default);
            using var retry = source.OpenIndependentCommandReadScope();
            var fresh = await retry.Source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            Assert.NotSame(source, retry.Source); Assert.NotSame(captured, fresh);
            Assert.Equal(next.ProtectedHead.LogGeneration, fresh.Proof.NextProtectedLkg.LogGeneration);
            using (var held = await lease.AcquireAsync(default))
            {
                var verified = await retry.Source.VerifyGroupDirectoryAsync(third.Binding.DeepId.CanonicalBytes,
                    third.Binding.Record.DeepAccountId, fresh, held, default);
                Assert.Equal(third.Binding.Record.DeepAccountId.ToArray(), verified.AccountId.ToArray());
            }
            Assert.Equal(before + 3, ProofRequests);
        }

        internal async Task CheckUnavailableGroupMemberAsync()
        {
            var source = Source(); var own = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            RejectProof = true;
            using var held = await new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock")).AcquireAsync(default);
            await Assert.ThrowsAsync<DeepIdV2DirectoryProofUnavailableException>(async () =>
                await source.VerifyGroupDirectoryAsync(peerCheckpoint!.Binding.DeepId.CanonicalBytes,
                    peerCheckpoint.Binding.Record.DeepAccountId, own, held, default));
        }

        internal async Task CheckInvalidGroupMemberAsync()
        {
            var source = Source(); var own = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            corruptGroupAcquisitionNonce = true; var before = ProofRequests;
            using (var held = await new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock")).AcquireAsync(default))
                await Assert.ThrowsAsync<FormatException>(async () =>
                    await source.VerifyGroupDirectoryAsync(peerCheckpoint!.Binding.DeepId.CanonicalBytes,
                        peerCheckpoint.Binding.Record.DeepAccountId, own, held, default));
            Assert.Equal(before + 1, ProofRequests);
            // No query-floor advance is authorized by the mismatched nonce.
            await proofs.RequireStillFreshAsync(own.Proof, own.Authority, default);
        }
    }
}
