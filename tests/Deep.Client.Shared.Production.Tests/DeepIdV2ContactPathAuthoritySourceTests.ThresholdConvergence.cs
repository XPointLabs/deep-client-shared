using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(0)] // Fully authenticated future threshold is scheduling only.
    [InlineData(1)] // A later XRC signature failure defeats the hint.
    [InlineData(2)] // A later XSS signature failure defeats the hint.
    [InlineData(3)] // Another threshold expires inside the same uncertainty.
    [InlineData(4)] // A future start outside the upper bound is not scheduling.
    [InlineData(5)] // The final actual reading already covers the start.
    [InlineData(6)] // Ordinary author completion remains strict.
    public async Task Did2ThresholdConvergence_FullSignedRetainedEntryKeepsEveryAuthorityCheck(int mode)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckSignedThresholdConvergenceAsync(mode);
    }

    [Theory]
    [InlineData(0)] // Natural lower-bound advance adopts the original once.
    [InlineData(1)] // A nonadvancing clock exhausts the finite attempt count.
    [InlineData(2)] // Caller cancellation during the wait preserves phase one.
    [InlineData(3)] // Actual protected proposal substitution after the wait fails.
    [InlineData(4)] // Current proof expiry after the wait fails.
    [InlineData(5)] // The original acquisition deadline includes a stalled fetch.
    [InlineData(6)] // A same-owner wait cannot cross a boot change.
    [InlineData(7)] // Actual protected source history is reread after waiting.
    [InlineData(8)] // A cancellation-ignoring late clock cannot adopt later.
    public async Task Did2ThresholdConvergence_OwnedRenewalWaitsOnlyForExactPendingResponse(int mode)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckOwnedThresholdConvergenceAsync(mode);
    }

    private sealed partial class Fixture
    {
        private Func<CancellationToken, ValueTask<OnionMonotonicReading>>? thresholdClockOverride;
        internal ParsedDeepIdV2RouteThreshold ThresholdWithFutureSelection(ParsedDeepIdV2RouteThreshold original, ulong start,
            bool expireSuccessor = false)
        {
            var pms = ResignRenewalWitnessRecord(original.Selection, new() { [8] = RenewalU64(start) }, 11);
            var xrc = ResignRenewalWitnessRecord(original.LiveRoute, new() { [7] = pms.CoreHash }, 21);
            var reference = ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes;
            var replacements = new Dictionary<int, ReadOnlyMemory<byte>> { [5] = reference, [9] = pms.CoreHash };
            if (BinaryPrimitives.ReadUInt64BigEndian(xrc.Field(3).Span) == 0)
            { replacements[4] = xrc.CoreHash; replacements[6] = reference; }
            if (expireSuccessor) replacements[11] = RenewalU64(start);
            var xss = ResignRenewalWitnessRecord(original.Successor, replacements, 14);
            return new(pms.CanonicalBytes.Span, xrc.CanonicalBytes.Span, xss.CanonicalBytes.Span);
        }

        internal async Task CheckSignedThresholdConvergenceAsync(int mode)
        {
            var source = Source(); var staged = await accounts.EnsureOwnPreKeyInventoryAsync(source);
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span),
                checkpoint.Binding, checkpoint.Directory);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, dca, Boot, Sample);
            Assert.True(recipient.TrustedUpperUnixSeconds > recipient.TrustedLowerUnixSeconds);
            using var device = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, Network,
                checkpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(checkpoint.Binding.Identity.ActiveDevices.Single(), default);
            var clock = new OnionTrustedTimeAuthority(this);
            var xra = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(recipient, fresh.Network, fresh.Authority,
                device!, 100, Bytes(32, 0xd1), Bytes(32, 0xd2), DeepIdentityCrypto.DeriveX25519PublicKey(Bytes(32, 0xd3)),
                recipient.TrustedLowerUnixSeconds, checked(recipient.TrustedUpperUnixSeconds + 30), clock);
            var threshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(recipient, fresh.Network, fresh.Authority,
                xra.CanonicalBytes, CreateRouteWitnesses(), recipient.TrustedLowerUnixSeconds,
                checked(recipient.TrustedUpperUnixSeconds + 20), clock);
            var start = checked((mode == 4 ? recipient.TrustedUpperUnixSeconds : recipient.TrustedLowerUnixSeconds) + 1);
            threshold = ThresholdWithFutureSelection(threshold, start, expireSuccessor: mode == 3);
            if (mode is 1 or 2)
            {
                var record = mode == 1 ? threshold.LiveRoute : threshold.Successor;
                var corrupted = record.CanonicalBytes.ToArray();
                corrupted[FieldOffset(corrupted, mode == 1 ? 21 : 14) + 32] ^= 1;
                threshold = new(threshold.Selection.CanonicalBytes.Span,
                    mode == 1 ? corrupted : threshold.LiveRoute.CanonicalBytes.Span,
                    mode == 2 ? corrupted : threshold.Successor.CanonicalBytes.Span);
                if (mode == 1)
                {
                    // Bind the dependent record to the corrupted exact XRC so
                    // closure validation reaches the intended witness failure.
                    var reference = ContactCodec.ArtifactReference("XRC1", threshold.LiveRoute).CanonicalBytes;
                    var replacements = new Dictionary<int, ReadOnlyMemory<byte>> { [5] = reference };
                    if (BinaryPrimitives.ReadUInt64BigEndian(threshold.LiveRoute.Field(3).Span) == 0)
                        replacements[6] = reference;
                    var successor = ResignRenewalWitnessRecord(threshold.Successor, replacements, 14);
                    threshold = new(threshold.Selection.CanonicalBytes.Span,
                        threshold.LiveRoute.CanonicalBytes.Span, successor.CanonicalBytes.Span);
                }
            }
            var request = new ContactRouteAuthorityWireRequest(Network, Bytes(32, 0xb3), fresh.Proof.QueriedDirectoryLeafKey.Span,
                fresh.Proof.NextProtectedLkg.LogGeneration, fresh.Proof.NextProtectedLkg.CoreHash.Span,
                staged.ExactDca1.Span, xra.CanonicalBytes.Span);
            var reads = 0;
            var verificationClock = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                new(Boot, mode == 5 && ++reads > 1 ? Sample + 1 : Sample)));
            async Task Verify() => _ = await DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(recipient,
                fresh.Network, fresh.Authority, request, threshold, fresh.Proof.ExactAdh1, verificationClock);
            if (mode == 0)
            {
                var future = await Assert.ThrowsAsync<DeepIdV2RouteNotBeforeException>(Verify);
                Assert.Equal(1U, future.RequiredDelaySeconds);
                Sample += future.RequiredDelaySeconds;
                await Verify(); // Same exact request/response; only actual monotonic time advanced.
            }
            else if (mode == 5) { await Verify(); Assert.Equal(2, reads); }
            else
            {
                var failure = mode == 6
                    ? await Assert.ThrowsAnyAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.CompleteGenesisAsync(
                        recipient, fresh.Network, fresh.Authority, device!, xra.CanonicalBytes, threshold, 2, clock))
                    : await Assert.ThrowsAnyAsync<CryptographicException>(Verify);
                Assert.IsNotType<DeepIdV2RouteNotBeforeException>(failure);
                if (mode is 1 or 2) Assert.Contains("witness signature", failure.Message, StringComparison.Ordinal);
                if (mode == 3) Assert.Contains("Expiry", failure.Message, StringComparison.Ordinal);
            }
        }

        internal async Task CheckOwnedThresholdConvergenceAsync(int mode)
        {
            await SeedShortPermanentProposalAsync();
            var backend = new RenewalBackend(this);
            await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend);
            ProofTime += 60; Sample += 60;
            using (Did2ContactRouteTestHooks.Push(point =>
                { if (point == Did2ContactRouteFailpoint.AfterProposal) throw new IOException("Retain exact successor proposal."); }))
                await Assert.ThrowsAsync<IOException>(async () => await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend));
            var original = await RouteSnapshot();
            backend.FutureRouteSelection = true;
            backend.WaitForRouteDeadline = mode == 5;
            using var cancellation = new CancellationTokenSource();
            var waits = 0;
            var lateClockReached = false;
            using var waitHook = Did2ContactThresholdWaitTestHooks.Push(point =>
            {
                if (point == Did2ContactThresholdWaitFailpoint.BeforeWait)
                { waits++; if (mode == 2) cancellation.Cancel(); }
                else if (mode == 0) Sample++;
                else if (mode == 3) innerStorage.DeleteBatchAsync([ProtectedDid2ContactRouteJournal.Slot]).GetAwaiter().GetResult();
                else if (mode == 4) Sample = backend.CurrentDeadline;
                else if (mode == 6) thresholdClockOverride = _ => ValueTask.FromResult(new OnionMonotonicReading(Bytes(16, 0xef), Sample));
                else if (mode == 7) DamageHistoryAnchorAsync(corrupt: false).GetAwaiter().GetResult();
                else if (mode == 8) thresholdClockOverride = async _ =>
                {
                    thresholdClockOverride = null; lateClockReached = true; cancellation.Cancel();
                    await Task.Delay(100); // Deliberately ignore cancellation in this external callback.
                    return new(Boot, Sample);
                };
            });
            var started = Stopwatch.GetTimestamp();
            try
            {
                if (mode == 0)
                {
                    var completed = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend, cancellation.Token);
                    Assert.Equal(1UL, completed.Generation); Assert.Equal(1, waits);
                    Assert.Equal(2, backend.RouteCalls); Assert.Equal(2, backend.RouteSignings);
                    using var state = await RouteState(); Assert.All(state.Entries.Values, entry => Assert.Equal(7, entry.Phase));
                }
                else
                {
                    if (mode == 1)
                    {
                        var future = await Assert.ThrowsAsync<DeepIdV2RouteNotBeforeException>(async () =>
                            await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend, cancellation.Token));
                        Assert.Equal(1U, future.RequiredDelaySeconds);
                        Assert.Equal(ProtectedDeepIdV2AccountOwner.MaximumRenewalThresholdVerificationAttempts - 1, waits);
                    }
                    else if (mode is 2 or 5 or 8)
                        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                            await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend, cancellation.Token));
                    else
                    {
                        var failure = await Record.ExceptionAsync(async () =>
                            await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend, cancellation.Token));
                        Assert.True(failure is CryptographicException or InvalidDataException, failure?.GetType().FullName ?? "No rejection");
                        Assert.IsNotType<DeepIdV2RouteNotBeforeException>(failure);
                    }
                    if (mode == 5)
                    {
                        Assert.Equal(0, waits); Assert.Equal(1, backend.RouteSignings);
                        Assert.InRange(Stopwatch.GetElapsedTime(started).TotalSeconds, 29, 45);
                    }
                    else { Assert.Equal(2, backend.RouteSignings); }
                    if (mode == 8) { Assert.True(lateClockReached); await Task.Delay(200); }
                    if (mode is 2 or 3 or 4 or 6 or 7 or 8) Assert.Equal(1, waits);
                    Assert.Equal(2, backend.RouteCalls);
                    Assert.Equal(1, backend.PublicationSignings); // No successor adoption/publication.
                    if (mode != 3)
                    {
                        var actual = await RouteSnapshot();
                        try { Assert.Equal(original, actual); }
                        finally { CryptographicOperations.ZeroMemory(actual); }
                    }
                }
            }
            finally { CryptographicOperations.ZeroMemory(original); }
        }
    }
}
