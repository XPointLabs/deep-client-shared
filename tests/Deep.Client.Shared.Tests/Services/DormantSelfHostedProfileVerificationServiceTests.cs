using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;

namespace Deep.Client.Shared.Tests.Services;

public sealed class DormantSelfHostedProfileVerificationServiceTests
{
    [Fact]
    public async Task AcceptedFrozenVectorsVerifyWithExactBoundedMetadata()
    {
        var manifest = P14A2TestSupport.Manifest();
        Assert.Equal("cd9d20a8ec8346d171d4cd070dde170aa5f471d7", manifest.AcceptedP14C2SourceCommit);
        foreach (var vector in manifest.Vectors)
        {
            var staging = new StagedSelfHostedProfileService(new InMemorySessionStore());
            var scope = P14A2TestSupport.Scope(0x91);
            var payload = P14A2TestSupport.Fixture(vector.File);
            var saved = await staging.SaveAsync(
                scope,
                StagedSelfHostedProfileLimits.SchemaVersion,
                payload);
            var service = new DormantSelfHostedProfileVerificationService(
                staging,
                new P14A2DeterministicVerifier());

            var outcome = await service.VerifyAsync(
                scope,
                saved.Candidate!.Id,
                P14A2TestSupport.Parameters());

            Assert.Equal(DormantSelfHostedProfileVerificationStatus.Verified, outcome.Status);
            var metadata = Assert.IsType<DormantSelfHostedProfileVerificationMetadata>(outcome.Metadata);
            Assert.Equal(manifest.Fingerprint, metadata.Fingerprint);
            Assert.Equal(manifest.MinimumProtocol, metadata.MinimumProtocol);
            Assert.Equal(manifest.MaximumProtocol, metadata.MaximumProtocol);
            Assert.Equal(vector.ComponentCount, metadata.ComponentCount);
            Assert.Equal(vector.BridgeCount, metadata.BridgeCount);
        }
    }

    [Fact]
    public async Task VerifierBoundRejectsStagedLargerCandidateWithoutMutation()
    {
        var store = new InMemorySessionStore();
        var staging = new StagedSelfHostedProfileService(store);
        var scope = P14A2TestSupport.Scope(0x92);
        var payload = Enumerable.Repeat((byte)0x5a, ProfileCarrierLimits.MaximumFilePayloadBytes + 1).ToArray();
        var saved = await staging.SaveAsync(scope, StagedSelfHostedProfileLimits.SchemaVersion, payload);
        var service = new DormantSelfHostedProfileVerificationService(staging, new P14A2DeterministicVerifier());

        var outcome = await service.VerifyAsync(scope, saved.Candidate!.Id, P14A2TestSupport.Parameters());
        var exported = await staging.ExportAsync(scope, saved.Candidate.Id);

        Assert.Equal(DormantSelfHostedProfileVerificationStatus.BoundsExceeded, outcome.Status);
        Assert.Null(outcome.Metadata);
        Assert.Equal(StagedSelfHostedProfileExportResult.Exported, exported.Result);
        Assert.Equal(payload, exported.GetCandidateBytesCopy());
        Assert.Single((await staging.ListAsync(scope)).Candidates);
    }

    [Fact]
    public async Task MissingMalformedTrustAndInvalidRequestAreFixedStatuses()
    {
        var staging = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var scope = P14A2TestSupport.Scope(0x93);
        var valid = P14A2TestSupport.Fixture("accepted-eff4523-default.dpf");
        var validSave = await staging.SaveAsync(scope, 1, valid);
        var malformed = valid.ToArray();
        malformed[0] ^= 0xff;
        var malformedSave = await staging.SaveAsync(scope, 1, malformed);
        var missingId = (await staging.SaveAsync(scope, 1, [0x01])).Candidate!.Id;
        await staging.DeleteAsync(scope, missingId);

        var accepting = new DormantSelfHostedProfileVerificationService(staging, new P14A2DeterministicVerifier());
        var rejecting = new DormantSelfHostedProfileVerificationService(staging, new RejectingVerifier());

        Assert.Equal(DormantSelfHostedProfileVerificationStatus.Missing,
            (await accepting.VerifyAsync(scope, missingId, P14A2TestSupport.Parameters())).Status);
        Assert.Equal(DormantSelfHostedProfileVerificationStatus.Malformed,
            (await accepting.VerifyAsync(scope, malformedSave.Candidate!.Id, P14A2TestSupport.Parameters())).Status);
        Assert.Equal(DormantSelfHostedProfileVerificationStatus.TrustRejected,
            (await rejecting.VerifyAsync(scope, validSave.Candidate!.Id, P14A2TestSupport.Parameters())).Status);
        Assert.Equal(DormantSelfHostedProfileVerificationStatus.InvalidRequest,
            (await accepting.VerifyAsync(scope, validSave.Candidate.Id,
                new(P14A2TestSupport.VerificationTime, P14A2TestSupport.ClockSkew, 0))).Status);
    }

    [Fact]
    public async Task VerifierDependencyFailuresAreSanitizedAndOomIsUnchanged()
    {
        const string sentinel = "verifier-provider-sensitive-sentinel";
        var staging = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var scope = P14A2TestSupport.Scope(0x94);
        var saved = await staging.SaveAsync(scope, 1,
            P14A2TestSupport.Fixture("accepted-eff4523-default.dpf"));
        var throwing = new DormantSelfHostedProfileVerificationService(
            staging,
            new ThrowingVerifier(new ProfileContractException(sentinel)));

        var outcome = await throwing.VerifyAsync(scope, saved.Candidate!.Id, P14A2TestSupport.Parameters());
        Assert.Equal(DormantSelfHostedProfileVerificationStatus.DependencyFailure, outcome.Status);
        Assert.DoesNotContain(sentinel, outcome.ToString(), StringComparison.Ordinal);

        var oom = new OutOfMemoryException(sentinel);
        var oomService = new DormantSelfHostedProfileVerificationService(staging, new ThrowingVerifier(oom));
        var actual = await Assert.ThrowsAsync<OutOfMemoryException>(() =>
            oomService.VerifyAsync(scope, saved.Candidate.Id, P14A2TestSupport.Parameters()));
        Assert.Same(oom, actual);
    }

    [Fact]
    public async Task AssociatedCancellationDuringVerificationIsSanitized()
    {
        var staging = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var scope = P14A2TestSupport.Scope(0x95);
        var saved = await staging.SaveAsync(scope, 1,
            P14A2TestSupport.Fixture("accepted-eff4523-default.dpf"));
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var service = new DormantSelfHostedProfileVerificationService(
            staging,
            new BlockingVerifier(new P14A2DeterministicVerifier(), entered, release));
        using var cancellation = new CancellationTokenSource();

        var verification = Task.Run(() => service.VerifyAsync(
            scope,
            saved.Candidate!.Id,
            P14A2TestSupport.Parameters(),
            cancellation.Token));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        cancellation.Cancel();
        release.Set();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => verification);
        Assert.True(exception.CancellationToken.IsCancellationRequested);
        Assert.Null(exception.InnerException);
        Assert.DoesNotContain("provider", exception.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExportSnapshotCanVerifyAfterConcurrentDeleteWithoutResurrection()
    {
        var staging = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var scope = P14A2TestSupport.Scope(0x96);
        var saved = await staging.SaveAsync(scope, 1,
            P14A2TestSupport.Fixture("accepted-eff4523-default.dpf"));
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var service = new DormantSelfHostedProfileVerificationService(
            staging,
            new BlockingVerifier(new P14A2DeterministicVerifier(), entered, release));

        var verification = Task.Run(() => service.VerifyAsync(
            scope, saved.Candidate!.Id, P14A2TestSupport.Parameters()));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        Assert.Equal(StagedSelfHostedProfileDeleteResult.Deleted,
            await staging.DeleteAsync(scope, saved.Candidate!.Id));
        release.Set();

        Assert.Equal(DormantSelfHostedProfileVerificationStatus.Verified,
            (await verification).Status);
        Assert.Empty((await staging.ListAsync(scope)).Candidates);
    }

    private sealed class RejectingVerifier : IMembershipSignatureVerifier
    {
        public bool Verify(ReadOnlySpan<byte> signerId, ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) => false;
    }

    private sealed class ThrowingVerifier(Exception failure) : IMembershipSignatureVerifier
    {
        public bool Verify(ReadOnlySpan<byte> signerId, ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) => throw failure;
    }

    private sealed class BlockingVerifier(
        IMembershipSignatureVerifier inner,
        ManualResetEventSlim entered,
        ManualResetEventSlim release) : IMembershipSignatureVerifier
    {
        private int first = 1;
        public bool Verify(ReadOnlySpan<byte> signerId, ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            if (Interlocked.Exchange(ref first, 0) == 1)
            {
                entered.Set();
                release.Wait(TimeSpan.FromSeconds(10));
            }
            return inner.Verify(signerId, publicKey, domain, signingBytes, signature);
        }
    }
}
