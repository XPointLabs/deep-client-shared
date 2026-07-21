using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;
using System.Text.Json;

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

    [Theory]
    [InlineData(ProfileCarrierLimits.MaximumFilePayloadBytes + 1)]
    [InlineData(StagedSelfHostedProfileLimits.MaxCandidateBytes)]
    public async Task VerifierBoundRejectsStagedLargerCandidateWithoutMutation(int payloadLength)
    {
        var store = new InMemorySessionStore();
        var staging = new StagedSelfHostedProfileService(store);
        var scope = P14A2TestSupport.Scope(0x92);
        var payload = Enumerable.Repeat((byte)0x5a, payloadLength).ToArray();
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
    public async Task VerificationPerformsExactlyOneRepositoryReadAndNoMutation()
    {
        var inner = new InMemorySessionStore();
        var seed = new StagedSelfHostedProfileService(inner);
        var scope = P14A2TestSupport.Scope(0x97);
        var bytes = P14A2TestSupport.Fixture("accepted-eff4523-default.dpf");
        var saved = await seed.SaveAsync(scope, 1, bytes);
        var before = await seed.ListAsync(scope);
        var repository = new CountingRepository(inner);
        var service = new DormantSelfHostedProfileVerificationService(
            new StagedSelfHostedProfileService(repository),
            new P14A2DeterministicVerifier());

        var outcome = await service.VerifyAsync(
            scope, saved.Candidate!.Id, P14A2TestSupport.Parameters());

        Assert.Equal(DormantSelfHostedProfileVerificationStatus.Verified, outcome.Status);
        Assert.Equal(1, repository.Reads);
        Assert.Equal(0, repository.Creates);
        Assert.Equal(0, repository.Replaces);
        Assert.Equal(0, repository.Deletes);
        Assert.Equal(before.Candidates, (await seed.ListAsync(scope)).Candidates);
        Assert.Equal(bytes, (await seed.ExportAsync(scope, saved.Candidate.Id)).GetCandidateBytesCopy());
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
        var missingId = (await staging.SaveAsync(scope, 1, new byte[] { 0x01 })).Candidate!.Id;
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
            new ThrowingVerifier(new SyntheticProviderException(sentinel)));

        var outcome = await throwing.VerifyAsync(scope, saved.Candidate!.Id, P14A2TestSupport.Parameters());
        Assert.Equal(DormantSelfHostedProfileVerificationStatus.DependencyFailure, outcome.Status);
        Assert.DoesNotContain(sentinel, outcome.ToString(), StringComparison.Ordinal);

        var oom = new OutOfMemoryException(sentinel);
        var oomService = new DormantSelfHostedProfileVerificationService(staging, new ThrowingVerifier(oom));
        var actual = await Assert.ThrowsAsync<OutOfMemoryException>(() =>
            oomService.VerifyAsync(scope, saved.Candidate.Id, P14A2TestSupport.Parameters()));
        Assert.Same(oom, actual);

        var unsolicitedCancellation = new DormantSelfHostedProfileVerificationService(
            staging,
            new ThrowingVerifier(new OperationCanceledException(sentinel)));
        var unsolicitedOutcome = await unsolicitedCancellation.VerifyAsync(
            scope, saved.Candidate.Id, P14A2TestSupport.Parameters());
        Assert.Equal(
            DormantSelfHostedProfileVerificationStatus.DependencyFailure,
            unsolicitedOutcome.Status);
        Assert.DoesNotContain(sentinel, unsolicitedOutcome.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task NullPublicInputsFollowStagingArgumentContract()
    {
        var staging = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var scope = P14A2TestSupport.Scope(0x98);
        var saved = await staging.SaveAsync(scope, 1,
            P14A2TestSupport.Fixture("accepted-eff4523-default.dpf"));
        var service = new DormantSelfHostedProfileVerificationService(
            staging, new P14A2DeterministicVerifier());

        Assert.Equal("accountScope", (await Assert.ThrowsAsync<ArgumentNullException>(() =>
            service.VerifyAsync(null!, saved.Candidate!.Id, P14A2TestSupport.Parameters()))).ParamName);
        Assert.Equal("candidateId", (await Assert.ThrowsAsync<ArgumentNullException>(() =>
            service.VerifyAsync(scope, null!, P14A2TestSupport.Parameters()))).ParamName);
        Assert.Equal("parameters", (await Assert.ThrowsAsync<ArgumentNullException>(() =>
            service.VerifyAsync(scope, saved.Candidate!.Id, null!))).ParamName);
    }

    [Fact]
    public async Task PublicOutcomeSerializationContainsNoHandlesOrCarrierBytes()
    {
        var staging = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var scope = P14A2TestSupport.Scope(0x99);
        var bytes = P14A2TestSupport.Fixture("accepted-eff4523-default.dpf");
        var saved = await staging.SaveAsync(scope, 1, bytes);
        var service = new DormantSelfHostedProfileVerificationService(
            staging, new P14A2DeterministicVerifier());

        var outcome = await service.VerifyAsync(
            scope, saved.Candidate!.Id, P14A2TestSupport.Parameters());
        var json = JsonSerializer.Serialize(outcome);

        Assert.DoesNotContain(Convert.ToBase64String(bytes), json, StringComparison.Ordinal);
        Assert.DoesNotContain("candidate", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("account", json, StringComparison.OrdinalIgnoreCase);
        Assert.All(typeof(DormantSelfHostedProfileVerificationOutcome).GetProperties(), property =>
            Assert.NotEqual(typeof(byte[]), property.PropertyType));
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
    public async Task DependencyStateIsPerCallAndConcurrentCallsAreSerialized()
    {
        var staging = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var scope = P14A2TestSupport.Scope(0x9a);
        var saved = await staging.SaveAsync(scope, 1,
            P14A2TestSupport.Fixture("accepted-eff4523-default.dpf"));
        var failFirst = new DormantSelfHostedProfileVerificationService(
            staging,
            new FailFirstVerifier(new P14A2DeterministicVerifier()));

        Assert.Equal(DormantSelfHostedProfileVerificationStatus.DependencyFailure,
            (await failFirst.VerifyAsync(
                scope, saved.Candidate!.Id, P14A2TestSupport.Parameters())).Status);
        Assert.Equal(DormantSelfHostedProfileVerificationStatus.Verified,
            (await failFirst.VerifyAsync(
                scope, saved.Candidate.Id, P14A2TestSupport.Parameters())).Status);

        var probe = new ConcurrencyProbeVerifier(new P14A2DeterministicVerifier());
        var serialized = new DormantSelfHostedProfileVerificationService(staging, probe);
        var results = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
            serialized.VerifyAsync(scope, saved.Candidate.Id, P14A2TestSupport.Parameters()))));
        Assert.All(results, outcome => Assert.Equal(
            DormantSelfHostedProfileVerificationStatus.Verified, outcome.Status));
        Assert.Equal(1, probe.MaximumActive);
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

    private sealed class SyntheticProviderException(string message) : Exception(message);

    private sealed class FailFirstVerifier(IMembershipSignatureVerifier inner) :
        IMembershipSignatureVerifier
    {
        private int fail = 1;

        public bool Verify(ReadOnlySpan<byte> signerId, ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            if (Interlocked.Exchange(ref fail, 0) == 1)
                throw new SyntheticProviderException("synthetic-first-call-failure");
            return inner.Verify(signerId, publicKey, domain, signingBytes, signature);
        }
    }

    private sealed class ConcurrencyProbeVerifier(IMembershipSignatureVerifier inner) :
        IMembershipSignatureVerifier
    {
        private int active;
        private int maximumActive;

        public int MaximumActive => Volatile.Read(ref maximumActive);

        public bool Verify(ReadOnlySpan<byte> signerId, ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            var current = Interlocked.Increment(ref active);
            var observed = Volatile.Read(ref maximumActive);
            while (current > observed)
            {
                observed = Interlocked.CompareExchange(
                    ref maximumActive, current, observed);
            }
            try
            {
                Thread.SpinWait(10_000);
                return inner.Verify(signerId, publicKey, domain, signingBytes, signature);
            }
            finally
            {
                Interlocked.Decrement(ref active);
            }
        }
    }

    private sealed class CountingRepository(IAtomicBoundedSettingsRepository inner) :
        IAtomicBoundedSettingsRepository
    {
        public int Reads { get; private set; }
        public int Creates { get; private set; }
        public int Replaces { get; private set; }
        public int Deletes { get; private set; }

        public Task<AtomicBoundedSettingReadOutcome> ReadAtomicBoundedSettingAsync(
            string key, int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default)
        {
            Reads++;
            return inner.ReadAtomicBoundedSettingAsync(key, maximumValueUtf8Bytes, cancellationToken);
        }

        public Task<AtomicBoundedSettingMutationResult> CreateAtomicBoundedSettingAsync(
            string key, ReadOnlyMemory<byte> utf8Json, int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default)
        {
            Creates++;
            return inner.CreateAtomicBoundedSettingAsync(
                key, utf8Json, maximumValueUtf8Bytes, cancellationToken);
        }

        public Task<AtomicBoundedSettingMutationResult> ReplaceAtomicBoundedSettingAsync(
            string key, AtomicBoundedSettingRevision expectedRevision,
            ReadOnlyMemory<byte> utf8Json, int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default)
        {
            Replaces++;
            return inner.ReplaceAtomicBoundedSettingAsync(
                key, expectedRevision, utf8Json, maximumValueUtf8Bytes, cancellationToken);
        }

        public Task<AtomicBoundedSettingMutationResult> DeleteAtomicBoundedSettingAsync(
            string key, AtomicBoundedSettingRevision expectedRevision,
            int maximumValueUtf8Bytes, CancellationToken cancellationToken = default)
        {
            Deletes++;
            return inner.DeleteAtomicBoundedSettingAsync(
                key, expectedRevision, maximumValueUtf8Bytes, cancellationToken);
        }
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
