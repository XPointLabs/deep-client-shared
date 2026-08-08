using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;
using Sodium;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class ScopedMailboxSecurityRegressionTests
{
    [Fact]
    public void Replica_pair_rejects_one_signing_key_for_two_replica_ids()
    {
        var signingKey = Bytes(32, 0x91);
        Assert.Throws<ArgumentException>(() => new MailboxCredentialReplicaPair(
            Bytes(32, 0x92),
            signingKey,
            Bytes(32, 0x93),
            signingKey));
    }

    [Fact]
    public async Task Import_rejects_forged_canonical_issuer_signature()
    {
        using var fixture = new Fixture();
        var decoded = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
            fixture.Generation.Retrieve!.CurrentGrant.Span);
        var forged = MailboxAuthenticatedCapabilityCodec.EncodeGrant(
            decoded with { IssuerSignature = Bytes(64, 0xe1) });
        var generation = fixture.Generation with
        {
            Retrieve = new MailboxCredentialGrantSet(
                forged,
                fixture.Generation.Retrieve.NextGrant.Span)
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            fixture.Store.InstallScopedCredentialAsync(
                generation, fixture.Authority));
        Assert.Equal(0, fixture.Count("mailbox_credential_scopes"));
    }

    [Fact]
    public async Task Import_rejects_signed_overlap_lifecycle()
    {
        using var fixture = new Fixture();
        var overlap = fixture.Grant(
            MailboxCapabilityDomain.Retrieve,
            serial: 0x31,
            fixture.Generation.Current,
            MailboxCapabilityLifecycle.Overlap,
            overlapUntilUnixSeconds: 1100);
        var generation = fixture.Generation with
        {
            Retrieve = new MailboxCredentialGrantSet(
                overlap,
                fixture.Generation.Retrieve!.NextGrant.Span)
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            fixture.Store.InstallScopedCredentialAsync(
                generation, fixture.Authority));
    }

    [Fact]
    public async Task Import_rejects_signed_grant_with_epoch_timestamp_drift()
    {
        using var fixture = new Fixture();
        var drifted = fixture.Grant(
            MailboxCapabilityDomain.Retrieve,
            serial: 0x31,
            fixture.Generation.Current,
            notBeforeUnixSeconds: fixture.Generation.Current
                .NotBeforeUnixSeconds + 1);
        var generation = fixture.Generation with
        {
            Retrieve = new MailboxCredentialGrantSet(
                drifted,
                fixture.Generation.Retrieve!.NextGrant.Span)
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            fixture.Store.InstallScopedCredentialAsync(
                generation, fixture.Authority));
    }

    [Fact]
    public async Task Import_rejects_reused_serial_even_when_grants_are_distinct()
    {
        using var fixture = new Fixture();
        var duplicateSerial = fixture.Grant(
            MailboxCapabilityDomain.Deposit,
            serial: 0x31,
            fixture.Generation.Current);
        var generation = fixture.Generation with
        {
            Deposit = new MailboxCredentialGrantSet(
                duplicateSerial,
                fixture.Generation.Deposit!.NextGrant.Span)
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            fixture.Store.InstallScopedCredentialAsync(
                generation, fixture.Authority));
    }

    [Theory]
    [InlineData(MailboxAuthenticatedOperation.Store)]
    [InlineData(MailboxAuthenticatedOperation.Retrieve)]
    [InlineData(MailboxAuthenticatedOperation.Ack)]
    public async Task Dispatch_revalidation_observes_live_revocation(
        MailboxAuthenticatedOperation operation)
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(
            fixture.Generation, fixture.Authority);
        fixture.Revocations.Revoked = true;

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Store.RevalidateScopedMailboxDispatchAsync(
                fixture.Selector,
                operation,
                fixture.Authority));
    }

    [Fact]
    public async Task Prepared_batch_retry_resumes_across_time_and_binds_exact_target_catalog()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(
            fixture.Generation, fixture.Authority);
        var parent = Bytes(16, 0xb1);
        var target = fixture.RetrieveTarget(0xb2);
        var created = DateTimeOffset.FromUnixTimeSeconds(1050);
        var request = new ScopedMailboxPrepareBatchRequest(
            fixture.Account, parent, parent,
            [Selector(target)], [target], created);
        var first = await fixture.Store.PrepareScopedMailboxBatchAsync(
            request, fixture.Signer, fixture.Authority);

        using var restarted = new SqliteSessionStore(fixture.Path);
        var resumed = await restarted.PrepareScopedMailboxBatchAsync(
                request with { CreatedAt = created.AddSeconds(1) },
                fixture.Signer,
                fixture.Authority);
        Assert.Equal(
            first.Frames.Single().GetCanonicalMau2Copy(),
            resumed.Frames.Single().GetCanonicalMau2Copy());

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            restarted.PrepareScopedMailboxBatchAsync(
                request with
                {
                    Targets = [fixture.RetrieveTarget(0xb3)],
                    Selectors = [Selector(fixture.RetrieveTarget(0xb3))]
                },
                fixture.Signer,
                fixture.Authority));

        fixture.DeletePreparedTargets();
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            restarted.PrepareScopedMailboxBatchAsync(
                request, fixture.Signer, fixture.Authority));
    }

    private static ScopedMailboxBatchSelector Selector(ScopedMailboxBatchTarget target) =>
        new(target.Selector,
            new MessageId(Convert.ToHexString(target.Binding.OperationId.Span)),
            target.Binding.Operation);

    [Fact]
    public async Task Logical_resume_reopens_exact_frames_and_fails_closed_on_conflict_revocation_and_corruption()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(
            fixture.Generation, fixture.Authority);
        var parent = Bytes(16, 0xc1);
        var target = fixture.RetrieveTarget(0xc2);
        var selector = Selector(target);
        var prepare = new ScopedMailboxPrepareBatchRequest(
            fixture.Account, parent, parent, [selector], [target],
            DateTimeOffset.FromUnixTimeSeconds(1050));
        var first = await fixture.Store.PrepareScopedMailboxBatchAsync(
            prepare, fixture.Signer, fixture.Authority);

        using var reopened = new SqliteSessionStore(fixture.Path);
        var resume = new ScopedMailboxResumeBatchRequest(
            fixture.Account, parent, parent, [selector]);
        var exact = await reopened.TryResumeScopedMailboxBatchAsync(
            resume, fixture.Signer, fixture.Authority);
        Assert.NotNull(exact);
        Assert.Equal(
            first.Frames.Single().GetCanonicalMau2Copy(),
            exact.Frames.Single().GetCanonicalMau2Copy());

        var otherSeed = Bytes(32, 0xe1);
        var otherSigner = new OperationSigner(
            otherSeed,
            new SodiumMailboxCapabilityCrypto().GetPublicKey(otherSeed));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            reopened.TryResumeScopedMailboxBatchAsync(
                resume, otherSigner, fixture.Authority));

        var expiredAuthority = new VerifiedOfficialMailboxAuthority(
            fixture.Authority.NetworkId,
            fixture.Authority.MinimumGeneration,
            fixture.Authority.TrustedIssuers,
            true,
            static () => true,
            fixture.Revocations,
            new FrozenTimeProvider(1201));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            reopened.TryResumeScopedMailboxBatchAsync(
                resume, fixture.Signer, expiredAuthority));

        var entitled = true;
        var unentitledAuthority = new VerifiedOfficialMailboxAuthority(
            fixture.Authority.NetworkId,
            fixture.Authority.MinimumGeneration,
            fixture.Authority.TrustedIssuers,
            true,
            () => entitled,
            fixture.Revocations,
            fixture.Authority.TimeProvider);
        entitled = false;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            reopened.TryResumeScopedMailboxBatchAsync(
                resume, fixture.Signer, unentitledAuthority));

        var changedSelector = selector with
        {
            WireMessageId = new MessageId("different-wire-id")
        };
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            reopened.TryResumeScopedMailboxBatchAsync(
                resume with { Selectors = [changedSelector] },
                fixture.Signer, fixture.Authority));

        fixture.Revocations.Revoked = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            reopened.TryResumeScopedMailboxBatchAsync(
                resume, fixture.Signer, fixture.Authority));
        fixture.Revocations.Revoked = false;

        fixture.DeletePreparedTargets();
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            reopened.TryResumeScopedMailboxBatchAsync(
                resume, fixture.Signer, fixture.Authority));
    }

    [Fact]
    public async Task Restart_preserves_semantic_fan_out_owner_and_rejects_membership_replan()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(
            fixture.Generation, fixture.Authority);
        var semantic = Bytes(16, 0xd0);
        var originalTarget = fixture.RetrieveTarget(0xd1);
        var originalSelector = Selector(originalTarget);
        var original = new ScopedMailboxPrepareBatchRequest(
            fixture.Account,
            originalTarget.Binding.OperationId,
            semantic,
            [originalSelector],
            [originalTarget],
            DateTimeOffset.FromUnixTimeSeconds(1050));
        var prepared = await fixture.Store.PrepareScopedMailboxBatchAsync(
            original, fixture.Signer, fixture.Authority);

        using var reopened = new SqliteSessionStore(fixture.Path);
        var changedTarget = fixture.RetrieveTarget(0xd2);
        var changedSelector = Selector(changedTarget);
        var changedResume = new ScopedMailboxResumeBatchRequest(
            fixture.Account,
            changedTarget.Binding.OperationId,
            semantic,
            [changedSelector]);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            reopened.TryResumeScopedMailboxBatchAsync(
                changedResume, fixture.Signer, fixture.Authority));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            reopened.PrepareScopedMailboxBatchAsync(
                new ScopedMailboxPrepareBatchRequest(
                    fixture.Account,
                    changedTarget.Binding.OperationId,
                    semantic,
                    [changedSelector],
                    [changedTarget],
                    DateTimeOffset.FromUnixTimeSeconds(1050)),
                fixture.Signer,
                fixture.Authority));

        var exact = await reopened.TryResumeScopedMailboxBatchAsync(
            new ScopedMailboxResumeBatchRequest(
                fixture.Account,
                originalTarget.Binding.OperationId,
                semantic,
                [originalSelector]),
            fixture.Signer,
            fixture.Authority);
        Assert.NotNull(exact);
        Assert.Equal(
            prepared.Frames.Single().GetCanonicalMau2Copy(),
            exact.Frames.Single().GetCanonicalMau2Copy());
        Assert.Equal(1, fixture.Count("mailbox_prepared_batches"));
        Assert.Equal(1, fixture.Count("transport_outbox_items"));
    }

    [Fact]
    public async Task Import_accepts_generation_independent_of_epoch_with_exact_domain_authority()
    {
        using var fixture = new Fixture();
        var retrieve = new MailboxCredentialGrantSet(
            fixture.Grant(
                MailboxCapabilityDomain.Retrieve,
                0x31,
                fixture.Generation.Current,
                generation: 40),
            fixture.Grant(
                MailboxCapabilityDomain.Retrieve,
                0x32,
                fixture.Generation.Next,
                generation: 41));
        var generation = fixture.Generation with { Retrieve = retrieve };
        var authority = fixture.AuthorityFor(
            retrieveMinimum: 40,
            retrieveMaximum: 41);

        await fixture.Store.InstallScopedCredentialAsync(generation, authority);

        Assert.Equal(1, fixture.Count("mailbox_credential_scopes"));
    }

    [Fact]
    public async Task Import_rejects_issuer_not_authorized_for_grant_domain()
    {
        using var fixture = new Fixture();
        var authority = fixture.AuthorityFor(
            retrieveKey: Bytes(32, 0xe1));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            fixture.Store.InstallScopedCredentialAsync(
                fixture.Generation, authority));
        Assert.Equal(0, fixture.Count("mailbox_credential_scopes"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Import_rejects_generation_floor_or_hard_validity_escape(
        bool generationFloor)
    {
        using var fixture = new Fixture();
        var authority = generationFloor
            ? fixture.AuthorityFor(minimumGeneration: 9)
            : fixture.AuthorityFor(validUntil: 1199);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            fixture.Store.InstallScopedCredentialAsync(
                fixture.Generation, authority));
        Assert.Equal(0, fixture.Count("mailbox_credential_scopes"));
    }

    [Fact]
    public async Task Restart_requires_exact_full_authority_policy_fingerprint()
    {
        using var fixture = new Fixture();
        await fixture.Store.InstallScopedCredentialAsync(
            fixture.Generation, fixture.Authority);
        using var restarted = new SqliteSessionStore(fixture.Path);
        var reordered = new VerifiedOfficialMailboxAuthority(
            fixture.Authority.NetworkId,
            fixture.Authority.MinimumGeneration,
            fixture.Authority.TrustedIssuers.Reverse().ToArray(),
            true,
            static () => true,
            fixture.Revocations,
            fixture.Authority.TimeProvider);

        _ = await restarted.ReadScopedMailboxRouteAsync(
            fixture.Selector, reordered);
        var changed = fixture.AuthorityFor(retrieveMaximum: 100);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            restarted.ReadScopedMailboxRouteAsync(
                fixture.Selector, changed));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly byte[] issuerSeed = Bytes(32, 0x01);
        private readonly byte[] holderSeed = Bytes(32, 0x21);
        private readonly SodiumMailboxCapabilityCrypto crypto = new();

        public Fixture()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"deep-scoped-security-{Guid.NewGuid():N}.db");
            Account = OutboxAccountScope.FromBytes(Bytes(32, 0x11));
            Selector = new MailboxCredentialSelector(
                Account,
                MailboxCredentialScopeKind.Self,
                Bytes(32, 0x12),
                Bytes(32, 0x13));
            Revocations = new MutableRevocations();
            IssuerPublicKey = crypto.GetPublicKey(issuerSeed);
            Authority = new VerifiedOfficialMailboxAuthority(
                Bytes(16, 0x14),
                1,
                [
                    Issuer(IssuerPublicKey, MailboxCapabilityDomain.Deposit),
                    Issuer(IssuerPublicKey, MailboxCapabilityDomain.Retrieve)
                ],
                true,
                static () => true,
                Revocations,
                new FrozenTimeProvider(1050));
            var membership = Bytes(32, 0x41);
            var currentPlacement = new BlindedPlacementId(Bytes(32, 0x51));
            var nextPlacement = new BlindedPlacementId(Bytes(32, 0x52));
            var current = new MailboxCredentialEpoch(
                7,
                900,
                1200,
                membership,
                currentPlacement.Bytes.Span,
                MailboxPlacementCommitment.Compute(currentPlacement));
            var next = new MailboxCredentialEpoch(
                8,
                1100,
                1400,
                Bytes(32, 0x42),
                nextPlacement.Bytes.Span,
                MailboxPlacementCommitment.Compute(nextPlacement));
            Generation = new ScopedMailboxCredentialGeneration(
                Selector,
                Bytes(32, 0x61),
                crypto.GetPublicKey(holderSeed),
                Bytes(32, 0x62),
                current,
                next,
                new MailboxCredentialGrantSet(
                    Grant(MailboxCapabilityDomain.Retrieve, 0x31, current),
                    Grant(MailboxCapabilityDomain.Retrieve, 0x32, next)),
                new MailboxCredentialGrantSet(
                    Grant(MailboxCapabilityDomain.Deposit, 0x33, current),
                    Grant(MailboxCapabilityDomain.Deposit, 0x34, next)),
                new MailboxCredentialReplicaPair(
                    Bytes(32, 0x71),
                    Bytes(32, 0x72),
                    Bytes(32, 0x73),
                    Bytes(32, 0x74)),
                new MailboxCredentialReplicaPair(
                    Bytes(32, 0x81),
                    Bytes(32, 0x82),
                    Bytes(32, 0x83),
                    Bytes(32, 0x84)));
            Signer = new OperationSigner(
                holderSeed,
                crypto.GetPublicKey(holderSeed));
            Store = new SqliteSessionStore(Path);
        }

        public string Path { get; }
        public SqliteSessionStore Store { get; }
        public OutboxAccountScope Account { get; }
        public MailboxCredentialSelector Selector { get; }
        public MutableRevocations Revocations { get; }
        public VerifiedOfficialMailboxAuthority Authority { get; }
        public byte[] IssuerPublicKey { get; }
        public ScopedMailboxCredentialGeneration Generation { get; }
        public OperationSigner Signer { get; }

        public VerifiedOfficialMailboxAuthority AuthorityFor(
            ulong minimumGeneration = 1,
            ReadOnlyMemory<byte> retrieveKey = default,
            ulong retrieveMinimum = 1,
            ulong retrieveMaximum = ulong.MaxValue,
            ulong validUntil = ulong.MaxValue) => new(
            Authority.NetworkId,
            minimumGeneration,
            [
                Issuer(
                    IssuerPublicKey,
                    MailboxCapabilityDomain.Deposit,
                    validUntil: validUntil),
                Issuer(
                    retrieveKey.IsEmpty ? IssuerPublicKey : retrieveKey,
                    MailboxCapabilityDomain.Retrieve,
                    retrieveMinimum,
                    retrieveMaximum,
                    validUntil)
            ],
            true,
            static () => true,
            Revocations,
            Authority.TimeProvider);

        public byte[] Grant(
            MailboxCapabilityDomain domain,
            byte serial,
            MailboxCredentialEpoch epoch,
            MailboxCapabilityLifecycle lifecycle =
                MailboxCapabilityLifecycle.Active,
            ulong overlapUntilUnixSeconds = 0,
            ulong? notBeforeUnixSeconds = null,
            ulong? expiresAtUnixSeconds = null,
            ulong? generation = null)
        {
            var unsigned = new MailboxAuthenticatedGrant
            {
                Domain = domain,
                Lifecycle = lifecycle,
                NetworkId = Authority.NetworkId,
                Epoch = epoch.Epoch,
                Generation = generation ?? epoch.Epoch,
                Serial = Bytes(16, serial),
                NotBeforeUnixSeconds = notBeforeUnixSeconds ??
                    epoch.NotBeforeUnixSeconds,
                ExpiresAtUnixSeconds = expiresAtUnixSeconds ??
                    epoch.ExpiresAtUnixSeconds,
                OverlapUntilUnixSeconds = overlapUntilUnixSeconds,
                PlacementCommitment = epoch.PlacementCommitment,
                MembershipCommitment = epoch.MembershipCommitment,
                IssuerPublicKey = IssuerPublicKey,
                HolderPublicKey = crypto.GetPublicKey(holderSeed),
                IssuerSignature = new byte[64]
            };
            return MailboxAuthenticatedCapabilityCodec.EncodeGrant(
                crypto.SignGrant(unsigned, issuerSeed));
        }

        private static MailboxCapabilityIssuerAuthority Issuer(
            ReadOnlyMemory<byte> publicKey,
            MailboxCapabilityDomain domain,
            ulong minimumGeneration = 1,
            ulong maximumGeneration = ulong.MaxValue,
            ulong validUntil = ulong.MaxValue) => new()
            {
                PublicKey = publicKey.ToArray(),
                Domain = domain,
                AllowedLifecycle = MailboxCapabilityLifecycle.Active,
                MinimumGeneration = minimumGeneration,
                MaximumGeneration = maximumGeneration,
                ValidFromUnixSeconds = 1,
                ValidUntilUnixSeconds = validUntil
            };

        public ScopedMailboxBatchTarget RetrieveTarget(byte operation) => new(
            Selector,
            MailboxAuthenticatedRequestTranscript.ForRetrieve(
                Generation.Current.Epoch,
                Bytes(16, operation),
                new BlindedMailboxId(Generation.MailboxId.Span),
                new BlindedPlacementId(
                    Generation.Current.PlacementId.Span),
                0,
                25,
                []));

        public int Count(string table)
        {
            using var connection = new SqliteConnection(
                $"Data Source={Path};Pooling=False");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = $"SELECT count(*) FROM {table};";
            return Convert.ToInt32(command.ExecuteScalar());
        }

        public void DeletePreparedTargets()
        {
            using var connection = new SqliteConnection(
                $"Data Source={Path};Pooling=False");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM mailbox_prepared_batch_targets;";
            command.ExecuteNonQuery();
        }

        public void Dispose()
        {
            Store.Dispose();
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { Path, Path + "-wal", Path + "-shm" })
            {
                if (File.Exists(candidate))
                {
                    File.Delete(candidate);
                }
            }
        }
    }

    private sealed class OperationSigner(byte[] seed, byte[] publicKey) :
        IMailboxOperationSigner
    {
        public SessionId SessionId =>
            SessionId.Parse("05" + new string('a', 64));
        public byte[] GetEd25519PublicKey() => publicKey.ToArray();
        public byte[] SignMailboxPresentation(
            MailboxAuthenticatedOperation operation,
            ReadOnlySpan<byte> canonicalPresentationSigningBytes) =>
            PublicKeyAuth.SignDetached(
                canonicalPresentationSigningBytes.ToArray(),
                PublicKeyAuth.GenerateKeyPair(seed).PrivateKey);
    }

    private sealed class MutableRevocations :
        IFreshMailboxCapabilityRevocationSource
    {
        public void ValidateFreshness() { }
        public bool Revoked { get; set; }
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => Revoked;
    }

    private sealed class FrozenTimeProvider(long seconds) : TimeProvider
    {
        private readonly DateTimeOffset now =
            DateTimeOffset.FromUnixTimeSeconds(seconds);
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static byte[] Bytes(int count, byte start)
    {
        var value = new byte[count];
        for (var index = 0; index < count; index++)
        {
            value[index] = unchecked((byte)(start + index));
        }
        if (value.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            value[0] = 1;
        }
        return value;
    }
}
