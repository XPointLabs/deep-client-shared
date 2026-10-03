using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2GrantCustody_TwoAccountsPersistBeforeCallbackLoseResponseAndReopenExactWinner()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        await fixture.CheckGrantCustodyAsync();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void Did2GrantCustody_HeaderRejectsBeforeReadingEntries(int fault)
    {
        var network = Bytes(16, 0x11); var account = Bytes(32, 0x12); var instance = Bytes(32, 0x13);
        var exact = ProtectedDid2MailboxGrantJournal.Empty(network, account, instance);
        if (fault == 0) exact[0] = 1; // Retired custody rejects even when empty.
        if (fault == 1) exact[1] = 1;
        if (fault == 2) BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2), 129);
        if (fault == 3) exact[11] = 0;
        if (fault == 4) exact[60] ^= 1;
        if (fault == 5) exact = exact.Append((byte)0).ToArray();
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxGrantJournal.Decode(exact, network, account, instance));
    }

    private sealed partial class Fixture
    {
        private DeepIdV2AccountService ReopenGrantReader() => new(peerStorage, Path.Combine(directory, "peer"),
            Network, 1, new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
            DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
        internal DeepIdV2ContactPathAuthoritySource GrantReaderSource(DeepIdV2AccountService account) =>
            new(bootstrap.GenesisPin, account, peerProofs!, closure, peerNetworkStore!, this);

        internal async Task<ProtectedDid2MailboxGrantJournal.State> ReadPeerGrantsAsync(bool own = false)
        {
            var selected = own ? innerStorage : peerStorage;
            using var key = await selected.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidOperationException();
            using var root = await selected.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidOperationException();
            var scope = key.Use(record => record.Slice(24, 64).ToArray());
            try { return root.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, Network,
                scope.AsSpan(0, 32), scope.AsSpan(32, 32))); }
            finally { CryptographicOperations.ZeroMemory(scope); }
        }

        internal async Task CheckGrantCustodyAsync()
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            var configuration = Did2OwnedPermanentContactPlan.Configuration();
            using var threshold = new OwnedRouteThreshold(this);
            var route = await EnsureRoute(plan.Intent.ToArray(), configuration, threshold, reopen: false);
            var publication = new OwnedPublicationSource(this, route);
            var replicas = new OwnedPublicationReplica(this, route);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), threshold, publication, replicas);
            var address = (await accounts.GetCurrentAsync())!.PermanentId;
            var reader = peerAccounts!; var source = GrantReaderSource(reader);
            var resolved = await reader.ResolvePermanentContactAsync(address, source,
                new SyntheticPermanentRead(this, source, replicas.ExactPublication));
            var transport = new OwnedGrantTransport(this) { CorruptResponse = true };
            await RequireRouteRejectionAsync(async () => await reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport));
            using (var pending = await ReadPeerGrantsAsync())
            {
                Assert.Equal(2UL, pending.Revision);
                Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(Assert.Single(pending.Entries).Value));
            }
            transport.CorruptResponse = false; transport.LoseResponse = true;
            reader = ReopenGrantReader(); source = GrantReaderSource(reader);
            await Assert.ThrowsAsync<IOException>(() => reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport));
            using (var pending = await ReadPeerGrantsAsync()) Assert.Equal(2UL, pending.Revision);
            transport.LoseResponse = false;
            reader = ReopenGrantReader(); source = GrantReaderSource(reader);
            using (Did2MailboxInstallationTestHooks.Push(point =>
                { if (point == Did2MailboxInstallationFailpoint.BeforeSql) throw new IOException("Injected before owned installation."); }))
                await Assert.ThrowsAsync<IOException>(() => reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport));
            Assert.Equal(3, transport.Calls);
            reader = ReopenGrantReader(); source = GrantReaderSource(reader);
            using (Did2MailboxInstallationTestHooks.Push(point =>
                { if (point == Did2MailboxInstallationFailpoint.AfterSql) throw new IOException("Injected after owned installation."); }))
                await Assert.ThrowsAsync<IOException>(() => reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport));
            Assert.Equal(3, transport.Calls); // Committed winner must not be reissued after either interruption.
            reader = ReopenGrantReader(); source = GrantReaderSource(reader);
            Did2OwnedMailboxTransportContext? heldPath = null;
            VerifiedDeepIdV2MailboxGrant verified;
            using (Did2MailboxInstallationTestHooks.PushHeldPath(async (context, installed, ct) =>
            {
                heldPath = context; var before = ProofRequests;
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(5));
                var network = await context.GetCurrentForMailboxAsync(installed.PlacementCommitment, timeout.Token);
                Assert.Equal(Network, network.NetworkId.ToArray());
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await context.GetCurrentForMailboxAsync(Bytes(32, 0x99), timeout.Token));
                Assert.Equal(before, ProofRequests); // Readonly held floors: no recursive account-lock/fetch.
            }))
                verified = await reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport);
            Assert.NotNull(heldPath);
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await heldPath.RequireCurrentAsync(default));
            await AssertInstalledGrantSqlAsync(verified, own: false);
            Assert.Equal(3, transport.Calls); Assert.True(transport.ExactRetry);
            Assert.True(transport.BuiltHeldFrame);
            using (var winner = await ReadPeerGrantsAsync())
            {
                Assert.Equal(3UL, winner.Revision);
                var entry = Assert.Single(winner.Entries).Value;
                Assert.True(ProtectedDid2MailboxGrantJournal.HasWinner(entry));
                Assert.Equal(verified.ExactXmg1.ToArray(), ProtectedDid2MailboxGrantJournal.Request(entry).ToArray());
                Assert.Equal(verified.ExactXmc2.ToArray(), ProtectedDid2MailboxGrantJournal.Response(entry).ToArray());
                // A corrupted seed, winner, phase or reserved byte is not repaired.
                foreach (var offset in new[] { 32, 96, 97, 100 + 435 + 32 })
                {
                    var damaged = entry.ToArray(); damaged[offset] ^= 1;
                    using var changed = new ProtectedDid2MailboxGrantJournal.State { Revision = 3 };
                    changed.Entries.Add(winner.Entries.Keys.Single(), damaged);
                    void Encode() => ProtectedDid2MailboxGrantJournal.Encode(changed,
                        Network, Bytes(32, 0x11), Bytes(32, 0x12));
                    if (offset == 32) Assert.Throws<CryptographicException>(Encode);
                    else if (offset is 96 or 97) Assert.Throws<InvalidDataException>(Encode);
                    else Assert.Throws<ContactFormatException>(Encode);
                }
            }
            reader = ReopenGrantReader(); source = GrantReaderSource(reader);
            var reopened = await reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport);
            Assert.Equal(verified.ExactXmg1.ToArray(), reopened.ExactXmg1.ToArray());
            Assert.Equal(verified.ExactXmc2.ToArray(), reopened.ExactXmc2.ToArray());
            await AssertInstalledGrantSqlAsync(reopened, own: false);
            Assert.Equal(3, transport.Calls); // Retained winner makes no issuer callback.
            Assert.False(await reader.HasOwnStagedPreKeyInventoryAsync()); // Not a session/acceptance/ACK.
            Assert.NotNull(transport.Dispatch);
            Assert.Throws<ObjectDisposedException>(() => transport.Dispatch.RequireActive());
            // The unpublished peer cannot acquire owner retrieval using a
            // public resolve/deposit grant as a substitute for phase7 custody.
            var unpublished = new OwnedGrantTransport(this, selfRetrieve: true);
            await Assert.ThrowsAsync<CryptographicException>(() => reader.AcquireOwnPermanentContactRetrieveGrantAsync(source, unpublished));
            Assert.Equal(0, unpublished.Calls);

            var retrieval = new OwnedGrantTransport(this, selfRetrieve: true) { LoseResponse = true };
            await Assert.ThrowsAsync<IOException>(() => accounts.AcquireOwnPermanentContactRetrieveGrantAsync(Source(), retrieval));
            using (var pending = await ReadPeerGrantsAsync(own: true))
            {
                Assert.Equal(2UL, pending.Revision);
                Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(Assert.Single(pending.Entries).Value));
            }
            retrieval.LoseResponse = false;
            var ownerReopened = ReopenAccount();
            var retrieved = await ownerReopened.AcquireOwnPermanentContactRetrieveGrantAsync(Source(ownerReopened), retrieval);
            Assert.Equal(MailboxCapabilityDomain.Retrieve, retrieved.Domain);
            Assert.Equal(2, retrieval.Calls); Assert.True(retrieval.ExactRetry); Assert.True(retrieval.BuiltHeldFrame);
            Assert.NotEqual(ContactCodec.Decode("XMG1", verified.ExactXmg1.Span).Field(5).ToArray(),
                ContactCodec.Decode("XMG1", retrieved.ExactXmg1.Span).Field(5).ToArray());
            using (var winner = await ReadPeerGrantsAsync(own: true))
            {
                var entry = Assert.Single(winner.Entries).Value;
                Assert.Equal(3UL, winner.Revision); Assert.True(ProtectedDid2MailboxGrantJournal.HasWinner(entry));
                Assert.Equal(retrieved.ExactXmc2.ToArray(), ProtectedDid2MailboxGrantJournal.Response(entry).ToArray());
            }
            ownerReopened = ReopenAccount();
            var retrieveAgain = await ownerReopened.AcquireOwnPermanentContactRetrieveGrantAsync(Source(ownerReopened), retrieval);
            Assert.Equal(retrieved.ExactXmg1.ToArray(), retrieveAgain.ExactXmg1.ToArray());
            Assert.Equal(retrieved.ExactXmc2.ToArray(), retrieveAgain.ExactXmc2.ToArray());
            Assert.Equal(2, retrieval.Calls);
            await AssertInstalledGrantSqlAsync(retrieveAgain, own: true);
            await peerStorage.DeleteBatchAsync([ProtectedDid2MailboxGrantJournal.Slot]);
            await Assert.ThrowsAsync<InvalidDataException>(() => ReopenGrantReader().GetCurrentAsync());
        }

        // Test-only independent SQLCipher observer. No runtime authority is
        // constructed by this reader, and no key/path/payload is logged.
        private async Task AssertInstalledGrantSqlAsync(VerifiedDeepIdV2MailboxGrant verified, bool own)
        {
            var selected = own ? innerStorage : peerStorage;
            using var root = await selected.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidOperationException();
            var record = root.Use(bytes => bytes.ToArray());
            var context = new byte["Deep/STORE-V2/application-state-key"u8.Length + 1 + 80];
            byte[] key = [];
            try
            {
                var domain = "Deep/STORE-V2/application-state-key"u8;
                domain.CopyTo(context); record.AsSpan(8, 80).CopyTo(context.AsSpan(domain.Length + 1));
                key = HMACSHA256.HashData(record.AsSpan(88, 32), context);
                var accountPath = own ? Path.Combine(directory, "deep-store-v2-account.dsv2") :
                    Path.Combine(directory, "peer", "deep-store-v2-account.dsv2");
                using var sql = new SqliteConnection(new SqliteConnectionStringBuilder
                { DataSource = accountPath + ".application.dmb1", Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
                sql.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, MailboxRandomKeyTestEncoding.Apply(sql, key));
                using var read = sql.CreateCommand();
                foreach (var table in new[] { "mailbox_credential_scopes", "mailbox_credential_epochs", "mailbox_credential_grants" })
                {
                    read.CommandText = $"SELECT COUNT(*) FROM {table};";
                    Assert.Equal(1, Convert.ToInt32(read.ExecuteScalar()));
                }
                foreach (var table in new[] { "mailbox_prepared_batches", "mailbox_prepared_batch_targets", "transport_outbox_items" })
                {
                    read.CommandText = $"SELECT COUNT(*) FROM {table};";
                    Assert.Equal(0, Convert.ToInt32(read.ExecuteScalar())); // Installation is not dispatch.
                }
                read.CommandText = "SELECT canonical_grant FROM mailbox_credential_grants;";
                Assert.Equal(verified.ExactGrant.ToArray(), (byte[])read.ExecuteScalar()!);
                read.CommandText = "SELECT scope_kind FROM mailbox_credential_scopes;";
                Assert.Equal(own ? 1 : 2, Convert.ToInt32(read.ExecuteScalar()));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(record); CryptographicOperations.ZeroMemory(context);
                CryptographicOperations.ZeroMemory(key);
            }
        }

        internal async Task<byte[]> IssueOwnedGrantAsync(AuthoredMailboxGrantRequest request,
            VerifiedDeepIdV2ContactRouteClosure route, bool retrieve, CancellationToken ct)
        {
            var effective = BinaryPrimitives.ReadUInt64BigEndian(route.Route.Reachability.Field(17).Span);
            var tuple = MailboxGrantRouteEvidenceAuthentication.CreateTuple(SHA256.HashData(request.ExactXmg1.Span),
                request.Record.Field(3).Span, MailboxGrantCapabilityDigest.Compute(request.Record.Field(4).Span, request.Domain),
                (byte)request.Domain, 1, route.Route.ExactHash.Span, effective);
            var signing = MailboxGrantRouteEvidenceAuthentication.GetSigningBytes(tuple);
            var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.ResolveInvite, request.Record.Field(3));
            var evidence = placement.RankedReplicaNodeIds.Select(id =>
            {
                var marker = Enumerable.Range(0x70, 3).Single(value => PublicKey((byte)value).AsSpan().SequenceEqual(id.Span));
                var pair = PublicKeyAuth.GenerateKeyPair(Bytes(32, (byte)marker));
                try { return new DeepIdV2MailboxGrantReplicaEvidence(id.Span, PublicKeyAuth.SignDetached(signing, pair.PrivateKey)); }
                finally { CryptographicOperations.ZeroMemory(pair.PrivateKey); }
            }).ToArray();
            var time = new OnionTrustedTimeAuthority(this);
            var invalid = evidence[0].Signature.ToArray(); invalid[^1] ^= 1;
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantIssuanceVerifier.VerifyAsync(
                route.Network, route.NetworkAuthority, operational.ExactPma2, request.ExactXmg1, route.ExactRouteClosure,
                effective, [new(evidence[0].NodeId.Span, invalid), evidence[1]], time, ct));
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantIssuanceVerifier.VerifyAsync(
                route.Network, route.NetworkAuthority, operational.ExactPma2, request.ExactXmg1, route.ExactRouteClosure,
                effective, [evidence[0], evidence[0]], time, ct));
            var authorized = await DeepIdV2MailboxGrantIssuanceVerifier.VerifyAsync(route.Network, route.NetworkAuthority,
                operational.ExactPma2, request.ExactXmg1, route.ExactRouteClosure, effective, evidence, time, ct);
            var wrong = new FixtureMailboxIssuer(retrieve ? (byte)0x31 : (byte)0x32);
            await Assert.ThrowsAsync<CryptographicException>(async () => await authorized.AuthorSuccessAsync(wrong, ct));
            Assert.Equal(0, wrong.Calls);
            var issuer = new FixtureMailboxIssuer(retrieve ? (byte)0x32 : (byte)0x31);
            var exact = (await authorized.AuthorSuccessAsync(issuer, ct)).ToArray();
            Assert.Equal(1, issuer.Calls);
            Assert.Equal(request.Record.Field(10).ToArray(), ContactCodec.Decode("XMC2", exact).Field(6).ToArray());
            return exact;
        }
    }

    // Actual account/native PQ/SQLCipher/protected custody and role signatures;
    // only the private issuer transport is in-process, not socket/device evidence.
    private sealed class OwnedGrantTransport(Fixture fixture, bool selfRetrieve = false, bool? ownerOnPrimary = null) : IDid2MailboxGrantTransport
    {
        internal bool CorruptResponse { get; set; }
        internal bool LoseResponse { get; set; }
        internal int Calls { get; private set; }
        internal bool ExactRetry { get; private set; } = true;
        internal Did2OwnedContactTransportContext? Dispatch { get; private set; }
        internal bool BuiltHeldFrame { get; private set; }
        internal Func<Task>? BeforeReturn { get; set; }
        private byte[]? requestBytes, responseBytes;
        public async ValueTask<ReadOnlyMemory<byte>> AcquireAsync(AuthoredMailboxGrantRequest request,
            VerifiedDeepIdV2ContactRouteClosure route, Did2OwnedContactTransportContext dispatch, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Calls++; Dispatch = dispatch; dispatch.RequireActive();
            using (var custody = await fixture.ReadPeerGrantsAsync(own: ownerOnPrimary ?? selfRetrieve))
            {
                var entry = Assert.Single(custody.Entries.Values,
                    value => ProtectedDid2MailboxGrantJournal.Request(value).Span.SequenceEqual(request.ExactXmg1.Span));
                Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(entry));
                Assert.Equal(request.ExactXmg1.ToArray(), ProtectedDid2MailboxGrantJournal.Request(entry).ToArray());
            }
            if (Calls == 1)
            {
                var canonical = ContactResolveCanonicalPathRequest.Decode(request.ExactXmg1.Span);
                Assert.Equal(ContactServiceRequestKind.AcquireMailboxGrant, canonical.RequestKind);
                var placement = ContactServicePlacementFactory.Create(dispatch.Network, canonical.RequestKind, canonical.ShardKey);
                var source = (ownerOnPrimary ?? selfRetrieve) ? fixture.Source(dispatch.Custody.Owner) : fixture.GrantReaderSource(dispatch.Custody.Owner);
                var paths = new ContactResolvePrivacyPathProvider(source, dispatch.Custody.Guards);
                var prepared = await paths.PrepareWithAuthorityAsync(OnionOperation.ContactResolve, canonical,
                    ReadOnlyMemory<byte>.Empty, new(dispatch.Network, placement), ct);
                var ledger = new CapturingEntropyLedger(dispatch.Custody.Entropy);
                var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(ledger),
                    new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
                using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request, ct);
                Assert.True(built.Frame.Length > request.ExactXmg1.Length);
                Assert.Equal(OnionEntropyCommitOutcome.Duplicate,
                    await dispatch.Custody.Entropy.CommitAsync(ledger.LastBatch!, ct));
                dispatch.RequireActive(); BuiltHeldFrame = true;
            }
            var exact = request.ExactXmg1.ToArray();
            if (requestBytes is null) requestBytes = exact;
            else { ExactRetry &= requestBytes.AsSpan().SequenceEqual(exact); Assert.True(ExactRetry); }
            if (responseBytes is null)
            {
                responseBytes = await fixture.IssueOwnedGrantAsync(request, route, selfRetrieve, ct);
            }
            if (LoseResponse) throw new IOException("Injected lost private grant response.");
            var response = responseBytes.ToArray(); if (CorruptResponse) response[^1] ^= 1;
            if (BeforeReturn is not null) await BeforeReturn();
            return response;
        }
    }

    private sealed class FixtureMailboxIssuer(byte marker) : IMailboxGrantIssuerSigner
    {
        public ReadOnlyMemory<byte> Ed25519PublicKey => PublicKey(marker);
        internal int Calls { get; private set; }
        public ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingBytes, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Calls++;
            var pair = PublicKeyAuth.GenerateKeyPair(Bytes(32, marker));
            try { return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(signingBytes.ToArray(), pair.PrivateKey)); }
            finally { CryptographicOperations.ZeroMemory(pair.PrivateKey); }
        }
    }
}
