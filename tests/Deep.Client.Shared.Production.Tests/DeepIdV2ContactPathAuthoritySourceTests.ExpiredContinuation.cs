using System.Buffers.Binary;
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
    [Theory]
    [InlineData("none")]
    [InlineData("before")]
    [InlineData("after")]
    [InlineData("overlap")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2DisjointExpiredContinuation_ClosesExactUnknownAndColdRestartsWithIndependentHolder(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, longMailboxWindow: true, encryptedStorage: true);
        var intent = Bytes(32, 0xc9);
        var (complete, _, _, _, _) = await fixture.PrepareNativeHelloCompletion(intent, verifyDraftRecovery: true);
        byte[] initial;
        using (var sent = await complete(fixture.Accounts)) initial = sent.ExactDph2.ToArray();
        fixture.TrackMailboxDispatchClock();
        var store = new OwnedStoreFixture(fixture, null, ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent), initial);
        _ = await fixture.StartNativeContact(intent, new OwnedGrantTransport(fixture, ownerOnPrimary: true), store);
        var issuer = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var terminal = new OwnedReadTerminal(fixture, initial)
        { RetainedEnvelope = store.StoredEnvelope, HasMoreAfterPage = true, CanonicalContinuation = true };
        Assert.Equal(1, (await fixture.SynchronizeNativeReceiver(issuer, terminal)).DurableTombstones);
        var expiry = BinaryPrimitives.ReadUInt64BigEndian(terminal.IssuedContinuation.AsSpan(24));
        if (fault != "overlap") fixture.AdvanceStoreSettlementClock(checked(expiry + 31));
        byte[] acquisition;
        using (var grants = await fixture.ReadPeerGrantsAsync())
            acquisition = SHA256.HashData(ProtectedDid2MailboxGrantJournal.Request(Assert.Single(grants.Entries).Value).Span);
        byte[] oldMau = [];
        var nextIssuer = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var reader = fixture.ReopenGrantReader();
        // Recreate the old producer using its real installed scoped credential,
        // factory, signed holder and native outbox, without bypassing authority.
        // The exact query has no captured page and its attempt remains unknown.
        using (Did2MailboxInstallationTestHooks.PushReadPreparation(async (sql, selector, route, signer, authority, ct) =>
            { _ = await fixture.StageDisjointContinuationAsync(sql, selector, route, signer, authority, expiry, fault != "overlap", ct); }))
            await Assert.ThrowsAsync<IOException>(() => reader.RenewOwnPermanentContactRetrieveGrantAsync(
                acquisition, fixture.GrantReaderSource(reader), nextIssuer));
        oldMau = fixture.StagedContinuationMau;
        Assert.NotEmpty(oldMau); Assert.Equal(1, nextIssuer.Calls); Assert.Equal(1, terminal.RetrieveCalls);
        using (var pending = await fixture.ReadPeerMailboxReads())
        {
            Assert.Equal(2, pending.Phase); Assert.Empty(pending.Closed);
            var grant = MailboxAuthenticatedClientRequestCodec.Decode(oldMau).Presentation.Grant;
            Assert.Equal(fault != "overlap", expiry <= grant.NotBeforeUnixSeconds); Assert.True(fixture.CurrentProofTime < grant.ExpiresAtUnixSeconds);
            Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxReadJournal.ClosedAttempt.Capture(
                pending.Active!, 2, grant.ExpiresAtUnixSeconds, expiry - 1, oldMau));
            if (fault == "overlap")
                Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxReadJournal.ClosedAttempt.Capture(
                    pending.Active!, 2, grant.ExpiresAtUnixSeconds, expiry, oldMau));
        }
        if (fault == "overlap") fixture.AdvanceStoreSettlementClock(checked(expiry + 31));
        fixture.ColdReopenCompactionStorage(); terminal.ReturnEmptyPage = true;
        var replacement = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        if (fault == "overlap")
        {
            terminal.LoseRetrieveReply = true;
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.SynchronizeNativeReceiver(replacement, terminal));
            Assert.Equal(0, replacement.Calls); Assert.Equal(oldMau, terminal.ExactRetrieveRequests[^1]);
            using var retained = await fixture.ReadPeerMailboxReads();
            Assert.Equal(2, retained.Phase); Assert.Empty(retained.Closed); Assert.Equal(SHA256.HashData(oldMau), retained.Active!.RetrieveMauHash);
            await fixture.RequireUnknownContinuationOutboxAsync(oldMau);
            CryptographicOperations.ZeroMemory(oldMau); return;
        }
        if (fault != "none")
        {
            var hit = false;
            using (Did2MailboxInstallationTestHooks.Push(point =>
            { if (point == (fault == "before" ? Did2MailboxInstallationFailpoint.BeforeReadClosure : Did2MailboxInstallationFailpoint.AfterReadClosure))
                { hit = true; throw new IOException("Disposable exact closure interruption."); } }))
                await Assert.ThrowsAsync<IOException>(() => fixture.SynchronizeNativeReceiver(replacement, terminal));
            Assert.True(hit); Assert.Equal(0, replacement.Calls); Assert.Equal(1, terminal.RetrieveCalls);
            fixture.ColdReopenCompactionStorage();
        }
        Assert.Equal(0, (await fixture.SynchronizeNativeReceiver(replacement, terminal)).ProcessedEnvelopes);
        Assert.Equal(1, replacement.Calls); Assert.Equal(2, terminal.RetrieveCalls); Assert.Equal(1, terminal.AckCalls);
        using var final = await fixture.ReadPeerMailboxReads();
        var closed = Assert.Single(final.Closed).Value;
        Assert.Equal(2, closed.Phase); Assert.Equal(oldMau, closed.ExactMau);
        Assert.True(closed.ClosedAtLower >= expiry); Assert.True(closed.ClosedAtLower < closed.GrantExpiry);
        Assert.Equal(closed.Counter, final.Counters[Convert.ToHexString(closed.Grant)]);
        var freshQuery = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
            MailboxAuthenticatedClientRequestCodec.Decode(terminal.ExactRetrieveRequests[1]).Binding.CanonicalRequest.Span);
        Assert.Equal(0UL, freshQuery.AfterCursor); Assert.Empty(freshQuery.ContinuationToken.ToArray());
        Assert.DoesNotContain(terminal.ExactRetrieveRequests, value => value.AsSpan().SequenceEqual(oldMau));
        await fixture.RequireUnknownContinuationOutboxAsync(oldMau);
        CryptographicOperations.ZeroMemory(oldMau);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("before-sql")]
    [InlineData("after-sql")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ExpiredIdleContinuation_ColdRestartsOnlyPaginationAndPreservesAcknowledgedInbox(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, longMailboxWindow: true, encryptedStorage: true);
        var intent = Bytes(32, 0xc8);
        var (complete, _, _, _, _) = await fixture.PrepareNativeHelloCompletion(intent, verifyDraftRecovery: true);
        byte[] initial;
        using (var sent = await complete(fixture.Accounts)) initial = sent.ExactDph2.ToArray();
        fixture.TrackMailboxDispatchClock();
        var store = new OwnedStoreFixture(fixture, null, ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent), initial);
        _ = await fixture.StartNativeContact(intent, new OwnedGrantTransport(fixture, ownerOnPrimary: true), store);
        var issuer = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var terminal = new OwnedReadTerminal(fixture, initial)
        { RetainedEnvelope = store.StoredEnvelope, HasMoreAfterPage = true, CanonicalContinuation = true };
        var first = await fixture.SynchronizeNativeReceiver(issuer, terminal);
        Assert.Equal(1, first.ProcessedEnvelopes); Assert.Equal(1, first.DurableTombstones); Assert.True(first.HasMore);
        Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(1, terminal.AckCalls);
        ulong generation, counter; string counterName; byte[] scopeBytes;
        using (var read = await fixture.ReadPeerMailboxReads())
        {
            Assert.Equal(0, read.Phase); Assert.Null(read.Active); Assert.Empty(read.Closed);
            var traversal = Assert.Single(read.Traversals).Value;
            Assert.Equal(terminal.Cursor, traversal.AfterCursor); Assert.Equal(terminal.IssuedContinuation, traversal.GetContinuationTokenCopy());
            generation = traversal.PollGeneration; var floor = Assert.Single(read.Counters); counter = floor.Value; counterName = floor.Key;
            scopeBytes = Convert.FromHexString(Assert.Single(read.Traversals).Key);
        }
        var beforeSql = await fixture.ReadPaginationSqlAsync(scopeBytes);
        var expiry = BinaryPrimitives.ReadUInt64BigEndian(terminal.IssuedContinuation.AsSpan(24));
        fixture.AdvanceStoreSettlementClock(checked(expiry + 31));
        fixture.ColdReopenCompactionStorage(); terminal.ReturnEmptyPage = true;
        var noIssuance = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        if (fault != "none")
        {
            var hit = false;
            using (Did2MailboxInstallationTestHooks.Push(point =>
            {
                if (point == (fault == "before-sql" ? Did2MailboxInstallationFailpoint.BeforeTraversalRestart : Did2MailboxInstallationFailpoint.AfterTraversalRestart))
                { hit = true; throw new IOException("Disposable pagination restart interruption."); }
            }))
                await Assert.ThrowsAsync<IOException>(() => fixture.SynchronizeNativeReceiver(noIssuance, terminal));
            Assert.True(hit); Assert.Equal(0, noIssuance.Calls); Assert.Equal(1, terminal.RetrieveCalls);
            using (var interrupted = await fixture.ReadPeerMailboxReads())
            { Assert.Equal(generation, Assert.Single(interrupted.Traversals).Value.PollGeneration); Assert.Null(interrupted.Active); }
            fixture.ColdReopenCompactionStorage();
        }
        Assert.Equal(0, (await fixture.SynchronizeNativeReceiver(noIssuance, terminal)).ProcessedEnvelopes);
        Assert.InRange(noIssuance.Calls, 0, 1); Assert.Equal(2, terminal.RetrieveCalls); Assert.Equal(1, terminal.AckCalls);
        var finalRequest = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
            MailboxAuthenticatedClientRequestCodec.Decode(terminal.ExactRetrieveRequests[1]).Binding.CanonicalRequest.Span);
        Assert.Equal(0UL, finalRequest.AfterCursor); Assert.Empty(finalRequest.ContinuationToken.ToArray());
        using var final = await fixture.ReadPeerMailboxReads();
        Assert.Equal(checked(generation + 2), Assert.Single(final.Traversals).Value.PollGeneration);
        if (noIssuance.Calls == 0) Assert.True(final.Counters[counterName] > counter);
        else { Assert.Equal(counter, final.Counters[counterName]); Assert.Equal(2, final.Counters.Count); }
        Assert.Empty(final.Closed); Assert.Null(final.Active);
        Assert.Single(terminal.ExactAckRequests); // Restart never re-ACKs or erases the acknowledged item.
        var afterSql = await fixture.ReadPaginationSqlAsync(scopeBytes);
        Assert.Equal(beforeSql[3], afterSql[3]); // Exact acknowledged encrypted inbox bytes survive.
        if (fault == "none")
        {
            await fixture.WritePaginationSqlForTestAsync(scopeBytes, beforeSql);
            fixture.ColdReopenCompactionStorage();
            var deniedIssuer = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.SynchronizeNativeReceiver(deniedIssuer, terminal));
            Assert.Equal(0, deniedIssuer.Calls); Assert.Equal(2, terminal.RetrieveCalls);
            var rejected = await fixture.ReadPaginationSqlAsync(scopeBytes);
            for (var i = 0; i < beforeSql.Length; i++) Assert.Equal(beforeSql[i], rejected[i]);
            await fixture.WritePaginationSqlForTestAsync(scopeBytes, afterSql);
            fixture.ColdReopenCompactionStorage();
            Assert.Equal(0, (await fixture.SynchronizeNativeReceiver(
                new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false), terminal)).ProcessedEnvelopes);
            Assert.Equal(1, terminal.AckCalls);
        }
    }

    private sealed partial class Fixture
    {
        internal async Task<byte[][]> ReadPaginationSqlAsync(byte[] scope)
        {
            byte[][] result = [];
            var account = (await ReopenGrantReader().GetCurrentAsync())!.AccountId.ToArray();
            await WithOwnedApplicationConnectionAsync(false, Network, account, sql =>
            {
                using var command = sql.CreateCommand();
                command.CommandText = "SELECT t.after_cursor,t.continuation_token,c.generation FROM client_mailbox_traversal t JOIN client_mailbox_poll_clock c USING(scope) WHERE scope=$scope;";
                command.Parameters.AddWithValue("$scope", scope);
                using (var row = command.ExecuteReader())
                { Assert.True(row.Read()); result = [(byte[])row[0], (byte[])row[1], (byte[])row[2], []]; Assert.False(row.Read()); }
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                command.CommandText = "SELECT cursor,digest,canonical_envelope,acknowledged FROM client_mailbox_inbox WHERE scope=$scope ORDER BY cursor;";
                using var inbox = command.ExecuteReader(); var count = 0;
                while (inbox.Read())
                { for (var i = 0; i < 3; i++) hash.AppendData((byte[])inbox[i]); Assert.Equal(1, inbox.GetInt32(3)); count++; }
                Assert.Equal(1, count); result[3] = hash.GetHashAndReset();
            });
            return result;
        }
        internal async Task WritePaginationSqlForTestAsync(byte[] scope, byte[][] exact)
        {
            var account = (await ReopenGrantReader().GetCurrentAsync())!.AccountId.ToArray();
            await WithOwnedApplicationConnectionAsync(false, Network, account, sql =>
            {
                using var transaction = sql.BeginTransaction(); using var command = sql.CreateCommand(); command.Transaction = transaction;
                command.CommandText = "UPDATE client_mailbox_traversal SET after_cursor=$cursor,continuation_token=$token WHERE scope=$scope; UPDATE client_mailbox_poll_clock SET generation=$generation WHERE scope=$scope;";
                command.Parameters.AddWithValue("$scope", scope); command.Parameters.AddWithValue("$cursor", exact[0]);
                command.Parameters.AddWithValue("$token", exact[1]); command.Parameters.AddWithValue("$generation", exact[2]);
                Assert.Equal(2, command.ExecuteNonQuery()); transaction.Commit();
            });
        }

        internal async Task<byte[]> StageDisjointContinuationAsync(SqliteDeepMailboxStore sql, MailboxCredentialSelector selector,
            ScopedMailboxResolvedRoute route, IMailboxOperationSigner signer, VerifiedOfficialMailboxAuthority authority,
            ulong expiry, bool disjoint, CancellationToken ct)
        {
            byte[] ownerScope;
            using (var key = await peerStorage.ReadOwnedAsync("deep.store.v2.sql-generation", ct) ?? throw new InvalidDataException())
                ownerScope = key.Use(bytes => bytes.Slice(24, 64).ToArray());
            using var qaRaw = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot, ct) ?? throw new InvalidDataException();
            var qaExact = qaRaw.Use(bytes => bytes.ToArray());
            using var read = ProtectedDid2MailboxReadJournal.Decode(qaExact, Network, ownerScope.AsSpan(0, 32), ownerScope.AsSpan(32));
            using var grantRaw = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct) ?? throw new InvalidDataException();
            var grantExact = grantRaw.Use(bytes => bytes.ToArray());
            using var grants = ProtectedDid2MailboxGrantJournal.Decode(grantExact, Network, ownerScope.AsSpan(0, 32), ownerScope.AsSpan(32));
            var publicKey = signer.GetEd25519PublicKey();
            var entry = Assert.Single(grants.Entries.Values, value => ProtectedDid2MailboxGrantJournal.IsAdoptedWinner(value) &&
                MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(value).Span).Field(8).Span)
                    .HolderPublicKey.Span.SequenceEqual(publicKey));
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8).Span);
            Assert.Equal(disjoint, expiry <= grant.NotBeforeUnixSeconds);
            var scope = ClientMailboxScope.Derive(selector.IssuerContext.Span, route.MailboxId, route.Epoch);
            var traversal = read.Traversals[Convert.ToHexString(scope.Value)];
            var operation = ClientMailboxAdapter.RetrieveOperationId(route, traversal);
            var body = MailboxAuthenticatedRequestTranscript.ForRetrieve(route.Epoch, operation, route.MailboxId, route.PlacementId,
                traversal.AfterCursor, ProtectedDid2MailboxReadJournal.NewPageMaximumItems, traversal.ContinuationToken);
            var hash = SHA256.HashData(MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant));
            read.Active = ProtectedDid2MailboxReadJournal.Cycle.Begin(hash, scope.Value, SHA256.HashData(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span),
                traversal.PollGeneration, body.CanonicalRequest.Span); read.Phase = 1;
            await SaveQa();
            ProtectedDid2MailboxGrantJournal.ReserveReadIntent(grants, entry); grants.Revision++;
            var reserved = ProtectedDid2MailboxGrantJournal.Encode(grants, Network, ownerScope.AsSpan(0, 32), ownerScope.AsSpan(32));
            Assert.True(await peerStorage.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, grantExact, reserved, ct));
            var prepared = await new MailboxAuthenticatedRequestFactory(sql, authority).CreateRetrieveAsync(selector.AccountScope,
                selector, signer, route, operation, traversal.AfterCursor, ProtectedDid2MailboxReadJournal.NewPageMaximumItems,
                traversal.GetContinuationTokenCopy(), ct);
            var exact = prepared.GetCanonicalMau3Copy(); read.Active.AdoptPrepared(exact, ack: false);
            read.Counters[Convert.ToHexString(hash)] = read.Active.RetrieveCounter; read.Phase = 2; await SaveQa();
            var item = (await sql.ReadTransportOutboxAsync(selector.AccountScope, OutboxLogicalId.FromBytes(operation), ct)).Item!;
            var now = authority.TimeProvider.GetUtcNow();
            Assert.Equal(TransportOutboxCommitResult.Applied, await sql.ApplyTransportOutboxTransitionAsync(TransportOutboxTransition.Attempted(
                selector.AccountScope, item.LogicalId, item.Revision, OutboxAttemptId.FromBytes(Bytes(16, 0xd8)),
                OutboxTransitionSource.Adapter, OutboxTransitionReason.DispatchStarted, now, now.AddSeconds(1)), ct));
            stagedContinuationMau = exact.ToArray();
            foreach (var bytes in new[] { ownerScope, qaExact, grantExact, reserved }) CryptographicOperations.ZeroMemory(bytes);
            throw new IOException("Genuine old-producer preparation interrupted before result.");

            async Task SaveQa()
            {
                read.Revision++;
                var next = ProtectedDid2MailboxReadJournal.Encode(read, Network, ownerScope.AsSpan(0, 32), ownerScope.AsSpan(32));
                Assert.True(await peerStorage.CompareExchangeAsync(ProtectedDid2MailboxReadJournal.Slot, qaExact, next, ct));
                CryptographicOperations.ZeroMemory(qaExact); qaExact = next;
            }
        }
        private byte[] stagedContinuationMau = [];
        internal byte[] StagedContinuationMau => stagedContinuationMau.ToArray();
        internal async Task RequireUnknownContinuationOutboxAsync(byte[] exact)
        {
            var request = MailboxAuthenticatedClientRequestCodec.Decode(exact);
            var account = (await ReopenGrantReader().GetCurrentAsync())!.AccountId.ToArray();
            await WithOwnedApplicationConnectionAsync(false, Network, account, sql =>
            {
                using var command = sql.CreateCommand();
                command.CommandText = "SELECT state,ciphertext_bundle FROM transport_outbox_items WHERE account_scope=$scope AND logical_id=$id;";
                command.Parameters.AddWithValue("$scope", Deep.Client.Shared.Services.ContactV1.VerifiedCurrentMailboxGrant.AccountScopeForHolder(request.Presentation.Grant.HolderPublicKey.Span).ToArray());
                command.Parameters.AddWithValue("$id", request.Binding.OperationId.ToArray());
                using var row = command.ExecuteReader(); Assert.True(row.Read());
                Assert.Equal((int)TransportOutboxState.Attempted, row.GetInt32(0)); Assert.Equal(exact, (byte[])row[1]); Assert.False(row.Read());
            });
        }
    }
}
