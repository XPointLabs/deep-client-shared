using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("draft")] [InlineData("native")] [InlineData("stopped")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryPaged_RetainedLegacyDraftOrdersBootstrapAndPreservesExactRetryOrStop(string state)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver, _) = await fixture.PrepareWrongAnchorPair();
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 1_000);
        var legacy = await fixture.InstallRetainedLegacyRouteDraft(sender);
        byte[]? originalEnvelope = null;
        if (state == "native")
        {
            using var native = await fixture.SendOwnedRouteUpdate(sender, legacy.Operation); originalEnvelope = native.ExactEnvelope.ToArray();
        }
        if (state == "stopped") await fixture.CancelNativeMessagingWork(sender, legacy.Operation);
        using var request = await fixture.PrepareOwnedHistory(receiver); Assert.NotNull(request);
        byte[] requestEnvelope;
        using (var native = await fixture.SendOwnedRouteUpdate(receiver, request!.OperationId)) requestEnvelope = native.ExactEnvelope.ToArray();
        var requestOperation = Dpe2Codec.Decode(requestEnvelope).OperationId.ToArray();
        using (var incoming = await fixture.ReceiveOwnedMessage(sender, requestEnvelope)) Assert.Equal(3, incoming.RouteProcessing[0]);
        if (state == "draft")
        {
            Assert.Equal(0L, await fixture.CountOwnHistoryDecisions(sender));
            var root = await fixture.ReadLegacyDraftRoot(sender);
            Assert.Null(await fixture.PrepareOwnedHistory(sender, requestOperation));
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => fixture.CreateOwnedRouteUpdate(sender));
            Assert.Equal(root, await fixture.ReadLegacyDraftRoot(sender));
            Assert.Equal(legacy.Operation, await fixture.SelectRouteMaintenance(sender));
            using var retry = await fixture.RetryOwnedRouteUpdate(sender, legacy.Operation);
            Assert.Equal(legacy.Exact, retry.ExactDmc2.ToArray());
            using var native = await fixture.SendOwnedRouteUpdate(sender, legacy.Operation); originalEnvelope = native.ExactEnvelope.ToArray();
            using var fresh = await fixture.CreateOwnedRouteUpdate(sender);
            Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(fresh.ExactDmc2.Span).ParsedPayload);
            Assert.Equal(legacy.Sequence + 1, fresh.SenderSequence);
        }
        else
        {
            Assert.True(await fixture.CountOwnHistoryDecisions(sender) > 0);
            if (state == "native")
            {
                using var retry = await fixture.RetryOwnedRouteUpdate(sender, legacy.Operation);
                Assert.Equal(legacy.Exact, retry.ExactDmc2.ToArray());
                using var replay = await fixture.SendOwnedRouteUpdate(sender, legacy.Operation);
                Assert.Equal(originalEnvelope, replay.ExactEnvelope.ToArray());
            }
            else
                await Assert.ThrowsAnyAsync<Exception>(() => fixture.RetryOwnedRouteUpdate(sender, legacy.Operation));
        }
    }

    private sealed partial class Fixture
    {
        // Historical DATA installation only: real signed publication records,
        // actual protected authored counter and existing pending->SQL->stable
        // custody. No removed fresh legacy author or qualification flag exists.
        internal async Task<(byte[] Operation, byte[] Exact, ulong Sequence)> InstallRetainedLegacyRouteDraft(Did2MessagingSessionScope scope)
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync(); byte[] route;
            using (var publication = await RouteState()) route = publication.Entries[Convert.ToHexString(plan.Intent.Span)].Record(6).ToArray();
            var closure = ContactRouteClosureCodec.Decode(route);
            var predecessor = await ActualInitialHelloHash(scope);
            var records = new[] { closure.Reachability, closure.Authorization, closure.Route, closure.Successor, closure.Projection, closure.Selection };
            var payload = new byte[97 + records.Sum(record => record.CanonicalBytes.Length)]; scope.Relationship.CopyTo(payload);
            BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(32), BinaryPrimitives.ReadUInt64BigEndian(closure.Reachability.Field(3).Span));
            predecessor.CopyTo(payload, 40); payload[72] = 6; var offset = 73;
            foreach (var record in records)
            {
                var bytes = record.CanonicalBytes; BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(offset), checked((uint)bytes.Length));
                bytes.Span.CopyTo(payload.AsSpan(offset + 4)); offset += 4 + bytes.Length;
            }
            var op = RandomNumberGenerator.GetBytes(32);
            var fresh = await Source().VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var accountLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            var owner = new ProtectedDeepIdV2AccountOwner(storage, accountLease, Path.Combine(directory, "deep-store-v2-account.dsv2"), Network, 1);
            using var current = await owner.ReadCurrentAsync(1_000, pq, default) ?? throw new InvalidDataException();
            using var held = await accountLease.AcquireAsync(default);
            using var app = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage,
                Path.Combine(directory, "deep-store-v2-account.dsv2"), current, held, default);
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidDataException();
            var before = raw.Use(bytes => bytes.ToArray()); raw.Dispose();
            using var journal = ProtectedDid2DirectTextJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
            var sequence = journal.NextSequence(scope); var created = checked(fresh.Proof.TrustedUpperUnixSeconds * 1000);
            var template = ApplicationCoreCodec.AuthorDmc2(scope.Network, RandomNumberGenerator.GetBytes(32), scope.Conversation,
                scope.LocalAccount, scope.LocalDevice, sequence, created, created + 120_000, Dmc2Flags.None, [],
                ApplicationCoreCodec.CreateMessageCreatePayload("historical route fixture data"));
            var exact = ReplaceControlPayload(template, payload);
            BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(FieldOffset(exact, 9)), (ushort)Dmc2ContentKind.ContactRouteUpdate);
            Assert.IsType<ContactRouteUpdateDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(exact).ParsedPayload);
            journal.AddPending(ProtectedDid2DirectTextJournal.Entry.Prepare(scope, op, ApplicationCoreCodec.DecodeDmc2(exact)));
            var pending = ProtectedDid2DirectTextJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
            Assert.True(await storage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot, before, pending));
            using (var mirrored = await app.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, op, default)) Assert.NotNull(mirrored);
            journal.Stabilize(Convert.ToHexString(op)); var stable = ProtectedDid2DirectTextJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
            Assert.True(await storage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot, pending, stable));
            foreach (var bytes in new[] { before, pending, stable, route, payload }) CryptographicOperations.ZeroMemory(bytes);
            return (op, exact, sequence);
        }

        internal async Task<long> CountOwnHistoryDecisions(Did2MessagingSessionScope scope)
        {
            long count = 0;
            await WithRouteReadSql(scope, (_, connection) =>
            {
                using var query = connection.CreateCommand(); query.CommandText = "SELECT COUNT(*) FROM route_decisions WHERE substr(decision,3,1)=x'01';";
                count = (long)query.ExecuteScalar()!;
            });
            return count;
        }
        internal async Task<byte[]> ReadLegacyDraftRoot(Did2MessagingSessionScope scope)
        {
            using var root = await NativeStorage(scope).ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidDataException();
            return root.Use(bytes => bytes.ToArray());
        }
    }
}
