using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AttachmentV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("stored")] [InlineData("cancelled")] [InlineData("expired")] [InlineData("draft")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OutboxAttachmentKeys_TerminalCleanupRemovesOnlyWorkingKeyCopiesAndColdRecovers(string outcome)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        var assetOperation = Bytes(32, 0xb1);
        var content = System.Text.Encoding.UTF8.GetBytes("Independent asset remains readable after outbox-only key copies retire.");
        using var asset = await fixture.PrepareOwnedAsset(sender, assetOperation, content, "key-owner.txt", "text/plain", 4_000_000);
        using var offer = await fixture.CreateOwnedAttachmentOffer(sender, assetOperation);
        var operation = offer.OperationId.ToArray();
        var exact = offer.ExactDmc2.ToArray(); var message = ApplicationCoreCodec.DecodeDmc2(exact);
        using var manifest = Assert.IsType<AttachmentOfferDmc2Payload>(message.ParsedPayload).Manifest;
        var key = manifest.ObjectKey.ToArray(); byte[] envelope = [];
        var stored = outcome == "stored"; var encrypted = outcome != "draft";
        var nativeBefore = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        using var assetRoot = await fixture.CompletedContactSendStorage(true).ReadOwnedAsync(ProtectedDid2AttachmentJournal.Slot) ?? throw new InvalidDataException();
        var assetBefore = assetRoot.Use(bytes => bytes.ToArray());
        try
        {
            if (encrypted)
            {
                using var sent = await fixture.SendOwnedMessage(sender, operation, message); envelope = sent.ExactEnvelope.ToArray();
            }
            var native = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
            try
            {
                var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
                var transport = encrypted ? new OwnedStoreFixture(fixture, sender, operation, envelope) : null;
                if (stored)
                {
                    await fixture.DeliverNativeMessage(sender, operation, grants, transport!);
                    await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
                }
                else if (outcome == "expired")
                {
                    using (Did2MailboxSendTestHooks.Push(point =>
                        { if (point == Did2MailboxSendFailpoint.AfterPreparedRoot) throw new IOException("Prepared attachment request before dispatch."); }))
                        await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport!));
                    ulong deadline;
                    using (var sends = await fixture.ReadMailboxSends()) deadline = Assert.Single(sends.Entries).Value.RetryUntil;
                    await fixture.AdvanceStoppedWorkToOriginalDeadline(deadline);
                }
                var hit = false;
                using (Did2CompactionTestHooks.Push(point =>
                    { if (point == Did2CompactionFailpoint.AfterSql) { hit = true; throw new IOException("Attachment working keys deleted before protected adoption."); } }))
                    await Assert.ThrowsAsync<IOException>(() => stored ? fixture.CompactNativeOrdinaryOutbox(sender, default) :
                        outcome == "expired" ? fixture.DeliverNativeMessage(sender, operation, grants, transport!) :
                        fixture.CancelNativeMessagingWork(sender, operation));
                Assert.True(hit); fixture.ColdReopenCompactionStorage(); var requests = fixture.ProofRequests;
                await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
                await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
                Assert.Equal(requests, fixture.ProofRequests);
                await fixture.AssertOutboxAttachmentKeyCopiesRetired(sender, operation, exact, key, stored, encrypted,
                    outcome == "expired" ? 2 : 1);
                Assert.Equal(native, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
                if (!encrypted) Assert.Equal(nativeBefore, native);
                using var assetAfter = await fixture.CompletedContactSendStorage(true).ReadOwnedAsync(ProtectedDid2AttachmentJournal.Slot) ?? throw new InvalidDataException();
                Assert.Equal(assetBefore, assetAfter.Use(bytes => bytes.ToArray()));
                using var recovered = await fixture.ReadPrimaryAsset(assetOperation);
                using var recoveredManifest = recovered.OwnManifest();
                Assert.True(recoveredManifest.Use(bytes => bytes.SequenceEqual(manifest.CanonicalBytes.Span)));
                using var plaintext = recovered.MaterializePlaintext(default);
                Assert.True(plaintext.Use(bytes => bytes.SequenceEqual(content)));
                if (stored)
                {
                    var cached = await fixture.DeliverNativeMessage(sender, operation, grants, transport!);
                    Assert.False(cached.IngressDispatched); Assert.Equal(1, transport!.Calls); Assert.Equal(1, grants.Calls);
                }
                else
                {
                    await fixture.CancelNativeMessagingWork(sender, operation);
                    Assert.Equal(stored ? 1 : 0, transport?.Calls ?? 0);
                }
                // No key-bearing working copy is recreated by read/retry/cancel.
                await fixture.AssertOutboxAttachmentKeyCopiesRetired(sender, operation, exact, key, stored, encrypted,
                    outcome == "expired" ? 2 : 1);
            }
            finally { CryptographicOperations.ZeroMemory(native); }
        }
        finally
        {
            foreach (var bytes in new[] { exact, key, envelope, nativeBefore, assetBefore, content }) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OutboxAttachmentKeys_ReadOnlySelectionCannotDestroyAnUnadoptedAssetKey()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        var assetOperation = Bytes(32, 0xb3); var content = new byte[] { 1, 2, 3 };
        using var asset = await fixture.PrepareOwnedAsset(sender, assetOperation, content, "owned.bin", "application/octet-stream", 4_000_000);
        using var offer = await fixture.CreateOwnedAttachmentOffer(sender, assetOperation);
        var operation = offer.OperationId.ToArray();
        using var sent = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(offer.ExactDmc2.Span));
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, sender, operation, sent.ExactEnvelope.ToArray());
        await fixture.DeliverNativeMessage(sender, operation, grants, transport);
        using var manifestOwner = asset.OwnManifest();
        var originalManifest = manifestOwner.Use(bytes => bytes.ToArray());
        using var parsedManifest = ApplicationCoreCodec.DecodeDam1(originalManifest);
        var objectKey = parsedManifest.ObjectKey.ToArray(); var damaged = originalManifest.ToArray();
        var keyOffset = damaged.AsSpan().IndexOf(objectKey); Assert.True(keyOffset >= 0); damaged[keyOffset] ^= 1;
        try
        {
            await fixture.ReplacePrimaryAssetManifest(sender, assetOperation, damaged);
            var beforeTampered = await fixture.ReadRawCompleteApplicationProjection(sender);
            var beforeRoots = await fixture.ReadCompletedContactSendRetainedRoots(sender);
            try
            {
                await Assert.ThrowsAsync<CryptographicException>(() => fixture.CompactNativeOrdinaryOutbox(sender, default));
                Assert.Equal(beforeTampered, await fixture.ReadRawCompleteApplicationProjection(sender));
                Assert.Equal(beforeRoots, await fixture.ReadCompletedContactSendRetainedRoots(sender));
            }
            finally { CryptographicOperations.ZeroMemory(beforeTampered); CryptographicOperations.ZeroMemory(beforeRoots); }
        }
        finally
        {
            await fixture.ReplacePrimaryAssetManifest(sender, assetOperation, originalManifest);
            foreach (var bytes in new[] { originalManifest, objectKey, damaged }) CryptographicOperations.ZeroMemory(bytes);
        }
        using (Did2AttachmentTestHooks.Push(point =>
            { if (point == Did2AttachmentFailpoint.AfterSqlBeforePending) throw new IOException("Inert asset SQL candidate, no protected adoption."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.PrepareOwnedAsset(sender, Bytes(32, 0xb5), content,
                "unadopted.bin", "application/octet-stream", 4_000_000));
        var sql = await fixture.ReadRawCompleteApplicationProjection(sender);
        var roots = await fixture.ReadCompletedContactSendRetainedRoots(sender);
        try
        {
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.CompactNativeOrdinaryOutbox(sender, default));
            Assert.Equal(sql, await fixture.ReadRawCompleteApplicationProjection(sender));
            Assert.Equal(roots, await fixture.ReadCompletedContactSendRetainedRoots(sender));
            await fixture.WithAuthoredApplicationConnectionAsync(sender, connection =>
            { using var count = connection.CreateCommand(); count.CommandText = "SELECT count(*) FROM local_attachment_objects;"; Assert.Equal(2L, count.ExecuteScalar()); });
            // Explicit asset-owner reconciliation, not outbox selection, may
            // discard its inert candidate under DR-0031 before outbox retry.
            using (var owned = await fixture.ReadPrimaryAsset(assetOperation))
            using (var plaintext = owned.MaterializePlaintext(default))
                Assert.True(plaintext.Use(bytes => bytes.SequenceEqual(content)));
            await fixture.CompactNativeOrdinaryOutbox(sender, default);
            Assert.False((await fixture.DeliverNativeMessage(sender, operation, grants, transport)).IngressDispatched);
            Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        }
        finally { CryptographicOperations.ZeroMemory(sql); CryptographicOperations.ZeroMemory(roots); }
    }

    private sealed partial class Fixture
    {
        internal Task ReplacePrimaryAssetManifest(Did2MessagingSessionScope scope, byte[] operation, byte[] manifest)
            => WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var write = connection.CreateCommand();
                write.CommandText = "UPDATE local_attachment_objects SET exact_manifest=$manifest WHERE operation_id=$op;";
                write.Parameters.AddWithValue("$manifest", manifest); write.Parameters.AddWithValue("$op", operation);
                Assert.Equal(1, write.ExecuteNonQuery());
            });
        internal Task<OwnedAttachmentPreparation> ReadPrimaryAsset(ReadOnlyMemory<byte> operation)
            => ReopenAccount().ReadOwnAttachmentAsync(operation, default);

        internal async Task AssertOutboxAttachmentKeyCopiesRetired(Did2MessagingSessionScope scope, byte[] operation,
            byte[] exactOffer, byte[] key, bool stored, bool committedHistory, int stoppedReason)
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidDataException();
            using var state = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var name = Convert.ToHexString(operation);
            Assert.False(state.Entries.ContainsKey(name));
            var marker = state.TerminalAudits[name];
            Assert.Equal(stored ? 3 : stoppedReason, (int)marker.Reason);
            Assert.Equal(48, marker.Exact.Length); Assert.True(marker.Exact.IndexOf(key) < 0);
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var work = connection.CreateCommand(); work.CommandText = "SELECT count(*) FROM direct_text_outbox WHERE operation_id=$op;";
                work.Parameters.AddWithValue("$op", operation); Assert.Equal(0L, work.ExecuteScalar());
                using var history = connection.CreateCommand();
                history.CommandText = "SELECT exact_dmc2 FROM authenticated_dmc2_inbox WHERE exact_dmc2_hash=$hash;";
                history.Parameters.AddWithValue("$hash", SHA256.HashData(exactOffer)); var retained = history.ExecuteScalar();
                Assert.Equal(committedHistory, retained is byte[]);
                if (retained is byte[] actual) { try { Assert.Equal(exactOffer, actual); } finally { CryptographicOperations.ZeroMemory(actual); } }
                using var audit = connection.CreateCommand(); audit.CommandText = "PRAGMA table_info(stopped_work_audit);";
                using var rows = audit.ExecuteReader(); var columns = new List<string>(); while (rows.Read()) columns.Add(rows.GetString(1));
                Assert.Equal(new[] { "operation_id", "reason", "stopped_at", "expires_at", "authenticator" }, columns);
            });
        }
    }
}
