using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("payload")]
    [InlineData("counter")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ArchiveEnrollment_OutgoingNativeMetadataCannotReplaceAuthoredPayloadAndCounterCustody(string defect)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var pair = await fixture.PrepareArchiveEnrollmentPair(0);
        using var original = await fixture.StageActualLegacyArchiveInput([pair.Sender]);
        using (Did2MessagingArchiveEnrollmentTestHooks.Push(point =>
            { if (point == Did2MessagingArchiveEnrollmentFailpoint.AfterSourceFrozen) throw new IOException("Frozen before authored source substitution."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.EnrollArchiveAccount());
        await fixture.CheckChangedArchiveAuthoredSource(pair.Sender, original, defect);
        fixture.ColdReopenCompactionStorage(); await fixture.EnrollArchiveAccount();
        await fixture.AssertArchiveAdoptedWithoutSourceMutation(original);
        await fixture.CheckArchiveAuthoredFinalProviderEdge(pair.Sender, defect);
    }

    private sealed partial class Fixture
    {
        // The same payload/counter defects are injected after an earlier
        // successful app read, inside the FINAL combined protected inventory.
        // A native-only fresh read cannot satisfy this paired-source claim.
        internal async Task CheckArchiveAuthoredFinalProviderEdge(Did2MessagingSessionScope scope, string defect)
        {
            using var draft = await CreateOwnedText(scope, "paired archive final provider edge");
            var operation = draft.OperationId.ToArray();
            using (var sent = await SendOwnedMessage(scope, operation, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span))) { }
            using (Did2CompactionTestHooks.Push(point =>
                { if (point == Did2CompactionFailpoint.AfterStage) throw new IOException("Staged before final paired-source substitution."); }))
                await Assert.ThrowsAsync<IOException>(() => CompactSenderPrefix(scope, 1, default));
            var authored = await CaptureOrdinaryWorkingRow(scope, operation);
            using var writer = await ArchiveAuthoredFixtureWriter(scope);
            var slots = new[] { Did2CompactionPlan.Slot, ProtectedDid2CompactionPlan.PartSlot(0),
                ProtectedDid2MessagingSessionCatalog.Slot, scope.FloorSlot, Did2MessagingHistoryCheckpoint.Slot(scope), Did2MessagingArchiveRoot.Slot(scope) };
            using var protectedBefore = await storage.ReadOwnedBatchAsync(slots);
            var nativeBefore = await ArchiveOriginalFingerprint(scope);
            var archiveBefore = await CaptureCompactionArchiveStorage(scope);
            var hit = false;
            try
            {
                storage.AfterPairedArchivePrefixReadGroup = () =>
                {
                    hit = true;
                    writer.Execute(connection =>
                    {
                        using var change = connection.CreateCommand();
                        change.CommandText = defect == "payload"
                            ? "UPDATE direct_text_outbox SET exact_dmc2=zeroblob(length(exact_dmc2)) WHERE operation_id=$operation;"
                            : "UPDATE direct_text_outbox SET sender_sequence=sender_sequence+1 WHERE operation_id=$operation;";
                        change.Parameters.AddWithValue("$operation", operation); Assert.Equal(1, change.ExecuteNonQuery());
                    });
                };
                var error = await Record.ExceptionAsync(() => SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default));
                Assert.True(hit, "The exact final combined app/native inventory callback did not run.");
                Assert.True(error is InvalidDataException or CryptographicException or FormatException,
                    "A native-only final read reused stale authored application permission: " + (error?.GetType().Name ?? "none"));
                using var after = await storage.ReadOwnedBatchAsync(slots);
                for (var i = 0; i < slots.Length; i++)
                    Assert.Equal(protectedBefore[i]!.Use(bytes => SHA256.HashData(bytes)), after[i]!.Use(bytes => SHA256.HashData(bytes)));
                Assert.Equal(nativeBefore, await ArchiveOriginalFingerprint(scope));
                Assert.Equal(archiveBefore, await CaptureCompactionArchiveStorage(scope));
            }
            finally
            {
                storage.AfterPairedArchivePrefixReadGroup = null;
                writer.Execute(connection =>
                {
                    using var restore = connection.CreateCommand();
                    restore.CommandText = "UPDATE direct_text_outbox SET sender_sequence=$sequence,exact_dmc2=$exact WHERE operation_id=$operation;";
                    restore.Parameters.AddWithValue("$sequence", authored[5]); restore.Parameters.AddWithValue("$exact", authored[8]);
                    restore.Parameters.AddWithValue("$operation", operation); Assert.Equal(1, restore.ExecuteNonQuery());
                });
                foreach (var bytes in authored.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
                CryptographicOperations.ZeroMemory(operation); CryptographicOperations.ZeroMemory(nativeBefore); CryptographicOperations.ZeroMemory(archiveBefore);
            }
            ColdReopenCompactionStorage(); await SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
            await AssertSenderCompactionIdle(scope);
        }

        private async Task<ArchiveExternalWriter> ArchiveAuthoredFixtureWriter(Did2MessagingSessionScope scope)
        {
            using var registration = await SqliteDeepIdV2AccountGeneration.ReadCompactionRegistrationUnderLeaseAsync(storage,
                scope.Network.ToArray(), scope.LocalAccount.ToArray(), default);
            var key = registration.Use(record =>
            {
                var domain = "Deep/STORE-V2/application-state-key"u8;
                var context = new byte[domain.Length + 1 + 80];
                try
                {
                    domain.CopyTo(context); record.Slice(8, 48).CopyTo(context.AsSpan(domain.Length + 1));
                    record.Slice(56, 32).CopyTo(context.AsSpan(domain.Length + 49));
                    return HMACSHA256.HashData(record.Slice(88, 32), context);
                }
                finally { CryptographicOperations.ZeroMemory(context); }
            });
            return new ArchiveExternalWriter(Path.Combine(directory, "deep-store-v2-account.dsv2.application.dmb1"), key);
        }

        internal async Task CheckChangedArchiveAuthoredSource(Did2MessagingSessionScope scope, ArchiveSourceObservation original, string defect)
        {
            byte[] operation = [];
            await WithArchiveFixtureSql(scope, connection =>
            {
                using var read = connection.CreateCommand(); read.CommandText = "SELECT operation FROM events WHERE direction=1 ORDER BY ordinal LIMIT 1;";
                operation = Assert.IsType<byte[]>(read.ExecuteScalar());
            });
            var authored = await CaptureOrdinaryWorkingRow(scope, operation);
            using var protectedBefore = await storage.ReadOwnedBatchAsync([ProtectedDid2MessagingSessionCatalog.Slot,
                ProtectedDid2MessagingArchiveEnrollment.Slot]);
            try
            {
                await WithAuthoredApplicationConnectionAsync(scope, connection =>
                {
                    using var change = connection.CreateCommand();
                    change.CommandText = defect == "payload" ?
                        "UPDATE direct_text_outbox SET exact_dmc2=zeroblob(length(exact_dmc2)) WHERE operation_id=$operation;" :
                        "UPDATE direct_text_outbox SET sender_sequence=sender_sequence+1 WHERE operation_id=$operation;";
                    change.Parameters.AddWithValue("$operation", operation); Assert.Equal(1, change.ExecuteNonQuery());
                });
                var error = await Record.ExceptionAsync(() => EnrollArchiveAccount());
                Assert.True(error is InvalidDataException or CryptographicException or FormatException,
                    "Outgoing classification trusted DPE2 metadata over independently authored originals: " + (error?.GetType().Name ?? "none"));
                await AssertArchiveSourceUnchanged(original);
                using var after = await storage.ReadOwnedBatchAsync([ProtectedDid2MessagingSessionCatalog.Slot,
                    ProtectedDid2MessagingArchiveEnrollment.Slot]);
                for (var index = 0; index < 2; index++)
                {
                    var expected = protectedBefore[index]!.Use(bytes => SHA256.HashData(bytes));
                    Assert.True(after[index]!.Use(bytes => SHA256.HashData(bytes).AsSpan().SequenceEqual(expected)),
                        "Rejected authored source advanced enrollment custody.");
                }
                await WithArchiveFixtureSql(scope, connection =>
                { using var version = connection.CreateCommand(); version.CommandText = "PRAGMA user_version;"; Assert.Equal(5L, Convert.ToInt64(version.ExecuteScalar())); });
                using var absent = await storage.ReadOwnedAsync(Did2MessagingArchiveRoot.Slot(scope)); Assert.Null(absent);
            }
            finally
            {
                // Restore only the exact test's prior source cells. Production
                // enrollment never repairs or derives them from native metadata.
                await WithAuthoredApplicationConnectionAsync(scope, connection =>
                {
                    using var restore = connection.CreateCommand();
                    restore.CommandText = "UPDATE direct_text_outbox SET sender_sequence=$sequence,exact_dmc2=$exact WHERE operation_id=$operation;";
                    restore.Parameters.AddWithValue("$sequence", authored[5]); restore.Parameters.AddWithValue("$exact", authored[8]);
                    restore.Parameters.AddWithValue("$operation", operation); Assert.Equal(1, restore.ExecuteNonQuery());
                });
                foreach (var bytes in authored.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
                CryptographicOperations.ZeroMemory(operation);
            }
        }
    }
}
