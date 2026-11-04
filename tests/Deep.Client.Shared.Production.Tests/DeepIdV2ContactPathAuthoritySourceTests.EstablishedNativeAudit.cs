using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2EstablishedNative_ColdAuditKeepsGenuineEmptyOrCancelledInitialSeparateFromEstablishedSend(bool cancelled)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, _) = await fixture.PrepareActiveNativePair();
        await fixture.CheckMixedInitialColdAudit(sender, cancelled);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2EstablishedNative_ColdAuditRejectsUnselectedEstablishedArchiveCorruptionBeforeAuthoring()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, _) = await fixture.PrepareActiveNativePair();
        await fixture.CheckUnselectedEstablishedArchiveColdAudit(sender);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckMixedInitialColdAudit(Did2MessagingSessionScope established, bool cancelled)
        {
            var intent = Bytes(32, 0xdb);
            var prepared = await PrepareNativeHelloCompletion(intent, oneTimeIndex: 0);
            var initial = await RegisterEmptySenderForCancellation(intent, prepared.Init, prepared.Hello, prepared.Complete, initialize: true);
            if (cancelled) await CancelPreSessionInitial(intent);
            var initialBefore = await ReadMessagingFloor(initial);
            Assert.Equal(Did2MessagingFloor.Empty(initial).Exact.ToArray(), initialBefore.Exact.ToArray());
            var establishedBefore = await ReadMessagingFloor(established);
            DropNativeRuntimes(); RetainNativeRuntimes();
            var callback = false;
            storage.AfterMessagingRegistrationReadGroup = () => callback = true;
            try
            {
                using var senderSource = new FileStream(SqliteDeepIdV2AccountGeneration.DeviceStatePath(
                    Path.Combine(directory, "deep-store-v2-account.dsv2")), FileMode.Open, FileAccess.Read, FileShare.None);
                using var receiverSource = new FileStream(SqliteDeepIdV2AccountGeneration.PreKeyStatePath(
                    Path.Combine(directory, "peer", "deep-store-v2-account.dsv2")), FileMode.Open, FileAccess.Read, FileShare.None);
                using var work = Did2MessagingSqlJournal.NativeWork.Measure();
                using var command = await CreateOwnedText(established, "mixed established and Initial custody");
                using var sent = await SendOwnedMessage(established, command.OperationId, ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span));
                Assert.Equal(SHA256.HashData(command.ExactDmc2.Span), sent.EventHash.ToArray());
                Assert.True(callback, "The actual native protected inventory must be read after the managed cold reopen.");
                Assert.Equal(1, work.Audits);
                var establishedAfter = await ReadMessagingFloor(established);
                Assert.Equal(establishedBefore.Ordinal + 1, establishedAfter.Ordinal);
                Assert.Equal(establishedBefore.RatchetGeneration + 1, establishedAfter.RatchetGeneration);
                Assert.Equal(initialBefore.Exact.ToArray(), (await ReadMessagingFloor(initial)).Exact.ToArray());
                using var writer = await ArchiveFixtureWriter(initial);
                writer.Execute(connection =>
                {
                    using var count = connection.CreateCommand();
                    count.CommandText = "SELECT count(*) FROM initial_events;"; Assert.Equal(0L, Convert.ToInt64(count.ExecuteScalar()));
                    count.CommandText = "SELECT count(*) FROM journal;"; Assert.Equal(0L, Convert.ToInt64(count.ExecuteScalar()));
                });
            }
            finally { storage.AfterMessagingRegistrationReadGroup = null; }
        }

        internal async Task CheckUnselectedEstablishedArchiveColdAudit(Did2MessagingSessionScope requested)
        {
            // A genuine second one-time-prekey relationship includes original
            // Accept/text events, so its archived tree has real proof nodes.
            // Import/activation alone would leave the sender's fact tree empty.
            var other = (await PrepareArchiveEnrollmentPair(0)).Sender;
            Assert.True((await ReadMessagingFloor(other)).Ordinal > 2);
            await ArchiveEntireEligibleSuffix(other);
            var requestedBefore = (await ReadMessagingFloor(requested)).Exact.ToArray();
            var applicationBefore = await ReadCompleteOrdinaryApplicationProjection(requested);
            var protectedBefore = await ReadCompletedContactSendRetainedRoots(requested);
            var otherArchiveBefore = (await ReadNativeArchive(other)).Exact.ToArray();
            using var writer = await ArchiveFixtureWriter(other);
            byte[] nodeHash = [], originalNode = [], damagedNode = [];
            writer.Execute(connection =>
            {
                using var read = connection.CreateCommand(); read.CommandText = "SELECT hash,exact FROM archive_nodes ORDER BY hash LIMIT 1;";
                using (var row = read.ExecuteReader())
                {
                    Assert.True(row.Read(), "The genuine unselected scope must have an actual archived proof node.");
                    nodeHash = row.GetFieldValue<byte[]>(0); originalNode = row.GetFieldValue<byte[]>(1); Assert.False(row.Read());
                }
                damagedNode = originalNode.ToArray(); damagedNode[^1] ^= 1;
                using var change = connection.CreateCommand(); change.CommandText = "UPDATE archive_nodes SET exact=$exact WHERE hash=$hash;";
                change.Parameters.AddWithValue("$exact", damagedNode); change.Parameters.AddWithValue("$hash", nodeHash);
                Assert.Equal(1, change.ExecuteNonQuery());
            });
            DropNativeRuntimes(); RetainNativeRuntimes();
            try
            {
                using var senderSource = new FileStream(SqliteDeepIdV2AccountGeneration.DeviceStatePath(
                    Path.Combine(directory, "deep-store-v2-account.dsv2")), FileMode.Open, FileAccess.Read, FileShare.None);
                using var receiverSource = new FileStream(SqliteDeepIdV2AccountGeneration.PreKeyStatePath(
                    Path.Combine(directory, "peer", "deep-store-v2-account.dsv2")), FileMode.Open, FileAccess.Read, FileShare.None);
                using var work = Did2MessagingSqlJournal.NativeWork.Measure();
                var error = await Record.ExceptionAsync(async () =>
                {
                    using var command = await CreateOwnedText(requested, "unselected corrupt archive cannot authorize new work");
                });
                Assert.True(error is CryptographicException or InvalidDataException or FormatException,
                    "Cold admission must audit the other established archive, without opening original SQL: " + error?.GetType().Name);
                Assert.Equal(0, work.Audits); // A failed audit cannot become a successful scheduling record.
                Assert.Equal(requestedBefore, (await ReadMessagingFloor(requested)).Exact.ToArray());
                Assert.Equal(applicationBefore, await ReadCompleteOrdinaryApplicationProjection(requested));
                Assert.Equal(protectedBefore, await ReadCompletedContactSendRetainedRoots(requested));
                Assert.Equal(otherArchiveBefore, (await ReadNativeArchive(other)).Exact.ToArray());
            }
            finally
            {
                writer.Execute(connection =>
                {
                    using var restore = connection.CreateCommand(); restore.CommandText = "UPDATE archive_nodes SET exact=$exact WHERE hash=$hash AND exact=$damaged;";
                    restore.Parameters.AddWithValue("$exact", originalNode); restore.Parameters.AddWithValue("$hash", nodeHash);
                    restore.Parameters.AddWithValue("$damaged", damagedNode); Assert.Equal(1, restore.ExecuteNonQuery());
                });
                foreach (var bytes in new[] { nodeHash, originalNode, damagedNode, requestedBefore, applicationBefore, protectedBefore, otherArchiveBefore })
                    CryptographicOperations.ZeroMemory(bytes);
            }
            DropNativeRuntimes();
            using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
            using (var command = await CreateOwnedText(requested, "exact archive restore permits fresh cold audit"))
            using (var sent = await SendOwnedMessage(requested, command.OperationId, ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span)))
            {
                Assert.Equal(SHA256.HashData(command.ExactDmc2.Span), sent.EventHash.ToArray());
                Assert.Equal(1, work.Audits);
            }
        }
    }
}
