using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Tests.ContactV1;

public sealed class SqliteXpk1ClaimJournalTests
{
    [Fact]
    public async Task ExactRetryAndTerminalFailureSurviveRestart()
    {
        using var fixture = new Fixture();
        var exact = Request(0x21, 0x41);
        var terminal = Xpc1Codec.Encode(
            exact,
            Xpc1Status.Expired,
            ContactServiceMutationOutcome.None,
            1_050,
            0,
            ContactServicePaddingClass.Bytes256,
            []);

        using (var store = fixture.Open())
        {
            var staged = await store.StageAsync(exact);
            Assert.Equal(Xpk1ClaimJournalDisposition.Staged, staged.Disposition);
            Assert.Equal(1UL, staged.Revision);
            var lease = Assert.IsType<PreKeyV1DurableClaimOperation>(
                staged.TryCreateDispatchOperation());

            var recorded = await store.RecordFailureAsync(lease, terminal);
            Assert.Equal(Xpk1ClaimJournalDisposition.ResultRecorded, recorded.Disposition);
            Assert.Equal(2UL, recorded.Revision);
            Assert.True(recorded.State.IsTerminal);
            Assert.Null(recorded.TryCreateDispatchOperation());
        }

        using (var reopened = fixture.Open())
        {
            var replay = await reopened.StageAsync(exact);
            Assert.Equal(Xpk1ClaimJournalDisposition.TerminalExactReplay, replay.Disposition);
            Assert.Equal(2UL, replay.Revision);
            Assert.Equal(terminal, replay.StoredResultWire.ToArray());
            Assert.Null(replay.TryCreateDispatchOperation());
        }
    }

    [Fact]
    public async Task SameOperationByteDriftForkLatchesDurably()
    {
        using var fixture = new Fixture();
        var exact = Request(0x31, 0x51);
        var drifted = Request(0x31, 0x52);

        using (var store = fixture.Open())
        {
            _ = await store.StageAsync(exact);
            var fork = await store.StageAsync(drifted);
            Assert.Equal(Xpk1ClaimJournalDisposition.ForkLatched, fork.Disposition);
            Assert.Equal(2UL, fork.Revision);
            Assert.True(fork.State.IsForkLatched);
            Assert.Null(fork.TryCreateDispatchOperation());
        }

        using (var reopened = fixture.Open())
        {
            var fork = await reopened.StageAsync(exact);
            Assert.Equal(Xpk1ClaimJournalDisposition.ForkLatched, fork.Disposition);
            Assert.Equal(2UL, fork.Revision);
            Assert.True(fork.State.IsForkLatched);
        }
    }

    [Fact]
    public void JournalRejectsAnotherAccountScopeOnRestart()
    {
        using var fixture = new Fixture();
        using (fixture.Open()) { }

        using var options = new SqliteXpk1ClaimJournalOptions(
            fixture.Path,
            fixture.Key,
            Scope(0x72));
        var error = Assert.Throws<ContactStateStoreOpenException>(() =>
            new SqliteXpk1ClaimJournal(options));
        Assert.Equal(ContactStateStoreOpenFailure.ScopeMismatch, error.Reason);
    }

    private static byte[] Request(byte operationMarker, byte viewMarker) =>
        Xpk1Codec.Encode(
            Bytes(16, 0x11),
            Bytes(32, operationMarker),
            Bytes(32, viewMarker),
            Bytes(32, 0x41),
            1_000,
            1_100,
            Bytes(32, 0x51),
            Bytes(32, 0x61),
            Bytes(32, 0x71),
            Bytes(32, 0x81),
            Bytes(32, 0x91));

    private static ContactStoreScope Scope(byte marker) =>
        ContactStoreScope.ForCurrentAccount(
            DeepAccountIdentityCapability.FromVerifiedInputs(
                DeepNetworkId16.FromVerifiedBytes(Bytes(16, 0x11)),
                1,
                AccountEd25519PublicKey32.FromVerifiedBytes(Bytes(32, marker)))
            .AccountId);

    private static byte[] Bytes(int length, byte marker) =>
        Enumerable.Repeat(marker, length).ToArray();

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            "deep-xpk1-journal-" + Guid.NewGuid().ToString("N"));

        internal Fixture() => Directory.CreateDirectory(directory);
        internal string Path => System.IO.Path.Combine(directory, "claims.xcj1");
        internal byte[] Key { get; } = Bytes(32, 0xa1);

        internal SqliteXpk1ClaimJournal Open()
        {
            using var options = new SqliteXpk1ClaimJournalOptions(Path, Key, Scope(0x71));
            return new SqliteXpk1ClaimJournal(options);
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Key);
            Directory.Delete(directory, recursive: true);
        }
    }
}
