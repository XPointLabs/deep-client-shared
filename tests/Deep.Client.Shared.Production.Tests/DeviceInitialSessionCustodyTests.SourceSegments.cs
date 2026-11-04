using System.Security.Cryptography;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeviceInitialSessionCustodyTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task PendingSourceSegment_ClosesAndZerosBeforeStableCasAndColdRecovery(bool sqlAlreadyCommitted)
    {
        using var fixture = new Fixture();
        using (var initial = fixture.Open()) await fixture.Initialize(initial);
        var pending = fixture.Pending();
        Assert.True(await fixture.Storage.CompareExchangeAsync(DeviceInitialSessionCheckpoint.Slot,
            await fixture.ReadCheckpoint(), pending));
        var retirements = await ProtectedInitialKeyRetirementJournal.ReadAsync(fixture.Storage, Network, Account, default);
        byte[] stable = [];
        try
        {
            if (sqlAlreadyCommitted)
            {
                using var prior = fixture.OpenSourceSegment();
                stable = prior.RecoverMessagingSourceSegment(Network, pending, retirements);
            }
            var source = fixture.OpenSourceSegment();
            try
            {
                var proposal = source.RecoverMessagingSourceSegment(Network, pending, retirements);
                if (sqlAlreadyCommitted) Assert.Equal(stable, proposal);
                CryptographicOperations.ZeroMemory(stable); stable = proposal;
            }
            finally { source.Dispose(); }
            Assert.True(source.IsKeyZeroedForTesting);
            fixture.RequireClosedSource();
            // An interrupted protected write leaves exactly the original
            // pending checkpoint; another fresh SQL owner may finish it.
            fixture.Storage.FailNextStabilize = true;
            await Assert.ThrowsAsync<IOException>(() => fixture.Storage.CompareExchangeAsync(
                DeviceInitialSessionCheckpoint.Slot, pending, stable));
            Assert.Equal(pending, await fixture.ReadCheckpoint());
            using (var recovered = fixture.OpenSourceSegment())
                Assert.Equal(stable, recovered.RecoverMessagingSourceSegment(Network, pending, retirements));
            fixture.RequireClosedSource();
            Assert.True(await fixture.Storage.CompareExchangeAsync(DeviceInitialSessionCheckpoint.Slot, pending, stable));
            // Independent existing cold-custody reader is the recovery oracle.
            using (var cold = fixture.Open())
                await cold.OpenInitialSessionCustodyAsync(fixture.Storage, Network, default);
            Assert.Equal(fixture.Payload(), fixture.ReadPayload());
            Assert.Equal(1L, fixture.Count("device_initial_sessions"));
            Assert.Equal(1L, fixture.Count("device_agreement_authorizations"));
        }
        finally { CryptographicOperations.ZeroMemory(pending); CryptographicOperations.ZeroMemory(stable); }
    }

    private sealed partial class Fixture
    {
        internal SqliteDeviceStateStore OpenSourceSegment() =>
            SqliteDeviceStateStore.OpenMessagingSourceSegment(new(Path.Combine(directory, "device.db"), key,
                DeviceAccountId32.FromBytes(Account), 1, 1, DeviceOperationId32.FromBytes(Instance), allowCreate: false), readOnlySource: false);

        internal void RequireClosedSource()
        {
            using var file = new FileStream(Path.Combine(directory, "device.db"), FileMode.Open, FileAccess.Read, FileShare.None);
            Assert.True(file.Length > 0);
        }
    }
}
