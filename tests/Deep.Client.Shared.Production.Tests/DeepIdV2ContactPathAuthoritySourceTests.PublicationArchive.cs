using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2PublicationArchive_ArchivedOriginalRetrieveContinuationAndPollingSurviveColdOwner()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckOwnedRenewalAsync(interruptedRetrieve: true, pollRetainedPaths: true,
            archiveCompletedPublications: true);
    }

    [Fact]
    public async Task Did2PublicationArchive_ExplicitOldSourceEnrollmentPreservesOriginalsAndRenewsBeyondWorkingCapacity()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        await fixture.FillPublicationWorkingSetAsync();
        var originals = await fixture.PublicationOriginalsAsync();
        try
        {
            var before = await fixture.MakePublicationEnrollmentSourceAsync();
            try
            {
                await Assert.ThrowsAnyAsync<InvalidDataException>(() => fixture.ReopenAccount().GetCurrentAsync());
                Assert.Equal(before, await fixture.RouteSnapshot());
                var status = await fixture.ReopenAccount().EnrollPublicationArchiveAsync();
                Assert.True(status.ArchivedEntries > 0);
                Assert.True(status.CanReservePublication);
                Assert.True(status.ReservedWorkingBytes + 4 + ProtectedDid2ContactRouteJournal.MaximumEntryBytes <= status.MaximumWorkingBytes);
                await fixture.RequirePublicationOriginalsAsync(originals);
                var replay = new RenewalBackend(fixture);
                using var cold = fixture.ReopenAccount();
                var result = await cold.EnsureOwnPermanentContactPublishedAsync(fixture.Source(cold), replay, replay, replay);
                Assert.Equal(0, replay.RouteSignings); Assert.Equal(0, replay.PublicationSignings); Assert.Equal(0, replay.ReplicaCalls);
                Assert.NotEmpty(result.ExactXpo1.ToArray());
                await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 120);
                await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 120);
                await fixture.RequirePublicationOriginalsAsync(originals, currentMayAdvance: true);
            }
            finally { CryptographicOperations.ZeroMemory(before); }
        }
        finally { foreach (var bytes in originals.Values) CryptographicOperations.ZeroMemory(bytes); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2PublicationArchive_AtomicEnrollmentRejectsBeforeCommitAndRecoversAfterCommittedStop(bool committed)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        await fixture.SeedPublicationArchivePairAsync();
        var originals = await fixture.PublicationOriginalsAsync();
        var before = await fixture.MakePublicationEnrollmentSourceAsync();
        try
        {
            fixture.ConfigurePublicationArchiveFault(committed);
            var failure = await Record.ExceptionAsync(() => fixture.ReopenAccount().EnrollPublicationArchiveAsync());
            Assert.True(committed ? failure is IOException : failure is CryptographicException);
            var actual = await fixture.RouteSnapshot();
            try
            {
                Assert.Equal(committed ? (byte)11 : (byte)10, actual[0]);
                if (!committed) Assert.Equal(before, actual);
            }
            finally { CryptographicOperations.ZeroMemory(actual); }
            var status = await fixture.ReopenAccount().EnrollPublicationArchiveAsync();
            Assert.True(status.ArchivedEntries > 0); Assert.True(status.CanReservePublication);
            await fixture.RequirePublicationOriginalsAsync(originals);
            using var cold = fixture.ReopenAccount();
            Assert.NotNull(await cold.GetCurrentAsync());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(before);
            foreach (var bytes in originals.Values) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2PublicationArchive_MissingOrChangedOriginalFailsColdAdmissionAndCannotRepairFromWorkingRoot(bool corrupt)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        await fixture.SeedPublicationArchivePairAsync();
        await fixture.ReopenAccount().EnrollPublicationArchiveAsync();
        await fixture.DamagePublicationArchiveAsync(corrupt);
        var before = await fixture.RouteSnapshot();
        try
        {
            using var cold = fixture.ReopenAccount();
            var failure = await Record.ExceptionAsync(() => cold.GetCurrentAsync());
            Assert.True(failure is InvalidDataException or CryptographicException);
            var enrollmentFailure = await Record.ExceptionAsync(() => fixture.ReopenAccount().EnrollPublicationArchiveAsync());
            Assert.True(enrollmentFailure is InvalidDataException or CryptographicException);
            Assert.Equal(before, await fixture.RouteSnapshot());
        }
        finally { CryptographicOperations.ZeroMemory(before); }
    }

    private sealed partial class Fixture
    {
        internal async Task SeedPublicationArchivePairAsync()
        {
            var backend = new RenewalBackend(this, genesisRouteLifetimeSeconds: 120);
            await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend);
            await RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 120);
        }

        internal async Task FillPublicationWorkingSetAsync()
        {
            await SeedPublicationArchivePairAsync();
            for (var index = 0; index < 24; index++)
            {
                using var state = await RouteState();
                Assert.Empty(state.Archived);
                if (ProtectedDid2ContactRouteJournal.ReservedBytes(state) + 4 + ProtectedDid2ContactRouteJournal.MaximumEntryBytes >
                    ProtectedDid2ContactRouteJournal.MaximumBytes)
                { Assert.True(state.Entries.Count >= 3); return; }
                await RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 120);
            }
            throw new InvalidDataException("Genuine publications did not reach the original bounded working reservation.");
        }

        internal async Task<Dictionary<string, byte[]>> PublicationOriginalsAsync()
        {
            using var state = await RouteState();
            return state.Entries.ToDictionary(pair => pair.Key, pair => pair.Value.Exact.ToArray(), StringComparer.Ordinal);
        }

        internal async Task RequirePublicationOriginalsAsync(Dictionary<string, byte[]> originals, bool currentMayAdvance = false)
        {
            using var state = await RouteState();
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            var current = Convert.ToHexString(plan.Intent.Span);
            foreach (var pair in originals)
            {
                if (currentMayAdvance && pair.Key == current)
                {
                    Assert.Contains(state.Entries.Values, entry => entry.Exact[32..].SequenceEqual(pair.Value.AsSpan(32)));
                    continue;
                }
                Assert.True(state.Entries.TryGetValue(pair.Key, out var actual));
                Assert.True(actual!.Exact.SequenceEqual(pair.Value));
            }
        }

        internal async Task<byte[]> MakePublicationEnrollmentSourceAsync()
        {
            var current = await RouteSnapshot();
            try
            {
                Assert.Equal((byte)11, current[0]); Assert.Equal(0, current[1]);
                // The V10 historical writer's exact framing: same first92
                // bytes and entries, without V11's32-byte working-owner field.
                var old = new byte[current.Length - 32];
                current.AsSpan(0, 92).CopyTo(old); old[0] = 10;
                current.AsSpan(124).CopyTo(old.AsSpan(92));
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, current, old));
                return old;
            }
            finally { CryptographicOperations.ZeroMemory(current); }
        }

        internal void ConfigurePublicationArchiveFault(bool committed)
        {
            storage.RejectPublicationArchiveInsert = !committed;
            storage.StopAfterPublicationArchiveInsert = committed;
        }

        internal async Task DamagePublicationArchiveAsync(bool corrupt)
        {
            using var state = await RouteState();
            Assert.NotEmpty(state.Archived);
            using var generation = await innerStorage.ReadOwnedAsync("deep.store.v2.sql-generation");
            var instance = generation!.Use(bytes => bytes.Slice(56, 32).ToArray());
            try
            {
                var slot = ProtectedDid2ContactRouteJournal.ArchiveSlot(instance, state.Archived.First().Key);
                using var original = await innerStorage.ReadOwnedAsync(slot);
                Assert.NotNull(original);
                if (!corrupt) { await innerStorage.DeleteBatchAsync([slot]); return; }
                var damaged = original.Use(bytes => bytes.ToArray());
                try
                {
                    damaged[^1] ^= 1;
                    await innerStorage.DeleteBatchAsync([slot]);
                    await innerStorage.WriteBatchAsync([new DeepSecureStorageWrite(slot, damaged)]);
                }
                finally { CryptographicOperations.ZeroMemory(damaged); }
            }
            finally { CryptographicOperations.ZeroMemory(instance); }
        }
    }
}
