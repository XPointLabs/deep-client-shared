namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task Did2PublicationArchive_LegitimateErasureRecoversColdAtEveryArchiveHandover(int handover)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        await fixture.CheckArchivedReadPathAsync(nonempty: false, handover: -1,
            archivePublication: true, archiveErasureHandover: handover);
    }

    [Fact]
    public async Task Did2PublicationArchive_OriginalObjectHorizonPinsArchiveAndHolderBeforeAnyErasure()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        await fixture.CheckArchivedReadPathAsync(nonempty: false, handover: -1,
            archivePublication: true, beforeHorizonOnly: true);
    }

    [Fact]
    public async Task Did2PublicationArchive_ErasureChecksExactGuardAndColdRetryPreservesNativeFence()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        await fixture.CheckArchivedReadPathAsync(nonempty: false, handover: -1,
            archivePublication: true, archiveErasureGuard: true);
    }

    [Fact]
    public async Task Did2PublicationArchive_AutomaticMaintenanceRetiresExactArchiveThroughOriginalOwner()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        await fixture.CheckArchivedReadPathAsync(nonempty: false, handover: -1,
            archivePublication: true, automaticMaintenance: true);
    }

    [Fact]
    public async Task Did2PublicationArchive_MissingOriginalCannotHideReintroducedTraversalDuringColdErasureCleanup()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        await fixture.CheckArchivedReadPathAsync(nonempty: false, handover: -1,
            archivePublication: true, archiveErasureHandover: 1, archiveMissingTraversal: true);
    }
}
