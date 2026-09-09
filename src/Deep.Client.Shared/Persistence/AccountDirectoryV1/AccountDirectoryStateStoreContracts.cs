using Deep.Client.Shared.Domain.AccountDirectoryV1;

namespace Deep.Client.Shared.Persistence.AccountDirectoryV1;

public enum AccountDirectoryStoreWriteDisposition { Applied = 1, Conflict = 2 }

public sealed record AccountDirectoryStoreWriteResult(
    AccountDirectoryStoreWriteDisposition Disposition,
    AccountDirectoryStateSnapshot? Snapshot);

public interface IAccountDirectoryStateStore
{
    ValueTask<AccountDirectoryStateSnapshot?> ReadAsync(CancellationToken cancellationToken);
    ValueTask<AccountDirectoryStoreWriteResult> CompareExchangeAsync(ulong? expectedRevision,
        AccountDirectoryStateSnapshot replacement, CancellationToken cancellationToken);
}

internal static class AccountDirectoryStateCloner
{
    internal static AccountDirectoryStateSnapshot? Clone(AccountDirectoryStateSnapshot? snapshot)
    {
        if (snapshot is null) return null;
        var lkg = snapshot.ProtectedLkg is null ? null : AccountDirectoryProtectedLkgState.RestorePersisted(
            snapshot.ProtectedLkg.ExactAdh1.Span, snapshot.ProtectedLkg.CoreHash.Span,
            snapshot.ProtectedLkg.LogGeneration, snapshot.ProtectedLkg.TreeSize);
        return new AccountDirectoryStateSnapshot(snapshot.Revision, lkg, snapshot.ForkLatched,
            snapshot.Subjects.Select(CloneSubject));
    }

    internal static AccountDirectorySubjectState CloneSubject(AccountDirectorySubjectState subject) => new(
        AccountDirectoryLeafKey32.FromBytes(subject.LeafKey.Span), subject.State, subject.RefreshReason,
        subject.ExactAdc1Reference.Span, subject.AccountGeneration, subject.DirectoryGeneration,
        subject.BootId.Span, subject.VerifiedAtMonotonic, subject.FreshnessDeadlineMonotonic,
        subject.AuthorizationId is null ? null : AccountDirectoryAuthorizationId32.FromBytes(subject.AuthorizationId.Span),
        subject.DeviceId is null ? null : AccountDirectoryDeviceId32.FromBytes(subject.DeviceId.Span));
}
