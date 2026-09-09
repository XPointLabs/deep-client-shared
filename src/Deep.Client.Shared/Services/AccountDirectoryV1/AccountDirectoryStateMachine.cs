using System.Security.Cryptography;
using Deep.Client.Shared.Domain.AccountDirectoryV1;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Client.Shared.Services.AccountDirectoryV1;

internal sealed class AccountDirectoryVerifiedUpdate
{
    private readonly byte[] callerLkgHash;
    internal AccountDirectoryVerifiedUpdate(AccountDirectoryProtectedLkgState nextLkg,
        AccountDirectorySubjectState subject, bool hasCallerLkg, ulong callerLkgTreeSize,
        ReadOnlySpan<byte> callerLkgHash)
    {
        NextLkg = nextLkg; Subject = subject; HasCallerLkg = hasCallerLkg;
        CallerLkgTreeSize = callerLkgTreeSize;
        this.callerLkgHash = hasCallerLkg ? AccountDirectoryHash32.FromBytes(callerLkgHash).ToArray()
            : callerLkgHash.Length == 32 && callerLkgHash.IndexOfAnyExcept((byte)0) < 0
                ? callerLkgHash.ToArray()
                : throw new ArgumentException("No-LKG proof must carry ZERO32.", nameof(callerLkgHash));
    }
    internal AccountDirectoryProtectedLkgState NextLkg { get; }
    internal AccountDirectorySubjectState Subject { get; }
    internal bool HasCallerLkg { get; }
    internal ulong CallerLkgTreeSize { get; }
    internal ReadOnlySpan<byte> CallerLkgHash => callerLkgHash;

    internal static AccountDirectoryVerifiedUpdate FromVerified(VerifiedAccountDirectoryFreshness verified,
        AccountDirectoryAuthorizationId32? authorizationId, AccountDirectoryDeviceId32? deviceId)
    {
        ArgumentNullException.ThrowIfNull(verified);
        var proof = AccountDirectoryAdp1Codec.Decode(verified.ExactAdp1.Span);
        var checkpoint = verified.CurrentCheckpoint;
        var state = AccountDirectoryClientState.Current;
        var reason = AccountDirectoryRefreshReason.None;
        var accountGeneration = 0UL; var directoryGeneration = 0UL;
        if (verified.ResultKind == AccountDirectoryAdp1ResultKind.NonMembership)
        { state = AccountDirectoryClientState.RevocationRefreshRequired; reason = AccountDirectoryRefreshReason.NonMembership; }
        else if (checkpoint is null)
            throw new InvalidOperationException("A verified CurrentValue has no verified ADC1 closure.");
        else
        {
            accountGeneration = checkpoint.Checkpoint.AccountGeneration;
            directoryGeneration = checkpoint.Directory.Record.DirectoryGeneration;
            var revokedAuthorization = authorizationId is not null
                && checkpoint.IsDcaAuthorizationRevoked(authorizationId.Span);
            var missingDevice = deviceId is not null && !checkpoint.Directory.Record.ActiveDevices.Any(entry =>
                CryptographicOperations.FixedTimeEquals(entry.DeviceId.Span, deviceId.Span));
            if (revokedAuthorization || missingDevice) state = AccountDirectoryClientState.RevokedAuthorization;
        }
        var subject = new AccountDirectorySubjectState(
            AccountDirectoryLeafKey32.FromBytes(verified.DirectoryLeafKey.Span), state, reason,
            verified.ExactAdc1Reference.Span, accountGeneration, directoryGeneration, verified.BootId.Span,
            verified.MonotonicSample, verified.FreshnessDeadlineMonotonicSeconds, authorizationId, deviceId);
        return new(AccountDirectoryProtectedLkgState.FromVerified(verified), subject, proof.HasLkg,
            proof.CallerLkgTreeSize, proof.CallerLkgAdh1CoreHash.Span);
    }
}

internal static class AccountDirectoryStateMachine
{
    internal static AccountDirectoryStateSnapshot ApplyVerified(AccountDirectoryStateSnapshot? current,
        AccountDirectoryVerifiedUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        if (current?.ForkLatched == true) return current;
        if (!BindsProtectedLkg(current?.ProtectedLkg, update))
            return current is null ? LatchFork(null, update.NextLkg, update.Subject)
                : RequireRefreshForBindingMismatch(current, update.Subject);
        if (!IsMonotonic(current?.ProtectedLkg, update.NextLkg))
            return LatchFork(current, update.NextLkg, update.Subject);

        var subjects = (current?.Subjects ?? []).Where(item => !item.LeafKey.Equals(update.Subject.LeafKey)).ToList();
        var prior = current?.Find(update.Subject.LeafKey);
        subjects.Add(prior?.State == AccountDirectoryClientState.RevokedAuthorization
            && update.Subject.State != AccountDirectoryClientState.RevokedAuthorization ? prior : update.Subject);
        return Advance(current, update.NextLkg, false, subjects);
    }

    internal static AccountDirectoryStateSnapshot MarkRefreshRequired(AccountDirectoryStateSnapshot? current,
        AccountDirectoryLeafKey32 leafKey, AccountDirectoryRefreshReason reason)
    {
        ArgumentNullException.ThrowIfNull(leafKey);
        if (reason == AccountDirectoryRefreshReason.None) throw new ArgumentOutOfRangeException(nameof(reason));
        if (current is null) throw new InvalidOperationException("Cannot mark freshness before protected directory state exists.");
        if (current.ForkLatched) return Advance(current, current.ProtectedLkg, true, current.Subjects.Select(Block));
        var subject = current.Find(leafKey);
        if (subject is null || subject.State is AccountDirectoryClientState.RevokedAuthorization
            or AccountDirectoryClientState.DirectoryForkBlocked) return current;
        if (subject.State == AccountDirectoryClientState.RevocationRefreshRequired && subject.RefreshReason == reason)
            return current;
        var subjects = current.Subjects.Select(item => item.LeafKey.Equals(leafKey)
            ? item.WithState(AccountDirectoryClientState.RevocationRefreshRequired, reason) : item);
        return Advance(current, current.ProtectedLkg, false, subjects);
    }

    internal static AccountDirectoryStateSnapshot LatchFork(AccountDirectoryStateSnapshot? current,
        AccountDirectoryProtectedLkgState? candidate = null, AccountDirectorySubjectState? candidateSubject = null)
    {
        if (current is null)
        {
            if (candidate is null || candidateSubject is null) throw new InvalidOperationException("First fork evidence needs a candidate LKG and subject.");
            return new AccountDirectoryStateSnapshot(1, candidate, true, [Block(candidateSubject)]);
        }
        if (current.ForkLatched) return current;
        var subjects = current.Subjects.ToList();
        if (candidateSubject is not null && subjects.All(item => !item.LeafKey.Equals(candidateSubject.LeafKey))) subjects.Add(candidateSubject);
        return Advance(current, current.ProtectedLkg ?? candidate, true, subjects.Select(Block));
    }

    private static bool BindsProtectedLkg(AccountDirectoryProtectedLkgState? current,
        AccountDirectoryVerifiedUpdate update) => current is null
        ? !update.HasCallerLkg
        : update.HasCallerLkg && update.CallerLkgTreeSize == current.TreeSize
            && Fixed(update.CallerLkgHash, current.CoreHash.Span);

    private static AccountDirectoryStateSnapshot RequireRefreshForBindingMismatch(
        AccountDirectoryStateSnapshot current, AccountDirectorySubjectState candidate)
    {
        var present = false;
        var subjects = current.Subjects.Select(subject =>
        {
            if (subject.LeafKey.Equals(candidate.LeafKey)) present = true;
            return subject.State == AccountDirectoryClientState.Current
                ? subject.WithState(AccountDirectoryClientState.RevocationRefreshRequired,
                    AccountDirectoryRefreshReason.HigherGossipFloorObserved)
                : subject;
        }).ToList();
        if (!present) subjects.Add(candidate.WithState(AccountDirectoryClientState.RevocationRefreshRequired,
            AccountDirectoryRefreshReason.HigherGossipFloorObserved));
        return Advance(current, current.ProtectedLkg, false, subjects);
    }

    private static bool IsMonotonic(AccountDirectoryProtectedLkgState? current,
        AccountDirectoryProtectedLkgState next)
    {
        if (current is null) return true;
        if (next.LogGeneration < current.LogGeneration || next.TreeSize < current.TreeSize) return false;
        if (next.LogGeneration == current.LogGeneration)
            return next.TreeSize == current.TreeSize && Fixed(next.CoreHash.Span, current.CoreHash.Span)
                && Fixed(next.ExactAdh1.Span, current.ExactAdh1.Span);
        return true;
    }

    private static AccountDirectorySubjectState Block(AccountDirectorySubjectState subject) =>
        subject.WithState(AccountDirectoryClientState.DirectoryForkBlocked, AccountDirectoryRefreshReason.None);
    private static AccountDirectoryStateSnapshot Advance(AccountDirectoryStateSnapshot? current,
        AccountDirectoryProtectedLkgState? lkg, bool fork, IEnumerable<AccountDirectorySubjectState> subjects) =>
        new(current is null ? 1 : checked(current.Revision + 1), lkg, fork, subjects);
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
