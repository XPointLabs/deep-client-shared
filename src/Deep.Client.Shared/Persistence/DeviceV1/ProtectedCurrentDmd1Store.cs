using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV1;

public interface IProtectedCurrentDmd1Store
{
    ValueTask<ProtectedCurrentDmd1CommitResult> CommitCurrentDmd1Async(
        DeviceOperationId32 operationId,
        Dmd1LineageState verifiedCandidate,
        CancellationToken cancellationToken);

    ValueTask<ProtectedDeviceAgreementAuthorizationResult> AuthorizeDeviceAgreementAsync(
        DeviceOperationId32 operationId,
        Dmd1LineageState verifiedCurrent,
        LocalDeviceX25519AgreementAuthority authority,
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlyMemory<byte> operationBinding,
        ReadOnlyMemory<byte> peerPublicKey,
        CancellationToken cancellationToken);
}

public sealed partial class SqliteDeviceStateStore
{
    public ValueTask<ProtectedCurrentDmd1CommitResult> CommitCurrentDmd1Async(
        DeviceOperationId32 operationId,
        Dmd1LineageState verifiedCandidate,
        CancellationToken cancellationToken) =>
        CommitCurrentDmd1CoreAsync(
            operationId,
            CurrentDmd1Evidence.FromVerified(verifiedCandidate),
            cancellationToken);

    public ValueTask<ProtectedDeviceAgreementAuthorizationResult> AuthorizeDeviceAgreementAsync(
        DeviceOperationId32 operationId,
        Dmd1LineageState verifiedCurrent,
        LocalDeviceX25519AgreementAuthority authority,
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlyMemory<byte> operationBinding,
        ReadOnlyMemory<byte> peerPublicKey,
        CancellationToken cancellationToken) =>
        AuthorizeDeviceAgreementCoreAsync(
            operationId,
            CurrentDmd1Evidence.FromVerified(verifiedCurrent),
            LocalDeviceAgreementBinding.FromAuthority(authority),
            purpose,
            operationBinding,
            peerPublicKey,
            cancellationToken);

#if DEEP_TEST_INTERNALS
    internal ValueTask<ProtectedCurrentDmd1CommitResult> CommitCurrentDmd1ForTestingAsync(
        DeviceOperationId32 operationId,
        CurrentDmd1Evidence evidence,
        CancellationToken cancellationToken) =>
        CommitCurrentDmd1CoreAsync(operationId, evidence, cancellationToken);

    internal ValueTask<ProtectedDeviceAgreementAuthorizationResult> AuthorizeDeviceAgreementForTestingAsync(
        DeviceOperationId32 operationId,
        CurrentDmd1Evidence evidence,
        LocalDeviceAgreementBinding device,
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlyMemory<byte> operationBinding,
        ReadOnlyMemory<byte> peerPublicKey,
        CancellationToken cancellationToken) =>
        AuthorizeDeviceAgreementCoreAsync(
            operationId, evidence, device, purpose, operationBinding, peerPublicKey, cancellationToken);
#endif

    private async ValueTask<ProtectedCurrentDmd1CommitResult> CommitCurrentDmd1CoreAsync(
        DeviceOperationId32 operationId,
        CurrentDmd1Evidence evidence,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operationId);
        ArgumentNullException.ThrowIfNull(evidence);
        using var lease = EnterOperation();
        if (!InScope(DeviceAccountId32.FromBytes(evidence.AccountId.Span), evidence.AccountGeneration))
            return Result(ProtectedCurrentDmd1CommitDisposition.Conflict, evidence);
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            var db = GetConnection();
            await using var transaction = db.BeginTransaction(deferred: false);
            var fingerprint = ProtectedCurrentDmd1Validation.FingerprintInstall(evidence);
            var priorFingerprint = ReadOperation(db, transaction, operationId);
            if (priorFingerprint is not null)
            {
                transaction.Commit();
                return Result(FixedEquals(priorFingerprint, fingerprint)
                    ? ProtectedCurrentDmd1CommitDisposition.ExactReplay
                    : ProtectedCurrentDmd1CommitDisposition.Conflict, evidence);
            }

            var current = ReadSnapshot(db, transaction);
            var prior = ReadProtectedDmd1(db, transaction);
            var transition = ProtectedCurrentDmd1StateMachine.Apply(current, prior, evidence);
            if (transition.Snapshot is not null && !ReferenceEquals(transition.Snapshot, current))
                WriteSnapshot(db, transaction, current?.Revision, transition.Snapshot);
            if (transition.Disposition is ProtectedCurrentDmd1CommitDisposition.Applied or
                ProtectedCurrentDmd1CommitDisposition.ExactReplay)
                WriteProtectedDmd1(db, transaction, evidence);
            if (transition.Disposition is ProtectedCurrentDmd1CommitDisposition.Applied or
                ProtectedCurrentDmd1CommitDisposition.ExactReplay or
                ProtectedCurrentDmd1CommitDisposition.ForkLatched)
            {
                InsertOperation(db, transaction, operationId, fingerprint);
            }
            DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.BeforeCommit);
            transaction.Commit();
            return Result(transition.Disposition, evidence);
        }
        finally
        {
            if (entered)
                gate.Release();
        }
    }

    private async ValueTask<ProtectedDeviceAgreementAuthorizationResult> AuthorizeDeviceAgreementCoreAsync(
        DeviceOperationId32 operationId,
        CurrentDmd1Evidence evidence,
        LocalDeviceAgreementBinding device,
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlyMemory<byte> operationBinding,
        ReadOnlyMemory<byte> peerPublicKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operationId);
        ProtectedCurrentDmd1Validation.ValidateAgreementInputs(
            purpose, operationBinding.Span, peerPublicKey.Span);
        using var lease = EnterOperation();
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            ThrowIfDisposed();
            var db = GetConnection();
            await using var transaction = db.BeginTransaction(deferred: false);
            var current = ReadSnapshot(db, transaction);
            var protectedCurrent = ReadProtectedDmd1(db, transaction);
            var disposition = ProtectedCurrentDmd1Validation.ValidateAuthorization(
                current, protectedCurrent, evidence, device);
            if (disposition != ProtectedDeviceAgreementDisposition.Granted)
            {
                transaction.Commit();
                return new ProtectedDeviceAgreementAuthorizationResult(disposition);
            }

            var fingerprint = ProtectedCurrentDmd1Validation.FingerprintAgreement(
                evidence, device, purpose, operationBinding.Span, peerPublicKey.Span);
            var priorFingerprint = ReadOperation(db, transaction, operationId);
            if (priorFingerprint is not null)
            {
                transaction.Commit();
                return new ProtectedDeviceAgreementAuthorizationResult(
                    FixedEquals(priorFingerprint, fingerprint)
                        ? ProtectedDeviceAgreementDisposition.AlreadyConsumed
                        : ProtectedDeviceAgreementDisposition.Conflict);
            }

            InsertOperation(db, transaction, operationId, fingerprint);
            InsertAgreementAuthorization(
                db, transaction, operationId, fingerprint, evidence, device, purpose,
                operationBinding.Span, peerPublicKey.Span);
            DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.BeforeAgreementAuthorizationCommit);
            transaction.Commit();
            return new ProtectedDeviceAgreementAuthorizationResult(
                ProtectedDeviceAgreementDisposition.Granted,
                new ProtectedDeviceAgreementAuthorization(
                    operationId, evidence, device, purpose, operationBinding.Span, peerPublicKey.Span));
        }
        finally
        {
            if (entered)
                gate.Release();
        }
    }

    private static CurrentDmd1Evidence? ReadProtectedDmd1(
        SqliteConnection db,
        SqliteTransaction? transaction)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT canonical_dmd1,drs_revision FROM protected_current_dmd1 WHERE singleton=1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return null;
        return CurrentDmd1Evidence.RestoreProtected(
            forkLatched: false,
            (byte[])reader[0],
            ReadU64((byte[])reader[1]));
    }

    private static void ValidateProtectedCurrentDmd1Semantics(
        SqliteConnection db,
        DeviceAccountStateSnapshot? snapshot)
    {
        var protectedCurrent = ReadProtectedDmd1(db, null);
        if (protectedCurrent is null)
        {
            if (ScalarLong(db, "SELECT COUNT(*) FROM device_agreement_authorizations;") != 0)
                throw new InvalidDataException(
                    "Device-agreement authorizations exist without a protected current DMD1.");
            return;
        }

        if (snapshot is null ||
            !snapshot.Directory.Head.AccountId.Span.SequenceEqual(protectedCurrent.AccountId.Span) ||
            snapshot.Directory.Head.AccountGeneration != protectedCurrent.AccountGeneration ||
            snapshot.Directory.Head.DirectoryGeneration != protectedCurrent.DirectoryGeneration ||
            !snapshot.Directory.Head.DirectoryHash.Span.SequenceEqual(protectedCurrent.DirectoryHash.Span) ||
            snapshot.Directory.Head.RevocationRevision != protectedCurrent.DrsRevision ||
            !snapshot.Directory.Head.RevocationHash.Span.SequenceEqual(protectedCurrent.DrsHash.Span))
        {
            throw new InvalidDataException(
                "Protected current DMD1 does not match the exact persisted directory head.");
        }

        var protectedDevices = protectedCurrent.Devices
            .Select(static value => $"{Convert.ToHexString(value.DeviceId.Span)}:{Convert.ToHexString(value.Dpd1Hash.Span)}")
            .OrderBy(static value => value, StringComparer.Ordinal);
        var stateDevices = snapshot.Directory.Head.ActiveDevices
            .Select(static value => $"{Convert.ToHexString(value.DeviceId.Span)}:{Convert.ToHexString(value.CertificateHash.Span)}")
            .OrderBy(static value => value, StringComparer.Ordinal);
        if (!protectedDevices.SequenceEqual(stateDevices, StringComparer.Ordinal))
            throw new InvalidDataException(
                "Protected current DMD1 active-device closure does not match persisted state.");

        using var command = db.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*)
            FROM device_agreement_authorizations AS authorization
            LEFT JOIN device_operation_dedup AS operation
              ON operation.operation_id=authorization.operation_id
             AND operation.fingerprint=authorization.fingerprint
            WHERE operation.operation_id IS NULL
               OR authorization.account_id!=$account
               OR authorization.account_generation!=$generation;
            """;
        Add(command, "$account", protectedCurrent.AccountId.ToArray());
        Add(command, "$generation", U64(protectedCurrent.AccountGeneration));
        if (Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) != 0)
            throw new InvalidDataException(
                "Persisted device-agreement authorization is detached from its operation burn or account scope.");
    }

    private static void WriteProtectedDmd1(
        SqliteConnection db,
        SqliteTransaction transaction,
        CurrentDmd1Evidence evidence)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO protected_current_dmd1(singleton,canonical_dmd1,drs_revision)
            VALUES(1,$canonical,$drs)
            ON CONFLICT(singleton) DO UPDATE SET canonical_dmd1=excluded.canonical_dmd1,drs_revision=excluded.drs_revision;
            """;
        Add(command, "$canonical", evidence.Canonical.ToArray());
        Add(command, "$drs", U64(evidence.DrsRevision));
        command.ExecuteNonQuery();
    }

    private static void InsertAgreementAuthorization(
        SqliteConnection db,
        SqliteTransaction transaction,
        DeviceOperationId32 operationId,
        string fingerprint,
        CurrentDmd1Evidence evidence,
        LocalDeviceAgreementBinding device,
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlySpan<byte> operationBinding,
        ReadOnlySpan<byte> peerPublicKey)
    {
        Insert(db, transaction, "INSERT INTO device_agreement_authorizations VALUES($o,$f,$dg,$dh,$a,$ag,$d,$g,$p,$u,$b,$k);",
            ("$o", operationId.ToArray()), ("$f", fingerprint),
            ("$dg", U64(evidence.DirectoryGeneration)), ("$dh", evidence.DirectoryHash.ToArray()),
            ("$a", evidence.AccountId.ToArray()), ("$ag", U64(evidence.AccountGeneration)),
            ("$d", device.DeviceId.ToArray()), ("$g", U64(device.DeviceGeneration)),
            ("$p", device.ExactDpd1Hash.ToArray()), ("$u", (int)purpose),
            ("$b", operationBinding.ToArray()), ("$k", peerPublicKey.ToArray()));
    }

    private static ProtectedCurrentDmd1CommitResult Result(
        ProtectedCurrentDmd1CommitDisposition disposition,
        CurrentDmd1Evidence evidence) =>
        new(disposition, evidence.DirectoryGeneration, evidence.DirectoryHash.Span);
}

public sealed partial class InMemoryDeviceStateStore
{
    private readonly Dictionary<string, CurrentDmd1Evidence> protectedCurrentDmd1 =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> agreementAuthorizations = new(StringComparer.Ordinal);

    public ValueTask<ProtectedCurrentDmd1CommitResult> CommitCurrentDmd1Async(
        DeviceOperationId32 operationId,
        Dmd1LineageState verifiedCandidate,
        CancellationToken cancellationToken) =>
        CommitCurrentDmd1CoreAsync(
            operationId, CurrentDmd1Evidence.FromVerified(verifiedCandidate), cancellationToken);

    public ValueTask<ProtectedDeviceAgreementAuthorizationResult> AuthorizeDeviceAgreementAsync(
        DeviceOperationId32 operationId,
        Dmd1LineageState verifiedCurrent,
        LocalDeviceX25519AgreementAuthority authority,
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlyMemory<byte> operationBinding,
        ReadOnlyMemory<byte> peerPublicKey,
        CancellationToken cancellationToken) =>
        AuthorizeDeviceAgreementCoreAsync(
            operationId, CurrentDmd1Evidence.FromVerified(verifiedCurrent),
            LocalDeviceAgreementBinding.FromAuthority(authority), purpose,
            operationBinding, peerPublicKey, cancellationToken);

#if DEEP_TEST_INTERNALS
    internal ValueTask<ProtectedCurrentDmd1CommitResult> CommitCurrentDmd1ForTestingAsync(
        DeviceOperationId32 operationId,
        CurrentDmd1Evidence evidence,
        CancellationToken cancellationToken) =>
        CommitCurrentDmd1CoreAsync(operationId, evidence, cancellationToken);

    internal ValueTask<ProtectedDeviceAgreementAuthorizationResult> AuthorizeDeviceAgreementForTestingAsync(
        DeviceOperationId32 operationId,
        CurrentDmd1Evidence evidence,
        LocalDeviceAgreementBinding device,
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlyMemory<byte> operationBinding,
        ReadOnlyMemory<byte> peerPublicKey,
        CancellationToken cancellationToken) =>
        AuthorizeDeviceAgreementCoreAsync(
            operationId, evidence, device, purpose, operationBinding, peerPublicKey, cancellationToken);
#endif

    private ValueTask<ProtectedCurrentDmd1CommitResult> CommitCurrentDmd1CoreAsync(
        DeviceOperationId32 operationId,
        CurrentDmd1Evidence evidence,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operationId);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            var stateKey = StateKey(evidence);
            var operationKey = OperationKey(stateKey, operationId);
            var fingerprint = ProtectedCurrentDmd1Validation.FingerprintInstall(evidence);
            if (operations.TryGetValue(operationKey, out var prior))
                return ValueTask.FromResult(new ProtectedCurrentDmd1CommitResult(
                    CryptographicEquals(prior, fingerprint)
                        ? ProtectedCurrentDmd1CommitDisposition.ExactReplay
                        : ProtectedCurrentDmd1CommitDisposition.Conflict,
                    evidence.DirectoryGeneration, evidence.DirectoryHash.Span));
            states.TryGetValue(stateKey, out var current);
            protectedCurrentDmd1.TryGetValue(stateKey, out var protectedCurrent);
            var transition = ProtectedCurrentDmd1StateMachine.Apply(current, protectedCurrent, evidence);
            if (transition.Snapshot is not null)
                states[stateKey] = transition.Snapshot;
            if (transition.Disposition is ProtectedCurrentDmd1CommitDisposition.Applied or
                ProtectedCurrentDmd1CommitDisposition.ExactReplay)
                protectedCurrentDmd1[stateKey] = evidence;
            if (transition.Disposition is ProtectedCurrentDmd1CommitDisposition.Applied or
                ProtectedCurrentDmd1CommitDisposition.ExactReplay or
                ProtectedCurrentDmd1CommitDisposition.ForkLatched)
            {
                operations.Add(operationKey, fingerprint);
            }
            return ValueTask.FromResult(new ProtectedCurrentDmd1CommitResult(
                transition.Disposition, evidence.DirectoryGeneration, evidence.DirectoryHash.Span));
        }
    }

    private ValueTask<ProtectedDeviceAgreementAuthorizationResult> AuthorizeDeviceAgreementCoreAsync(
        DeviceOperationId32 operationId,
        CurrentDmd1Evidence evidence,
        LocalDeviceAgreementBinding device,
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlyMemory<byte> operationBinding,
        ReadOnlyMemory<byte> peerPublicKey,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ProtectedCurrentDmd1Validation.ValidateAgreementInputs(
            purpose, operationBinding.Span, peerPublicKey.Span);
        lock (gate)
        {
            var stateKey = StateKey(evidence);
            states.TryGetValue(stateKey, out var current);
            protectedCurrentDmd1.TryGetValue(stateKey, out var protectedCurrent);
            var disposition = ProtectedCurrentDmd1Validation.ValidateAuthorization(
                current, protectedCurrent, evidence, device);
            if (disposition != ProtectedDeviceAgreementDisposition.Granted)
                return ValueTask.FromResult(new ProtectedDeviceAgreementAuthorizationResult(disposition));
            var operationKey = OperationKey(stateKey, operationId);
            var fingerprint = ProtectedCurrentDmd1Validation.FingerprintAgreement(
                evidence, device, purpose, operationBinding.Span, peerPublicKey.Span);
            if (operations.TryGetValue(operationKey, out var prior))
                return ValueTask.FromResult(new ProtectedDeviceAgreementAuthorizationResult(
                    CryptographicEquals(prior, fingerprint)
                        ? ProtectedDeviceAgreementDisposition.AlreadyConsumed
                        : ProtectedDeviceAgreementDisposition.Conflict));
            operations.Add(operationKey, fingerprint);
            agreementAuthorizations.Add(operationKey, fingerprint);
            return ValueTask.FromResult(new ProtectedDeviceAgreementAuthorizationResult(
                ProtectedDeviceAgreementDisposition.Granted,
                new ProtectedDeviceAgreementAuthorization(
                    operationId, evidence, device, purpose, operationBinding.Span, peerPublicKey.Span)));
        }
    }

    private static string StateKey(CurrentDmd1Evidence evidence) =>
        $"{Convert.ToHexString(evidence.AccountId.Span)}:{evidence.AccountGeneration}";

    private static string OperationKey(string stateKey, DeviceOperationId32 operationId) =>
        $"{stateKey}:{Convert.ToHexString(operationId.Span)}";
}

internal sealed class ProtectedCurrentDmd1Transition
{
    internal ProtectedCurrentDmd1Transition(
        ProtectedCurrentDmd1CommitDisposition disposition,
        DeviceAccountStateSnapshot? snapshot)
    {
        Disposition = disposition;
        Snapshot = snapshot;
    }

    internal ProtectedCurrentDmd1CommitDisposition Disposition { get; }
    internal DeviceAccountStateSnapshot? Snapshot { get; }
}

internal static class ProtectedCurrentDmd1StateMachine
{
    internal static ProtectedCurrentDmd1Transition Apply(
        DeviceAccountStateSnapshot? current,
        CurrentDmd1Evidence? protectedCurrent,
        CurrentDmd1Evidence candidate)
    {
        if (current is null)
        {
            if (candidate.ForkLatched)
            {
                try
                {
                    var forked = DeviceDirectoryState.Restore(
                        DeviceDirectoryState.Start(candidate.DirectoryFacts).Next.Head,
                        forkLatched: true,
                        []);
                    return new(ProtectedCurrentDmd1CommitDisposition.ForkLatched,
                        new DeviceAccountStateSnapshot(1, forked, []));
                }
                catch (InvalidOperationException)
                {
                    return new(ProtectedCurrentDmd1CommitDisposition.InvalidLineage, null);
                }
            }
            try
            {
                var directory = DeviceDirectoryState.Start(candidate.DirectoryFacts).Next;
                return new(ProtectedCurrentDmd1CommitDisposition.Applied,
                    new DeviceAccountStateSnapshot(1, directory, []));
            }
            catch (InvalidOperationException)
            {
                return new(ProtectedCurrentDmd1CommitDisposition.InvalidLineage, null);
            }
        }

        if (current.Directory.ForkLatched || candidate.ForkLatched)
            return new(ProtectedCurrentDmd1CommitDisposition.ForkLatched,
                Latch(current));
        if (protectedCurrent is not null &&
            protectedCurrent.DirectoryGeneration == candidate.DirectoryGeneration &&
            protectedCurrent.DirectoryHash.Span.SequenceEqual(candidate.DirectoryHash.Span) &&
            !protectedCurrent.Canonical.Span.SequenceEqual(candidate.Canonical.Span))
            return new(ProtectedCurrentDmd1CommitDisposition.ForkLatched,
                Latch(current));

        var transition = current.Directory.PrepareTransition(candidate.DirectoryFacts);
        return transition.Disposition switch
        {
            DeviceDirectoryTransitionDisposition.AcceptedSuccessor =>
                new(ProtectedCurrentDmd1CommitDisposition.Applied,
                    Copy(current, transition.Next)),
            DeviceDirectoryTransitionDisposition.ExactReplay =>
                new(protectedCurrent is not null && protectedCurrent.ExactEquals(candidate)
                        ? ProtectedCurrentDmd1CommitDisposition.ExactReplay
                        : ProtectedCurrentDmd1CommitDisposition.Applied,
                    current),
            DeviceDirectoryTransitionDisposition.StaleCandidate =>
                new(ProtectedCurrentDmd1CommitDisposition.Stale, current),
            DeviceDirectoryTransitionDisposition.ForkLatched or
                DeviceDirectoryTransitionDisposition.RevokedDeviceReuse =>
                new(ProtectedCurrentDmd1CommitDisposition.ForkLatched,
                    Copy(current, transition.Next)),
            _ => new(ProtectedCurrentDmd1CommitDisposition.InvalidLineage, current)
        };
    }

    private static DeviceAccountStateSnapshot Latch(DeviceAccountStateSnapshot current) =>
        current.Directory.ForkLatched
            ? current
            : Copy(current, DeviceDirectoryState.Restore(
                current.Directory.Head, true, current.LocalRevocationFloor));

    private static DeviceAccountStateSnapshot Copy(
        DeviceAccountStateSnapshot current,
        DeviceDirectoryState directory) =>
        new(checked(current.Revision + 1), directory, current.RevocationSagas,
            current.HistoryDecisions, current.Repairs);
}

internal static class ProtectedCurrentDmd1Validation
{
    internal static ProtectedDeviceAgreementDisposition ValidateAuthorization(
        DeviceAccountStateSnapshot? current,
        CurrentDmd1Evidence? protectedCurrent,
        CurrentDmd1Evidence supplied,
        LocalDeviceAgreementBinding device)
    {
        if (current?.Directory.ForkLatched == true || supplied.ForkLatched)
            return ProtectedDeviceAgreementDisposition.ForkLatched;
        if (current is null || protectedCurrent is null)
            return ProtectedDeviceAgreementDisposition.MissingCurrentDmd1;
        if (!protectedCurrent.ExactEquals(supplied) ||
            current.Directory.Head.DirectoryGeneration != supplied.DirectoryGeneration ||
            !current.Directory.Head.DirectoryHash.Span.SequenceEqual(supplied.DirectoryHash.Span))
            return supplied.DirectoryGeneration < current.Directory.Head.DirectoryGeneration
                ? ProtectedDeviceAgreementDisposition.Stale
                : ProtectedDeviceAgreementDisposition.Conflict;
        if (current.Directory.IsLocallyRevoked(DeviceIdentifier32.FromBytes(device.DeviceId.Span)) ||
            !supplied.Matches(device))
            return ProtectedDeviceAgreementDisposition.RevokedOrSuperseded;
        return ProtectedDeviceAgreementDisposition.Granted;
    }

    internal static void ValidateAgreementInputs(
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlySpan<byte> operationBinding,
        ReadOnlySpan<byte> peerPublicKey)
    {
        if (purpose is not (LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1 or
            LocalDeviceX25519AgreementPurpose.Dph2ResponderDh2))
            throw new ArgumentOutOfRangeException(nameof(purpose));
        if (operationBinding.Length != 32 || operationBinding.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte operation binding is required.", nameof(operationBinding));
        if (peerPublicKey.Length != 32 || peerPublicKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte peer X25519 key is required.", nameof(peerPublicKey));
    }

    internal static string FingerprintInstall(CurrentDmd1Evidence evidence) =>
        Fingerprint("Deep/DeviceV1/current-DMD1-install", evidence.Canonical.Span);

    internal static string FingerprintAgreement(
        CurrentDmd1Evidence evidence,
        LocalDeviceAgreementBinding device,
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlySpan<byte> operationBinding,
        ReadOnlySpan<byte> peerPublicKey)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "Deep/DeviceV1/agreement-authorization"u8);
        Append(hash, evidence.DirectoryHash.Span);
        Append(hash, device.NetworkId.Span);
        Append(hash, device.AccountId.Span);
        AppendU64(hash, device.AccountGeneration);
        Append(hash, device.DeviceId.Span);
        AppendU64(hash, device.DeviceGeneration);
        Append(hash, device.ExactDpd1Hash.Span);
        Append(hash, [(byte)purpose]);
        Append(hash, operationBinding);
        Append(hash, peerPublicKey);
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static string Fingerprint(string domain, ReadOnlySpan<byte> value)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, Encoding.ASCII.GetBytes(domain));
        Append(hash, value);
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static void AppendU64(IncrementalHash hash, ulong value)
    {
        Span<byte> encoded = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        Append(hash, encoded);
    }
}
