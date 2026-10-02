using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// The constructor is closed: only an independently checked protected/SQL
// stable import can authorize source retirement. No secret bytes are retained.
internal sealed class Did2InitialStateTransfer
{
    internal Did2MessagingSessionScope Scope { get; }
    internal Did2MessagingFloor ImportedFloor { get; }
    private readonly byte[] metadata;
    internal ReadOnlySpan<byte> Operation => metadata.AsSpan(268, 32);
    private Did2InitialStateTransfer(Did2MessagingSessionScope scope, Did2MessagingFloor floor, byte[] metadata)
    { Scope = scope; ImportedFloor = floor; this.metadata = metadata; }
    internal static async Task<Did2InitialStateTransfer> VerifyAsync(Did2MessagingSessionScope scope,
        Did2MessagingProtectedCheckpoint checkpoint, Did2MessagingSqlJournal sql, CancellationToken ct)
    {
        var floor = await checkpoint.ReadAsync(ct).ConfigureAwait(false);
        if (floor.Phase != 1 || floor.Status != 0 || floor.Ordinal != 1 || floor.RatchetGeneration != 1)
            throw new InvalidDataException("Retirement requires the exact stable unactivated first import.");
        ct.ThrowIfCancellationRequested(); var metadata = sql.VerifyInitialImport(floor);
        return new(scope, floor, metadata);
    }
    internal void RequireSender(DeepIdV2InitialSessionCommit record)
    {
        RequireCommon(1, record.CanonicalSpan, record.InitialStateHashSpan, record.Record,
            record.EventHashSpan);
        if (!Fixed(record.Directory.DirectoryHash.Span, Scope.LocalDirectory))
            throw new CryptographicException("Retirement source has a different local directory.");
    }
    internal void RequireReceiver(DeepIdV2InitialContactSessionCommit record)
    {
        RequireCommon(2, record.CanonicalSpan, record.InitialStateHashSpan, record.Record,
            DeviceInitialSessionCheckpoint.EventHash(record.ExactInitSpan, record.ExactHelloSpan));
        if (!Fixed(record.Directory.RecordHash.Span, Scope.LocalDirectory))
            throw new CryptographicException("Retirement source has a different local directory.");
    }
    private void RequireCommon(byte role, ReadOnlySpan<byte> basis, ReadOnlySpan<byte> stateHash,
        Dph2Record record, ReadOnlySpan<byte> eventHash)
    {
        if ((role == 1) != Scope.IsInitiator || !Fixed(SHA256.HashData(basis), Scope.InitialBasis) ||
            !Fixed(stateHash, ImportedFloor.RatchetHash) || !Fixed(eventHash, metadata.AsSpan(300, 32)) ||
            !Fixed(SHA256.HashData(Dph2Codec.Encode(record)), metadata.AsSpan(332, 32)) ||
            !Fixed(record.ClaimOperationId.Span, Operation) || !Fixed(record.SessionId.Span, Scope.Session) ||
            !Fixed(record.NetworkId.Span, Scope.Network))
            throw new CryptographicException("Mutable import differs from the exact authenticated source custody.");
    }
    internal static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        Did2MessagingSessionScope.Fixed(left, right);
}

internal sealed class Did2InitialKeyRetirementReceipt
{
    internal Did2InitialStateTransfer Transfer { get; }
    private readonly byte[] entry;
    internal ReadOnlySpan<byte> ExactEntry => entry;
    internal ReadOnlySpan<byte> Operation => Transfer.Operation;
    internal byte[] Commitment => SHA256.HashData(entry);
    private Did2InitialKeyRetirementReceipt(Did2InitialStateTransfer transfer, ReadOnlySpan<byte> entry)
    { Transfer = transfer; this.entry = entry.ToArray(); }
    // Invoked by source owners only after verifying the deletion transaction.
    internal static async Task<Did2InitialKeyRetirementReceipt> VerifyStableAsync(Did2InitialStateTransfer transfer,
        IDeepSecureStorage storage, ProtectedInitialKeyRetirementJournal.Entry expected, CancellationToken ct)
    {
        var state = await ProtectedInitialKeyRetirementJournal.ReadAsync(storage, transfer.Scope.Network.ToArray(),
            transfer.Scope.LocalAccount.ToArray(), ct).ConfigureAwait(false);
        var retained = state.Find(expected.Role, expected.SourceInstance, expected.Ordinal);
        if (retained is null || retained.Phase != 2 || !Did2InitialStateTransfer.Fixed(retained.Exact, expected.Stable().Exact) ||
            !Did2InitialStateTransfer.Fixed(retained.ScopeHash, transfer.Scope.Hash) ||
            !Did2InitialStateTransfer.Fixed(retained.Basis, transfer.Scope.InitialBasis) ||
            !Did2InitialStateTransfer.Fixed(retained.TrsHash, transfer.ImportedFloor.RatchetHash))
            throw new CryptographicException("Retirement receipt has no exact protected completed deletion.");
        return new(transfer, retained.Exact);
    }
}
