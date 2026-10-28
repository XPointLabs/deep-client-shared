using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private static readonly string[] ArchiveAuthoredSlots =
        [ProtectedDid2ContactAcceptJournal.Slot, ProtectedDid2DirectTextJournal.Slot, ProtectedDid2GroupJournal.Slot];

    // Exact source framing: domain00 || actualAccount32 || scope32 || each
    // ordinal-sorted literal slot name(LP-u16 UTF8) || typed NULL(0) or
    // blob(2 || length:u64 || exact protected bytes), followed by the existing
    // canonical complete application schema/table/row/cell stream. Literal names:
    // deep.store.v2.contact-accept-journal, deep.store.v2.direct-text-journal,
    // deep.store.v2.groups. Only the
    // incremental hash state survives the SQL/key acquisition callback; no
    // private Group/Accept/DirectText root bytes enter SQL or artifact output.
    private async Task<(byte[] SqlHash, byte[] DirectRootHash)> CaptureArchiveAuthoredSourceAsync(
        VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/archive-enrollment-authored"u8); hash.AppendData([0]);
        hash.AppendData(current.AccountId.Span); hash.AppendData(scope.Hash);
        var before = await AppendArchiveAuthoredRootsAsync(hash, scope, ct).ConfigureAwait(false);
        byte[] sqlHash;
        using (var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
            storage, sqlStatePath, current, held, ct).ConfigureAwait(false))
            sqlHash = await application.CaptureMessagingArchiveAuthoredSourceAsync(hash, scope, ct).ConfigureAwait(false);
        using var comparison = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var after = await AppendArchiveAuthoredRootsAsync(comparison, scope, ct).ConfigureAwait(false);
        if (!Did2MessagingSessionScope.Fixed(before.FramesHash, after.FramesHash) ||
            !Did2MessagingSessionScope.Fixed(before.DirectRootHash, after.DirectRootHash))
            throw new CryptographicException("Actual authored source roots changed across enrollment SQL acquisition.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        return (sqlHash, before.DirectRootHash);
    }

    private async Task<(byte[] FramesHash, byte[] DirectRootHash)> AppendArchiveAuthoredRootsAsync(
        IncrementalHash target, Did2MessagingSessionScope scope, CancellationToken ct)
    {
        var slots = ArchiveAuthoredSlots.OrderBy(static slot => slot, StringComparer.Ordinal).ToArray();
        using var actual = await storage.ReadOwnedBatchAsync(slots, ct).ConfigureAwait(false);
        using var frames = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[]? direct = null;
        for (var i = 0; i < slots.Length; i++)
        {
            var slot = slots[i]; var name = Encoding.UTF8.GetBytes(slot); var length = new byte[8];
            BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)name.Length));
            target.AppendData(length.AsSpan(0, 2)); target.AppendData(name);
            frames.AppendData(length.AsSpan(0, 2)); frames.AppendData(name);
            var owned = actual[i];
            if (owned is null)
            {
                if (slot == ProtectedDid2DirectTextJournal.Slot) throw new InvalidDataException("The actual protected authored counter root is absent.");
                target.AppendData([0]); frames.AppendData([0]); continue;
            }
            owned.Use(raw =>
            {
                if (slot == ProtectedDid2DirectTextJournal.Slot)
                { using var parsed = ProtectedDid2DirectTextJournal.Decode(raw, scope.Network, scope.LocalAccount, scope.Instance); direct = SHA256.HashData(raw); }
                else if (slot == ProtectedDid2ContactAcceptJournal.Slot)
                { using var parsed = ProtectedDid2ContactAcceptJournal.Decode(raw, scope.Network, scope.LocalAccount, scope.Instance); }
                else
                { using var parsed = ProtectedDid2GroupJournal.Decode(raw, scope.Network, scope.LocalAccount, scope.Instance); }
                BinaryPrimitives.WriteUInt64BigEndian(length, checked((ulong)raw.Length));
                target.AppendData([2]); target.AppendData(length); target.AppendData(raw);
                frames.AppendData([2]); frames.AppendData(length); frames.AppendData(raw);
            });
        }
        return (frames.GetHashAndReset(), direct ?? throw new InvalidDataException("The actual authored root was not selected."));
    }
}
