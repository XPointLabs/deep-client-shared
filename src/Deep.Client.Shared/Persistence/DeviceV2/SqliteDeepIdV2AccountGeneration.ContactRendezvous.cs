using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    internal static async ValueTask<VerifiedDeepIdV2ContactUpdateRendezvous> EnsureContactRendezvousUnderLeaseAsync(
        IDeepSecureStorage storage, VerifiedDeepIdV2CurrentAccount current, ReadOnlyMemory<byte> intent,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        OnionMonotonicReading reading, OnionTrustedTimeAuthority trustedTime, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(intent.Span);
        var network = fresh.Proof.NetworkId;
        using var keyOwner = await storage.ReadOwnedAsync(KeySlot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("The protected account instance is absent.");
        var keyRecord = keyOwner.Use(static bytes => bytes.ToArray());
        byte[]? exact = null, next = null, entry = null, scalar = null;
        try
        {
            ValidateRecord(keyRecord, network.Span, current.AccountId.Span);
            var instance = keyRecord.AsMemory(56, 32);
            using var snapshot = await storage.ReadOwnedAsync(ProtectedContactRendezvousJournal.Slot, ct)
                .ConfigureAwait(false) ?? throw new InvalidDataException("The protected rendezvous snapshot is absent.");
            exact = snapshot.Use(static bytes => bytes.ToArray());
            using var state = ProtectedContactRendezvousJournal.Decode(exact, network.Span, current.AccountId.Span, instance.Span);
            var name = Convert.ToHexString(intent.Span);
            if (!state.Entries.TryGetValue(name, out var retained))
            {
                if (state.Entries.Count >= ProtectedContactRendezvousJournal.MaximumIntents)
                    throw new IOException("The protected rendezvous journal is full.");
                scalar = Random32();
                var publicKey = DeepIdentityCrypto.DeriveX25519PublicKey(scalar);
                var elapsed = checked(reading.SampleSeconds - fresh.Proof.MonotonicSample);
                var issued = checked(fresh.Proof.TrustedLowerUnixSeconds + elapsed);
                var expires = Math.Min(checked(issued + 86_400), Math.Min(
                    fresh.Network.MaximumRecordExpiryUnixSeconds,
                    current.Verified.PublicEvidence.Binding.Identity.ActiveDevices.Single().Certificate.ExpiresAtUnixSeconds));
                var authored = await DeepIdV2ContactUpdateRendezvousAuthor.AuthorGenesisAsync(fresh.Proof,
                    fresh.Network, current.Verified.DeviceSecrets, Random32(), publicKey, issued, expires,
                    trustedTime, ct).ConfigureAwait(false);
                entry = new byte[ProtectedContactRendezvousJournal.EntryBytes];
                intent.Span.CopyTo(entry); scalar.CopyTo(entry, 32); authored.ExactXur1.Span.CopyTo(entry.AsSpan(64));
                state.Entries.Add(name, entry);
                retained = entry;
                next = ProtectedContactRendezvousJournal.Encode(state, network.Span, current.AccountId.Span, instance.Span);
                ct.ThrowIfCancellationRequested();
                if (!await storage.CompareExchangeAsync(ProtectedContactRendezvousJournal.Slot, exact, next, ct).ConfigureAwait(false))
                    throw new IOException("The protected rendezvous snapshot changed during account-owned commit.");
            }
            // Release only the reverified exact winner, after protected commit.
            // Expired/revoked winners fail; they are never overwritten on retry.
            return await DeepIdV2ContactUpdateRendezvousVerifier.VerifyAsync(retained.AsMemory(64),
                fresh.Proof, trustedTime, ct).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyRecord);
            if (exact is not null) CryptographicOperations.ZeroMemory(exact);
            if (next is not null) CryptographicOperations.ZeroMemory(next);
            if (entry is not null) CryptographicOperations.ZeroMemory(entry);
            if (scalar is not null) CryptographicOperations.ZeroMemory(scalar);
        }
    }

    private static byte[] Random32()
    {
        var bytes = new byte[32];
        do RandomNumberGenerator.Fill(bytes); while (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return bytes;
    }
}
