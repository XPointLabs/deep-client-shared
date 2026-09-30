using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    internal static async ValueTask<DeepIdV2ClaimRequestCustody> OpenClaimRequestCustodyAsync(
        IDeepSecureStorage storage, DeepIdV2AccountFileLease accountLease, string statePath,
        VerifiedDeepIdV2CurrentAccount current, CancellationToken ct)
    {
        using var secret = await storage.ReadOwnedAsync(KeySlot, ct).ConfigureAwait(false)
            ?? throw new InvalidDataException("The DID2 SQL key record is absent.");
        var record = secret.Use(static value => value.ToArray());
        try
        {
            var network = current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.NetworkId;
            ValidateRecord(record, network.Span, current.AccountId.Span);
            var binding = AccountBinding.From(current.Verified, current.AccountId.Span,
                network.Span, current.DisplayName, current.PermanentId.CanonicalText, record.AsSpan(56, 32));
            // Root kind 8 owns the local exact XPK1 V2 reservation snapshot.
            // Reuse the existing account/instance-bound two-slot floor protocol,
            // not a V1 journal, an unprotected database or one OS slot per claim.
            var root = new OnionCustodyRoot(storage, accountLease, statePath, binding, 8,
                ClaimRequestStore.HeaderBytes + ClaimRequestStore.MaximumRequests * ClaimRequestStore.RequestBytes);
            var store = new ClaimRequestStore(root);
            var row = await root.ReadUnderLeaseAsync(ct).ConfigureAwait(false);
            if (row is not null) store.Decode(row.Payload);
            return new(store);
        }
        finally { CryptographicOperations.ZeroMemory(record); }
    }

    private sealed class ClaimRequestStore(OnionCustodyRoot root) : IDeepIdV2ClaimRequestCustodyStore
    {
        internal const int RequestBytes = 438, HeaderBytes = 6, MaximumRequests = 1024;

        public async ValueTask<ReadOnlyMemory<byte>> ReserveAsync(ReadOnlyMemory<byte> exactRequest,
            CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (exactRequest.Length != RequestBytes)
                throw new InvalidDataException("The DID2 claim request has a different fixed size.");
            // Own the input before any await; caller mutation cannot change the reservation.
            var request = Validate(exactRequest.ToArray());
            var id = Convert.ToHexString(request.Field(2).Span);
            for (var attempt = 0; attempt < 8; attempt++)
            {
                ct.ThrowIfCancellationRequested();
                var row = await root.ReadAsync(ct).ConfigureAwait(false);
                var state = row is null ? new State(false, new(StringComparer.Ordinal)) : Decode(row.Payload);
                RequireUnforked(state);
                if (state.Requests.TryGetValue(id, out var prior))
                {
                    if (Fixed(prior, request.CanonicalBytes.Span)) return prior.ToArray();
                    if (await root.CompareExchangeAsync(row, Encode(state with { Forked = true }), ct).ConfigureAwait(false))
                        throw new CryptographicException("The DID2 claim operation conflicts with its durable request.");
                    continue;
                }
                if (state.Requests.Count >= MaximumRequests)
                    throw new IOException("The DID2 claim reservation journal is full.");
                state.Requests.Add(id, request.CanonicalBytes.ToArray());
                if (await root.CompareExchangeAsync(row, Encode(state), ct).ConfigureAwait(false))
                    return request.CanonicalBytes.ToArray();
            }
            throw new IOException("DID2 claim request custody remained contended.");
        }

        public async ValueTask<ReadOnlyMemory<byte>?> FindAsync(ReadOnlyMemory<byte> operationId,
            CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (operationId.Length != 32 || operationId.Span.IndexOfAnyExcept((byte)0) < 0)
                throw new ArgumentException("An exact nonzero claim operation is required.", nameof(operationId));
            var id = Convert.ToHexString(operationId.Span);
            var row = await root.ReadAsync(ct).ConfigureAwait(false);
            if (row is null) return null;
            var state = Decode(row.Payload);
            RequireUnforked(state);
            if (!state.Requests.TryGetValue(id, out var exact)) return null;
            return new ReadOnlyMemory<byte>(exact.ToArray());
        }

        internal State Decode(byte[] payload)
        {
            // Local SQL payload only: version, irreversible fork flag, count,
            // then operation-sorted exact Protocol-owned XPK1 requests.
            if (payload.Length < HeaderBytes || payload[0] != 2 || payload[1] > 1)
                throw new InvalidDataException("The DID2 claim custody snapshot is malformed.");
            var count = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(2, 4));
            if (count is < 1 or > MaximumRequests || payload.Length != HeaderBytes + count * RequestBytes)
                throw new InvalidDataException("The DID2 claim custody snapshot is outside its closed bound.");
            var requests = new SortedDictionary<string, byte[]>(StringComparer.Ordinal);
            string? previous = null;
            for (var index = 0; index < count; index++)
            {
                var exact = payload.AsSpan(HeaderBytes + index * RequestBytes, RequestBytes).ToArray();
                var parsed = Validate(exact);
                var id = Convert.ToHexString(parsed.Field(2).Span);
                if (previous is not null && string.CompareOrdinal(previous, id) >= 0 || !requests.TryAdd(id, exact))
                    throw new InvalidDataException("DID2 claim reservations are not canonical and unique.");
                previous = id;
            }
            return new(payload[1] == 1, requests);
        }

        private ParsedXpk1V2 Validate(byte[] exact)
        {
            var parsed = DeepIdV2PreKeyClaimRequestCodec.Decode(exact);
            if (!Fixed(parsed.Field(1).Span, root.NetworkId.Span))
                throw new CryptographicException("The DID2 claim request belongs to another account network.");
            return parsed;
        }

        private static byte[] Encode(State state)
        {
            var payload = new byte[HeaderBytes + state.Requests.Count * RequestBytes];
            payload[0] = 2;
            payload[1] = state.Forked ? (byte)1 : (byte)0;
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(2, 4), checked((uint)state.Requests.Count));
            var index = HeaderBytes;
            foreach (var exact in state.Requests.Values) { exact.CopyTo(payload, index); index += RequestBytes; }
            return payload;
        }

        private static void RequireUnforked(State state)
        {
            if (state.Forked) throw new CryptographicException("DID2 claim request custody is fork-latched.");
        }

        internal sealed record State(bool Forked, SortedDictionary<string, byte[]> Requests);
    }
}
