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
            // Root kind 8 owns the local exact XPK1/XPC1 V2 custody snapshot.
            // Reuse the existing account/instance-bound two-slot floor protocol,
            // not a V1 journal, an unprotected database or one OS slot per claim.
            var root = new OnionCustodyRoot(storage, accountLease, statePath, binding, 8,
                ClaimRequestStore.MaximumPayloadBytes);
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
        // Every accepted reservation has space for the largest closed XPC1
        // bucket. Public-byte capacity cannot be exhausted only after claim.
        internal const int MaximumPayloadBytes = HeaderBytes + MaximumRequests * (RequestBytes + 4 + 16384);

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
                    if (Fixed(prior.Request, request.CanonicalBytes.Span)) return prior.Request.ToArray();
                    if (await root.CompareExchangeAsync(row, Encode(state with { Forked = true }), ct).ConfigureAwait(false))
                        throw new CryptographicException("The DID2 claim operation conflicts with its durable request.");
                    continue;
                }
                if (state.Requests.Count >= MaximumRequests)
                    throw new IOException("The DID2 claim reservation journal is full.");
                state.Requests.Add(id, new(request.CanonicalBytes.ToArray(), null));
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
            return new ReadOnlyMemory<byte>(exact.Request.ToArray());
        }

        public async ValueTask<ReadOnlyMemory<byte>?> FindResultAsync(ReadOnlyMemory<byte> operationId,
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
            if (!state.Requests.TryGetValue(id, out var exact) || exact.Result is null) return null;
            return new ReadOnlyMemory<byte>(exact.Result.ToArray());
        }

        public async ValueTask<ReadOnlyMemory<byte>> RecordVerifiedResultAsync(
            VerifiedXpc1V2ReplicaSignatures verified, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(verified);
            ct.ThrowIfCancellationRequested();
            // The only write entry point requires Protocol's selected-replica
            // signature capability. Own both byte arrays before any await.
            var request = Validate(verified.ExactRequest.ToArray());
            var result = verified.ExactResult.ToArray();
            ValidateResult(result, request.CanonicalBytes.Span);
            var id = Convert.ToHexString(request.Field(2).Span);
            for (var attempt = 0; attempt < 8; attempt++)
            {
                ct.ThrowIfCancellationRequested();
                var row = await root.ReadAsync(ct).ConfigureAwait(false);
                var state = row is null ? new State(false, new(StringComparer.Ordinal)) : Decode(row.Payload);
                RequireUnforked(state);
                if (!state.Requests.TryGetValue(id, out var prior))
                    throw new InvalidOperationException("The DID2 claim result has no durable exact reservation.");
                if (!Fixed(prior.Request, request.CanonicalBytes.Span) ||
                    prior.Result is not null && !Fixed(prior.Result, result))
                {
                    if (await root.CompareExchangeAsync(row, Encode(state with { Forked = true }), ct).ConfigureAwait(false))
                        throw new CryptographicException("The DID2 claim result conflicts with its durable exact pair.");
                    continue;
                }
                if (prior.Result is not null) return prior.Result.ToArray();
                state.Requests[id] = prior with { Result = result };
                if (await root.CompareExchangeAsync(row, Encode(state), ct).ConfigureAwait(false))
                    return result.ToArray();
            }
            throw new IOException("DID2 claim result custody remained contended.");
        }

        internal State Decode(byte[] payload)
        {
            // Local SQL payload only: version, irreversible fork flag, count,
            // then operation-sorted exact XPK1, u32 result length and optional
            // padded XPC1. Version 2 request-only snapshots require QA reset.
            if (payload.Length < HeaderBytes || payload.Length > MaximumPayloadBytes ||
                payload[0] != 3 || payload[1] > 1)
                throw new InvalidDataException("The DID2 claim custody snapshot is malformed.");
            var count = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(2, 4));
            if (count is < 1 or > MaximumRequests || payload.Length < HeaderBytes + count * (RequestBytes + 4))
                throw new InvalidDataException("The DID2 claim custody snapshot is outside its closed bound.");
            var requests = new SortedDictionary<string, Entry>(StringComparer.Ordinal);
            string? previous = null;
            var offset = HeaderBytes;
            for (var index = 0; index < count; index++)
            {
                if (payload.Length - offset < RequestBytes + 4)
                    throw new InvalidDataException("The DID2 claim custody entry is truncated.");
                var exact = payload.AsSpan(offset, RequestBytes).ToArray();
                var parsed = Validate(exact);
                offset += RequestBytes;
                var length = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset, 4));
                offset += 4;
                if (length is not (0 or 256 or 1024 or 4096 or 16384) || length > payload.Length - offset)
                    throw new InvalidDataException("The DID2 claim custody result size is invalid.");
                byte[]? result = null;
                if (length != 0)
                {
                    result = payload.AsSpan(offset, checked((int)length)).ToArray();
                    ValidateResult(result, exact);
                    offset += checked((int)length);
                }
                var id = Convert.ToHexString(parsed.Field(2).Span);
                if (previous is not null && string.CompareOrdinal(previous, id) >= 0 || !requests.TryAdd(id, new(exact, result)))
                    throw new InvalidDataException("DID2 claim reservations are not canonical and unique.");
                previous = id;
            }
            if (offset != payload.Length)
                throw new InvalidDataException("The DID2 claim custody snapshot has trailing bytes.");
            return new(payload[1] == 1, requests);
        }

        private static void ValidateResult(ReadOnlySpan<byte> result, ReadOnlySpan<byte> request)
        {
            var parsed = DeepIdV2PreKeyClaimResultCodec.Decode(result, request);
            if (parsed.Status is not (Xpc1V2Status.Claimed or Xpc1V2Status.Replay) ||
                parsed.MutationOutcome != Xpc1V2MutationOutcome.DurablyCommitted)
                throw new InvalidDataException("DID2 claim custody accepts only verified successful results.");
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
            var length = checked(HeaderBytes + state.Requests.Values.Sum(entry =>
                RequestBytes + 4 + (entry.Result?.Length ?? 0)));
            if (length > MaximumPayloadBytes)
                throw new IOException("The DID2 claim custody byte capacity is exhausted.");
            var payload = new byte[length];
            payload[0] = 3;
            payload[1] = state.Forked ? (byte)1 : (byte)0;
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(2, 4), checked((uint)state.Requests.Count));
            var index = HeaderBytes;
            foreach (var entry in state.Requests.Values)
            {
                entry.Request.CopyTo(payload, index);
                index += RequestBytes;
                BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(index, 4), checked((uint)(entry.Result?.Length ?? 0)));
                index += 4;
                if (entry.Result is not null) { entry.Result.CopyTo(payload, index); index += entry.Result.Length; }
            }
            return payload;
        }

        private static void RequireUnforked(State state)
        {
            if (state.Forked) throw new CryptographicException("DID2 claim request custody is fork-latched.");
        }

        internal sealed record Entry(byte[] Request, byte[]? Result);
        internal sealed record State(bool Forked, SortedDictionary<string, Entry> Requests);
    }
}
