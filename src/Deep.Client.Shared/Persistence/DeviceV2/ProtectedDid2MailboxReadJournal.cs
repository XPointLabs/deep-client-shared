using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Protected local commitments, not caller-mintable transport/ACK authority.
internal static class ProtectedDid2MailboxReadJournal
{
    internal const string Slot = "deep.store.v2.mailbox-read-journal";
    internal const int HeaderBytes = 96, MaximumFloors = 128, MaximumItems = 8;
    internal const int MaximumPageBytes = 48 + 256 + MaximumItems * (12 + MailboxClientLimits.MaximumEncryptedEnvelopeLength);
    internal const int MaximumAckReplyBytes = 40 + MaximumItems * (2 + MailboxReceiptV3Limits.MaximumQuorumLength);
    internal const int MaximumBytes = 750_000;

    internal sealed class State : IDisposable
    {
        internal ulong Revision = 1;
        internal byte Phase;
        internal SortedDictionary<string, ulong> Counters { get; } = new(StringComparer.Ordinal);
        internal SortedDictionary<string, ClientMailboxTraversal> Traversals { get; } = new(StringComparer.Ordinal);
        internal Cycle? Active;
        internal ulong MinimumCounter(ReadOnlySpan<byte> grant) => checked(Counters.GetValueOrDefault(Name(grant)) + 1);
        public void Dispose() { Active?.Dispose(); Active = null; Counters.Clear(); Traversals.Clear(); }
    }

    internal sealed class Cycle : IDisposable
    {
        internal byte[] Grant = [], Scope = [], Route = [], RetrieveBody = [], RetrieveMauHash = new byte[32],
            Page = [], AckBody = [], AckMauHash = new byte[32], AckReply = [];
        internal ulong PollGeneration, RetrieveCounter, CapturedAt, AckCounter;

        internal static Cycle Begin(ReadOnlySpan<byte> grant, ReadOnlySpan<byte> scope, ReadOnlySpan<byte> route,
            ulong pollGeneration, ReadOnlySpan<byte> retrieveBody)
        {
            Require32(grant); Require32(scope); Require32(route);
            if (retrieveBody.Length is < 108 or > 364) throw Bad();
            _ = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(retrieveBody);
            return new() { Grant = grant.ToArray(), Scope = scope.ToArray(), Route = route.ToArray(),
                PollGeneration = pollGeneration, RetrieveBody = retrieveBody.ToArray() };
        }

        internal MailboxRetrievePage ReadPage()
        {
            if (CapturedAt == 0 || Page.Length is < 48 or > MaximumPageBytes) throw Bad();
            var request = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(RetrieveBody);
            // Structural validation at retained capture time, never current authority.
            var page = MailboxClientCodec.DecodeRetrievePage(Page, new()
            {
                NowUnixSeconds = CapturedAt,
                EpochWindow = new() { CurrentEpoch = request.Epoch, CurrentNotBeforeUnixSeconds = 1,
                    CurrentExpiresAtUnixSeconds = ulong.MaxValue, NextEpoch = 0,
                    NextNotBeforeUnixSeconds = 0, NextExpiresAtUnixSeconds = 0 },
                CapabilityPolicy = new() { CurrentBucket = 0, MinimumGeneration = 1 }, AllowLegacyMirrorOverlap = false
            });
            RequirePage(request, page);
            return page;
        }

        internal void Capture(ReadOnlySpan<byte> page, ulong at, MailboxClientDecodePolicy policy)
        {
            if (Page.Length != 0 || CapturedAt != 0 || RetrieveCounter == 0 || at == 0 ||
                page.Length is < 48 or > MaximumPageBytes || policy.NowUnixSeconds != at) throw Bad();
            RequirePage(MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(RetrieveBody),
                MailboxClientCodec.DecodeRetrievePage(page, policy));
            Page = page.ToArray(); CapturedAt = at;
        }

        internal void AdoptPrepared(ReadOnlySpan<byte> exactMau, bool ack)
        {
            var body = ack ? AckBody : RetrieveBody;
            if (exactMau.IsEmpty || exactMau.Length > 8_192 || body.Length == 0 ||
                (ack ? AckCounter : RetrieveCounter) != 0) throw Bad();
            var request = MailboxAuthenticatedClientRequestCodec.Decode(exactMau);
            if (request.Binding.Operation != (ack ? MailboxAuthenticatedOperation.Ack : MailboxAuthenticatedOperation.Retrieve) ||
                !Fixed(request.Binding.CanonicalRequest.Span, body) ||
                request.Presentation.Grant.Domain != MailboxCapabilityDomain.Retrieve ||
                !Fixed(SHA256.HashData(MailboxAuthenticatedCapabilityCodec.EncodeGrant(request.Presentation.Grant)), Grant) ||
                request.Presentation.ReplayCounter == 0 ||
                !PublicKeyAuth.VerifyDetached(request.Presentation.HolderSignature.ToArray(),
                    MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(request.Presentation), request.Presentation.Grant.HolderPublicKey.ToArray()))
                throw new CryptographicException("Prepared mailbox read differs from protected holder/body custody.");
            if (ack) { AckCounter = request.Presentation.ReplayCounter; AckMauHash = SHA256.HashData(exactMau); }
            else { RetrieveCounter = request.Presentation.ReplayCounter; RetrieveMauHash = SHA256.HashData(exactMau); }
        }

        internal byte[] AckOperation()
        {
            if (RetrieveCounter == 0 || Page.Length == 0) throw Bad();
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData("Deep/Local/DID2/MailboxAckOperation/1"u8); hash.AppendData([0]);
            hash.AppendData(Scope); hash.AppendData(Grant); hash.AppendData(RetrieveMauHash); hash.AppendData(SHA256.HashData(Page));
            return hash.GetHashAndReset()[..16];
        }

        internal static void RequirePage(MailboxAuthenticatedRetrieveBody request, MailboxRetrievePage page)
        {
            if (page.Epoch != request.Epoch || !Fixed(page.OperationId.Span, request.OperationId.Span) ||
                page.Items.Count > request.MaximumItems || page.Items.Count > MaximumItems ||
                page.Items.Any(item => item.Cursor <= request.AfterCursor ||
                    !Fixed(item.Envelope.MailboxId.Bytes.Span, request.MailboxId.Bytes.Span) ||
                    !Fixed(item.Envelope.PlacementId.Bytes.Span, request.PlacementId.Bytes.Span)))
                throw new CryptographicException("Captured mailbox page differs from its protected request.");
        }

        public void Dispose()
        {
            foreach (var bytes in new[] { Grant, Scope, Route, RetrieveBody, RetrieveMauHash, Page, AckBody, AckMauHash, AckReply })
                CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { using var state = new State(); return Encode(state, network, account, instance); }

    internal static State Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (exact.Length is < HeaderBytes or > MaximumBytes || exact[0] != 1 || exact[1] > 6 ||
            !Fixed(exact.Slice(12, 16), network) || !Fixed(exact.Slice(28, 32), account) || !Fixed(exact.Slice(60, 32), instance) ||
            exact.Slice(94, 2).IndexOfAnyExcept((byte)0) >= 0) throw Bad();
        var counters = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(2));
        var scopes = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(92));
        if (counters > MaximumFloors || scopes > MaximumFloors) throw Bad();
        var state = new State { Phase = exact[1], Revision = BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(4)) };
        try
        {
            var reader = new Reader(exact[HeaderBytes..]); string? previous = null;
            for (var i = 0; i < counters; i++)
            {
                var name = Name(reader.Take(32)); var counter = reader.U64();
                if (counter == 0 || previous is not null && string.CompareOrdinal(previous, name) >= 0) throw Bad();
                state.Counters.Add(name, counter); previous = name;
            }
            previous = null;
            for (var i = 0; i < scopes; i++)
            {
                var name = Name(reader.Take(32)); var generation = reader.U64(); var after = reader.U64();
                var token = reader.Blob(256);
                if (previous is not null && string.CompareOrdinal(previous, name) >= 0) throw Bad();
                state.Traversals.Add(name, new(after, token, generation)); previous = name;
            }
            if (state.Phase != 0)
            {
                var cycle = state.Active = new Cycle();
                cycle.Grant = reader.Take(32).ToArray(); cycle.Scope = reader.Take(32).ToArray(); cycle.Route = reader.Take(32).ToArray();
                cycle.PollGeneration = reader.U64(); cycle.RetrieveBody = reader.Blob(364).ToArray();
                cycle.RetrieveCounter = reader.U64(); cycle.RetrieveMauHash = reader.Take(32).ToArray();
                cycle.CapturedAt = reader.U64(); cycle.Page = reader.Blob(MaximumPageBytes).ToArray();
                cycle.AckBody = reader.Blob(5_000).ToArray(); cycle.AckCounter = reader.U64(); cycle.AckMauHash = reader.Take(32).ToArray();
                cycle.AckReply = reader.Blob(MaximumAckReplyBytes).ToArray();
            }
            if (!reader.End) throw Bad(); Validate(state); return state;
        }
        catch { state.Dispose(); throw; }
    }

    internal static byte[] Encode(State state, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance); Validate(state);
        using var stream = new MemoryStream();
        try
        {
            var header = new byte[HeaderBytes]; header[0] = 1; header[1] = state.Phase;
            BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2), checked((ushort)state.Counters.Count));
            BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(4), state.Revision);
            network.CopyTo(header.AsSpan(12)); account.CopyTo(header.AsSpan(28)); instance.CopyTo(header.AsSpan(60));
            BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(92), checked((ushort)state.Traversals.Count)); stream.Write(header);
            foreach (var pair in state.Counters) { stream.Write(Convert.FromHexString(pair.Key)); Write64(stream, pair.Value); }
            foreach (var pair in state.Traversals)
            { stream.Write(Convert.FromHexString(pair.Key)); Write64(stream, pair.Value.PollGeneration); Write64(stream, pair.Value.AfterCursor); WriteBlob(stream, pair.Value.ContinuationToken); }
            if (state.Active is { } c)
            {
                stream.Write(c.Grant); stream.Write(c.Scope); stream.Write(c.Route); Write64(stream, c.PollGeneration); WriteBlob(stream, c.RetrieveBody);
                Write64(stream, c.RetrieveCounter); stream.Write(c.RetrieveMauHash); Write64(stream, c.CapturedAt); WriteBlob(stream, c.Page);
                WriteBlob(stream, c.AckBody); Write64(stream, c.AckCounter); stream.Write(c.AckMauHash);
                WriteBlob(stream, c.AckReply);
            }
            var exact = stream.ToArray();
            try { using var verified = Decode(exact, network, account, instance); return exact; }
            catch { CryptographicOperations.ZeroMemory(exact); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(stream.GetBuffer().AsSpan(0, checked((int)stream.Length))); }
    }

    private static void Validate(State state)
    {
        if (state.Phase > 6 || state.Counters.Count > MaximumFloors || state.Traversals.Count > MaximumFloors ||
            state.Revision < checked((ulong)(state.Counters.Count + state.Traversals.Count) + 1) ||
            (state.Phase == 0) != (state.Active is null)) throw Bad();
        foreach (var pair in state.Counters) { if (Name(Convert.FromHexString(pair.Key)) != pair.Key || pair.Value == 0) throw Bad(); }
        foreach (var pair in state.Traversals)
        { if (Name(Convert.FromHexString(pair.Key)) != pair.Key) throw Bad(); _ = new ClientMailboxTraversal(pair.Value.AfterCursor, pair.Value.ContinuationToken, pair.Value.PollGeneration); }
        if (state.Active is not { } c) return;
        Require32(c.Grant); Require32(c.Scope); Require32(c.Route);
        if (c.RetrieveBody.Length is < 108 or > 364 || c.Page.Length > MaximumPageBytes || c.AckBody.Length > 5_000 ||
            c.RetrieveMauHash.Length != 32 || c.AckMauHash.Length != 32 || c.AckReply.Length > MaximumAckReplyBytes ||
            state.Phase != 6 && c.AckReply.Length != 0) throw Bad();
        var request = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(c.RetrieveBody);
        if (request.MaximumItems is < 1 or > MaximumItems || !state.Traversals.TryGetValue(Name(c.Scope), out var traversal) ||
            (state.Phase >= 2 ? c.RetrieveCounter == 0 || Zero(c.RetrieveMauHash) : c.RetrieveCounter != 0 || !Zero(c.RetrieveMauHash)) ||
            (state.Phase >= 3 ? c.CapturedAt == 0 || c.Page.Length == 0 : c.CapturedAt != 0 || c.Page.Length != 0) ||
            (state.Phase >= 5) != (c.AckBody.Length != 0) ||
            (state.Phase == 6 ? c.AckCounter <= c.RetrieveCounter || Zero(c.AckMauHash) : c.AckCounter != 0 || !Zero(c.AckMauHash))) throw Bad();
        if (state.Phase >= 2 && state.Counters.GetValueOrDefault(Name(c.Grant)) != (state.Phase == 6 ? c.AckCounter : c.RetrieveCounter)) throw Bad();
        var page = state.Phase >= 3 ? c.ReadPage() : null;
        var after = state.Phase >= 4 ? page!.HasMore ? page.NextCursor : 0 : request.AfterCursor;
        var token = state.Phase >= 4 ? page!.HasMore ? page.ContinuationToken : ReadOnlyMemory<byte>.Empty : request.ContinuationToken;
        if (traversal.PollGeneration != (state.Phase >= 4 ? checked(c.PollGeneration + 1) : c.PollGeneration) ||
            traversal.AfterCursor != after || !Fixed(traversal.ContinuationToken, token.Span)) throw Bad();
        if (state.Phase >= 5)
        {
            var ack = MailboxAuthenticatedRequestTranscript.DecodeAckBody(c.AckBody);
            if (page!.Items.Count == 0 || ack.Epoch != request.Epoch || !Fixed(ack.OperationId.Span, c.AckOperation()) ||
                !Fixed(ack.MailboxId.Bytes.Span, request.MailboxId.Bytes.Span) || !Fixed(ack.PlacementId.Bytes.Span, request.PlacementId.Bytes.Span) ||
                ack.IsFinalPage == page.HasMore || !Fixed(ack.ContinuationToken.Span, token.Span) || ack.Acknowledgements.Count != page.Items.Count) throw Bad();
            for (var i = 0; i < page.Items.Count; i++)
                if (ack.Acknowledgements[i].Cursor != page.Items[i].Cursor || !Fixed(ack.Acknowledgements[i].EnvelopeDigest.Span, page.Items[i].Envelope.DeduplicationDigest.Span)) throw Bad();
            if (c.AckReply.Length != 0)
            {
                var response = MailboxAggregateAckCodec.DecodeMqr3(c.AckReply);
                if (response.Epoch != ack.Epoch || !Fixed(response.OperationId.Span, ack.OperationId.Span) || response.TombstoneQuorums.Count != page.Items.Count) throw Bad();
            }
        }
    }

    private ref struct Reader(ReadOnlySpan<byte> bytes)
    {
        private ReadOnlySpan<byte> remaining = bytes;
        internal bool End => remaining.IsEmpty;
        internal ReadOnlySpan<byte> Take(int count) { if (count < 0 || count > remaining.Length) throw Bad(); var value = remaining[..count]; remaining = remaining[count..]; return value; }
        internal ulong U64() => BinaryPrimitives.ReadUInt64BigEndian(Take(8));
        internal ReadOnlySpan<byte> Blob(int maximum) { var length = BinaryPrimitives.ReadUInt32BigEndian(Take(4)); if (length > maximum) throw Bad(); return Take(checked((int)length)); }
    }
    private static void Write64(Stream stream, ulong value) { Span<byte> bytes = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); stream.Write(bytes); }
    private static void WriteBlob(Stream stream, ReadOnlySpan<byte> value) { Span<byte> bytes = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, checked((uint)value.Length)); stream.Write(bytes); stream.Write(value); }
    internal static string Name(ReadOnlySpan<byte> value) { Require32(value); return Convert.ToHexString(value); }
    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { if (network.Length != 16 || Zero(network)) throw Bad(); Require32(account); Require32(instance); }
    private static void Require32(ReadOnlySpan<byte> value) { if (value.Length != 32 || Zero(value)) throw Bad(); }
    private static bool Zero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;
    internal static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static InvalidDataException Bad() => new("Protected mailbox read shape, phase, scope or bound is inconsistent; explicit reset is required.");
}
