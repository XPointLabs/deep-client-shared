using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static class ProtectedDid2ContactRouteJournal
{
    internal const string Slot = "deep.store.v2.contact-route-journal";
    internal const int HeaderBytes = 92, PrefixBytes = 170, MaximumIntents = 128;
    internal const byte Version = 8;
    internal const int MaximumEntryBytes = 477_511;
    // Matches the journaled production secure-store per-slot limit. Pending
    // routes reserve enough space for phase 7 before a threshold callback.
    internal const int MaximumBytes = DeepSecureStorageRegistration.MaximumValueBytes;
    private static readonly int[] Limits = [473, 550, 3476, 4012, 3523, 611, 23295, 65535, 65575, ContactPublicationAuthorityWireCodec.MaximumRequestBytes, 93092, 16384, ContactRouteAuthorityWireCodec.MaximumRequestBytes, ContactRouteAuthorityWireCodec.MaximumIssuanceAdh1Bytes];

    internal sealed class State : IDisposable
    {
        internal SortedDictionary<string, Entry> Entries { get; } = new(StringComparer.Ordinal);
        public void Dispose() { foreach (var entry in Entries.Values) entry.Dispose(); Entries.Clear(); }
    }

    internal sealed class Entry : IDisposable
    {
        private readonly byte[] exact;
        private readonly (int Start, int Length)[] records;
        private Entry(byte[] exact, (int, int)[] records) { this.exact = exact; this.records = records; }
        internal byte Phase => exact[32];
        internal int ReservedBytes => Phase < 7 ? MaximumEntryBytes : exact.Length;
        internal ReadOnlySpan<byte> Exact => exact;
        internal ReadOnlyMemory<byte> Record(int index) => exact.AsMemory(records[index].Start, records[index].Length).ToArray();
        internal bool Matches(Did2ContactRouteConfiguration configuration) =>
            BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(36)) == configuration.Quota &&
            BinaryPrimitives.ReadUInt16BigEndian(exact.AsSpan(40)) == configuration.MinimumReader &&
            Fixed(exact.AsSpan(42, 32), configuration.AntiSpamHash.Span);

        internal static Entry Proposal(ReadOnlySpan<byte> intent, Did2ContactRouteConfiguration configuration,
            ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> keyId, ReadOnlySpan<byte> nonce,
            ReadOnlyMemory<byte> exactDca, ContactRecord xra, ContactRouteAuthorityWireRequest request,
            ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            var prefix = new byte[PrefixBytes];
            var encoded = ContactRouteAuthorityWireCodec.EncodeRequest(request);
            try
            {
                Required32(intent); Required32(scalar); Required32(keyId); Required32(nonce);
                intent.CopyTo(prefix); prefix[32] = 1;
                BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(36), configuration.Quota);
                BinaryPrimitives.WriteUInt16BigEndian(prefix.AsSpan(40), configuration.MinimumReader);
                configuration.AntiSpamHash.Span.CopyTo(prefix.AsSpan(42)); scalar.CopyTo(prefix.AsSpan(74));
                keyId.CopyTo(prefix.AsSpan(106)); nonce.CopyTo(prefix.AsSpan(138));
                return Build(prefix, [exactDca, xra.CanonicalBytes, default, default, default, default, default, default, default, default, default, default, encoded, default], network, account);
            }
            finally { CryptographicOperations.ZeroMemory(prefix); CryptographicOperations.ZeroMemory(encoded); }
        }
        internal Entry WithThreshold(VerifiedDeepIdV2ContactRouteIssuance issuance, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if (Phase != 1) throw new InvalidOperationException("A threshold can only adopt its retained proposal.");
            var exactRequest = ContactRouteAuthorityWireCodec.EncodeRequest(issuance.Request);
            if (!Fixed(exactRequest, Record(12).Span))
                throw new CryptographicException("Verified issuance differs from the exact protected request.");
            var threshold = issuance.Threshold;
            return Next(2, [Record(0), Record(1), threshold.Selection.CanonicalBytes,
                threshold.LiveRoute.CanonicalBytes, threshold.Successor.CanonicalBytes, default, default, default, default, default, default, default, Record(12), issuance.ExactIssuanceAdh1], network, account);
        }
        internal Entry WithCompletion(VerifiedDeepIdV2ContactRouteClosure route, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if (Phase != 2) throw new InvalidOperationException("Completion requires retained threshold custody.");
            return Next(3, [Record(0), Record(1), Record(2), Record(3), Record(4),
                route.ExactXir1V2, route.ExactRouteClosure, default, default, default, default, default, Record(12), Record(13)], network, account);
        }
        internal Entry WithContactObject(AuthoredDeepIdV2ContactObject candidate, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if (Phase != 3) throw new InvalidOperationException("Contact object adoption requires completed route custody.");
            return Next(4, [Record(0), Record(1), Record(2), Record(3), Record(4), Record(5), Record(6),
                candidate.Closure.CanonicalBytes, candidate.ProtectedDcr1, default, default, default, Record(12), Record(13)], network, account);
        }

        internal Entry WithPublicationRequest(ContactPublicationAuthorityWireRequest request, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if (Phase != 4) throw new InvalidOperationException("Publication request requires protected contact object custody.");
            var encoded = ContactPublicationAuthorityWireCodec.EncodeRequest(request);
            try
            {
                return Next(5, [Record(0), Record(1), Record(2), Record(3), Record(4), Record(5), Record(6),
                    Record(7), Record(8), encoded, default, default, Record(12), Record(13)], network, account);
            }
            finally { CryptographicOperations.ZeroMemory(encoded); }
        }
        internal Entry WithPublicationResponse(ReadOnlyMemory<byte> exactResponse, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if (Phase != 5) throw new InvalidOperationException("Publication response requires exact pending request custody.");
            return Next(6, [Record(0), Record(1), Record(2), Record(3), Record(4), Record(5), Record(6),
                Record(7), Record(8), Record(9), exactResponse, default, Record(12), Record(13)], network, account);
        }

        internal Entry WithPublicationCommit(VerifiedDeepIdV2PublicationCommit result, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if (Phase != 6) throw new InvalidOperationException("Publication commit requires exact threshold response custody.");
            return Next(7, [Record(0), Record(1), Record(2), Record(3), Record(4), Record(5), Record(6),
                Record(7), Record(8), Record(9), Record(10), result.ExactXpo1, Record(12), Record(13)], network, account);
        }

        internal Entry RebindCommittedIntent(ReadOnlySpan<byte> intent, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if (Phase != 7) throw new InvalidOperationException("Only a verified completed renewal can replace current custody.");
            Required32(intent);
            var bytes = exact.ToArray();
            try { intent.CopyTo(bytes); return Decode(bytes, network, account); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }

        private Entry Next(byte phase, ReadOnlyMemory<byte>[] values, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            var prefix = exact.AsSpan(0, PrefixBytes).ToArray();
            try { prefix[32] = phase; return Build(prefix, values, network, account); }
            finally { CryptographicOperations.ZeroMemory(prefix); }
        }
        private static Entry Build(byte[] prefix, ReadOnlyMemory<byte>[] values, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if (values.Length != Limits.Length) throw new InvalidDataException("Protected route record count differs.");
            var size = PrefixBytes + 4 * Limits.Length;
            for (var index = 0; index < values.Length; index++)
            {
                if (values[index].Length > Limits[index]) throw new InvalidDataException("A route record exceeds its exact bound.");
                size = checked(size + values[index].Length);
            }
            var bytes = new byte[size];
            try
            {
                prefix.CopyTo(bytes, 0); var offset = PrefixBytes;
                foreach (var value in values)
                {
                    BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset), checked((uint)value.Length)); offset += 4;
                    value.Span.CopyTo(bytes.AsSpan(offset)); offset += value.Length;
                }
                return Decode(bytes, network, account);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        internal static Entry Decode(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if (bytes.Length is < PrefixBytes + 56 + 473 + 550 + ContactRouteAuthorityWireCodec.MinimumRequestBytes or > MaximumEntryBytes || bytes[32] is < 1 or > 7 ||
                bytes.Slice(33, 3).IndexOfAnyExcept((byte)0) >= 0 ||
                BinaryPrimitives.ReadUInt32BigEndian(bytes[36..]) is < 1 or > 65_535 ||
                BinaryPrimitives.ReadUInt16BigEndian(bytes[40..]) is < 1 or > 256)
                throw new InvalidDataException("A protected route phase/configuration is incompatible.");
            foreach (var start in new[] { 0, 42, 74, 106, 138 }) Required32(bytes.Slice(start, 32));
            var slices = new (int Start, int Length)[Limits.Length]; var offset = PrefixBytes; var phase = bytes[32];
            for (var index = 0; index < slices.Length; index++)
            {
                if (bytes.Length - offset < 4) throw new InvalidDataException("Protected route framing is truncated.");
                var size = BinaryPrimitives.ReadUInt32BigEndian(bytes[offset..]); offset += 4;
                if (size > Limits[index] || size > bytes.Length - offset ||
                    (index == 12 || index == 13 && phase >= 2 || index < 2 || phase >= 2 && index < 5 || phase >= 3 && index < 7 || phase >= 4 && index < 9 || phase >= 5 && index < 10 || phase >= 6 && index < 11 || phase == 7) != (size != 0))
                    throw new InvalidDataException("Protected route phase/record size differs.");
                slices[index] = (offset, checked((int)size)); offset += checked((int)size);
            }
            if (offset != bytes.Length) throw new InvalidDataException("Protected route has trailing bytes.");
            var dca = DeepIdV2ContactAuthorizationCodec.Decode(Slice(bytes, slices[0]));
            var xra = ContactCodec.Decode("XRA1", Slice(bytes, slices[1]));
            if (!Fixed(dca.NetworkId.Span, network) || !Fixed(dca.DeepAccountId.Span, account) ||
                !Fixed(xra.Field(1).Span, network) || !Fixed(xra.Field(14).Span, dca.PublisherDeviceId.Span) ||
                !Fixed(xra.Field(9).Span, bytes.Slice(42, 32)) || !Fixed(xra.Field(10).Span, bytes.Slice(106, 32)) ||
                BinaryPrimitives.ReadUInt32BigEndian(xra.Field(8).Span) != BinaryPrimitives.ReadUInt32BigEndian(bytes[36..]) ||
                !DeepIdentityCrypto.X25519PublicKeyMatchesPrivateScalar(bytes.Slice(74, 32), xra.Field(11).Span))
                throw new CryptographicException("Protected route configuration/key custody differs from its exact proposal.");
            var thresholdRequest = ContactRouteAuthorityWireCodec.DecodeRequest(Slice(bytes, slices[12]));
            if (!Fixed(thresholdRequest.NetworkId.Span, network) ||
                !Fixed(thresholdRequest.RequestNonce.Span, bytes.Slice(138, 32)) ||
                !Fixed(thresholdRequest.ExactDca1.Span, Slice(bytes, slices[0])) ||
                !Fixed(thresholdRequest.ExactXra1.Span, Slice(bytes, slices[1])))
                throw new CryptographicException("Protected route request differs from its exact owned proposal.");
            if (phase >= 2)
            {
                var issuanceHead = AccountDirectoryAdh1Codec.Decode(Slice(bytes, slices[13]));
                if (!Fixed(issuanceHead.NetworkId.Span, network))
                    throw new CryptographicException("Protected issuance head belongs to another network.");
                var threshold = new ParsedDeepIdV2RouteThreshold(Slice(bytes, slices[2]), Slice(bytes, slices[3]), Slice(bytes, slices[4]));
                if (!Fixed(threshold.Selection.Field(1).Span, network) || !Fixed(threshold.LiveRoute.Field(1).Span, network) ||
                    !Fixed(threshold.Successor.Field(1).Span, network) ||
                    !Fixed(threshold.LiveRoute.Field(5).Span, ContactCodec.ArtifactReference("XRA1", xra).CanonicalBytes.Span))
                    throw new CryptographicException("Protected threshold belongs to another route.");
            }
            if (phase >= 3)
            {
                var invite = DeepIdV2InviteRendezvousCodec.Decode(Slice(bytes, slices[5]));
                var closure = ContactRouteClosureCodec.Decode(Slice(bytes, slices[6]));
                if (!Fixed(invite.Field(1).Span, network) ||
                    !Fixed(invite.Field(16).Span[6..], dca.RecordHash.Span) ||
                    !Fixed(closure.Authorization.CanonicalBytes.Span, Slice(bytes, slices[1])) ||
                    !Fixed(closure.Selection.CanonicalBytes.Span, Slice(bytes, slices[2])) ||
                    !Fixed(closure.Route.CanonicalBytes.Span, Slice(bytes, slices[3])) ||
                    !Fixed(closure.Successor.CanonicalBytes.Span, Slice(bytes, slices[4])))
                    throw new CryptographicException("Protected completion differs from exact retained route custody.");
            }
            if (phase >= 4)
            {
                var closure = DeepIdV2ResolverClosureCodec.Decode(Slice(bytes, slices[7]));
                if (!Fixed(closure.Bundle.Field(6).Span, Slice(bytes, slices[0])) ||
                    !Fixed(closure.Bundle.Field(14).Span[40..], Slice(bytes, slices[5])) ||
                    !Fixed(closure.Bundle.Field(1).Span, network) || !Fixed(closure.Bundle.Field(2).Span, account) ||
                    BinaryPrimitives.ReadUInt64BigEndian(closure.Bundle.Field(8).Span) !=
                        BinaryPrimitives.ReadUInt64BigEndian(DeepIdV2InviteRendezvousCodec.Decode(Slice(bytes, slices[5])).Field(3).Span) ||
                    BinaryPrimitives.ReadUInt32BigEndian(closure.Bundle.Field(16).Span) != 9 ||
                    slices[8].Length != slices[7].Length + 40)
                    throw new CryptographicException("Protected contact object differs from its exact route/delegation custody.");
            }

            if (phase >= 5)
            {
                var request = ContactPublicationAuthorityWireCodec.DecodeRequest(Slice(bytes, slices[9]));
                if (!Fixed(request.ExactDca1.Span, Slice(bytes, slices[0])) ||
                    !Fixed(request.ExactDcr1.Span, Slice(bytes, slices[7])) ||
                    !Fixed(request.ObjectCiphertext.Span, Slice(bytes, slices[8])) ||
                    !Fixed(request.ExactRouteClosure.Span, Slice(bytes, slices[6])))
                    throw new CryptographicException("Protected publication request differs from exact owned object custody.");
                if (phase >= 6)
                {
                    var response = ContactPublicationAuthorityWireCodec.DecodeResponse(request, Slice(bytes, slices[10]));
                    if (phase == 7)
                    {
                        var xpu = Xpu1Codec.Decode(response.ExactXpu1.Span);
                        var result = Xpo1Codec.Decode(Slice(bytes, slices[11]), response.ExactXpu1.Span);
                        if (result.Status is not (Xpo1Status.Committed or Xpo1Status.ExactReplay) ||
                            result.MutationOutcome != ContactServiceMutationOutcome.DurablyCommitted ||
                            BinaryPrimitives.ReadUInt64BigEndian(result.Field(16).Span) != xpu.Generation ||
                            !Fixed(result.Field(17).Span, xpu.ObjectCiphertextHash.Span) ||
                            BinaryPrimitives.ReadUInt64BigEndian(result.Field(18).Span) != checked(xpu.Generation + 1))
                            throw new CryptographicException("Protected publication result is not its exact durable commit.");
                    }
                }
            }

            return new(bytes.ToArray(), slices);
        }
        private static ReadOnlySpan<byte> Slice(ReadOnlySpan<byte> value, (int Start, int Length) slice) => value.Slice(slice.Start, slice.Length);
        public void Dispose() => CryptographicOperations.ZeroMemory(exact);
    }

    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { using var state = new State(); return Encode(state, network, account, instance); }
    internal static byte[] Encode(State state, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        Scope(network, account, instance);
        if (state.Entries.Count > MaximumIntents) throw new IOException("Protected route capacity is exhausted.");
        var size = HeaderBytes; var reserved = HeaderBytes; ulong revision = 1;
        foreach (var pair in state.Entries)
        {
            using var checkedEntry = Entry.Decode(pair.Value.Exact, network, account);
            if (pair.Key != Convert.ToHexString(checkedEntry.Exact[..32])) throw new InvalidDataException("Protected route intent name differs.");
            size = checked(size + 4 + checkedEntry.Exact.Length); revision += checkedEntry.Phase;
            reserved = checked(reserved + 4 + checkedEntry.ReservedBytes);
        }
        if (reserved > MaximumBytes) throw new IOException("Protected route byte capacity is exhausted before publication.");
        var result = new byte[size]; result[0] = Version;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), checked((ushort)state.Entries.Count));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(4), revision);
        network.CopyTo(result.AsSpan(12)); account.CopyTo(result.AsSpan(28)); instance.CopyTo(result.AsSpan(60));
        var offset = HeaderBytes;
        foreach (var entry in state.Entries.Values)
        {
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset), checked((uint)entry.Exact.Length)); offset += 4;
            entry.Exact.CopyTo(result.AsSpan(offset)); offset += entry.Exact.Length;
        }
        return result;
    }
    internal static State Decode(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        Scope(network, account, instance);
        if (bytes.Length is < HeaderBytes or > MaximumBytes || bytes[0] != Version || bytes[1] != 0 ||
            !Fixed(bytes.Slice(12, 16), network) || !Fixed(bytes.Slice(28, 32), account) || !Fixed(bytes.Slice(60, 32), instance))
            throw new InvalidDataException("Protected route journal is incompatible or belongs to another account instance.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);
        if (count > MaximumIntents) throw new InvalidDataException("Protected route count is outside its bound.");
        var state = new State(); var offset = HeaderBytes; var reserved = HeaderBytes; ulong revision = 1; string? previous = null;
        try
        {
            for (var index = 0; index < count; index++)
            {
                if (bytes.Length - offset < 4) throw new InvalidDataException("Protected route journal is truncated.");
                var size = BinaryPrimitives.ReadUInt32BigEndian(bytes[offset..]); offset += 4;
                if (size > MaximumEntryBytes || size > bytes.Length - offset) throw new InvalidDataException("Protected route entry size is hostile.");
                var entry = Entry.Decode(bytes.Slice(offset, checked((int)size)), network, account); offset += checked((int)size);
                var name = Convert.ToHexString(entry.Exact[..32]);
                if (previous is not null && string.CompareOrdinal(previous, name) >= 0)
                { entry.Dispose(); throw new InvalidDataException("Protected route intents are duplicate or unsorted."); }
                state.Entries.Add(name, entry); previous = name; revision += entry.Phase;
                reserved = checked(reserved + 4 + entry.ReservedBytes);
                if (reserved > MaximumBytes) throw new InvalidDataException("Protected route reservation exceeds its byte capacity.");
            }
            if (offset != bytes.Length || BinaryPrimitives.ReadUInt64BigEndian(bytes[4..]) != revision)
                throw new InvalidDataException("Protected route revision/trailing bytes are noncanonical.");
            return state;
        }
        catch { state.Dispose(); throw; }
    }
    private static void Scope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { if (network.Length != 16 || network.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("Exact network scope is required."); Required32(account); Required32(instance); }
    private static void Required32(ReadOnlySpan<byte> bytes)
    { if (bytes.Length != 32 || bytes.IndexOfAnyExcept((byte)0) < 0) throw new InvalidDataException("An exact nonzero protected route field is required."); }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
