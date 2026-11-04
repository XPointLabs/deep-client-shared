using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    private sealed partial class Fixture
    {
        // Canonical untrusted anchor DATA for Protocol-level signed-graph
        // tests only. This is never submitted to a native session or presented
        // as authenticated Hello/consent. Real XUR/DCA/route signatures remain
        // independently verified by their existing owners.
        private async Task<ParsedDmc2> RouteHistoryFixtureAnchorDataAsync(ParsedDeepIdV2ContactMailboxRoute package,
            ReadOnlyMemory<byte> relationship, ReadOnlyMemory<byte> conversation)
        {
            var intent = RandomNumberGenerator.GetBytes(32);
            VerifiedDeepIdV2ContactUpdateRendezvous rendezvous;
            try { rendezvous = await accounts.EnsureOwnContactRendezvousAsync(intent, Source()); }
            finally { CryptographicOperations.ZeroMemory(intent); }
            var route = package.ExactBytes;
            var payload = new byte[682 + route.Length]; relationship.Span.CopyTo(payload);
            "DAB2"u8.CopyTo(payload.AsSpan(32)); BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(36), 2);
            checkpoint.Binding.Record.RecordHash.Span.CopyTo(payload.AsSpan(38));
            checkpoint.Directory.Record.RecordHash.Span.CopyTo(payload.AsSpan(70));
            SHA256.HashData(checkpoint.Binding.Record.CanonicalBytes.Span).CopyTo(payload, 102);
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(134), (ushort)ContactPolicy.AllowRouteUpdates);
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(136), 538);
            rendezvous.ExactXur1.Span.CopyTo(payload.AsSpan(140));
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(678), checked((uint)route.Length)); route.Span.CopyTo(payload.AsSpan(682));
            var template = ApplicationCoreCodec.AuthorDmc2(Network, Bytes(32, 0xba), conversation.Span,
                checkpoint.Binding.Record.DeepAccountId.Span, checkpoint.Binding.Identity.ActiveDevices.Single().Certificate.DeviceId.Span,
                2, 1_000_000, 1_001_000, Dmc2Flags.None, [], ApplicationCoreCodec.CreateMessageCreatePayload("untrusted historical anchor data"));
            var exact = ReplaceControlPayload(template, payload);
            BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(FieldOffset(exact, 9)), (ushort)Dmc2ContentKind.ContactHello);
            return ApplicationCoreCodec.DecodeDmc2(exact);
        }

        private static ContactRouteAuthorityWireRequest RouteHistoryFixtureRequest(DeepIdV2CurrentContactAuthorization recipient,
            VerifiedDeepIdV2ContactRoutePredecessor predecessor, ReadOnlyMemory<byte> advertisement, byte nonce) =>
            new(recipient.Freshness.NetworkId.Span, Bytes(32, nonce), recipient.Freshness.QueriedDirectoryLeafKey.Span,
                recipient.Freshness.NextProtectedLkg.LogGeneration, recipient.Freshness.NextProtectedLkg.CoreHash.Span,
                recipient.Authorization.Record.CanonicalBytes.Span, advertisement.Span,
                predecessor.ExactXir1V2.Span, predecessor.ExactRouteClosure.Span);

        // The exact ordinary request exists BEFORE the real test witnesses
        // issue its threshold. The response keeps that nonce and actual ADH;
        // no later threshold is retrofitted into a pretend original exchange.
        private async Task<(ParsedDeepIdV2RouteThreshold Threshold, DeepIdV2ContactRouteRecordedPair Pair)> IssueRouteHistoryFixtureAsync(
            ContactRouteAuthorityWireRequest request, DeepIdV2CurrentContactAuthorization recipient,
            VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
            VerifiedDeepIdV2ContactRoutePredecessor predecessor, ulong expiry, OnionTrustedTimeAuthority time,
            CancellationToken ct = default, RouteWitness[]? signers = null)
        {
            var threshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdSuccessorAsync(recipient, network, authority,
                predecessor, request.ExactXra1, signers ?? CreateRouteWitnesses(), expiry, time, ct);
            var issuance = await DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(recipient, network, authority,
                request, threshold, recipient.Freshness.ExactAdh1, time, ct);
            return (threshold, RouteHistoryFixturePair(issuance));
        }

        private static DeepIdV2ContactRouteRecordedPair RouteHistoryFixturePair(VerifiedDeepIdV2ContactRouteIssuance issuance)
        {
            var request = issuance.Request; var threshold = issuance.Threshold;
            var response = new ContactRouteAuthorityWireResponse(request.NetworkId.Span, request.RequestNonce.Span,
                threshold.Selection.CanonicalBytes.Span, threshold.LiveRoute.CanonicalBytes.Span,
                threshold.Successor.CanonicalBytes.Span, issuance.ExactIssuanceAdh1.Span);
            return new(ContactRouteAuthorityWireCodec.EncodeRequest(request), ContactRouteAuthorityWireCodec.EncodeResponse(request, response));
        }
    }
}
