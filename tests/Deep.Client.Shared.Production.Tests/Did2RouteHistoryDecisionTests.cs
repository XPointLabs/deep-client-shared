using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2RouteHistoryDecisionTests
{
    [Fact]
    public void NativeDecisionRecoveryKeepsExactBodyAndRatchetWithoutManufacturingAnEvent()
    {
        var scope = Scope(); var before = Stable(scope); var body = Body(scope); var payload = Payload(scope, before, body);
        var pending = Pending(scope, before, payload);
        using var mutation = OwnedDid2MessagingMutation.RecoverProtectedPending(scope, pending, payload);
        Assert.Equal(6, mutation.Kind); Assert.Equal(0, mutation.Direction); Assert.Equal(1696, mutation.Exact.Length);
        Assert.Equal(body, mutation.RouteDecisionBody.ToArray());
        Assert.Empty(mutation.NextTrs.ToArray()); Assert.Empty(mutation.Envelope.ToArray());
        Assert.Empty(mutation.SessionInit.ToArray()); Assert.Empty(mutation.ContactHello.ToArray());
        Assert.Throws<InvalidOperationException>(() => mutation.AuthenticatedDmc2.ToArray());
        var after = mutation.Successor.Cleanup(scope).Stable(scope);
        Assert.Equal(before.Ordinal + 1, after.Ordinal);
        Assert.Equal(before.Exact.Slice(76, 72).ToArray(), after.Exact.Slice(76, 72).ToArray());
        var expected = SHA256.HashData([.. Encoding.UTF8.GetBytes("Deep/STORE-V2/route-history-decision"), 0,
            .. scope.Hash, .. before.Exact.Span, .. SHA256.HashData(body)]);
        Assert.Equal(expected, mutation.Operation.ToArray());
    }

    [Theory]
    [InlineData(6)] [InlineData(7)] [InlineData(196)] [InlineData(204)] [InlineData(236)]
    [InlineData(332)] [InlineData(587)] [InlineData(588)] [InlineData(592)] [InlineData(596)]
    [InlineData(600)] [InlineData(604)] [InlineData(608)] [InlineData(671)]
    public void MetadataOnlyDecisionValidationRejectsChangedRetainedStateEvidenceOrBodyLengths(int offset)
    {
        var scope = Scope(); var payload = Payload(scope, Stable(scope), Body(scope)); var header = payload[..672];
        header[offset] ^= 1;
        Assert.Throws<InvalidDataException>(() => OwnedDid2MessagingMutation.ValidateMetadata(header));
    }

    [Theory]
    [InlineData("related-direction")] [InlineData("related-atom")] [InlineData("related-reserved")]
    [InlineData("selected-direction")] [InlineData("selected-atom")]
    [InlineData("unknown-action")] [InlineData("old-outcome-interval")] [InlineData("trailing")]
    public void ConflictBodyRejectsMalformedSourcesAndNeverTreatsStagedBytesAsQualification(string defect)
    {
        var scope = Scope(); var body = Body(scope, conflict: true);
        switch (defect)
        {
            case "related-direction": body[773] = 2; break;
            case "related-atom": body[860] = 4; break;
            case "related-reserved": body[861] = 1; break;
            case "selected-direction": body[125] = 2; break;
            case "selected-atom": body[212] = 4; break;
            case "unknown-action": body[1] = 5; break;
            case "old-outcome-interval": body[676] = 2; break;
            case "trailing": body = [.. body, 0]; break;
        }
        Assert.Throws<InvalidDataException>(() => Did2RouteHistoryDecision.Decode(body, scope));
    }

    [Theory]
    [InlineData(268)] [InlineData(300)] [InlineData(672 + 740)]
    public void ProtectedPayloadHashCannotRepairChangedDecisionOperationOrBodyBinding(int offset)
    {
        var scope = Scope(); var before = Stable(scope); var payload = Payload(scope, before, Body(scope)); payload[offset] ^= 1;
        var pending = Pending(scope, before, payload);
        Assert.Throws<CryptographicException>(() => OwnedDid2MessagingMutation.RecoverProtectedPending(scope, pending, payload));
    }

    [Fact]
    public void ReducerUsesExplicitDecisionOffsetsAndRejectsPredecessorWidth()
    {
        var scope = Scope(); var raw = Did2MessagingArchiveReducer.Empty(scope).Exact.ToArray();
        Stable(scope).Exact.Span.CopyTo(raw.AsSpan(36)); Hash(90).CopyTo(raw, 224); raw[899] = 1;
        var own = Decision(5, 90); var peer = Decision(6, 91);
        own.Exact.Span.CopyTo(raw.AsSpan(904)); peer.Exact.Span.CopyTo(raw.AsSpan(992));
        var reducer = Did2MessagingArchiveReducer.Decode(raw, scope);
        Assert.Equal(1136, reducer.Exact.Length);
        Assert.Equal(own.Exact.ToArray(), reducer.Reference(Did2MessagingArchiveReducer.ReferenceKind.OwnDecision).Exact.ToArray());
        Assert.Equal(peer.Exact.ToArray(), reducer.Reference(Did2MessagingArchiveReducer.ReferenceKind.PeerDecision).Exact.ToArray());
        Assert.Equal(raw[872..904], reducer.Exact.Slice(872, 32).ToArray());
        Assert.Throws<InvalidDataException>(() => Did2MessagingArchiveReducer.Decode(raw[..960], scope));
        raw[1080] = 1; Assert.Throws<InvalidDataException>(() => Did2MessagingArchiveReducer.Decode(raw, scope));
    }

    internal static byte[] Hash(int value) => SHA256.HashData(Encoding.UTF8.GetBytes("route decision fixture " + value));
    internal static Did2MessagingSessionScope Scope()
    {
        var raw = new byte[404]; raw[0] = 1; raw[1] = 1; raw.AsSpan(4, 16).Fill(1);
        foreach (var offset in new[] { 20, 52, 92, 132, 172, 212, 244, 276, 308, 340, 372 }) Hash(offset).CopyTo(raw, offset);
        foreach (var offset in new[] { 84, 124, 164, 204 }) Put(raw, offset, 1);
        return Did2MessagingSessionScope.RestoreMetadata(raw);
    }
    internal static Did2MessagingArchiveReference Event(byte direction, ulong ordinal, ulong rowId) =>
        Did2MessagingArchiveReference.Event(direction, ordinal, rowId, Hash(checked((int)ordinal)), Hash(checked((int)rowId + 100)));
    internal static Did2MessagingArchiveReference Decision(ulong ordinal, ulong rowId) =>
        Did2MessagingArchiveReference.Decision(ordinal, rowId, Hash(checked((int)ordinal + 200)), Hash(checked((int)rowId + 300)));
    internal static Did2MessagingFloor Stable(Did2MessagingSessionScope scope)
    {
        var raw = Did2MessagingFloor.Empty(scope).Exact.ToArray(); raw[2] = 1; Put(raw, 36, 10); Hash(1).CopyTo(raw, 44);
        Put(raw, 76, 4); Hash(2).CopyTo(raw, 84); Hash(3).CopyTo(raw, 116); return Did2MessagingFloor.Decode(raw, scope);
    }
    private static byte[] Body(Did2MessagingSessionScope scope, bool conflict = false)
    {
        var raw = new byte[1024]; raw[0] = 1; raw[1] = conflict ? (byte)4 : (byte)1; raw[2] = 1; scope.Hash.CopyTo(raw.AsSpan(4));
        var initial = Did2MessagingArchiveReference.Initial(Hash(4));
        (conflict ? Decision(5, 20) : Did2MessagingArchiveReference.Absent()).Exact.Span.CopyTo(raw.AsSpan(36));
        (conflict ? Event(1, 7, 21) : initial).Exact.Span.CopyTo(raw.AsSpan(124)); raw[212] = conflict ? (byte)1 : (byte)0;
        Did2RouteHistorySource.From(initial, 0).Exact.Span.CopyTo(raw.AsSpan(220));
        Did2RouteHistorySource.From(initial, 0).Exact.Span.CopyTo(raw.AsSpan(316));
        Event(1, 8, 22).Exact.Span.CopyTo(raw.AsSpan(412)); Event(2, 3, 23).Exact.Span.CopyTo(raw.AsSpan(588));
        raw[676] = 3; Put(raw, 684, 1000); Put(raw, 692, 2000); Put(raw, 700, 1); Hash(5).CopyTo(raw, 708); Hash(6).CopyTo(raw, 740);
        if (conflict) Did2RouteHistorySource.From(Event(1, 4, 24), 1).Exact.Span.CopyTo(raw.AsSpan(772));
        return raw;
    }
    private static byte[] Payload(Did2MessagingSessionScope scope, Did2MessagingFloor before, byte[] body)
    {
        var header = new byte[672]; "MSP2"u8.CopyTo(header); header[4] = 2; header[5] = 6; header[7] = 1;
        before.Exact.Span.CopyTo(header.AsSpan(8)); before.Exact.Span.Slice(76, 72).CopyTo(header.AsSpan(196));
        SHA256.HashData(body).CopyTo(header, 300);
        SHA256.HashData([.. Encoding.UTF8.GetBytes("Deep/STORE-V2/route-history-decision"), 0, .. scope.Hash, .. before.Exact.Span, .. SHA256.HashData(body)]).CopyTo(header, 268);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(596), 1024); return [.. header, .. body];
    }
    private static Did2MessagingFloor Pending(Did2MessagingSessionScope scope, Did2MessagingFloor before, byte[] payload) =>
        Did2MessagingFloor.Pending(scope, before, 1, before.RatchetGeneration, before.RatchetCommitment, before.RatchetHash, payload.AsSpan(0, 672), payload);
    private static void Put(byte[] raw, int offset, ulong value) => BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(offset), value);
}
