using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using static Deep.Client.Shared.Production.Tests.Did2RouteHistoryDecisionTests;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2MessagingArchiveRouteFactsTests
{
    [Fact]
    public void CandidatesCannotOverwriteFirstVerifiedIdentityOrManufactureAFault()
    {
        var scope = Scope(); var selector = Did2MessagingArchiveRouteFacts.HistorySelector(2, 1, 8);
        var builder = Builder(scope);
        var first = Did2RouteHistorySource.From(Event(2, 3, 10), 1);
        var fresh = Did2RouteHistorySource.From(Event(2, 5, 11), 2);
        builder.Add(Did2MessagingArchiveFamily.RouteHistory, selector, Did2MessagingArchiveRouteFacts.Candidate(first, 10));
        builder.Add(Did2MessagingArchiveFamily.RouteHistory, selector, Did2MessagingArchiveRouteFacts.Verified(Decision(6, 40), Hash(1)));
        builder.Add(Did2MessagingArchiveFamily.RouteHistory, selector, Did2MessagingArchiveRouteFacts.Candidate(fresh, 12));
        builder.Add(Did2MessagingArchiveFamily.RouteHistory, selector, Did2MessagingArchiveRouteFacts.Candidate(first, 10));
        var value = builder.Read(Did2MessagingArchiveFamily.RouteHistory, selector)!;
        Assert.Equal(Decision(6, 40).Exact.ToArray(), value[..88]); Assert.Equal(Hash(1), value[88..120]);
        Assert.Equal(fresh.Exact.ToArray(), value[120..216]); Assert.Equal(12UL, BinaryPrimitives.ReadUInt64BigEndian(value.AsSpan(216)));
        var root = builder.Complete().PatriciaHash.ToArray();
        Assert.Throws<CryptographicException>(() => builder.Add(Did2MessagingArchiveFamily.RouteHistory, selector,
            Did2MessagingArchiveRouteFacts.Verified(Decision(7, 41), Hash(2))));
        Assert.Equal(root, builder.Complete().PatriciaHash.ToArray());
    }

    [Fact]
    public void LatestRequestProofRetainsGreatestSequenceAndEarliestExactDuplicate()
    {
        var scope = Scope(); var selector = Did2MessagingArchiveRouteFacts.LatestRequestSelector(); var builder = Builder(scope);
        var late = Request(Event(1, 8, 20), 12); var first = Request(Event(1, 4, 21), 12);
        builder.Add(Did2MessagingArchiveFamily.RouteControl, selector, late);
        builder.Add(Did2MessagingArchiveFamily.RouteControl, selector, Request(Event(1, 3, 22), 10));
        builder.Add(Did2MessagingArchiveFamily.RouteControl, selector, first);
        var result = builder.Complete(); var node = Assert.Single(result.Nodes);
        Assert.Equal(first, Did2MessagingArchivePatricia.VerifyProof(scope, result.PatriciaHash.Span,
            Did2MessagingArchiveFamily.RouteControl, selector, [node.Exact]));
        Assert.Null(Did2MessagingArchivePatricia.VerifyProof(scope, result.PatriciaHash.Span,
            Did2MessagingArchiveFamily.RouteControl, Did2MessagingArchiveRouteFacts.CorrelationSelector(2, Hash(80)), [node.Exact]));
        Assert.Throws<InvalidDataException>(() => Did2MessagingArchivePatricia.VerifyProof(scope, result.PatriciaHash.Span,
            Did2MessagingArchiveFamily.RouteControl, selector, []));
        Assert.Equal(result.PatriciaHash.ToArray(), builder.Complete().PatriciaHash.ToArray());
    }

    [Theory]
    [InlineData("direction")] [InlineData("short")] [InlineData("trailing")]
    [InlineData("incoming")] [InlineData("zero-sequence")]
    public void LatestRequestRejectsForeignDirectionOrNoncanonicalShape(string defect)
    {
        var selector = new byte[] { 4, 1 }; var value = Request(Event(1, 4, 20), 10);
        switch (defect)
        {
            case "direction": selector[1] = 2; break;
            case "short": selector = [4]; break;
            case "trailing": selector = [4, 1, 0]; break;
            case "incoming": value[1] = 2; break;
            case "zero-sequence": value.AsSpan(88).Clear(); break;
        }
        Assert.Throws<InvalidDataException>(() => Did2MessagingArchivePatricia.Leaf(Scope(), Did2MessagingArchiveFamily.RouteControl, selector, value));
    }

    [Fact]
    public void PurposesKeepOrdinaryBoundsAndRejectUnboundedHistorySelectorsBeforeAnyStorage()
    {
        Assert.Equal(71, Did2RouteHistorySelection.Current().MaximumAuthoredOriginals);
        Assert.Equal(71, Did2RouteHistorySelection.Custody(Hash(1)).MaximumAuthoredOriginals);
        Assert.Equal(95, Did2RouteHistorySelection.Initial().MaximumAuthoredOriginals);
        var facts = Enumerable.Range(0, 13).Select(index => new Did2RouteHistoryFactSelector(Did2MessagingArchiveFamily.RouteHistory,
            Did2MessagingArchiveRouteFacts.HistorySelector(1, 2, checked((ulong)index)))).ToArray();
        Assert.Throws<ArgumentException>(() => Did2RouteHistorySelection.Initial(facts));
        Assert.Throws<ArgumentException>(() => Did2RouteHistorySelection.Current(facts[..3]));
        Assert.Equal(95, Did2RouteHistorySelection.Conflict(Hash(1), 1, 2, facts[..8]).MaximumAuthoredOriginals);
        Assert.Throws<ArgumentException>(() => Did2RouteHistorySelection.Conflict(Hash(1), 1, 2, facts[..9]));
        Assert.Throws<ArgumentException>(() => Did2RouteHistorySelection.PositionConflict(Hash(1), facts[..5]));
    }

    [Fact]
    public void ActualSelectedFactAbsenceRemainsNullAndCapturedPresentBytesAreOwned()
    {
        var selector = new Did2RouteHistoryFactSelector(Did2MessagingArchiveFamily.RouteControl, Did2MessagingArchiveRouteFacts.LatestRequestSelector());
        Assert.Null(Did2RouteHistoryFact.Capture(selector, null).Value);
        var actual = Request(Event(1, 4, 20), 10); var expected = actual.ToArray();
        var fact = Did2RouteHistoryFact.Capture(selector, actual); actual.AsSpan().Clear();
        Assert.True(fact.Value.HasValue); Assert.Equal(expected, fact.Value.GetValueOrDefault().ToArray());
    }

    private static Did2MessagingArchiveBuilder Builder(Did2MessagingSessionScope scope) =>
        new(scope, Did2MessagingArchiveReducer.Empty(scope).Basis.Ordinal == 0 ? Did2MessagingArchiveRoot.Empty(scope).PatriciaHash : throw new InvalidOperationException(), static _ => null);
    private static byte[] Request(Did2MessagingArchiveReference reference, ulong sequence)
    { var value = new byte[96]; reference.Exact.Span.CopyTo(value); BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(88), sequence); return value; }
}
