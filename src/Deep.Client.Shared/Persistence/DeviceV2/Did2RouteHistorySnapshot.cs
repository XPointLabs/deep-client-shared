using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed class Did2RouteHistoryFactSelector
{
    private readonly byte[] selector;
    internal Did2RouteHistoryFactSelector(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector)
    {
        if (family is not (Did2MessagingArchiveFamily.RouteHistory or Did2MessagingArchiveFamily.RouteControl))
            throw new ArgumentException("A route-history selection requires a closed F7/F8 purpose.", nameof(family));
        Did2MessagingArchivePatricia.RequireSelector(family, selector); Family = family; this.selector = selector.ToArray();
    }
    internal Did2MessagingArchiveFamily Family { get; }
    internal ReadOnlyMemory<byte> Selector => selector;
}

internal sealed class Did2RouteHistorySelection
{
    internal const int MaximumFacts = 12;
    private readonly byte[] operation;
    internal Did2RouteHistorySelection(ReadOnlySpan<byte> operation, byte selectedAtomIndex,
        IReadOnlyList<Did2RouteHistoryFactSelector>? facts = null) : this(operation, selectedAtomIndex, facts, 0, false) { }
    private Did2RouteHistorySelection(ReadOnlySpan<byte> operation, byte selectedAtomIndex,
        IReadOnlyList<Did2RouteHistoryFactSelector>? facts, byte conflictClass, bool positionConflict)
    {
        if (operation.Length != 32 || Did2MessagingSessionScope.Zero(operation) || selectedAtomIndex > 3)
            throw new ArgumentException("An exact original operation and bounded atom index are required.");
        this.operation = operation.ToArray(); SelectedAtomIndex = selectedAtomIndex; Facts = Capture(facts);
        ConflictClass = conflictClass; IsPositionConflict = positionConflict;
        if (IsConflict && Facts.Count > 8) throw new ArgumentException("Conflict qualification exceeds its eight selected fact purposes.", nameof(facts));
    }
    private Did2RouteHistorySelection(bool initial, bool current, ReadOnlySpan<byte> operation, IReadOnlyList<Did2RouteHistoryFactSelector>? facts = null)
    { this.operation = operation.ToArray(); IsInitial = initial; IsCurrent = current; IsCustody = !initial && !current; Facts = Capture(facts); }
    internal static Did2RouteHistorySelection Initial(IReadOnlyList<Did2RouteHistoryFactSelector>? facts = null) => new(true, false, [], facts);
    internal static Did2RouteHistorySelection Current(Did2RouteHistoryFactSelector? completed = null)
    {
        if (completed is not null && (completed.Family != Did2MessagingArchiveFamily.RouteHistory || completed.Selector.Span[1] != 1))
            throw new ArgumentException("Current route resolution accepts only one completed-history selector.", nameof(completed));
        return new(false, true, [], completed is null ? null : [completed]);
    }
    internal static Did2RouteHistorySelection Current(IReadOnlyList<Did2RouteHistoryFactSelector> facts)
    {
        ArgumentNullException.ThrowIfNull(facts);
        if (facts.Count > 2 || facts.Any(fact => fact.Family != Did2MessagingArchiveFamily.RouteHistory))
            throw new ArgumentException("Current route resolution accepts only its endpoint C/P history facts.", nameof(facts));
        return new(false, true, [], facts);
    }
    internal static Did2RouteHistorySelection Custody(ReadOnlySpan<byte> operation)
    {
        if (operation.Length != 32 || Did2MessagingSessionScope.Zero(operation)) throw new ArgumentException("An exact native operation is required.", nameof(operation));
        return new(false, false, operation);
    }
    internal static Did2RouteHistorySelection Conflict(ReadOnlySpan<byte> operation, byte selectedAtomIndex, byte conflictClass,
        IReadOnlyList<Did2RouteHistoryFactSelector>? facts = null)
    {
        if (conflictClass is not (1 or 2) || selectedAtomIndex is < 1 or > 3)
            throw new ArgumentException("A signed conflict requires one exact C/P atom purpose.");
        return new(operation, selectedAtomIndex, facts, conflictClass, false);
    }
    internal static Did2RouteHistorySelection PositionConflict(ReadOnlySpan<byte> operation,
        IReadOnlyList<Did2RouteHistoryFactSelector>? facts = null)
    {
        var result = new Did2RouteHistorySelection(operation, 0, facts, 0, true);
        if (result.Facts.Count > 4 || result.Facts.Any(fact => fact.Family != Did2MessagingArchiveFamily.RouteHistory))
            throw new ArgumentException("Native position conflict accepts only four bounded adopted-history facts.", nameof(facts));
        return result;
    }
    internal bool IsInitial { get; }
    internal bool IsCurrent { get; }
    internal bool IsCustody { get; }
    internal bool IsPositionConflict { get; }
    internal byte ConflictClass { get; }
    internal bool IsConflict => ConflictClass != 0;
    internal int MaximumAuthoredOriginals => IsCurrent || IsCustody ? Did2RouteHistorySnapshot.MaximumCurrentAuthoredOriginals : Did2RouteHistorySnapshot.MaximumCatchupAuthoredOriginals;
    internal ReadOnlyMemory<byte> Operation => operation;
    internal byte SelectedAtomIndex { get; }
    internal IReadOnlyList<Did2RouteHistoryFactSelector> Facts { get; }
    private static IReadOnlyList<Did2RouteHistoryFactSelector> Capture(IReadOnlyList<Did2RouteHistoryFactSelector>? facts)
    {
        if (facts is null) return Array.Empty<Did2RouteHistoryFactSelector>();
        var count = facts.Count;
        if (count is < 0 or > MaximumFacts) throw new ArgumentException("A selected control exceeds its bounded fact inventory.", nameof(facts));
        var result = new List<Did2RouteHistoryFactSelector>(); var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var fact in facts)
        {
            var copy = new Did2RouteHistoryFactSelector(fact.Family, fact.Selector.Span);
            if (!seen.Add(((byte)copy.Family).ToString() + Convert.ToHexString(copy.Selector.Span)))
                throw new ArgumentException("A selected control repeats a typed fact.", nameof(facts));
            result.Add(copy);
            if (result.Count > count) throw new ArgumentException("The selected fact inventory changed its count.", nameof(facts));
        }
        if (result.Count != count) throw new ArgumentException("The selected fact inventory changed its count.", nameof(facts));
        return result.AsReadOnly();
    }
}

internal sealed record Did2RouteHistoryFact(Did2RouteHistoryFactSelector Selector, ReadOnlyMemory<byte>? Value)
{
    internal static Did2RouteHistoryFact Capture(Did2RouteHistoryFactSelector selector, byte[]? value) => value is null ?
        new(selector, (ReadOnlyMemory<byte>?)null) : new(selector, new ReadOnlyMemory<byte>(value.ToArray()));
}

internal sealed class Did2RouteHistoryStoredDecision : IDisposable
{
    internal Did2RouteHistoryStoredDecision(Did2MessagingArchiveReference reference, byte[] metadata, Did2RouteHistoryDecision body)
    { Reference = reference; Metadata = metadata; Body = body; }
    internal Did2MessagingArchiveReference Reference { get; }
    internal ReadOnlyMemory<byte> Metadata { get; }
    internal Did2RouteHistoryDecision Body { get; }
    public void Dispose() { if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(Metadata, out var value)) CryptographicOperations.ZeroMemory(value.AsSpan()); }
}

// Detached exact data from one actual native snapshot. It carries no Protocol
// qualification or current permission and must be physically rejoined after
// every provider edge. Sources are bounded and remain owned by this snapshot.
internal sealed class Did2RouteHistorySnapshot : IDisposable
{
    internal const int MaximumCurrentAuthoredOriginals = 71, MaximumCatchupAuthoredOriginals = 95;
    private readonly byte[] initialSessionInit, initialHello, transcript;
    internal Did2RouteHistorySnapshot(Did2MessagingSessionScope scope, Did2MessagingFloor before, byte subject,
        Did2MessagingArchiveRoot archiveRoot, Did2MessagingArchiveReducer reducer, Did2RouteHistorySelection selection,
        Did2RouteHistoryStoredDecision? previousDecision, Did2MessagingArchiveOriginal selectedOriginal,
        Did2MessagingArchiveOriginal anchorOriginal, IReadOnlyList<Did2MessagingArchiveOriginal> originals,
        IReadOnlyList<Did2RouteHistoryStoredDecision> decisions, IReadOnlyList<Did2RouteHistoryFact> facts,
        Did2MessagingArchiveReference l, Did2MessagingArchiveReference consent, Did2MessagingArchiveReference fault,
        byte[] initialSessionInit, byte[] initialHello, byte[] transcript,
        Did2MessagingArchiveReference? positionConflict = null, byte[]? positionConflictFact = null)
    {
        Scope = scope; Before = before; Subject = subject; ArchiveRoot = archiveRoot; Reducer = reducer; Selection = selection;
        PreviousDecision = previousDecision; SelectedOriginal = selectedOriginal; AnchorOriginal = anchorOriginal;
        Originals = originals; Decisions = decisions; Facts = facts; L = l; Consent = consent; FirstFault = fault;
        this.initialSessionInit = initialSessionInit; this.initialHello = initialHello; this.transcript = transcript;
        PositionConflict = positionConflict; PositionConflictFact = positionConflictFact is null ? (ReadOnlyMemory<byte>?)null : new ReadOnlyMemory<byte>(positionConflictFact);
    }
    internal Did2MessagingSessionScope Scope { get; }
    internal Did2MessagingFloor Before { get; }
    internal byte Subject { get; }
    internal Did2MessagingArchiveRoot ArchiveRoot { get; }
    internal Did2MessagingArchiveReducer Reducer { get; }
    internal Did2RouteHistorySelection Selection { get; }
    internal int MaximumAuthoredOriginals => Selection.MaximumAuthoredOriginals;
    internal Did2RouteHistoryStoredDecision? PreviousDecision { get; }
    internal Did2MessagingArchiveOriginal SelectedOriginal { get; }
    internal byte SelectedAtomIndex => Selection.SelectedAtomIndex;
    internal Did2MessagingArchiveReference Anchor => AnchorOriginal.Reference;
    internal Did2MessagingArchiveOriginal AnchorOriginal { get; }
    internal IReadOnlyList<Did2MessagingArchiveOriginal> Originals { get; }
    internal IReadOnlyList<Did2RouteHistoryStoredDecision> Decisions { get; }
    internal IReadOnlyList<Did2RouteHistoryFact> Facts { get; }
    internal Did2RouteHistorySource C => PreviousDecision?.Body.C ?? Did2RouteHistorySource.Absent();
    internal Did2RouteHistorySource P => PreviousDecision?.Body.P ?? Did2RouteHistorySource.Absent();
    internal Did2MessagingArchiveReference L { get; }
    internal Did2MessagingArchiveReference Consent { get; }
    internal Did2MessagingArchiveReference FirstFault { get; }
    internal Did2MessagingArchiveReference? PositionConflict { get; }
    internal ReadOnlyMemory<byte>? PositionConflictFact { get; }
    internal ReadOnlyMemory<byte> InitialSessionInit => initialSessionInit;
    internal ReadOnlyMemory<byte> InitialHello => initialHello;
    internal ReadOnlySpan<byte> Transcript => transcript;
    internal Did2MessagingArchiveOriginal FindOriginal(Did2MessagingArchiveReference reference) =>
        Originals.Single(row => Did2MessagingSessionScope.Fixed(row.Reference.Exact.Span, reference.Exact.Span));
    internal Did2RouteHistoryStoredDecision FindDecision(Did2MessagingArchiveReference reference) =>
        Decisions.Single(row => Did2MessagingSessionScope.Fixed(row.Reference.Exact.Span, reference.Exact.Span));
    public void Dispose()
    {
        foreach (var original in Originals) original.Dispose(); foreach (var decision in Decisions) decision.Dispose();
        CryptographicOperations.ZeroMemory(initialSessionInit); CryptographicOperations.ZeroMemory(initialHello); CryptographicOperations.ZeroMemory(transcript);
    }
}
