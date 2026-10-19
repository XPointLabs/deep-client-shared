using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Services.ContactV2;

public sealed partial class DeepIdV2ContactPathAuthoritySource
{
    // One immutable public grammar frame, never a native row, proof, currentness
    // result or private/key cache. Atomic publication also supports callers that
    // share a source; no mutable parser result is returned to external code.
    private sealed record MailboxGrammar(byte[] ProjectionBytes, byte[][] PolicyBytes,
        ContactRecord Projection, ContactRecord[] Policies);
    private MailboxGrammar? mailboxGrammar;
    private long mailboxInputDecodes;
    internal long MailboxInputDecodes => Interlocked.Read(ref mailboxInputDecodes);

    private (ContactRecord Projection, ContactRecord[] Policies) ParseMailboxInputs(DeepIdV2NetworkClosureArtifacts exact)
    {
        var projection = exact.ExactOrderedPmt2Chain[^1];
        var policies = exact.ExactOrderedPma2Chain;
        var memo = Volatile.Read(ref mailboxGrammar);
        if (memo is not null && projection.Span.SequenceEqual(memo.ProjectionBytes) &&
            memo.PolicyBytes.Length == policies.Count &&
            !policies.Where((bytes, index) => !bytes.Span.SequenceEqual(memo.PolicyBytes[index])).Any())
            return (memo.Projection, memo.Policies);
        var parsed = (Projection: ContactCodec.Decode("PMT2", projection.Span),
            Policies: policies.Select(bytes => ContactCodec.Decode("PMA2", bytes.Span)).ToArray());
        Interlocked.Increment(ref mailboxInputDecodes);
        // Larger valid inputs use the full parser, not a new wire limit.
        var keep = projection.Length + policies.Sum(bytes => (long)bytes.Length) <= 4 * 1024 * 1024;
        Volatile.Write(ref mailboxGrammar, keep ? new(projection.ToArray(),
            policies.Select(bytes => bytes.ToArray()).ToArray(), parsed.Projection, parsed.Policies) : null);
        return parsed;
    }
}
