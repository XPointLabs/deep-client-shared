using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class ProtectedDid2MailboxReadJournal
{
    internal const int MaximumActiveCycleBytes = 6 * 32 + 4 * 8 + 4 * 4 + 364 + 5_000 + MaximumPageBytes + MaximumAckReplyBytes;
    internal const int MaximumNewCycleGrowthBytes = MaximumActiveCycleBytes + 32 + 8 + 32 + 8 + 8 + 4 + 256;

    // Reserve a complete next page/ACK before its issuer callback, not after
    // accepting a grant that cannot fit. Existing byte/counter bounds remain.
    internal static void RequireRoomForNewCycle(int idleRootBytes)
    {
        if (idleRootBytes < HeaderBytes || idleRootBytes > MaximumBytes - MaximumNewCycleGrowthBytes)
            throw new IOException("Protected mailbox read capacity cannot fit a complete new cycle; retained attempts cannot be evicted.");
    }

    // Local facts only; actual original SQL, holder and current lower-time
    // closure must be independently joined by the held account owner.
    internal sealed class ClosedAttempt : IDisposable
    {
        internal byte[] Grant = [], Scope = [], Route = [], RetrieveBody = [], MauHash = [], ExactMau = [];
        internal byte Phase;
        internal ulong PollGeneration, GrantExpiry, ClosedAtLower, Counter;

        internal static ClosedAttempt Capture(Cycle cycle, byte phase, ulong expiry, ulong lower, ReadOnlySpan<byte> exactMau)
        {
            if (cycle.CapturedAt != 0 || cycle.Page.Length != 0 || cycle.AckBody.Length != 0 ||
                cycle.AckCounter != 0 || !Zero(cycle.AckMauHash) || cycle.AckReply.Length != 0) throw Bad();
            var result = new ClosedAttempt
            {
                Grant = cycle.Grant.ToArray(), Scope = cycle.Scope.ToArray(), Route = cycle.Route.ToArray(),
                RetrieveBody = cycle.RetrieveBody.ToArray(), MauHash = cycle.RetrieveMauHash.ToArray(), ExactMau = exactMau.ToArray(),
                Phase = phase, PollGeneration = cycle.PollGeneration, GrantExpiry = expiry, ClosedAtLower = lower, Counter = cycle.RetrieveCounter
            };
            try { result.RequireShape(); return result; }
            catch { result.Dispose(); throw; }
        }

        internal void RequireShape()
        {
            Require32(Grant); Require32(Scope); Require32(Route);
            if (Phase is not (1 or 2) || GrantExpiry == 0 || ClosedAtLower < GrantExpiry ||
                RetrieveBody.Length is < 108 or > 364 || MauHash.Length != 32 || ExactMau.Length > 8_192 ||
                (Phase == 1 ? Counter != 0 || !Zero(MauHash) || ExactMau.Length != 0 : Counter == 0 || Zero(MauHash) || ExactMau.Length == 0)) throw Bad();
            _ = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(RetrieveBody);
            if (Phase == 1) return;
            var mau = MailboxAuthenticatedClientRequestCodec.Decode(ExactMau);
            if (mau.Binding.Operation != MailboxAuthenticatedOperation.Retrieve ||
                !Fixed(mau.Binding.CanonicalRequest.Span, RetrieveBody) || mau.Presentation.ReplayCounter != Counter ||
                mau.Presentation.Grant.Domain != MailboxCapabilityDomain.Retrieve ||
                mau.Presentation.Grant.ExpiresAtUnixSeconds != GrantExpiry ||
                !Fixed(SHA256.HashData(ExactMau), MauHash) ||
                !Fixed(SHA256.HashData(MailboxAuthenticatedCapabilityCodec.EncodeGrant(mau.Presentation.Grant)), Grant) ||
                !PublicKeyAuth.VerifyDetached(mau.Presentation.HolderSignature.ToArray(),
                    MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(mau.Presentation), mau.Presentation.Grant.HolderPublicKey.ToArray()))
                throw new CryptographicException("Closed Retrieve differs from its exact original signed frame.");
        }

        public void Dispose()
        {
            foreach (var bytes in new[] { Grant, Scope, Route, RetrieveBody, MauHash, ExactMau }) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void ReadClosed(ref Reader reader, State state, int count)
    {
        string? previous = null;
        for (var index = 0; index < count; index++)
        {
            var attempt = new ClosedAttempt();
            try
            {
                attempt.Grant = reader.Take(32).ToArray(); attempt.Scope = reader.Take(32).ToArray(); attempt.Route = reader.Take(32).ToArray();
                attempt.PollGeneration = reader.U64(); attempt.Phase = reader.Take(1)[0]; attempt.GrantExpiry = reader.U64(); attempt.ClosedAtLower = reader.U64();
                attempt.RetrieveBody = reader.Blob(364).ToArray(); attempt.Counter = reader.U64(); attempt.MauHash = reader.Take(32).ToArray(); attempt.ExactMau = reader.Blob(8_192).ToArray();
                attempt.RequireShape(); var name = Name(attempt.Grant);
                if (previous is not null && string.CompareOrdinal(previous, name) >= 0) throw Bad();
                state.Closed.Add(name, attempt); previous = name;
            }
            catch { attempt.Dispose(); throw; }
        }
    }

    private static void WriteClosed(Stream stream, State state)
    {
        foreach (var attempt in state.Closed.Values)
        {
            stream.Write(attempt.Grant); stream.Write(attempt.Scope); stream.Write(attempt.Route); Write64(stream, attempt.PollGeneration);
            stream.WriteByte(attempt.Phase); Write64(stream, attempt.GrantExpiry); Write64(stream, attempt.ClosedAtLower);
            WriteBlob(stream, attempt.RetrieveBody); Write64(stream, attempt.Counter); stream.Write(attempt.MauHash); WriteBlob(stream, attempt.ExactMau);
        }
    }

    private static void ValidateClosed(State state)
    {
        foreach (var pair in state.Closed)
        {
            var attempt = pair.Value; attempt.RequireShape();
            if (pair.Key != Name(attempt.Grant) ||
                !state.Traversals.TryGetValue(Name(attempt.Scope), out var traversal) || traversal.PollGeneration < attempt.PollGeneration ||
                attempt.Phase == 2 && state.Counters.GetValueOrDefault(pair.Key) != attempt.Counter ||
                state.Active is { } active && (Fixed(active.Grant, attempt.Grant) || Fixed(active.AckGrantHash, attempt.Grant))) throw Bad();
        }
    }
}
