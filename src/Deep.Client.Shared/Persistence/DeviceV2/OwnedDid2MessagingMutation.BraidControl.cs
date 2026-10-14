using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class OwnedDid2MessagingMutation
{
    internal static OwnedDid2MessagingMutation BraidControl(Did2MessagingSessionScope scope,
        Did2MessagingFloor stable, ExactBraidRecoveryPersistencePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        _ = Did2MessagingFloor.Decode(stable.Exact.Span, scope);
        var prior = plan.PriorTrs1.ToArray(); var next = plan.NextTrs1.ToArray();
        try
        {
            if (stable.Phase != 1 || stable.Status != 1 || !plan.HasStateMutation || stable.RatchetGeneration == ulong.MaxValue ||
                plan.PriorStateGeneration != stable.RatchetGeneration || plan.NextStateGeneration != stable.RatchetGeneration + 1 ||
                plan.CheckpointPriorGeneration != stable.RatchetGeneration || plan.ExpectedJournalGeneration != stable.Ordinal ||
                !Fixed(plan.PriorStateCommitment.Span, stable.RatchetCommitment) ||
                !Fixed(plan.CheckpointPriorCommitment.Span, stable.RatchetCommitment) ||
                !Fixed(plan.JournalPredecessor.Span, stable.Head) || !Fixed(SHA256.HashData(prior), stable.RatchetHash))
                throw new CryptographicException("Braid control differs from its active protected predecessor.");
            var before = Facts(prior, scope); var after = Facts(next, scope);
            if (before.Generation != stable.RatchetGeneration || !Fixed(before.StateCommitment, stable.RatchetCommitment) ||
                after.Generation != plan.NextStateGeneration || !Fixed(after.StateCommitment, plan.NextStateCommitment.Span) || after.TerminallyLatched)
                throw new CryptographicException("Braid control state differs from its sealed successor.");
            var direction = plan.Direction switch
            {
                ExactBraidRecoveryDurableDirection.Send => (byte)3,
                ExactBraidRecoveryDurableDirection.Receive => (byte)4,
                _ => throw new InvalidDataException("Braid control direction is unknown."),
            };
            var header = HeaderFor(5, direction, 1, stable, plan.NextStateGeneration, plan.NextStateCommitment.Span,
                SHA256.HashData(next), plan.OperationId.Span, plan.ExactControlHash.Span, plan.ExactControlHash.Span);
            Put(header, 364, plan.ExactHeaderHash.Span); Put(header, 396, plan.DeletionManifestCommitment.Span);
            Put(header, 460, plan.ExactControlHash.Span);
            return Encode(scope, header, next, plan.ExactControl.Span, [], [], []);
        }
        finally { CryptographicOperations.ZeroMemory(prior); CryptographicOperations.ZeroMemory(next); }
    }

    internal static void RequireControlEnvelope(Did2MessagingSessionScope scope, int direction,
        ReadOnlySpan<byte> operation, ReadOnlySpan<byte> metadata, ReadOnlySpan<byte> exactControl)
    {
        ValidateMetadata(metadata);
        if (metadata[5] != 5 || direction is not (3 or 4) || metadata[6] != direction)
            throw new InvalidDataException("Retained Braid control has a different closed kind/direction.");
        var control = Dbr2Codec.Decode(exactControl); var hash = SHA256.HashData(exactControl);
        var projection = Dbr2Codec.GetAuthenticationInput(control);
        try
        {
            if (!Fixed(control.NetworkId.Span, scope.Network) || !Fixed(control.SessionId.Span, scope.Session) ||
                !Fixed(control.SenderDeviceId.Span, direction == 3 ? scope.LocalDevice : scope.RemoteDevice) ||
                !Fixed(control.RecipientDeviceId.Span, direction == 3 ? scope.RemoteDevice : scope.LocalDevice) ||
                !Fixed(control.OperationId.Span, operation) || !Fixed(operation, metadata.Slice(268, 32)) ||
                !Fixed(hash, metadata.Slice(300, 32)) || !Fixed(hash, metadata.Slice(332, 32)) ||
                !Fixed(hash, metadata.Slice(460, 32)) || !Fixed(SHA256.HashData(projection), metadata.Slice(364, 32)))
                throw new CryptographicException("Braid control differs from its exact committed metadata.");
        }
        finally { CryptographicOperations.ZeroMemory(projection); }
    }
}
