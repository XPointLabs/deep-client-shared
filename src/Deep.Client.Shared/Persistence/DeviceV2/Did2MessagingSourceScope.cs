using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Read-only source/history verification, never deletion/import authority.
internal static class Did2MessagingSourceScope
{
    internal static void RequireSender(Did2MessagingSessionScope scope, DeepIdV2InitialSessionCommit source)
    {
        RequireCommon(scope, true, source.CanonicalSpan, source.Record);
        if (!Did2MessagingSessionScope.Fixed(source.Directory.DirectoryHash.Span, scope.LocalDirectory))
            throw new CryptographicException("Mutable sender scope differs from its retained directory.");
    }
    internal static void RequireReceiver(Did2MessagingSessionScope scope, DeepIdV2InitialContactSessionCommit source)
    {
        RequireCommon(scope, false, source.CanonicalSpan, source.Record);
        if (!Did2MessagingSessionScope.Fixed(source.Directory.RecordHash.Span, scope.LocalDirectory) ||
            !Did2MessagingSessionScope.Fixed(source.ConversationId.Span, scope.Conversation))
            throw new CryptographicException("Mutable receiver scope differs from its retained contact/directory.");
    }
    private static void RequireCommon(Did2MessagingSessionScope scope, bool sender,
        ReadOnlySpan<byte> metadata, Dph2Record record)
    {
        if (scope.IsInitiator != sender || !Did2MessagingSessionScope.Fixed(SHA256.HashData(metadata), scope.InitialBasis) ||
            !Did2MessagingSessionScope.Fixed(record.NetworkId.Span, scope.Network) ||
            !Did2MessagingSessionScope.Fixed(record.SessionId.Span, scope.Session) ||
            !Did2MessagingSessionScope.Fixed(sender ? record.InitiatorAccountId.Span : record.ResponderAccountId.Span, scope.LocalAccount) ||
            !Did2MessagingSessionScope.Fixed(sender ? record.ResponderAccountId.Span : record.InitiatorAccountId.Span, scope.RemoteAccount) ||
            !Did2MessagingSessionScope.Fixed(sender ? record.InitiatorDeviceId.Span : record.ResponderDeviceId.Span, scope.LocalDevice) ||
            !Did2MessagingSessionScope.Fixed(sender ? record.ResponderDeviceId.Span : record.InitiatorDeviceId.Span, scope.RemoteDevice) ||
            (sender ? record.InitiatorDeviceGeneration : record.ResponderDeviceGeneration) != scope.LocalDeviceGeneration ||
            (sender ? record.ResponderDeviceGeneration : record.InitiatorDeviceGeneration) != scope.RemoteDeviceGeneration)
            throw new CryptographicException("Mutable messaging scope has no exact authenticated source.");
    }

    internal static void RequireRetirement(ProtectedInitialKeyRetirementJournal.Entry? entry,
        Did2MessagingSessionScope scope, bool requireRetired, bool live)
    {
        if (entry is not null && (!Did2MessagingSessionScope.Fixed(entry.ScopeHash, scope.Hash) ||
            !Did2MessagingSessionScope.Fixed(entry.Basis, scope.InitialBasis)) ||
            requireRetired && (entry is null || entry.Phase != 2 || live))
            throw new CryptographicException("Mutable messaging has a different/incomplete source retirement.");
    }
}
