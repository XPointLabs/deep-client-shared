namespace Deep.Client.Shared.Features;

public sealed record ClientFeatureFlags(
    bool GroupsV2Enabled = true,
    bool CommunitiesEnabled = false,
    bool CallsEnabled = false,
    bool ShareExtensionEnabled = false,
    bool AttachmentEncryptionEnabled = true,
    bool BackgroundSyncEnabled = true,
    bool PushNotificationsEnabled = true,
    bool TransportRequired = false,
    bool StubTransportAllowed = true,
    bool MembershipTrustEnabled = false,
    bool PersistentTransportOutboxEnabled = false,
    bool MetadataPrivateTransportRequired = false,
    bool ClientMailboxAdapterEnabled = false)
{
    public static ClientFeatureFlags Defaults { get; } = new();

    public static ClientFeatureFlags ReleaseDefaults { get; } = new(
        GroupsV2Enabled: true,
        CommunitiesEnabled: false,
        CallsEnabled: true,
        ShareExtensionEnabled: false,
        AttachmentEncryptionEnabled: true,
        BackgroundSyncEnabled: true,
        PushNotificationsEnabled: true,
        TransportRequired: true,
        StubTransportAllowed: false,
        MembershipTrustEnabled: false,
        PersistentTransportOutboxEnabled: false,
        MetadataPrivateTransportRequired: true,
        ClientMailboxAdapterEnabled: false);
}

public sealed class FeatureDisabledException(string featureName)
    : NotSupportedException($"{featureName} is currently behind a feature flag.");
