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
    bool LegacyEmbeddedBootstrapRollbackAllowed = false,
    bool PersistentTransportOutboxEnabled = false,
    bool MetadataPrivateTransportRequired = false,
    bool ClientMailboxAdapterEnabled = false)
{
    public ClientFeatureFlags(
        bool groupsV2Enabled,
        bool communitiesEnabled,
        bool callsEnabled,
        bool shareExtensionEnabled,
        bool attachmentEncryptionEnabled,
        bool backgroundSyncEnabled,
        bool pushNotificationsEnabled,
        bool transportRequired,
        bool stubTransportAllowed,
        bool membershipTrustEnabled,
        bool legacyEmbeddedBootstrapRollbackAllowed)
        : this(
            groupsV2Enabled,
            communitiesEnabled,
            callsEnabled,
            shareExtensionEnabled,
            attachmentEncryptionEnabled,
            backgroundSyncEnabled,
            pushNotificationsEnabled,
            transportRequired,
            stubTransportAllowed,
            membershipTrustEnabled,
            legacyEmbeddedBootstrapRollbackAllowed,
            PersistentTransportOutboxEnabled: false,
            MetadataPrivateTransportRequired: false,
            ClientMailboxAdapterEnabled: false)
    {
    }

    public void Deconstruct(
        out bool groupsV2Enabled,
        out bool communitiesEnabled,
        out bool callsEnabled,
        out bool shareExtensionEnabled,
        out bool attachmentEncryptionEnabled,
        out bool backgroundSyncEnabled,
        out bool pushNotificationsEnabled,
        out bool transportRequired,
        out bool stubTransportAllowed,
        out bool membershipTrustEnabled,
        out bool legacyEmbeddedBootstrapRollbackAllowed)
    {
        groupsV2Enabled = GroupsV2Enabled;
        communitiesEnabled = CommunitiesEnabled;
        callsEnabled = CallsEnabled;
        shareExtensionEnabled = ShareExtensionEnabled;
        attachmentEncryptionEnabled = AttachmentEncryptionEnabled;
        backgroundSyncEnabled = BackgroundSyncEnabled;
        pushNotificationsEnabled = PushNotificationsEnabled;
        transportRequired = TransportRequired;
        stubTransportAllowed = StubTransportAllowed;
        membershipTrustEnabled = MembershipTrustEnabled;
        legacyEmbeddedBootstrapRollbackAllowed =
            LegacyEmbeddedBootstrapRollbackAllowed;
    }

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
        LegacyEmbeddedBootstrapRollbackAllowed: false,
        PersistentTransportOutboxEnabled: false,
        MetadataPrivateTransportRequired: true,
        ClientMailboxAdapterEnabled: false);
}

public sealed class FeatureDisabledException(string featureName)
    : NotSupportedException($"{featureName} is currently behind a feature flag.");
