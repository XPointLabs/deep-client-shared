namespace Deep.Client.Shared.Services;

/// <summary>
/// A stable fail-closed signal that the selected transport has no production
/// E2EE-01 authority capable of proving exact DPE2/ratchet transitions.
/// </summary>
public sealed class MessagingV1CryptoUnavailableException : InvalidOperationException
{
    public const string ProductionCapabilityUnavailable =
        "E2EE01_PRODUCTION_CAPABILITY_UNAVAILABLE";

    internal MessagingV1CryptoUnavailableException()
        : base(
            "The configured transport has no production E2EE-01 authority for " +
            "authenticated MSG-01 evidence. DPE1 and caller-controlled DPE2 " +
            "verification callbacks are not accepted as fallbacks.")
    {
    }

    public string Code => ProductionCapabilityUnavailable;
}
