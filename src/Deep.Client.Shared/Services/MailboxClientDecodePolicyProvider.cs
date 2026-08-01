using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Produces a fresh mailbox decode policy at the verification boundary.  A policy snapshot
/// must never be retained by a long-lived transport because its wall-clock value is security
/// critical for envelope, epoch, and capability expiry checks.
/// </summary>
public interface IMailboxClientDecodePolicyProvider
{
    MailboxClientDecodePolicy GetCurrent();
}

public sealed class TimeProviderMailboxClientDecodePolicyProvider :
    IMailboxClientDecodePolicyProvider
{
    private readonly MailboxEpochWindow epochWindow;
    private readonly MailboxCapabilityDecodePolicy capabilityPolicy;
    private readonly TimeProvider timeProvider;

    public TimeProviderMailboxClientDecodePolicyProvider(
        MailboxEpochWindow epochWindow,
        MailboxCapabilityDecodePolicy capabilityPolicy,
        TimeProvider timeProvider)
    {
        this.epochWindow = epochWindow ?? throw new ArgumentNullException(nameof(epochWindow));
        this.capabilityPolicy = capabilityPolicy ??
            throw new ArgumentNullException(nameof(capabilityPolicy));
        this.timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        epochWindow.Validate();
        _ = GetCurrent();
    }

    public MailboxClientDecodePolicy GetCurrent()
    {
        var now = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (now <= 0)
            throw new InvalidOperationException("Mailbox decode time is outside its valid range.");
        return new MailboxClientDecodePolicy
        {
            NowUnixSeconds = checked((ulong)now),
            EpochWindow = epochWindow with { },
            CapabilityPolicy = capabilityPolicy with { },
            AllowLegacyMirrorOverlap = false
        };
    }
}
