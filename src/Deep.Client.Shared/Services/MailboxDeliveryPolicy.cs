using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Services;

public enum MailboxDeliveryMode
{
    DirectP2p = 1,
    OfficialCloud = 2,
    UserManagedNetwork = 3
}

/// <summary>Semantic delivery class is deliberately outside the encrypted wire body.</summary>
public enum MailboxDeliveryKind
{
    Direct = 1,
    GroupState = 2,
    GroupMessage = 3
}

public sealed record MailboxDeliveryRequest(
    OutboundMessageEnvelope Envelope,
    MailboxDeliveryKind Kind);

/// <summary>
/// Explicit product-policy boundary. Direct P2P and paid official cloud are
/// separate choices; transport failure never changes the selected mode.
/// </summary>
public sealed record MailboxDeliveryDecision(
    MailboxDeliveryMode Mode,
    VerifiedOfficialMailboxAuthority? OfficialAuthority,
    MailboxCredentialSelector? Selector = null)
{
    public void Validate()
    {
        if (Mode is MailboxDeliveryMode.DirectP2p or MailboxDeliveryMode.UserManagedNetwork)
        {
            if (OfficialAuthority is not null || Selector is not null)
            {
                throw new InvalidOperationException(
                    "Direct P2P must not carry official-cloud authority.");
            }
            return;
        }
        if (Mode != MailboxDeliveryMode.OfficialCloud ||
            OfficialAuthority is null || Selector is null)
        {
            throw new InvalidOperationException(
                "Mailbox delivery policy is invalid.");
        }
        OfficialAuthority.Validate();
    }
}

public interface IMailboxDeliveryPolicy
{
    Task<MailboxDeliveryDecision> DecideAsync(
        MailboxDeliveryRequest request,
        CancellationToken cancellationToken = default);
}

public sealed class DirectP2pMailboxDeliveryPolicy : IMailboxDeliveryPolicy
{
    public Task<MailboxDeliveryDecision> DecideAsync(
        MailboxDeliveryRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Envelope);
        if (!Enum.IsDefined(request.Kind))
            throw new ArgumentOutOfRangeException(nameof(request));
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new MailboxDeliveryDecision(
            MailboxDeliveryMode.DirectP2p, null));
    }
}

/// <summary>
/// Selects infrastructure operated by the user (or by a community chosen by the user).
/// This lane is free and is deliberately distinct from both radio/direct P2P and the
/// official managed cloud.
/// </summary>
public sealed class UserManagedMailboxDeliveryPolicy : IMailboxDeliveryPolicy
{
    public Task<MailboxDeliveryDecision> DecideAsync(
        MailboxDeliveryRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Envelope);
        if (!Enum.IsDefined(request.Kind))
            throw new ArgumentOutOfRangeException(nameof(request));
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new MailboxDeliveryDecision(
            MailboxDeliveryMode.UserManagedNetwork, null));
    }
}

/// <summary>Fail-closed official-cloud policy. It has no transport fallback.</summary>
public sealed class OfficialCloudMailboxDeliveryPolicy : IMailboxDeliveryPolicy
{
    private readonly VerifiedOfficialMailboxAuthority authority;
    private readonly Func<MailboxDeliveryRequest, MailboxCredentialSelector> selector;

    public OfficialCloudMailboxDeliveryPolicy(
        VerifiedOfficialMailboxAuthority authority,
        Func<MailboxDeliveryRequest, MailboxCredentialSelector> selector)
    {
        this.authority = authority ?? throw new ArgumentNullException(nameof(authority));
        this.selector = selector ?? throw new ArgumentNullException(nameof(selector));
        authority.Validate();
    }

    public Task<MailboxDeliveryDecision> DecideAsync(
        MailboxDeliveryRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Envelope);
        if (!Enum.IsDefined(request.Kind))
            throw new ArgumentOutOfRangeException(nameof(request));
        cancellationToken.ThrowIfCancellationRequested();
        authority.Validate();
        var selected = selector(request) ?? throw new InvalidOperationException(
            "Official cloud has no scoped credential for this delivery target.");
        return Task.FromResult(new MailboxDeliveryDecision(
            MailboxDeliveryMode.OfficialCloud, authority, selected));
    }
}
