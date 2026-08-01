using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Services;

public enum MailboxTransportProtocol
{
    DirectP2p = 1,
    AuthenticatedMau2 = 2
}

public enum MailboxInfrastructureOwnership
{
    DirectP2p = 1,
    UserManaged = 2,
    OfficialManaged = 3
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
    MailboxTransportProtocol Protocol,
    MailboxInfrastructureOwnership Ownership,
    VerifiedOfficialMailboxAuthority? Authority,
    MailboxCredentialSelector? Selector = null)
{
    public void Validate()
    {
        if (Protocol == MailboxTransportProtocol.DirectP2p)
        {
            if (Ownership != MailboxInfrastructureOwnership.DirectP2p ||
                Authority is not null || Selector is not null)
            {
                throw new InvalidOperationException(
                    "Direct P2P must not carry official-cloud authority.");
            }
            return;
        }
        if (Protocol != MailboxTransportProtocol.AuthenticatedMau2 ||
            Ownership is not (MailboxInfrastructureOwnership.UserManaged or
                MailboxInfrastructureOwnership.OfficialManaged) ||
            Authority is null || Selector is null)
        {
            throw new InvalidOperationException(
                "Mailbox delivery policy is invalid.");
        }
        if (Ownership == MailboxInfrastructureOwnership.UserManaged &&
            Authority.RequiresManagedEntitlement)
        {
            throw new InvalidOperationException(
                "User-managed MAU2 must not depend on managed-cloud entitlement.");
        }
        if (Ownership == MailboxInfrastructureOwnership.OfficialManaged &&
            !Authority.RequiresManagedEntitlement)
        {
            throw new InvalidOperationException(
                "Official-managed MAU2 must enforce entitlement at dispatch.");
        }
        Authority.Validate();
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
            MailboxTransportProtocol.DirectP2p,
            MailboxInfrastructureOwnership.DirectP2p,
            null));
    }
}

/// <summary>
/// Selects infrastructure operated by the user (or by a community chosen by the user).
/// This lane is free and is deliberately distinct from both radio/direct P2P and the
/// official managed cloud.
/// </summary>
public sealed class AuthenticatedMau2MailboxDeliveryPolicy : IMailboxDeliveryPolicy
{
    private readonly VerifiedOfficialMailboxAuthority authority;
    private readonly Func<MailboxDeliveryRequest, MailboxCredentialSelector> selector;
    private readonly MailboxInfrastructureOwnership ownership;

    public AuthenticatedMau2MailboxDeliveryPolicy(
        MailboxInfrastructureOwnership ownership,
        VerifiedOfficialMailboxAuthority authority,
        Func<MailboxDeliveryRequest, MailboxCredentialSelector> selector)
    {
        if (ownership is not (MailboxInfrastructureOwnership.UserManaged or
            MailboxInfrastructureOwnership.OfficialManaged))
            throw new ArgumentOutOfRangeException(nameof(ownership));
        this.ownership = ownership;
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
            "Authenticated MAU2 has no scoped credential for this delivery target.");
        return Task.FromResult(new MailboxDeliveryDecision(
            MailboxTransportProtocol.AuthenticatedMau2,
            ownership,
            authority,
            selected));
    }
}
