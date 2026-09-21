#if DEEP_CLEAN_PRODUCTION
namespace Deep.Client.Shared.Services;

/// <summary>
/// A mailbox revocation authority that proves freshness at each dispatch
/// boundary. Production implementations are supplied by the account-scoped
/// authority package, never by a Session-derived credential importer.
/// </summary>
public interface IFreshMailboxCapabilityRevocationSource :
    Deep.Protocol.DeepExtension.MailboxCapabilities.IMailboxCapabilityRevocationSource
{
    void ValidateFreshness();
}
#endif
