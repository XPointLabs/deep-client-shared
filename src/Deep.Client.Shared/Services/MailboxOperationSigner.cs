#if DEEP_CLEAN_PRODUCTION
namespace Deep.Client.Shared.Services;

/// <summary>
/// Per-operation mailbox signing authority. It exposes only the exact MCP2
/// presentation operation and never exposes a generic signer or private key.
/// </summary>
public interface IMailboxOperationSigner
{
    byte[] GetEd25519PublicKey();

    byte[] SignMailboxPresentation(
        Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxAuthenticatedOperation operation,
        ReadOnlySpan<byte> canonicalPresentationSigningBytes);
}
#endif
