using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Persistence.PreKeyV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Services.ContactV1;

/// <summary>
/// Bounded responder-side bridge from one verified ContactV1 relationship and
/// one exact XPC1/DPH2 pair into the device-wide pre-key/session commit saga.
/// It performs no transport, decoding-based trust elevation, or persistence of
/// its own.
/// </summary>
internal sealed class ContactInitialSessionCoordinator
{
    private readonly SqlitePreKeyV1SecretOwner preKeyOwner;
    private readonly SqliteMessagingCryptoV1Store sessionStore;
    private readonly VerifiedContactBundleEvidence relationship;
    private readonly DeepAccountService accountService;
    private readonly DeepLocalIdentitySnapshot localIdentity;
    private readonly int maximumMessagesWithoutPqInjection;
    private int active;

    internal ContactInitialSessionCoordinator(
        SqlitePreKeyV1SecretOwner preKeyOwner,
        SqliteMessagingCryptoV1Store sessionStore,
        VerifiedContactBundleEvidence relationship,
        DeepAccountService accountService,
        DeepLocalIdentitySnapshot localIdentity,
        int maximumMessagesWithoutPqInjection)
    {
        this.preKeyOwner = preKeyOwner ?? throw new ArgumentNullException(nameof(preKeyOwner));
        this.sessionStore = sessionStore ?? throw new ArgumentNullException(nameof(sessionStore));
        this.relationship = relationship ?? throw new ArgumentNullException(nameof(relationship));
        this.accountService = accountService ?? throw new ArgumentNullException(nameof(accountService));
        this.localIdentity = localIdentity ?? throw new ArgumentNullException(nameof(localIdentity));
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
            throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        this.maximumMessagesWithoutPqInjection = maximumMessagesWithoutPqInjection;
    }

    internal async ValueTask<PreKeyV1InitialSessionSagaResult> CommitAsync(
        VerifiedXpc1PreKeyClaimReceipt claimReceipt,
        VerifiedDph2Initiation initiation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claimReceipt);
        ArgumentNullException.ThrowIfNull(initiation);
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.CompareExchange(ref active, 1, 0) != 0)
            throw new InvalidOperationException(
                "This contact initial-session coordinator already has an active operation.");

        byte[]? exactDph2 = null;
        byte[]? accountId = null;
        byte[]? conversationId = null;
        byte[]? networkId = null;
        byte[]? responderAccountId = null;
        byte[]? responderDeviceId = null;
        DeepResponderIdentitySecretLease? identityLease = null;
        try
        {
            exactDph2 = initiation.ExactBytes.ToArray();
            var dph2 = Dph2Codec.Decode(exactDph2);
            accountId = relationship.Scope.AccountId.Bytes.ToArray();
            conversationId = relationship.ConversationId.ToArray();
            networkId = claimReceipt.NetworkId.ToArray();
            responderAccountId = claimReceipt.ResponderAccountId.ToArray();
            responderDeviceId = claimReceipt.ResponderDeviceId.ToArray();

            RequireSame(relationship.Address.NetworkId.Span, networkId,
                "The verified XPC1 claim belongs to another contact network.");
            RequireSame(accountId, responderAccountId,
                "The verified XPC1 responder is not the local relationship account.");
            RequireSame(relationship.RemoteAccountId.Span, dph2.InitiatorAccountId.Span,
                "The verified DPH2 initiator is not the relationship's remote account.");
            if (!preKeyOwner.OwnsResponder(
                    networkId,
                    responderAccountId,
                    responderDeviceId,
                    claimReceipt.ResponderDeviceGeneration))
                throw new CryptographicException(
                    "The verified XPC1 responder is outside the device-wide pre-key owner scope.");
            if (!sessionStore.OwnsContactInitialSession(
                    accountId,
                    responderDeviceId,
                    claimReceipt.ResponderDeviceGeneration,
                    conversationId,
                    initiation.SessionId.Span))
                throw new CryptographicException(
                    "The relationship, responder, conversation, or session differs from the messaging store scope.");

            identityLease = await accountService.OpenCurrentResponderIdentitySecretLeaseAsync(
                    localIdentity,
                    maximumMessagesWithoutPqInjection,
                    cancellationToken)
                .ConfigureAwait(false);
            RequireSame(localIdentity.NetworkId.Span, networkId,
                "The account-owned responder factory belongs to another network.");
            RequireSame(localIdentity.Account.AccountIdentity.AccountId.Bytes.Span, responderAccountId,
                "The account-owned responder factory belongs to another account.");
            RequireSame(localIdentity.Device.DeviceId.Bytes.Span, responderDeviceId,
                "The account-owned responder factory belongs to another device.");
            if (localIdentity.Device.DeviceGeneration != claimReceipt.ResponderDeviceGeneration)
                throw new CryptographicException(
                    "The account-owned responder factory belongs to another device generation.");

            using var verifiedClaim = claimReceipt.BindForInitialSession(initiation);
            using var reservation = verifiedClaim.ConsumeForDevicePreKeyOwner();
            return await preKeyOwner.CommitInitialSessionSagaAsync(
                    reservation,
                    verifiedClaim,
                    sessionStore,
                    identityLease.OpenFactory(),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            Zero(exactDph2);
            Zero(accountId);
            Zero(conversationId);
            Zero(networkId);
            Zero(responderAccountId);
            Zero(responderDeviceId);
            identityLease?.Dispose();
            Volatile.Write(ref active, 0);
        }
    }

    private static void RequireSame(
        ReadOnlySpan<byte> expected,
        ReadOnlySpan<byte> actual,
        string message)
    {
        if (expected.Length != actual.Length ||
            !CryptographicOperations.FixedTimeEquals(expected, actual))
            throw new CryptographicException(message);
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
            CryptographicOperations.ZeroMemory(value);
    }
}
