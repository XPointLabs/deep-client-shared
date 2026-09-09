using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Services.ContactV1;

public enum ContactAddressImportFailure
{
    NonCanonicalOrUnsupported = 1,
    WrongNetwork = 2,
    LocalCapacityExceeded = 3,
}

public sealed class ContactAddressImportException : FormatException
{
    public ContactAddressImportException(ContactAddressImportFailure failure, string message, Exception? inner = null)
        : base(message, inner) => Failure = failure;
    public ContactAddressImportFailure Failure { get; }
}

public sealed record ContactAddressImportResult(
    PendingContactAddressWriteDisposition Disposition,
    PendingContactAddress PendingAddress);

/// <summary>
/// Performs only canonical local address import. Resolver/directory lookup and
/// relationship creation are intentionally outside this service.
/// </summary>
public sealed class ContactAddressImportService
{
    private readonly IContactStateStore store;
    private readonly byte[] networkId;
    private readonly TimeProvider timeProvider;

    public ContactAddressImportService(
        IContactStateStore store,
        ReadOnlyMemory<byte> networkId16,
        TimeProvider? timeProvider = null)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        if (networkId16.Length != 16 || networkId16.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Network ID must be exactly 16 nonzero bytes.", nameof(networkId16));
        networkId = networkId16.ToArray();
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask<ContactAddressImportResult> ImportAsync(
        string input,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ImportedContactAddress imported;
        try
        {
            ArgumentNullException.ThrowIfNull(input);
            imported = input.StartsWith(DeepInvitationTextCodec.Prefix, StringComparison.Ordinal)
                ? ImportInvitation(input)
                : ImportPermanent(input);
        }
        catch (Exception exception) when (exception is
            ArgumentException or ApplicationCoreFormatException or ContactFormatException)
        {
            throw new ContactAddressImportException(
                ContactAddressImportFailure.NonCanonicalOrUnsupported,
                "Only a canonical permanent Deep ID or canonical deepinvite DIA1 is accepted.",
                exception);
        }

        var candidate = new PendingContactAddress(imported, timeProvider.GetUtcNow());
        var write = await store.PutPendingAddressAsync(candidate, cancellationToken).ConfigureAwait(false);
        if (write.Disposition == PendingContactAddressWriteDisposition.CapacityExceeded || write.Address is null)
        {
            throw new ContactAddressImportException(
                ContactAddressImportFailure.LocalCapacityExceeded,
                "The local pending-contact address limit has been reached.");
        }

        return new ContactAddressImportResult(write.Disposition, write.Address);
    }

    private ImportedContactAddress ImportPermanent(string input)
    {
        var did = ApplicationCoreCodec.DecodeDeepIdText(input);
        return new ImportedContactAddress(
            ContactAddressKind.PermanentDeepId,
            networkId,
            did.CanonicalBytes.Span,
            did.Text,
            expiresAtUnixSeconds: null);
    }

    private ImportedContactAddress ImportInvitation(string input)
    {
        var invitation = DeepInvitationTextCodec.DecodeCanonical(input);
        if (!CryptographicOperations.FixedTimeEquals(networkId, invitation.Field(1).Span))
        {
            throw new ContactAddressImportException(
                ContactAddressImportFailure.WrongNetwork,
                "The invitation belongs to another network.");
        }

        return new ImportedContactAddress(
            ContactAddressKind.OneTimeInvitation,
            networkId,
            invitation.CanonicalBytes.Span,
            input,
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(invitation.Field(8).Span));
    }
}
