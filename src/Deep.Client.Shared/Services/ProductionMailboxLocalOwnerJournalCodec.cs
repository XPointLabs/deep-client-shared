using System.Text;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Canonical, bounded encoding of the already signed Registry LocalOwner material needed to
/// finish an interrupted LKG/runtime publication without network access. It contains no private
/// key. Recovery always runs the normal production signature and binding verification again.
/// </summary>
internal static class ProductionMailboxLocalOwnerJournalCodec
{
    internal const int MaximumEncodedLength = 512 * 1024;
    internal const int MaximumBase64Length = 699_052;
    private static ReadOnlySpan<byte> Magic => "PLJ2"u8;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static byte[] Encode(ProductionMailboxLocalOwnerBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, StrictUtf8, leaveOpen: true);
        writer.Write(Magic);
        writer.Write((byte)2);
        WriteBytes(writer, bundle.HolderEd25519PublicKey.Span, 32, 32);
        WriteBytes(writer, bundle.MailboxOwnerEd25519PublicKey.Span, 32, 32);
        WriteBytes(writer, bundle.IdempotencyKey.Span, 32, 32);
        WriteBytes(writer, bundle.BlindedMailboxId.Span, 32, 32);
        WriteBytes(writer, bundle.BlindedPlacementId.Span, 32, 32);
        WriteBytes(writer, bundle.SelectionInputCommitment.Span, 32, 32);
        WriteBytes(writer, bundle.CanonicalRouteCertificate.Span,
            ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength,
            ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength);
        WriteBytes(writer, bundle.RouteCertificateSha256.Span, 32, 32);
        WriteBytes(writer, bundle.CanonicalRouteAdvertisement.Span,
            ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength,
            ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength);
        WriteBytes(writer, bundle.RouteAdvertisementSha256.Span, 32, 32);
        WriteOptionalBytes(writer, bundle.CanonicalSelectionSuccessor.Span,
            ProductionMailboxSelectionSuccessorConstants.MaximumArtifactBytes);
        WriteOptionalBytes(writer, bundle.SelectionSuccessorSha256.Span, 32);
        WriteBytes(writer, bundle.ControlPlane.CanonicalAuthority.Span, 1, 128 * 1024);
        WriteBytes(writer, bundle.ControlPlane.CanonicalRevocationSnapshot.Span, 1, 128 * 1024);
        WriteBytes(writer, bundle.ControlPlane.CanonicalTopology.Span, 1, 128 * 1024);
        WriteBytes(writer, bundle.ControlPlane.CanonicalCurrentSelection.Span, 1, 128 * 1024);
        WriteBytes(writer, bundle.ControlPlane.CanonicalNextSelection.Span, 1, 128 * 1024);
        if (bundle.Selections is not { Count: 2 })
            throw Invalid("LocalOwner journal requires exactly two selections.");
        writer.Write(2);
        for (var selectionIndex = 0; selectionIndex < 2; selectionIndex++)
        {
            if (bundle.Selections.Count != 2)
                throw Invalid("LocalOwner journal selection collection changed.");
            var selection = bundle.Selections[selectionIndex];
            ArgumentNullException.ThrowIfNull(selection);
            writer.Write(selection.Epoch);
            writer.Write(selection.Generation);
            WriteBytes(writer, selection.CanonicalSelection.Span, 1, 128 * 1024);
            if (selection.Replicas is not { Count: 2 })
                throw Invalid("LocalOwner journal selection requires two replicas.");
            writer.Write(2);
            for (var replicaIndex = 0; replicaIndex < 2; replicaIndex++)
            {
                if (selection.Replicas.Count != 2)
                    throw Invalid("LocalOwner journal replica collection changed.");
                var replica = selection.Replicas[replicaIndex];
                ArgumentNullException.ThrowIfNull(replica);
                WriteBytes(writer, replica.ReplicaId.Span, 32, 32);
                ArgumentNullException.ThrowIfNull(replica.HttpsEndpoint);
                var originalEndpoint = replica.HttpsEndpoint.OriginalString;
                if (originalEndpoint.Length is <= 0 or > 2_048 ||
                    !replica.HttpsEndpoint.IsAbsoluteUri)
                    throw Invalid("LocalOwner journal replica URI is not absolute.");
                WriteString(writer, replica.HttpsEndpoint.AbsoluteUri, 2_048);
                WriteBytes(writer, replica.CurrentSpkiSha256.Span, 32, 32);
                WriteBytes(writer, replica.NextSpkiSha256.Span, 32, 32);
            }
        }
        if (bundle.Grants is not { Count: 2 })
            throw Invalid("LocalOwner journal requires exactly two grants.");
        writer.Write(2);
        for (var grantIndex = 0; grantIndex < 2; grantIndex++)
        {
            if (bundle.Grants.Count != 2)
                throw Invalid("LocalOwner journal grant collection changed.");
            var grant = bundle.Grants[grantIndex];
            ArgumentNullException.ThrowIfNull(grant);
            writer.Write((byte)grant.Domain);
            writer.Write(grant.Epoch);
            writer.Write(grant.Generation);
            WriteBytes(writer, grant.CanonicalGrant.Span, 1, 16 * 1024);
        }
        writer.Write(bundle.IssuedAtUnixSeconds);
        writer.Write(bundle.ExpiresAtUnixSeconds);
        writer.Flush();
        if (stream.Length is <= 0 or > MaximumEncodedLength)
            throw Invalid("LocalOwner journal payload length is invalid.");
        return stream.ToArray();
    }

    internal static ProductionMailboxLocalOwnerBundle Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is <= 0 or > MaximumEncodedLength)
            throw Invalid("LocalOwner journal payload length is invalid.");
        try
        {
            using var stream = new MemoryStream(encoded.ToArray(), writable: false);
            using var reader = new BinaryReader(stream, StrictUtf8, leaveOpen: true);
            if (!ReadExact(reader, 4).AsSpan().SequenceEqual(Magic) || reader.ReadByte() != 2)
                throw Invalid("LocalOwner journal framing is invalid.");
            var holder = ReadBytes(reader, 32, 32);
            var owner = ReadBytes(reader, 32, 32);
            var idempotency = ReadBytes(reader, 32, 32);
            var mailbox = ReadBytes(reader, 32, 32);
            var placement = ReadBytes(reader, 32, 32);
            var selectionCommitment = ReadBytes(reader, 32, 32);
            var routeCertificate = ReadBytes(reader,
                ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength,
                ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength);
            var routeCertificateHash = ReadBytes(reader, 32, 32);
            var routeAdvertisement = ReadBytes(reader,
                ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength,
                ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength);
            var routeAdvertisementHash = ReadBytes(reader, 32, 32);
            var selectionSuccessor = ReadBytes(reader, 0,
                ProductionMailboxSelectionSuccessorConstants.MaximumArtifactBytes);
            var selectionSuccessorHash = ReadBytes(reader, 0, 32);
            var authority = ReadBytes(reader, 1, 128 * 1024);
            var revocations = ReadBytes(reader, 1, 128 * 1024);
            var topology = ReadBytes(reader, 1, 128 * 1024);
            var currentSelection = ReadBytes(reader, 1, 128 * 1024);
            var nextSelection = ReadBytes(reader, 1, 128 * 1024);
            if (reader.ReadInt32() != 2)
                throw Invalid("LocalOwner journal selection count is invalid.");
            var selections = new ProductionMailboxSelectionBinding[2];
            for (var index = 0; index < selections.Length; index++)
            {
                var epoch = reader.ReadUInt64();
                var generation = reader.ReadUInt64();
                var canonical = ReadBytes(reader, 1, 128 * 1024);
                if (reader.ReadInt32() != 2)
                    throw Invalid("LocalOwner journal replica count is invalid.");
                var replicas = new ProductionMailboxReplicaBinding[2];
                for (var replicaIndex = 0; replicaIndex < replicas.Length; replicaIndex++)
                {
                    var replicaId = ReadBytes(reader, 32, 32);
                    var endpoint = new Uri(ReadString(reader, 2_048), UriKind.Absolute);
                    var currentPin = ReadBytes(reader, 32, 32);
                    var nextPin = ReadBytes(reader, 32, 32);
                    replicas[replicaIndex] = new ProductionMailboxReplicaBinding(
                        replicaId, endpoint, currentPin, nextPin);
                }
                selections[index] = new ProductionMailboxSelectionBinding(
                    epoch, generation, canonical, replicas);
            }
            if (reader.ReadInt32() != 2)
                throw Invalid("LocalOwner journal grant count is invalid.");
            var grants = new ProductionMailboxGrantBinding[2];
            for (var index = 0; index < grants.Length; index++)
                grants[index] = new ProductionMailboxGrantBinding(
                    (MailboxCapabilityDomain)reader.ReadByte(),
                    reader.ReadUInt64(),
                    reader.ReadUInt64(),
                    ReadBytes(reader, 1, 16 * 1024));
            var issued = reader.ReadUInt64();
            var expires = reader.ReadUInt64();
            if (stream.Position != stream.Length)
                throw Invalid("LocalOwner journal has trailing data.");
            return new ProductionMailboxLocalOwnerBundle(
                holder,
                owner,
                idempotency,
                mailbox,
                placement,
                selectionCommitment,
                new ProductionMailboxControlPlaneArtifacts(
                    authority,
                    revocations,
                    topology,
                    currentSelection,
                    nextSelection),
                selections,
                grants,
                routeCertificate,
                routeCertificateHash,
                routeAdvertisement,
                routeAdvertisementHash,
                selectionSuccessor,
                selectionSuccessorHash,
                issued,
                expires);
        }
        catch (Exception exception) when (exception is EndOfStreamException or
            IOException or DecoderFallbackException or UriFormatException or
            OverflowException)
        {
            throw Invalid("LocalOwner journal payload is malformed.", exception);
        }
    }

    private static void WriteBytes(
        BinaryWriter writer,
        ReadOnlySpan<byte> value,
        int minimum,
        int maximum)
    {
        if (value.Length < minimum || value.Length > maximum)
            throw Invalid("LocalOwner journal byte field length is invalid.");
        writer.Write(value.Length);
        writer.Write(value);
    }

    private static void WriteOptionalBytes(
        BinaryWriter writer,
        ReadOnlySpan<byte> value,
        int maximum)
    {
        if (value.Length > maximum)
            throw Invalid("LocalOwner journal optional byte field length is invalid.");
        writer.Write(value.Length);
        writer.Write(value);
    }

    private static byte[] ReadBytes(BinaryReader reader, int minimum, int maximum)
    {
        var length = reader.ReadInt32();
        if (length < minimum || length > maximum)
            throw Invalid("LocalOwner journal byte field length is invalid.");
        return ReadExact(reader, length);
    }

    private static void WriteString(BinaryWriter writer, string value, int maximumBytes)
    {
        if (string.IsNullOrEmpty(value) || value.Length > maximumBytes)
            throw Invalid("LocalOwner journal string length is invalid.");
        var byteCount = StrictUtf8.GetByteCount(value);
        if (byteCount is <= 0 || byteCount > maximumBytes)
            throw Invalid("LocalOwner journal string length is invalid.");
        var encoded = StrictUtf8.GetBytes(value);
        if (encoded.Length != byteCount) throw Invalid(
            "LocalOwner journal string encoding length changed.");
        writer.Write(encoded.Length);
        writer.Write(encoded);
    }

    private static string ReadString(BinaryReader reader, int maximumBytes) =>
        StrictUtf8.GetString(ReadBytes(reader, 1, maximumBytes));

    private static byte[] ReadExact(BinaryReader reader, int length)
    {
        var value = reader.ReadBytes(length);
        if (value.Length != length) throw new EndOfStreamException();
        return value;
    }

    private static InvalidDataException Invalid(string message, Exception? inner = null) =>
        new(message, inner);
}
