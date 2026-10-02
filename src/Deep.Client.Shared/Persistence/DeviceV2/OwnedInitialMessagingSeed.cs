using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Internal initial-to-mutable handoff. Not a durable transfer or
/// retirement/dispatch/ACK capability. No raw-TRS constructor or public export.</summary>
internal sealed class OwnedInitialMessagingSeed : IDisposable
{
    private readonly List<byte[]> buffers = [];
    private readonly byte[] instance, basis, trs, init, hello, peerCredential;
    private int disposed;
    internal bool IsInitiator { get; }
    internal ParsedDmd1 LocalDirectory { get; }
    internal ParsedDmd1 RemoteDirectory { get; }
    internal Dph2Record Initiation { get; }
    internal ReadOnlySpan<byte> Instance => Live(instance);
    internal ReadOnlySpan<byte> InitialBasisHash => Live(basis);
    internal ReadOnlySpan<byte> ExactTrs => Live(trs);
    internal ReadOnlySpan<byte> ExactSessionInit => Live(init);
    internal ReadOnlySpan<byte> ExactContactHello => Live(hello);
    internal ReadOnlySpan<byte> ExactPeerCredential => Live(peerCredential);
    internal ReadOnlyMemory<byte> ConversationId { get; }
    internal ReadOnlyMemory<byte> RelationshipId { get; }

    private OwnedInitialMessagingSeed(bool initiator, ReadOnlySpan<byte> databaseInstance,
        ReadOnlySpan<byte> exactCustody, ReadOnlySpan<byte> exactTrs, ReadOnlySpan<byte> exactInit,
        ReadOnlySpan<byte> exactHello, Dph2Record initiation, ParsedDmd1 ownDirectory, ParsedDmd1 peerDirectory,
        ParsedDid2 peerDid)
    {
        IsInitiator = initiator; Initiation = initiation; LocalDirectory = ownDirectory; RemoteDirectory = peerDirectory;
        try
        {
            if (databaseInstance.Length != 32 || databaseInstance.IndexOfAnyExcept((byte)0) < 0)
                throw new ArgumentException("An owned messaging database instance is required.", nameof(databaseInstance));
            var sessionInit = ApplicationCoreCodec.DecodeDmc2(exactInit);
            var contactHello = ApplicationCoreCodec.DecodeDmc2(exactHello);
            if (sessionInit.ParsedPayload is not SessionInitDmc2Payload initial ||
                contactHello.ParsedPayload is not ContactHelloDmc2Payload contact ||
                !Fixed(initial.SenderDirectory.RecordHash.Span, (initiator ? ownDirectory : peerDirectory).RecordHash.Span) ||
                !Fixed(contact.InitiatorDmd1Hash.Span, initial.SenderDmd1Hash.Span) ||
                !Fixed(sessionInit.NetworkId.Span, initiation.NetworkId.Span) ||
                !Fixed(contactHello.NetworkId.Span, initiation.NetworkId.Span) ||
                !Fixed(sessionInit.SenderAccountId.Span, initiation.InitiatorAccountId.Span) ||
                !Fixed(contactHello.SenderAccountId.Span, initiation.InitiatorAccountId.Span) ||
                !Fixed(sessionInit.SenderDeviceId.Span, initiation.InitiatorDeviceId.Span) ||
                !Fixed(contactHello.SenderDeviceId.Span, initiation.InitiatorDeviceId.Span) ||
                Fixed(sessionInit.LogicalMessageId.Span, contactHello.LogicalMessageId.Span) ||
                contactHello.SenderClientSequence <= sessionInit.SenderClientSequence ||
                contactHello.CreatedAtUnixMilliseconds < sessionInit.CreatedAtUnixMilliseconds ||
                !Fixed(sessionInit.ConversationId.Span, contactHello.ConversationId.Span) ||
                !Fixed(contactHello.ConversationId.Span, ApplicationCoreVerifier.ComputeContactConversationId(initiation.NetworkId.Span,
                    contact.RelationshipId.Span, initiation.InitiatorAccountId.Span, initiation.ResponderAccountId.Span)))
                throw new CryptographicException("Initial messaging seed has a different authenticated event stream.");
            var facts = MessagingCryptoV1Trs1.ValidateDeviceBinding(exactTrs, initiation.SessionId.Span,
                initiator ? initiation.InitiatorDeviceId.Span : initiation.ResponderDeviceId.Span,
                initiator ? initiation.InitiatorDeviceGeneration : initiation.ResponderDeviceGeneration);
            MessagingCryptoV1Trs1.RequireResponderContactBinding(exactTrs,
                initiator ? initiation.ResponderDeviceId.Span : initiation.InitiatorDeviceId.Span,
                initiator ? initiation.ResponderDeviceGeneration : initiation.InitiatorDeviceGeneration);
            MessagingCryptoV1Trs1.RequireLocalDirectoryBinding(exactTrs, ownDirectory.RecordHash.Span);
            MessagingCryptoV1Trs1.RequireRemoteDirectoryBinding(exactTrs, peerDirectory.RecordHash.Span);
            if (facts.Generation != 1 || facts.TerminallyLatched)
                throw new CryptographicException("Initial messaging seed is not an active initial ratchet.");
            instance = Own(databaseInstance); basis = SHA256.HashData(exactCustody); buffers.Add(basis);
            trs = Own(exactTrs); init = Own(exactInit); hello = Own(exactHello);
            peerCredential = Own(peerDid.CanonicalBytes.Span);
            ConversationId = Own(contactHello.ConversationId.Span); RelationshipId = Own(contact.RelationshipId.Span);
        }
        catch { Dispose(); throw; }
    }

    internal static async ValueTask<OwnedInitialMessagingSeed> FromSenderAsync(DeepIdV2InitialSessionCommit custody,
        ReadOnlyMemory<byte> exactInit, ReadOnlyMemory<byte> exactHello, ReadOnlyMemory<byte> databaseInstance,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority ownAuthority,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(custody);
        ArgumentNullException.ThrowIfNull(source); ArgumentNullException.ThrowIfNull(ownAuthority);
        ArgumentNullException.ThrowIfNull(peer); RequireInstance(databaseInstance.Span);
        ArgumentNullException.ThrowIfNull(held); held.RequireActive();
        var own = ownAuthority.Proof;
        // Own event inputs before any await. Hash-bound custody authorizes the
        // exact events; a caller's decoded/plaintext substitute cannot enter.
        if (exactInit.IsEmpty || exactHello.IsEmpty || exactInit.Length > 32768 || exactHello.Length > 32768)
            throw new InvalidDataException("Initial messaging event bounds are exceeded.");
        var init = exactInit.ToArray(); var hello = exactHello.ToArray();
        var instance = databaseInstance.ToArray(); OwnedInitialMessagingSeed? seed = null;
        try
        {
            _ = custody.RequireInitialConversation(init, hello);
            var first = await source.RecheckEndpointPairUnderLeaseAsync(ownAuthority, peer, held, ct).ConfigureAwait(false);
            var directories = RequireCurrentScope(custody.Record, true, own, peer, first);
            if (!Fixed(custody.Directory.DirectoryHash.Span, directories.Own.RecordHash.Span))
                throw new CryptographicException("Sender messaging seed differs from its exact retained directory.");
            await ApplicationCoreVerifier.RequireContactHelloEndpointBindingsAsync(ApplicationCoreCodec.DecodeDmc2(hello),
                own, peer, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            seed = new(true, instance, custody.CanonicalSpan, custody.ExactTrsSpan, init, hello,
                custody.Record, directories.Own, directories.Peer, peer.CurrentCheckpoint!.Binding.DeepId);
            await RequireFinalAsync(seed, ownAuthority, peer, source, held, first, ct).ConfigureAwait(false);
            var result = seed; seed = null; return result;
        }
        finally { seed?.Dispose(); CryptographicOperations.ZeroMemory(init); CryptographicOperations.ZeroMemory(hello); CryptographicOperations.ZeroMemory(instance); }
    }

    internal static async ValueTask<OwnedInitialMessagingSeed> FromReceiverAsync(DeepIdV2InitialContactSessionCommit custody,
        ReadOnlyMemory<byte> databaseInstance, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority ownAuthority,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(custody);
        ArgumentNullException.ThrowIfNull(source); ArgumentNullException.ThrowIfNull(ownAuthority);
        ArgumentNullException.ThrowIfNull(peer); RequireInstance(databaseInstance.Span);
        ArgumentNullException.ThrowIfNull(held); held.RequireActive();
        var own = ownAuthority.Proof;
        var instance = databaseInstance.ToArray(); OwnedInitialMessagingSeed? seed = null;
        try
        {
            var first = await source.RecheckEndpointPairUnderLeaseAsync(ownAuthority, peer, held, ct).ConfigureAwait(false);
            var directories = RequireCurrentScope(custody.Record, false, own, peer, first);
            if (!Fixed(custody.Directory.RecordHash.Span, directories.Own.RecordHash.Span))
                throw new CryptographicException("Receiver messaging seed differs from its exact retained directory.");
            await ApplicationCoreVerifier.RequireContactHelloEndpointBindingsAsync(ApplicationCoreCodec.DecodeDmc2(custody.ExactHelloSpan),
                peer, own, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            seed = new(false, instance, custody.CanonicalSpan, custody.ExactTrsSpan, custody.ExactInitSpan,
                custody.ExactHelloSpan, custody.Record, directories.Own, directories.Peer, peer.CurrentCheckpoint!.Binding.DeepId);
            await RequireFinalAsync(seed, ownAuthority, peer, source, held, first, ct).ConfigureAwait(false);
            var result = seed; seed = null; return result;
        }
        finally { seed?.Dispose(); CryptographicOperations.ZeroMemory(instance); }
    }

    private static (ParsedDmd1 Own, ParsedDmd1 Peer) RequireCurrentScope(Dph2Record record, bool initiator,
        VerifiedDeepIdV2DirectoryFreshness own, VerifiedDeepIdV2DirectoryFreshness peer, OnionMonotonicReading reading)
    {
        ArgumentNullException.ThrowIfNull(own); ArgumentNullException.ThrowIfNull(peer);
        var local = own.CurrentCheckpoint?.Directory.Record;
        var remote = peer.CurrentCheckpoint?.Directory.Record;
        if (local is null || remote is null || !own.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds) ||
            !peer.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds) ||
            !Fixed(local.NetworkId.Span, record.NetworkId.Span) || !Fixed(remote.NetworkId.Span, record.NetworkId.Span) ||
            !Fixed(local.DeepAccountId.Span, initiator ? record.InitiatorAccountId.Span : record.ResponderAccountId.Span) ||
            !Fixed(remote.DeepAccountId.Span, initiator ? record.ResponderAccountId.Span : record.InitiatorAccountId.Span))
            throw new CryptographicException("Initial messaging seed lacks its independently current DID2 endpoints.");
        RequireDevice(own, initiator ? record.InitiatorDeviceId : record.ResponderDeviceId,
            initiator ? record.InitiatorDeviceGeneration : record.ResponderDeviceGeneration);
        RequireDevice(peer, initiator ? record.ResponderDeviceId : record.InitiatorDeviceId,
            initiator ? record.ResponderDeviceGeneration : record.InitiatorDeviceGeneration);
        return (local, remote);
    }
    private static void RequireDevice(VerifiedDeepIdV2DirectoryFreshness proof, ReadOnlyMemory<byte> id, ulong generation)
    {
        var active = proof.CurrentCheckpoint!.Binding.Identity.ActiveDevices.SingleOrDefault(device => Fixed(device.Certificate.DeviceId.Span, id.Span));
        var entry = proof.CurrentCheckpoint.Directory.Record.ActiveDevices.SingleOrDefault(device => Fixed(device.DeviceId.Span, id.Span));
        if (active is null || entry is null || active.Certificate.DeviceGeneration != generation ||
            !Fixed(entry.Dpd1Reference.CanonicalHash.Span, active.Certificate.CanonicalHash.Span))
            throw new CryptographicException("Initial messaging seed device is not exact active DID2 authority.");
    }
    internal static void RequireFreshScope(Did2MessagingSessionScope scope,
        VerifiedDeepIdV2DirectoryFreshness own, VerifiedDeepIdV2DirectoryFreshness peer, OnionMonotonicReading reading)
    {
        var local = own.CurrentCheckpoint?.Directory.Record;
        var remote = peer.CurrentCheckpoint?.Directory.Record;
        if (local is null || remote is null ||
            !own.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds) ||
            !peer.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds) ||
            !Fixed(local.NetworkId.Span, scope.Network) || !Fixed(remote.NetworkId.Span, scope.Network) ||
            !Fixed(local.DeepAccountId.Span, scope.LocalAccount) || !Fixed(remote.DeepAccountId.Span, scope.RemoteAccount) ||
            !Fixed(local.RecordHash.Span, scope.LocalDirectory) || !Fixed(remote.RecordHash.Span, scope.RemoteDirectory) ||
            local.AccountGeneration != System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]) ||
            remote.AccountGeneration != System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[164..]))
            throw new CryptographicException("Owned messaging import has different current endpoint heads.");
        RequireDevice(own, scope.LocalDevice.ToArray(), scope.LocalDeviceGeneration);
        RequireDevice(peer, scope.RemoteDevice.ToArray(), scope.RemoteDeviceGeneration);
    }
    private static async ValueTask RequireFinalAsync(OwnedInitialMessagingSeed seed,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, OnionMonotonicReading first, CancellationToken ct)
    {
        var final = await source.RecheckEndpointPairUnderLeaseAsync(own, peer, held, ct).ConfigureAwait(false); ct.ThrowIfCancellationRequested();
        if (final.SampleSeconds < first.SampleSeconds || !Fixed(final.BootId.Span, first.BootId.Span))
            throw new CryptographicException("Initial messaging seed crossed a protected clock discontinuity.");
        _ = RequireCurrentScope(seed.Initiation, seed.IsInitiator, own.Proof, peer, final);
    }
    private static void RequireInstance(ReadOnlySpan<byte> instance)
    {
        if (instance.Length != 32 || instance.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An owned messaging database instance is required.", nameof(instance));
    }
    private byte[] Own(ReadOnlySpan<byte> bytes) { var result = bytes.ToArray(); buffers.Add(result); return result; }
    private ReadOnlySpan<byte> Live(byte[] bytes)
    { ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this); return bytes; }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => DeepIdV2InitialContactSessionCommit.Fixed(left, right);
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        foreach (var buffer in buffers) CryptographicOperations.ZeroMemory(buffer);
        GC.SuppressFinalize(this);
    }
    ~OwnedInitialMessagingSeed() => Dispose();
}
