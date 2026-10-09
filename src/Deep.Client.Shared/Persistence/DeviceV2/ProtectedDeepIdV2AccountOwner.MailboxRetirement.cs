using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal sealed partial class MailboxEpochExclusion
    {
        // Local observed obligations, not serialized settlement/permission flags.
        [Flags]
        internal enum RetirementDependency : ushort
        {
            None = 0, AcquisitionChain = 1, SendWork = 2, SendFloor = 4,
            ReadWork = 8, ReadFloor = 16, ReadTraversal = 32,
            OrdinaryWork = 64, AttachmentWork = 128,
            UnresolvedReceiptOrObject = 256, RetainedRetrievePath = 512
        }

        internal Task<RetirementDependencies> CaptureRetirementDependenciesAsync(CancellationToken ct = default) =>
            RetirementDependencies.OpenAsync(this, ct);

        // Bound to the actual live exclusion, not reconstructible from hashes,
        // a parsed plan or caller-supplied 'no dependencies' assertions.
        internal sealed class RetirementDependencies
        {
            private readonly MailboxEpochExclusion exclusion;
            private readonly Did2CompactionPlan.RootReadback[] guards;
            private RetirementDependencies(MailboxEpochExclusion exclusion,
                RetirementDependency dependencies, Did2CompactionPlan.RootReadback[] guards)
            { this.exclusion = exclusion; Dependencies = dependencies; this.guards = guards; }

            internal RetirementDependency Dependencies { get; }
            internal IReadOnlyList<Did2CompactionPlan.RootReadback> Guards => guards.Select(guard =>
                new Did2CompactionPlan.RootReadback(guard.Kind, guard.Selector.ToArray(), guard.Digest.ToArray())).ToArray();

            internal static async Task<RetirementDependencies> OpenAsync(MailboxEpochExclusion exclusion, CancellationToken ct)
            {
                await exclusion.gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    await exclusion.RecheckUnderGateAsync(ct).ConfigureAwait(false);
                    var result = await CaptureUnderGateAsync(exclusion, ct).ConfigureAwait(false);
                    await exclusion.RecheckUnderGateAsync(ct).ConfigureAwait(false);
                    await result.RequireExactGuardsUnderGateAsync(ct).ConfigureAwait(false);
                    return result;
                }
                finally { exclusion.gate.Release(); }
            }

            internal async Task RecheckAsync(CancellationToken ct = default)
            {
                await exclusion.gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    await exclusion.RecheckUnderGateAsync(ct).ConfigureAwait(false);
                    await RequireExactGuardsUnderGateAsync(ct).ConfigureAwait(false);
                    await exclusion.RecheckUnderGateAsync(ct).ConfigureAwait(false);
                }
                finally { exclusion.gate.Release(); }
            }

            internal static async Task<RetirementDependencies> CaptureUnderGateAsync(MailboxEpochExclusion exclusion, CancellationToken ct)
            {
                var owner = exclusion.owner; var account = exclusion.current.AccountId;
                var instance = exclusion.instance; var network = owner.networkId;
                using var grantRaw = await ReadAsync(owner.storage, ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false);
                using var grants = grantRaw.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, network, account.Span, instance));
                if (!grantRaw.Use(bytes => FixedRoute(bytes, exclusion.root)))
                    throw new CryptographicException("Retirement dependency capture changed original grant custody.");
                var entry = grants.Entries[Convert.ToHexString(exclusion.acquisition)];
                var scope = entry.AsSpan(0, 32).ToArray(); var route = entry.AsSpan(64, 32).ToArray();
                var scopeName = Convert.ToHexString(scope);
                var request = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span);
                var retrieve = request.Field(6).Span[0] == (byte)MailboxCapabilityDomain.Retrieve;
                byte[] readScope = [];
                byte[] grant = ProtectedDid2MailboxGrantJournal.HasWinner(entry)
                    ? SHA256.HashData(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8).Span) : [];
                try
                {
                    if (retrieve)
                    {
                        // Acquisition Scope(route, locator, domain) is NOT the
                        // installed mailbox scope used by read cycles/traversals.
                        // Derive the same original route/epoch binding as the
                        // actual retained credential and Retrieve producer.
                        var original = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span);
                        readScope = ClientMailboxScope.Derive(route, new BlindedMailboxId(original.Reachability.Field(2).Span),
                            BinaryPrimitives.ReadUInt64BigEndian(original.Selection.Field(4).Span)).ToArray();
                    }
                    var selection = grants.Selections[scopeName];
                    var dependencies = selection.Pending is not null ||
                        grants.Entries.Values.Count(value => value.AsSpan(0, 32).SequenceEqual(scope)) != 1
                        ? RetirementDependency.AcquisitionChain : RetirementDependency.None;
                    using var sendRaw = await ReadAsync(owner.storage, ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false);
                    using var send = sendRaw.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, network, account.Span, instance));
                    if (send.Entries.Values.Any(value => FixedRoute(value.ScopeHash, scope) || FixedRoute(value.RouteHash, route) ||
                            grant.Length != 0 && FixedRoute(value.GrantHash, grant))) dependencies |= RetirementDependency.SendWork;
                    if (grant.Length != 0 && send.Floors.Values.Any(value => FixedRoute(value.GrantHash, grant)))
                        dependencies |= RetirementDependency.SendFloor;
                    using var readRaw = await ReadAsync(owner.storage, ProtectedDid2MailboxReadJournal.Slot, ct).ConfigureAwait(false);
                    using var read = readRaw.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, network, account.Span, instance));
                    if (read.Active is { } active && (readScope.Length != 0 && FixedRoute(active.Scope, readScope) || FixedRoute(active.Route, route) ||
                            grant.Length != 0 && FixedRoute(active.Grant, grant))) dependencies |= RetirementDependency.ReadWork;
                    if (grant.Length != 0 && read.Counters.ContainsKey(Convert.ToHexString(grant))) dependencies |= RetirementDependency.ReadFloor;
                    if (readScope.Length != 0 && read.Traversals.ContainsKey(Convert.ToHexString(readScope)))
                        dependencies |= RetirementDependency.ReadTraversal;
                    using var ordinaryRaw = await ReadAsync(owner.storage, ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false);
                    using var ordinary = ordinaryRaw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, network, account.Span, instance));
                    // Current ordinary/asset roots do not contain a complete
                    // grant-to-receipt/object dependency index. Do not infer
                    // unrelatedness from a missing grant field or empty poll.
                    if (ordinary.Entries.Count != 0) dependencies |= RetirementDependency.OrdinaryWork;
                    using var attachmentRaw = await ReadAsync(owner.storage, ProtectedDid2AttachmentJournal.Slot, ct).ConfigureAwait(false);
                    using var attachments = attachmentRaw.Use(bytes => ProtectedDid2AttachmentJournal.Decode(bytes, network, account.Span, instance));
                    if (attachments.Entries.Count != 0) dependencies |= RetirementDependency.AttachmentWork;
                    using var catalogRaw = await ReadAsync(owner.storage, ProtectedDid2MessagingSessionCatalog.Slot, ct).ConfigureAwait(false);
                    using var catalog = catalogRaw.Use(bytes => ProtectedDid2MessagingSessionCatalog.Decode(bytes, network, account.Span, instance));
                    if (grant.Length != 0 || catalog.Count != 0) dependencies |= RetirementDependency.UnresolvedReceiptOrObject;
                    if (retrieve)
                        dependencies |= RetirementDependency.RetainedRetrievePath;
                    using var registration = await SqliteDeepIdV2AccountGeneration.ReadCompactionRegistrationUnderLeaseAsync(
                        owner.storage, network, account, ct).ConfigureAwait(false);
                    var native = await SqliteDeepIdV2AccountGeneration.ReadNativeReplayFenceUnderLeaseAsync(
                        owner.storage, owner.lease, owner.sqlStatePath, exclusion.current, exclusion.held, ct).ConfigureAwait(false);
                    var guards = new[]
                    {
                        Fact(Did2CompactionPlan.RootKind.Ordinary, ProtectedDid2DirectTextJournal.Slot, ordinaryRaw),
                        Fact(Did2CompactionPlan.RootKind.Send, ProtectedDid2MailboxSendJournal.Slot, sendRaw),
                        Fact(Did2CompactionPlan.RootKind.Grant, ProtectedDid2MailboxGrantJournal.Slot, grantRaw),
                        Fact(Did2CompactionPlan.RootKind.Read, ProtectedDid2MailboxReadJournal.Slot, readRaw),
                        Fact(Did2CompactionPlan.RootKind.SessionCatalog, ProtectedDid2MessagingSessionCatalog.Slot, catalogRaw),
                        Fact(Did2CompactionPlan.RootKind.Attachment, ProtectedDid2AttachmentJournal.Slot, attachmentRaw),
                        Fact(Did2CompactionPlan.RootKind.AccountRegistration, SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, registration),
                        native
                    };
                    ct.ThrowIfCancellationRequested(); exclusion.held.RequireOwner(owner.lease);
                    return new(exclusion, dependencies, guards);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(scope); CryptographicOperations.ZeroMemory(route);
                    CryptographicOperations.ZeroMemory(grant); CryptographicOperations.ZeroMemory(readScope);
                }
            }

            internal async Task RequireExactGuardsUnderGateAsync(CancellationToken ct)
            {
                var owner = exclusion.owner;
                var slots = new[] { ProtectedDid2DirectTextJournal.Slot, ProtectedDid2MailboxSendJournal.Slot,
                    ProtectedDid2MailboxGrantJournal.Slot, ProtectedDid2MailboxReadJournal.Slot,
                    ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDid2AttachmentJournal.Slot,
                    SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot };
                for (var index = 0; index < slots.Length; index++)
                {
                    using var actual = await ReadAsync(owner.storage, slots[index], ct).ConfigureAwait(false);
                    if (!actual.Use(bytes => FixedRoute(SHA256.HashData(bytes), guards[index].Digest.Span)))
                        throw new CryptographicException("A captured retirement dependency root changed; reselection is required.");
                }
                var native = await SqliteDeepIdV2AccountGeneration.ReadNativeReplayFenceUnderLeaseAsync(
                    owner.storage, owner.lease, owner.sqlStatePath, exclusion.current, exclusion.held, ct).ConfigureAwait(false);
                if (!FixedRoute(native.Selector.Span, guards[^1].Selector.Span) || !FixedRoute(native.Digest.Span, guards[^1].Digest.Span))
                    throw new CryptographicException("The captured native retirement fence changed.");
                ct.ThrowIfCancellationRequested(); exclusion.held.RequireOwner(owner.lease);
            }

            private static async Task<OwnedDeepSecret> ReadAsync(IDeepSecureStorage storage, string slot, CancellationToken ct) =>
                await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Retirement lost a mandatory dependency root; no repair is permitted.");
            private static Did2CompactionPlan.RootReadback Fact(Did2CompactionPlan.RootKind kind, string slot, OwnedDeepSecret raw) =>
                new(kind, CompactionSlotSelector(slot), raw.Use(bytes => SHA256.HashData(bytes)));
        }
    }
}
