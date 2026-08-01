using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence;

internal enum InMemoryScopedMailboxFaultPoint
{
    ImportBeforePublish = 1,
    SwitchBeforePublish = 2,
    PrepareBeforePublish = 3,
    PrepareAfterPublish = 4
}

/// <summary>
/// Test/dev parity implementation of the scoped mailbox credential boundary.
/// Production composition remains <see cref="SqliteSessionStore"/>. Every
/// mutation publishes one copy-on-write aggregate containing credentials,
/// counters, prepared target catalogs, and equivalent outbox snapshots.
/// </summary>
public sealed class InMemoryScopedMailboxCredentialRepository :
    IScopedMailboxCredentialRepository
{
    private const int MaximumOutboxItems = 4096;
    private const long MaximumOutboxBytes = 256L * 1024 * 1024;
    private readonly object gate = new();
    private readonly Action<InMemoryScopedMailboxFaultPoint>? fault;
    private Snapshot current = new();

    public InMemoryScopedMailboxCredentialRepository()
    {
    }

    internal InMemoryScopedMailboxCredentialRepository(
        Action<InMemoryScopedMailboxFaultPoint> fault)
    {
        this.fault = fault ?? throw new ArgumentNullException(nameof(fault));
    }

    public Task InstallScopedCredentialAsync(
        ScopedMailboxCredentialGeneration generation,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default) =>
        InstallScopedCredentialBatchAsync(
            [generation], authority, cancellationToken);

    public Task InstallScopedCredentialBatchAsync(
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateImportBatch(generations, authority);
        lock (gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidate = current.Clone();
            foreach (var generation in generations)
            {
                var key = ScopeKey(generation.Selector.ScopeId.Span);
                var canonical = CredentialMaterial(generation, authority);
                if (candidate.Credentials.TryGetValue(key, out var existing))
                {
                    if (!Fixed(existing.CanonicalMaterial, canonical))
                    {
                        throw new InvalidOperationException(
                            "Mailbox credential import conflicts with the exact persisted scope.");
                    }
                    continue;
                }

                EnsureNoCrossScopeReuse(candidate, generation);
                candidate.Credentials.Add(
                    key,
                    new StoredCredential(
                        CloneGeneration(generation),
                        canonical,
                        authority.NetworkId.ToArray(),
                        authority.PolicyFingerprint.ToArray(),
                        generation.Current.Epoch));
            }
            fault?.Invoke(
                InMemoryScopedMailboxFaultPoint.ImportBeforePublish);
            cancellationToken.ThrowIfCancellationRequested();
            current = candidate;
        }
        return Task.CompletedTask;
    }

    public Task SwitchScopedCredentialEpochAsync(
        MailboxCredentialSelector selector,
        ulong epoch,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selector);
        authority.Validate();
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidate = current.Clone();
            var stored = GetCredential(candidate, selector);
            ValidateStoredAuthority(stored, selector, authority);
            var generation = stored.Generation;
            var target = generation.Next;
            if (stored.ActiveEpoch == ulong.MaxValue ||
                epoch != stored.ActiveEpoch + 1 ||
                epoch != target.Epoch ||
                authority.NowUnixSeconds < target.NotBeforeUnixSeconds ||
                authority.NowUnixSeconds > target.ExpiresAtUnixSeconds)
            {
                throw new InvalidOperationException(
                    "Mailbox epoch handoff is not authorized.");
            }
            stored.ActiveEpoch = epoch;
            fault?.Invoke(
                InMemoryScopedMailboxFaultPoint.SwitchBeforePublish);
            cancellationToken.ThrowIfCancellationRequested();
            current = candidate;
        }
        return Task.CompletedTask;
    }

    public Task<ScopedMailboxResolvedRoute> ReadScopedMailboxRouteAsync(
        MailboxCredentialSelector selector,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selector);
        authority.Validate();
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            var stored = GetCredential(current, selector);
            ValidateStoredAuthority(stored, selector, authority);
            return Task.FromResult(Route(stored, selector, authority));
        }
    }

    public Task<ScopedMailboxResolvedRoute>
        RevalidateScopedMailboxDispatchAsync(
        MailboxCredentialSelector selector,
        MailboxAuthenticatedOperation operation,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selector);
        authority.Validate();
        cancellationToken.ThrowIfCancellationRequested();
        var role = ScopedMailboxCredentialValidator.RoleFor(operation);
        ScopedMailboxCredentialValidator.EnsureRoleAllowed(selector, role);
        lock (gate)
        {
            var resolved = Resolve(
                current,
                selector,
                role,
                authority,
                binding: null,
                allocateCounter: false);
            return Task.FromResult(resolved.Route);
        }
    }

    public Task<ScopedMailboxPreparedBatch> PrepareScopedMailboxBatchAsync(
        ScopedMailboxPrepareBatchRequest request,
        IMailboxOperationSigner signer,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        authority.Validate();
        ScopedMailboxCredentialValidator.ValidateBatch(request, signer);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidate = current.Clone();
            var batchKey = BatchKey(
                request.AccountScope.Value,
                request.ParentOperationId.Span);
            var planDigest =
                ScopedMailboxCredentialValidator.ComputePlanDigest(request);
            if (candidate.Batches.TryGetValue(batchKey, out var resumed))
            {
                return Task.FromResult(Resume(
                    candidate,
                    resumed,
                    request,
                    signer,
                    authority,
                    planDigest));
            }

            var frames = new List<MailboxAuthenticatedRequestFrame>(
                request.Targets.Count);
            var targets = new List<StoredTarget>(request.Targets.Count);
            foreach (var target in request.Targets)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var role = ScopedMailboxCredentialValidator.RoleFor(
                    target.Binding.Operation);
                ScopedMailboxCredentialValidator.EnsureRoleAllowed(
                    target.Selector, role);
                var resolved = Resolve(
                    candidate,
                    target.Selector,
                    role,
                    authority,
                    target.Binding,
                    allocateCounter: true);
                var frame = ScopedMailboxCredentialValidator.Sign(
                    target.Binding,
                    signer,
                    resolved.Grant,
                    resolved.Counter,
                    resolved.HolderKey);
                var canonical = frame.GetCanonicalMau2Copy();
                var outboxKey = OutboxKey(
                    request.AccountScope.Value,
                    target.Binding.OperationId.Span);
                if (candidate.Outbox.ContainsKey(outboxKey))
                {
                    throw new InvalidOperationException(
                        "Mailbox target operation conflicts with durable outbox state.");
                }
                if (candidate.Outbox.Count >= MaximumOutboxItems ||
                    candidate.OutboxBytes >
                        MaximumOutboxBytes - canonical.Length)
                {
                    throw new InvalidOperationException(
                        "Mailbox prepared batch exceeds durable outbox capacity.");
                }
                candidate.Outbox.Add(outboxKey, canonical.ToArray());
                candidate.OutboxBytes = checked(
                    candidate.OutboxBytes + canonical.Length);
                targets.Add(new StoredTarget(
                    target.Selector.ScopeId.ToArray(),
                    target.Binding.Operation,
                    target.Binding.OperationId.ToArray(),
                    target.Binding.RequestDigest.ToArray(),
                    target.Binding.CanonicalRequest.ToArray(),
                    resolved.Counter,
                    canonical.ToArray()));
                frames.Add(frame);
            }

            candidate.Batches.Add(
                batchKey,
                new StoredBatch(
                    planDigest.ToArray(),
                    request.CreatedAt.ToUnixTimeMilliseconds(),
                    request.Targets.Count,
                    targets));
            fault?.Invoke(
                InMemoryScopedMailboxFaultPoint.PrepareBeforePublish);
            cancellationToken.ThrowIfCancellationRequested();
            current = candidate;
            try
            {
                fault?.Invoke(
                    InMemoryScopedMailboxFaultPoint.PrepareAfterPublish);
                cancellationToken.ThrowIfCancellationRequested();
            }
            catch
            {
                throw new TransportOutboxCommitOutcomeUnknownException();
            }
            return Task.FromResult(new ScopedMailboxPreparedBatch(
                request.ParentOperationId, frames));
        }
    }

    internal int CredentialCountForTests()
    {
        lock (gate)
        {
            return current.Credentials.Count;
        }
    }

    internal int PreparedBatchCountForTests()
    {
        lock (gate)
        {
            return current.Batches.Count;
        }
    }

    internal int EquivalentOutboxCountForTests()
    {
        lock (gate)
        {
            return current.Outbox.Count;
        }
    }

    internal IReadOnlyList<ulong> NextCountersForTests()
    {
        lock (gate)
        {
            return current.Counters.Values.Order().ToArray();
        }
    }

    internal void DeletePreparedTargetsForTests(
        OutboxAccountScope account,
        ReadOnlySpan<byte> parentOperationId)
    {
        ArgumentNullException.ThrowIfNull(account);
        lock (gate)
        {
            var candidate = current.Clone();
            var batch = candidate.Batches[BatchKey(
                account.Value, parentOperationId)];
            batch.Targets.Clear();
            current = candidate;
        }
    }

    internal void SetAllNextCountersForTests(ulong value)
    {
        lock (gate)
        {
            var candidate = current.Clone();
            foreach (var key in candidate.Counters.Keys.ToArray())
            {
                candidate.Counters[key] = value;
            }
            current = candidate;
        }
    }

    private static ScopedMailboxPreparedBatch Resume(
        Snapshot snapshot,
        StoredBatch stored,
        ScopedMailboxPrepareBatchRequest request,
        IMailboxOperationSigner signer,
        VerifiedOfficialMailboxAuthority authority,
        byte[] planDigest)
    {
        if (!Fixed(stored.PlanDigest, planDigest) ||
            stored.CreatedAtUnixMilliseconds !=
                request.CreatedAt.ToUnixTimeMilliseconds() ||
            stored.TargetCount != request.Targets.Count)
        {
            throw new InvalidOperationException(
                "Mailbox batch operation conflicts with durable preparation.");
        }

        if (stored.Targets.Count != stored.TargetCount)
        {
            throw new InvalidDataException(
                "Mailbox prepared batch target catalog is incomplete.");
        }

        var frames = new List<MailboxAuthenticatedRequestFrame>(
            request.Targets.Count);
        for (var ordinal = 0; ordinal < request.Targets.Count; ordinal++)
        {
            var requested = request.Targets[ordinal];
            var persisted = stored.Targets[ordinal];
            if (persisted.Counter == 0 ||
                persisted.Operation != requested.Binding.Operation ||
                !Fixed(persisted.ScopeId,
                    requested.Selector.ScopeId.Span) ||
                !Fixed(persisted.OperationId,
                    requested.Binding.OperationId.Span) ||
                !Fixed(persisted.RequestDigest,
                    requested.Binding.RequestDigest.Span) ||
                !Fixed(persisted.CanonicalRequest,
                    requested.Binding.CanonicalRequest.Span))
            {
                throw new InvalidDataException(
                    "Mailbox prepared batch target catalog is corrupt.");
            }
            var outboxKey = OutboxKey(
                request.AccountScope.Value,
                requested.Binding.OperationId.Span);
            if (!snapshot.Outbox.TryGetValue(outboxKey, out var outbox) ||
                !Fixed(outbox, persisted.Frame))
            {
                throw new InvalidDataException(
                    "Mailbox prepared batch lost an outbox target.");
            }
            var role = ScopedMailboxCredentialValidator.RoleFor(
                requested.Binding.Operation);
            var resolved = Resolve(
                snapshot,
                requested.Selector,
                role,
                authority,
                requested.Binding,
                allocateCounter: false);
            ValidateResumedFrame(
                persisted, requested, resolved, signer);
            frames.Add(new MailboxAuthenticatedRequestFrame(
                persisted.Operation,
                persisted.Frame));
        }
        return new ScopedMailboxPreparedBatch(
            request.ParentOperationId, frames);
    }

    private static void ValidateResumedFrame(
        StoredTarget stored,
        ScopedMailboxBatchTarget requested,
        Resolved resolved,
        IMailboxOperationSigner signer)
    {
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(
            stored.Frame);
        var persistedGrant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(
            decoded.Presentation.Grant);
        var currentGrant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(
            resolved.Grant);
        var signerKey = signer.GetEd25519PublicKey();
        try
        {
            if (decoded.Presentation.ReplayCounter != stored.Counter ||
                !Fixed(persistedGrant, currentGrant) ||
                !Fixed(signerKey, resolved.HolderKey) ||
                !new SodiumMailboxCapabilityCrypto().VerifyHolder(
                    resolved.HolderKey,
                    MailboxAuthenticatedCapabilityCodec
                        .GetPresentationSigningBytes(decoded.Presentation),
                    decoded.Presentation.HolderSignature.Span))
            {
                throw new InvalidDataException(
                    "Mailbox prepared batch frame is stale or corrupt.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signerKey);
        }
    }

    private static Resolved Resolve(
        Snapshot snapshot,
        MailboxCredentialSelector selector,
        MailboxCredentialRole role,
        VerifiedOfficialMailboxAuthority authority,
        MailboxAuthenticatedRequestBinding? binding,
        bool allocateCounter)
    {
        var stored = GetCredential(snapshot, selector);
        ValidateStoredAuthority(stored, selector, authority);
        var generation = stored.Generation;
        var epoch = Epoch(generation, stored.ActiveEpoch);
        if (authority.NowUnixSeconds < epoch.NotBeforeUnixSeconds ||
            authority.NowUnixSeconds > epoch.ExpiresAtUnixSeconds)
        {
            throw new InvalidOperationException(
                "Scoped mailbox credential authority is stale or mismatched.");
        }
        if (binding is not null)
        {
            ScopedMailboxCredentialValidator.ValidateBindingRoute(
                binding,
                epoch.Epoch,
                generation.MailboxId.Span,
                epoch.PlacementId.Span);
        }
        var encoded = Grant(generation, role, epoch.Epoch);
        var grant = ScopedMailboxCredentialValidator.ValidateCanonicalGrant(
            encoded.Span,
            role,
            epoch.Epoch,
            epoch.NotBeforeUnixSeconds,
            epoch.ExpiresAtUnixSeconds,
            epoch.PlacementCommitment.Span,
            epoch.MembershipCommitment.Span,
            generation.HolderPublicKey.Span,
            authority,
            rejectRevoked: true);
        var digest = SHA256.HashData(encoded.Span);
        var counter = 0UL;
        if (allocateCounter)
        {
            var counterKey = CounterKey(
                selector.ScopeId.Span,
                epoch.Epoch,
                digest);
            counter = snapshot.Counters.TryGetValue(
                counterKey, out var value) ? value : 1;
            if (counter == 0 || counter == ulong.MaxValue)
            {
                throw new InvalidOperationException(
                    "Mailbox replay counter is exhausted.");
            }
            snapshot.Counters[counterKey] = checked(counter + 1);
        }
        return new Resolved(
            grant,
            counter,
            generation.HolderPublicKey.ToArray(),
            Route(stored, selector, authority));
    }

    private static ScopedMailboxResolvedRoute Route(
        StoredCredential stored,
        MailboxCredentialSelector selector,
        VerifiedOfficialMailboxAuthority authority)
    {
        ValidateStoredAuthority(stored, selector, authority);
        var generation = stored.Generation;
        var epoch = Epoch(generation, stored.ActiveEpoch);
        if (authority.NowUnixSeconds < epoch.NotBeforeUnixSeconds ||
            authority.NowUnixSeconds > epoch.ExpiresAtUnixSeconds)
        {
            throw new InvalidOperationException(
                "Exact scoped mailbox route is unavailable.");
        }
        if (selector.Kind == MailboxCredentialScopeKind.Group &&
            !Fixed(
                epoch.MembershipCommitment.Span,
                selector.GroupMembershipCommitment.Span))
        {
            throw new InvalidOperationException(
                "Exact scoped mailbox route is unavailable.");
        }
        return new ScopedMailboxResolvedRoute(
            epoch.Epoch,
            new BlindedMailboxId(generation.MailboxId.Span),
            new BlindedPlacementId(epoch.PlacementId.Span),
            epoch.PlacementCommitment,
            epoch.MembershipCommitment,
            CloneReplicas(generation.Replicas));
    }

    private static void ValidateImportBatch(
        IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
        VerifiedOfficialMailboxAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(generations);
        authority.Validate();
        if (generations.Count is < 1 or >
            ScopedMailboxCredentialValidator.MaximumBatchTargets)
        {
            throw new ArgumentException(
                "Scoped mailbox credential import is invalid.",
                nameof(generations));
        }
        var scopes = new HashSet<string>(StringComparer.Ordinal);
        var materials = new HashSet<string>(StringComparer.Ordinal);
        var serials = new HashSet<string>(StringComparer.Ordinal);
        foreach (var generation in generations)
        {
            ScopedMailboxCredentialValidator.ValidateGeneration(
                generation, authority, serials);
            if (!scopes.Add(ScopeKey(generation.Selector.ScopeId.Span)))
            {
                throw new InvalidDataException(
                    "Scoped mailbox import repeats a scope.");
            }
            foreach (var material in UniqueMaterials(generation))
            {
                if (!materials.Add(Convert.ToHexString(material.Span)))
                {
                    throw new InvalidDataException(
                        "Scoped mailbox import reuses credential material across scopes.");
                }
            }
        }
    }

    private static void EnsureNoCrossScopeReuse(
        Snapshot snapshot,
        ScopedMailboxCredentialGeneration generation)
    {
        foreach (var existing in snapshot.Credentials.Values)
        {
            foreach (var candidate in UniqueMaterials(generation))
            foreach (var persisted in UniqueMaterials(existing.Generation))
            {
                if (Fixed(candidate.Span, persisted.Span))
                {
                    throw new InvalidDataException(
                        "Scoped mailbox credential material is already bound to another scope.");
                }
            }
            foreach (var candidate in Grants(generation))
            foreach (var persisted in Grants(existing.Generation))
            {
                var left = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                    candidate.Span);
                var right = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                    persisted.Span);
                if (Fixed(left.IssuerPublicKey.Span,
                        right.IssuerPublicKey.Span) &&
                    Fixed(left.Serial.Span, right.Serial.Span))
                {
                    throw new InvalidDataException(
                        "Scoped mailbox grant serial is already bound to another scope.");
                }
            }
        }
    }

    private static void ValidateStoredAuthority(
        StoredCredential stored,
        MailboxCredentialSelector selector,
        VerifiedOfficialMailboxAuthority authority)
    {
        authority.Validate();
        if (!stored.Generation.Selector.AccountScope.Equals(
                selector.AccountScope) ||
            !Fixed(stored.NetworkId, authority.NetworkId.Span) ||
            !Fixed(stored.AuthorityPolicyDigest,
                authority.PolicyFingerprint.Span))
        {
            throw new InvalidOperationException(
                "Scoped mailbox credential authority is stale or mismatched.");
        }
    }

    private static StoredCredential GetCredential(
        Snapshot snapshot,
        MailboxCredentialSelector selector) =>
        snapshot.Credentials.TryGetValue(
            ScopeKey(selector.ScopeId.Span), out var stored)
            ? stored
            : throw new InvalidOperationException(
                "Exact scoped mailbox credential is unavailable.");

    private static MailboxCredentialEpoch Epoch(
        ScopedMailboxCredentialGeneration generation,
        ulong epoch) => epoch == generation.Current.Epoch
        ? generation.Current
        : epoch == generation.Next.Epoch
            ? generation.Next
            : throw new InvalidDataException(
                "Scoped mailbox active epoch is corrupt.");

    private static ReadOnlyMemory<byte> Grant(
        ScopedMailboxCredentialGeneration generation,
        MailboxCredentialRole role,
        ulong epoch)
    {
        var set = role == MailboxCredentialRole.Retrieve
            ? generation.Retrieve
            : generation.Deposit;
        if (set is null)
        {
            throw new InvalidOperationException(
                "Exact scoped mailbox credential is unavailable.");
        }
        return epoch == generation.Current.Epoch
            ? set.CurrentGrant
            : epoch == generation.Next.Epoch
                ? set.NextGrant
                : throw new InvalidDataException(
                    "Scoped mailbox active epoch is corrupt.");
    }

    private static IEnumerable<ReadOnlyMemory<byte>> UniqueMaterials(
        ScopedMailboxCredentialGeneration generation)
    {
        yield return generation.Generation;
        yield return generation.MailboxId;
        foreach (var grant in Grants(generation))
        {
            yield return grant;
        }
    }

    private static IEnumerable<ReadOnlyMemory<byte>> Grants(
        ScopedMailboxCredentialGeneration generation)
    {
        if (generation.Retrieve is { } retrieve)
        {
            yield return retrieve.CurrentGrant;
            yield return retrieve.NextGrant;
        }
        if (generation.Deposit is { } deposit)
        {
            yield return deposit.CurrentGrant;
            yield return deposit.NextGrant;
        }
    }

    private static byte[] CredentialMaterial(
        ScopedMailboxCredentialGeneration generation,
        VerifiedOfficialMailboxAuthority authority)
    {
        using var stream = new MemoryStream();
        Write(stream, generation.Selector.AccountScope.Value);
        stream.WriteByte((byte)generation.Selector.Kind);
        Write(stream, generation.Selector.SubjectId.Span);
        Write(stream, generation.Selector.IssuerContext.Span);
        WriteNullable(
            stream,
            generation.Selector.GroupMembershipCommitment.Span);
        Write(stream, authority.NetworkId.Span);
        Write(stream, authority.PolicyFingerprint.Span);
        Write(stream, generation.Generation.Span);
        Write(stream, generation.HolderPublicKey.Span);
        Write(stream, generation.MailboxId.Span);
        WriteEpoch(stream, generation.Current);
        WriteEpoch(stream, generation.Next);
        WriteGrantSet(stream, generation.Retrieve);
        WriteGrantSet(stream, generation.Deposit);
        Write(stream, generation.Replicas.FirstId.Span);
        Write(stream, generation.Replicas.FirstSigningKey.Span);
        Write(stream, generation.Replicas.SecondId.Span);
        Write(stream, generation.Replicas.SecondSigningKey.Span);
        return stream.ToArray();
    }

    private static void WriteEpoch(
        Stream stream,
        MailboxCredentialEpoch epoch)
    {
        WriteU64(stream, epoch.Epoch);
        WriteU64(stream, epoch.NotBeforeUnixSeconds);
        WriteU64(stream, epoch.ExpiresAtUnixSeconds);
        Write(stream, epoch.MembershipCommitment.Span);
        Write(stream, epoch.PlacementId.Span);
        Write(stream, epoch.PlacementCommitment.Span);
    }

    private static void WriteGrantSet(
        Stream stream,
        MailboxCredentialGrantSet? set)
    {
        stream.WriteByte(set is null ? (byte)0 : (byte)1);
        if (set is not null)
        {
            Write(stream, set.CurrentGrant.Span);
            Write(stream, set.NextGrant.Span);
        }
    }

    private static void WriteNullable(
        Stream stream,
        ReadOnlySpan<byte> value)
    {
        stream.WriteByte(value.IsEmpty ? (byte)0 : (byte)1);
        if (!value.IsEmpty)
        {
            Write(stream, value);
        }
    }

    private static void Write(Stream stream, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        stream.Write(length);
        stream.Write(value);
    }

    private static void WriteU64(Stream stream, ulong value)
    {
        Span<byte> encoded = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        stream.Write(encoded);
    }

    private static ScopedMailboxCredentialGeneration CloneGeneration(
        ScopedMailboxCredentialGeneration generation) => new(
        new MailboxCredentialSelector(
            OutboxAccountScope.FromBytes(
                generation.Selector.AccountScope.Value),
            generation.Selector.Kind,
            generation.Selector.SubjectId.Span,
            generation.Selector.IssuerContext.Span,
            generation.Selector.GroupMembershipCommitment.Span),
        generation.Generation.ToArray(),
        generation.HolderPublicKey.ToArray(),
        generation.MailboxId.ToArray(),
        CloneEpoch(generation.Current),
        CloneEpoch(generation.Next),
        CloneGrantSet(generation.Retrieve),
        CloneGrantSet(generation.Deposit),
        CloneReplicas(generation.Replicas));

    private static MailboxCredentialEpoch CloneEpoch(
        MailboxCredentialEpoch epoch) => new(
        epoch.Epoch,
        epoch.NotBeforeUnixSeconds,
        epoch.ExpiresAtUnixSeconds,
        epoch.MembershipCommitment.Span,
        epoch.PlacementId.Span,
        epoch.PlacementCommitment.Span);

    private static MailboxCredentialGrantSet? CloneGrantSet(
        MailboxCredentialGrantSet? set) => set is null
        ? null
        : new MailboxCredentialGrantSet(
            set.CurrentGrant.Span,
            set.NextGrant.Span);

    private static MailboxCredentialReplicaPair CloneReplicas(
        MailboxCredentialReplicaPair replicas) => new(
        replicas.FirstId.Span,
        replicas.FirstSigningKey.Span,
        replicas.SecondId.Span,
        replicas.SecondSigningKey.Span);

    private static string ScopeKey(ReadOnlySpan<byte> scope) =>
        Convert.ToHexString(scope);
    private static string BatchKey(
        ReadOnlySpan<byte> account,
        ReadOnlySpan<byte> parent) =>
        Convert.ToHexString(account) + ":" + Convert.ToHexString(parent);
    private static string OutboxKey(
        ReadOnlySpan<byte> account,
        ReadOnlySpan<byte> operation) =>
        Convert.ToHexString(account) + ":" + Convert.ToHexString(operation);
    private static string CounterKey(
        ReadOnlySpan<byte> scope,
        ulong epoch,
        ReadOnlySpan<byte> digest) =>
        Convert.ToHexString(scope) + ":" + epoch.ToString("X16") +
        ":" + Convert.ToHexString(digest);
    private static bool Fixed(
        ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        ScopedMailboxCredentialValidator.Fixed(left, right);

    private sealed class Snapshot
    {
        public Dictionary<string, StoredCredential> Credentials { get; } =
            new(StringComparer.Ordinal);
        public Dictionary<string, ulong> Counters { get; } =
            new(StringComparer.Ordinal);
        public Dictionary<string, StoredBatch> Batches { get; } =
            new(StringComparer.Ordinal);
        public Dictionary<string, byte[]> Outbox { get; } =
            new(StringComparer.Ordinal);
        public long OutboxBytes { get; set; }

        public Snapshot Clone()
        {
            var clone = new Snapshot { OutboxBytes = OutboxBytes };
            foreach (var pair in Credentials)
            {
                clone.Credentials.Add(pair.Key, pair.Value.Clone());
            }
            foreach (var pair in Counters)
            {
                clone.Counters.Add(pair.Key, pair.Value);
            }
            foreach (var pair in Batches)
            {
                clone.Batches.Add(pair.Key, pair.Value.Clone());
            }
            foreach (var pair in Outbox)
            {
                clone.Outbox.Add(pair.Key, pair.Value.ToArray());
            }
            return clone;
        }
    }

    private sealed class StoredCredential(
        ScopedMailboxCredentialGeneration generation,
        byte[] canonicalMaterial,
        byte[] networkId,
        byte[] authorityPolicyDigest,
        ulong activeEpoch)
    {
        public ScopedMailboxCredentialGeneration Generation { get; } =
            generation;
        public byte[] CanonicalMaterial { get; } = canonicalMaterial;
        public byte[] NetworkId { get; } = networkId;
        public byte[] AuthorityPolicyDigest { get; } = authorityPolicyDigest;
        public ulong ActiveEpoch { get; set; } = activeEpoch;
        public StoredCredential Clone() => new(
            CloneGeneration(Generation),
            CanonicalMaterial.ToArray(),
            NetworkId.ToArray(),
            AuthorityPolicyDigest.ToArray(),
            ActiveEpoch);
    }

    private sealed class StoredBatch(
        byte[] planDigest,
        long createdAtUnixMilliseconds,
        int targetCount,
        List<StoredTarget> targets)
    {
        public byte[] PlanDigest { get; } = planDigest;
        public long CreatedAtUnixMilliseconds { get; } =
            createdAtUnixMilliseconds;
        public int TargetCount { get; } = targetCount;
        public List<StoredTarget> Targets { get; } = targets;
        public StoredBatch Clone() => new(
            PlanDigest.ToArray(),
            CreatedAtUnixMilliseconds,
            TargetCount,
            Targets.Select(static target => target.Clone()).ToList());
    }

    private sealed class StoredTarget(
        byte[] scopeId,
        MailboxAuthenticatedOperation operation,
        byte[] operationId,
        byte[] requestDigest,
        byte[] canonicalRequest,
        ulong counter,
        byte[] frame)
    {
        public byte[] ScopeId { get; } = scopeId;
        public MailboxAuthenticatedOperation Operation { get; } = operation;
        public byte[] OperationId { get; } = operationId;
        public byte[] RequestDigest { get; } = requestDigest;
        public byte[] CanonicalRequest { get; } = canonicalRequest;
        public ulong Counter { get; } = counter;
        public byte[] Frame { get; } = frame;
        public StoredTarget Clone() => new(
            ScopeId.ToArray(),
            Operation,
            OperationId.ToArray(),
            RequestDigest.ToArray(),
            CanonicalRequest.ToArray(),
            Counter,
            Frame.ToArray());
    }

    private sealed record Resolved(
        MailboxAuthenticatedGrant Grant,
        ulong Counter,
        byte[] HolderKey,
        ScopedMailboxResolvedRoute Route);
}
