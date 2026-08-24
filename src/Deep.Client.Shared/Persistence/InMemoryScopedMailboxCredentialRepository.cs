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
    PrepareAfterPublish = 4,
    RotationBeforePublish = 5
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

    public Task RotateScopedCredentialBatchAsync(
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
                if (!candidate.Credentials.TryGetValue(key, out var existing))
                    throw new InvalidOperationException(
                        "Mailbox credential rotation requires an installed scope.");
                var canonical = CredentialMaterial(generation, authority);
                if (Fixed(existing.CanonicalMaterial, canonical))
                    continue;
                EnsureNoCrossScopeReuse(candidate, generation);
                EnsureRotationOverlap(existing, generation, authority);
                candidate.Credentials[key] = new StoredCredential(
                    CloneGeneration(generation),
                    canonical,
                    authority.NetworkId.ToArray(),
                    authority.PolicyFingerprint.ToArray(),
                    generation.Current.Epoch);
                var counterPrefix = key + ":";
                var overlapMarker = ":" + generation.Current.Epoch.ToString("X16") + ":";
                foreach (var counterKey in candidate.Counters.Keys
                    .Where(item => item.StartsWith(counterPrefix, StringComparison.Ordinal) &&
                        !item.Contains(overlapMarker, StringComparison.Ordinal))
                    .ToArray())
                {
                    candidate.Counters.Remove(counterKey);
                }
            }
            fault?.Invoke(InMemoryScopedMailboxFaultPoint.RotationBeforePublish);
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
            var semanticOwnerExists = ValidateSemanticBatchOwnership(
                candidate,
                request.AccountScope.Value,
                request.SemanticOperationId.Span,
                request.ParentOperationId.Span);
            var planDigest =
                ScopedMailboxCredentialValidator.ComputePlanDigest(request);
            if (candidate.Batches.TryGetValue(batchKey, out var resumed))
            {
                return Task.FromResult(ResumeLogical(
                    candidate,
                    resumed,
                    new ScopedMailboxResumeBatchRequest(
                        request.AccountScope,
                        request.ParentOperationId,
                        request.SemanticOperationId,
                        request.Selectors),
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
                    request.SemanticOperationId.ToArray(),
                    planDigest.ToArray(),
                    request.CreatedAt.ToUnixTimeMilliseconds(),
                    request.Targets.Count,
                    targets));
            if (semanticOwnerExists || !candidate.SemanticOwners.TryAdd(
                    SemanticBatchKey(
                        request.AccountScope.Value,
                        request.SemanticOperationId.Span),
                    batchKey))
            {
                throw new InvalidDataException(
                    "Mailbox semantic operation owner is corrupt.");
            }
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

    public Task<ScopedMailboxPreparedBatch?> TryResumeScopedMailboxBatchAsync(
        ScopedMailboxResumeBatchRequest request,
        IMailboxOperationSigner signer,
        VerifiedOfficialMailboxAuthority authority,
        CancellationToken cancellationToken = default)
    {
        authority.Validate();
        ScopedMailboxCredentialValidator.ValidateResumeBatch(request, signer);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            var batchKey = BatchKey(
                request.AccountScope.Value, request.ParentOperationId.Span);
            var semanticOwnerExists = ValidateSemanticBatchOwnership(
                current,
                request.AccountScope.Value,
                request.SemanticOperationId.Span,
                request.ParentOperationId.Span);
            if (!current.Batches.TryGetValue(batchKey, out var stored))
            {
                if (semanticOwnerExists)
                {
                    throw new InvalidDataException(
                        "Mailbox semantic batch owner lost its prepared batch.");
                }
                return Task.FromResult<ScopedMailboxPreparedBatch?>(null);
            }

            var resumed = ResumeLogical(
                current,
                stored,
                request,
                signer,
                authority,
                ScopedMailboxCredentialValidator.ComputePlanDigest(request));
            return Task.FromResult<ScopedMailboxPreparedBatch?>(resumed);
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

    private static ScopedMailboxPreparedBatch ResumeLogical(
        Snapshot snapshot,
        StoredBatch stored,
        ScopedMailboxResumeBatchRequest request,
        IMailboxOperationSigner signer,
        VerifiedOfficialMailboxAuthority authority,
        byte[] planDigest)
    {
        if (!Fixed(stored.PlanDigest, planDigest) ||
            stored.TargetCount != request.Selectors.Count)
        {
            throw new InvalidOperationException(
                "Mailbox batch operation conflicts with durable preparation.");
        }
        if (stored.Targets.Count != stored.TargetCount)
        {
            throw new InvalidDataException(
                "Mailbox prepared batch target catalog is incomplete.");
        }

        var frames = new List<MailboxAuthenticatedRequestFrame>(stored.TargetCount);
        for (var ordinal = 0; ordinal < stored.TargetCount; ordinal++)
        {
            var logical = request.Selectors[ordinal];
            var persisted = stored.Targets[ordinal];
            if (persisted.Counter == 0 ||
                persisted.Operation != logical.Operation ||
                !Fixed(persisted.ScopeId, logical.Selector.ScopeId.Span))
            {
                throw new InvalidDataException(
                    "Mailbox prepared batch target catalog is corrupt.");
            }
            var outboxKey = OutboxKey(
                request.AccountScope.Value, persisted.OperationId);
            if (!snapshot.Outbox.TryGetValue(outboxKey, out var outbox) ||
                !Fixed(outbox, persisted.Frame))
            {
                throw new InvalidDataException(
                    "Mailbox prepared batch lost an outbox target.");
            }
            var decoded = MailboxAuthenticatedClientRequestCodec.Decode(persisted.Frame);
            if (!Fixed(decoded.Binding.OperationId.Span, persisted.OperationId) ||
                !Fixed(decoded.Binding.RequestDigest.Span, persisted.RequestDigest) ||
                !Fixed(decoded.Binding.CanonicalRequest.Span, persisted.CanonicalRequest))
            {
                throw new InvalidDataException(
                    "Mailbox prepared batch target is corrupt.");
            }
            var requested = new ScopedMailboxBatchTarget(
                logical.Selector, decoded.Binding);
            var role = ScopedMailboxCredentialValidator.RoleFor(logical.Operation);
            var resolved = Resolve(
                snapshot, logical.Selector, role, authority,
                decoded.Binding, allocateCounter: false);
            ValidateResumedFrame(persisted, requested, resolved, signer);
            frames.Add(new MailboxAuthenticatedRequestFrame(
                persisted.Operation, persisted.Frame));
        }
        return new ScopedMailboxPreparedBatch(request.ParentOperationId, frames);
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
            epoch.ExpiresAtUnixSeconds,
            new BlindedMailboxId(generation.MailboxId.Span),
            new BlindedPlacementId(epoch.PlacementId.Span),
            epoch.PlacementCommitment,
            epoch.MembershipCommitment,
            CloneReplicas(generation.ReplicasFor(epoch.Epoch)));
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
            if (Fixed(existing.Generation.Selector.ScopeId.Span,
                    generation.Selector.ScopeId.Span))
                continue;
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

    private static void EnsureRotationOverlap(
        StoredCredential existing,
        ScopedMailboxCredentialGeneration incoming,
        VerifiedOfficialMailboxAuthority authority)
    {
        var prior = existing.Generation;
        if (prior.Next.Epoch != incoming.Current.Epoch ||
            existing.ActiveEpoch > incoming.Current.Epoch ||
            Fixed(prior.Generation.Span, incoming.Generation.Span) ||
            !Fixed(existing.NetworkId, authority.NetworkId.Span) ||
            !Fixed(prior.HolderPublicKey.Span, incoming.HolderPublicKey.Span) ||
            !Fixed(prior.MailboxId.Span, incoming.MailboxId.Span) ||
            !Fixed(prior.Selector.ScopeId.Span, incoming.Selector.ScopeId.Span) ||
            !EqualEpoch(prior.Next, incoming.Current) ||
            !EqualReplicas(prior.NextReplicas, incoming.CurrentReplicas) ||
            !EqualOverlapGrant(prior.Retrieve, incoming.Retrieve) ||
            !EqualOverlapGrant(prior.Deposit, incoming.Deposit) ||
            EqualEpochMaterial(prior.Current, incoming.Next) ||
            Grants(prior).Any(oldGrant =>
                new[] { incoming.Retrieve?.NextGrant, incoming.Deposit?.NextGrant }
                    .Where(static item => item.HasValue)
                    .Any(nextGrant => Fixed(oldGrant.Span, nextGrant!.Value.Span))))
        {
            throw new InvalidOperationException(
                "Mailbox rotation does not preserve exact E+1 overlap or reuses retired material.");
        }

        static bool EqualEpoch(MailboxCredentialEpoch left, MailboxCredentialEpoch right) =>
            left.Epoch == right.Epoch &&
            left.NotBeforeUnixSeconds == right.NotBeforeUnixSeconds &&
            left.ExpiresAtUnixSeconds == right.ExpiresAtUnixSeconds &&
            EqualEpochMaterial(left, right);
        static bool EqualEpochMaterial(MailboxCredentialEpoch left, MailboxCredentialEpoch right) =>
            Fixed(left.MembershipCommitment.Span, right.MembershipCommitment.Span) &&
            Fixed(left.PlacementId.Span, right.PlacementId.Span) &&
            Fixed(left.PlacementCommitment.Span, right.PlacementCommitment.Span);
        static bool EqualReplicas(MailboxCredentialReplicaPair left, MailboxCredentialReplicaPair right) =>
            Fixed(left.FirstId.Span, right.FirstId.Span) &&
            Fixed(left.FirstSigningKey.Span, right.FirstSigningKey.Span) &&
            Fixed(left.SecondId.Span, right.SecondId.Span) &&
            Fixed(left.SecondSigningKey.Span, right.SecondSigningKey.Span);
        static bool EqualOverlapGrant(MailboxCredentialGrantSet? oldSet, MailboxCredentialGrantSet? newSet) =>
            oldSet is null && newSet is null ||
            oldSet is not null && newSet is not null &&
            Fixed(oldSet.NextGrant.Span, newSet.CurrentGrant.Span);
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
        WriteReplicas(stream, generation.CurrentReplicas);
        WriteReplicas(stream, generation.NextReplicas);
        return stream.ToArray();
    }

    private static void WriteReplicas(
        Stream stream,
        MailboxCredentialReplicaPair replicas)
    {
        Write(stream, replicas.FirstId.Span);
        Write(stream, replicas.FirstSigningKey.Span);
        Write(stream, replicas.SecondId.Span);
        Write(stream, replicas.SecondSigningKey.Span);
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
        CloneReplicas(generation.CurrentReplicas),
        CloneReplicas(generation.NextReplicas));

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
    private static string SemanticBatchKey(
        ReadOnlySpan<byte> account,
        ReadOnlySpan<byte> semantic) =>
        Convert.ToHexString(account) + ":" + Convert.ToHexString(semantic);
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

    private static bool ValidateSemanticBatchOwnership(
        Snapshot snapshot,
        ReadOnlySpan<byte> accountScope,
        ReadOnlySpan<byte> semanticOperationId,
        ReadOnlySpan<byte> parentOperationId)
    {
        var batchKey = BatchKey(accountScope, parentOperationId);
        var semanticKey = SemanticBatchKey(accountScope, semanticOperationId);
        if (snapshot.SemanticOwners.TryGetValue(semanticKey, out var ownedBatchKey))
        {
            if (!string.Equals(ownedBatchKey, batchKey, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "Mailbox semantic operation conflicts with its durable fan-out.");
            }
            if (!snapshot.Batches.TryGetValue(batchKey, out var ownedBatch) ||
                !Fixed(ownedBatch.SemanticOperationId, semanticOperationId))
            {
                throw new InvalidDataException(
                    "Mailbox semantic operation owner is corrupt.");
            }
            return true;
        }

        if (snapshot.Batches.TryGetValue(batchKey, out var parentBatch))
        {
            if (!Fixed(parentBatch.SemanticOperationId, semanticOperationId))
            {
                throw new InvalidOperationException(
                    "Mailbox logical fan-out belongs to another semantic operation.");
            }
            throw new InvalidDataException(
                "Mailbox prepared batch lost its semantic operation owner.");
        }
        return false;
    }

    private sealed class Snapshot
    {
        public Dictionary<string, StoredCredential> Credentials { get; } =
            new(StringComparer.Ordinal);
        public Dictionary<string, ulong> Counters { get; } =
            new(StringComparer.Ordinal);
        public Dictionary<string, StoredBatch> Batches { get; } =
            new(StringComparer.Ordinal);
        public Dictionary<string, string> SemanticOwners { get; } =
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
            foreach (var pair in SemanticOwners)
            {
                clone.SemanticOwners.Add(pair.Key, pair.Value);
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
        byte[] semanticOperationId,
        byte[] planDigest,
        long createdAtUnixMilliseconds,
        int targetCount,
        List<StoredTarget> targets)
    {
        public byte[] SemanticOperationId { get; } = semanticOperationId;
        public byte[] PlanDigest { get; } = planDigest;
        public long CreatedAtUnixMilliseconds { get; } =
            createdAtUnixMilliseconds;
        public int TargetCount { get; } = targetCount;
        public List<StoredTarget> Targets { get; } = targets;
        public StoredBatch Clone() => new(
            SemanticOperationId.ToArray(),
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
