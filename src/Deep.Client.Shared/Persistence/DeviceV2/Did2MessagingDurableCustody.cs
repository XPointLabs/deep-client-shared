namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Exact durable recovery coordinator under the account lease. This
/// is not a Protocol authority, account catalog, retirement receipt or ACK
/// owner. Those higher boundaries must be composed before shipping activation.</summary>
internal sealed class Did2MessagingDurableCustody(Did2MessagingSessionScope scope,
    Did2MessagingProtectedCheckpoint checkpoint, OwnedDid2MessagingStorage sql)
{
    private readonly Did2MessagingSessionScope scope = scope ?? throw new ArgumentNullException(nameof(scope));
    private readonly Did2MessagingProtectedCheckpoint checkpoint = checkpoint ?? throw new ArgumentNullException(nameof(checkpoint));
    private readonly OwnedDid2MessagingStorage sql = sql ?? throw new ArgumentNullException(nameof(sql));

    internal async Task<Did2MessagingFloor> ReconcileAsync(CancellationToken ct)
    {
        using var timing = ClientPersistenceTiming.Measure(ClientPersistencePhase.NativeReconcile);
        var protectedFloor = await ReadCurrentFloorAsync(ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        var sqlTip = await sql.WithSqlAsync(journal => protectedFloor.Phase == 1 ? journal.VerifyOrdinaryState() : journal.VerifyTip(), ct).ConfigureAwait(false);
        if (protectedFloor.Phase == 1)
        {
            RequireSame(protectedFloor, sqlTip);
            await checkpoint.EraseStableOrphansAsync(protectedFloor, ct).ConfigureAwait(false);
            RequireSame(protectedFloor, await ReadCurrentFloorAsync(ct).ConfigureAwait(false));
            return protectedFloor;
        }
        if (protectedFloor.Phase == 3)
        {
            // SQL already committed and was verified before cleanup. Verify it
            // again after restart; erased parts need not be resurrected.
            RequireSame(protectedFloor.Stable(scope), sqlTip);
            var bytes = protectedFloor.Exact.ToArray(); bytes[1] = 2;
            var pending = Did2MessagingFloor.Decode(bytes, scope);
            return await FinishCurrentSqlAsync(pending, ct).ConfigureAwait(false);
        }
        using var owned = await checkpoint.ReadPendingAsync(protectedFloor, ct).ConfigureAwait(false);
        RequireSame(protectedFloor, await ReadCurrentFloorAsync(ct).ConfigureAwait(false));
        using var mutation = owned.Use(bytes => OwnedDid2MessagingMutation.RecoverProtectedPending(scope, protectedFloor, bytes));
        var expected = mutation.Successor.Cleanup(scope).Stable(scope);
        if (Did2MessagingSessionScope.Fixed(sqlTip.Exact.Span, mutation.Predecessor.Exact.Span))
        {
            ct.ThrowIfCancellationRequested(); await sql.WithSqlAsync(journal => { journal.Append(mutation); RequireSame(expected, journal.VerifyTip()); }, ct).ConfigureAwait(false);
        }
        else RequireSame(expected, sqlTip);
        return await FinishCurrentSqlAsync(mutation.Successor, ct).ConfigureAwait(false);
    }

    internal async Task<Did2MessagingFloor> CommitOwnedAsync(OwnedDid2MessagingMutation mutation, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(mutation);
        // Parsed/recovered control metadata is not new activation permission.
        // A separate closed retirement owner must stage control transitions.
        if (mutation.Kind is not (1 or 2 or 5)) throw new InvalidOperationException("DID2 activation/latch mutation requires its separate closed authority.");
        if (!Did2MessagingSessionScope.Fixed(scope.Exact, mutation.Scope.Exact) || mutation.Successor.Ordinal > long.MaxValue)
            throw new InvalidDataException("DID2 mutable custody scope/capacity differs before staging.");
        var stable = await ReconcileAsync(ct).ConfigureAwait(false);
        var expected = mutation.Successor.Cleanup(scope).Stable(scope);
        if (Did2MessagingSessionScope.Fixed(stable.Exact.Span, expected.Exact.Span)) return stable;
        RequireSame(stable, mutation.Predecessor);
        await sql.WithSqlAsync(journal => journal.RequireAppendCapacity(stable), ct).ConfigureAwait(false);
        await checkpoint.StageAsync(stable, mutation.Successor, mutation.Exact, ct).ConfigureAwait(false);
        RequireSame(mutation.Successor, await ReadCurrentFloorAsync(ct).ConfigureAwait(false));
#if DEEP_TEST_INTERNALS
        if (mutation.Kind is 2 or 5) await Did2MessagingCommitTestHooks.HitAsync(Did2MessagingCommitFailpoint.AfterPending).ConfigureAwait(false);
#endif
        ct.ThrowIfCancellationRequested(); await sql.WithSqlAsync(journal => { journal.Append(mutation); RequireSame(expected, journal.VerifyOrdinaryState()); }, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        if (mutation.Kind is 2 or 5) await Did2MessagingCommitTestHooks.HitAsync(Did2MessagingCommitFailpoint.AfterSql).ConfigureAwait(false);
#endif
        var completed = await FinishCurrentSqlAsync(mutation.Successor, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        if (mutation.Kind is 2 or 5) await Did2MessagingCommitTestHooks.HitAsync(Did2MessagingCommitFailpoint.AfterStable).ConfigureAwait(false);
#endif
        return completed;
    }

    internal async Task<Did2MessagingFloor> ActivateRetiredAsync(Did2InitialKeyRetirementReceipt receipt, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        using var mutation = OwnedDid2MessagingMutation.Activate(receipt);
        if (!Did2MessagingSessionScope.Fixed(scope.Exact, mutation.Scope.Exact))
            throw new System.Security.Cryptography.CryptographicException("Retirement activation belongs to a different mutable scope.");
        var stable = await ReconcileAsync(ct).ConfigureAwait(false);
        var expected = mutation.Successor.Cleanup(scope).Stable(scope);
        if (Did2MessagingSessionScope.Fixed(stable.Exact.Span, expected.Exact.Span)) return stable;
        RequireSame(stable, mutation.Predecessor);
        await checkpoint.StageAsync(stable, mutation.Successor, mutation.Exact, ct).ConfigureAwait(false);
        RequireSame(mutation.Successor, await ReadCurrentFloorAsync(ct).ConfigureAwait(false));
        await sql.WithSqlAsync(journal => { journal.Append(mutation); RequireSame(expected, journal.VerifyTip()); }, ct).ConfigureAwait(false);
        return await FinishCurrentSqlAsync(mutation.Successor, ct).ConfigureAwait(false);
    }

    internal async Task<Did2InitialStateTransfer> VerifyInitialTransferAsync(CancellationToken ct)
    {
        _ = await ReconcileAsync(ct).ConfigureAwait(false);
        return await Did2InitialStateTransfer.VerifyAsync(scope, checkpoint, sql, ct).ConfigureAwait(false);
    }

    internal async Task LatchOwnedSendAsync(Did2OwnedSendConflict conflict, CancellationToken ct)
    {
        using var mutation = OwnedDid2MessagingMutation.LatchOwnedSend(conflict);
        await sql.WithSqlAsync(journal => journal.RequireScope(conflict.Scope), ct).ConfigureAwait(false);
        var stable = await ReconcileAsync(ct).ConfigureAwait(false);
        RequireSame(stable, mutation.Predecessor);
        if (mutation.Successor.Ordinal > long.MaxValue)
            throw new InvalidOperationException("DID2 terminal journal capacity is exhausted.");
        await sql.WithSqlAsync(journal => journal.RequireTerminalCapacity(stable), ct).ConfigureAwait(false);
        var expected = mutation.Successor.Cleanup(scope).Stable(scope);
        await checkpoint.StageAsync(stable, mutation.Successor, mutation.Exact, ct).ConfigureAwait(false);
        RequireSame(mutation.Successor, await ReadCurrentFloorAsync(ct).ConfigureAwait(false));
        ct.ThrowIfCancellationRequested(); await sql.WithSqlAsync(journal => { journal.Append(mutation); RequireSame(expected, journal.VerifyTip()); }, ct).ConfigureAwait(false);
        _ = await FinishCurrentSqlAsync(mutation.Successor, ct).ConfigureAwait(false);
    }

    internal async Task<OwnedDeepSecret> ReadActiveStateAsync(CancellationToken ct)
    {
        var stable = await ReconcileAsync(ct).ConfigureAwait(false);
        if (stable.Status != 1) throw new InvalidOperationException("Ordinary DID2 messaging is blocked until verified initial-key retirement.");
        ct.ThrowIfCancellationRequested(); return await sql.WithSqlAsync(journal => journal.ReadVerifiedLatest(stable), ct).ConfigureAwait(false);
    }

    internal async Task<Did2MessagingFloor> ReadCurrentFloorAsync(CancellationToken ct)
    {
        return await sql.WithSqlAsync(journal => journal.ReadOpenedFloor(), ct).ConfigureAwait(false);
    }

    private async Task<Did2MessagingFloor> FinishCurrentSqlAsync(Did2MessagingFloor pending, CancellationToken ct)
    {
        _ = await ReadCurrentFloorAsync(ct).ConfigureAwait(false);
        var completed = await checkpoint.FinishVerifiedSqlCommitAsync(pending, ct).ConfigureAwait(false);
        RequireSame(completed, await ReadCurrentFloorAsync(ct).ConfigureAwait(false));
        return completed;
    }
    private static void RequireSame(Did2MessagingFloor expected, Did2MessagingFloor actual)
    {
        if (!Did2MessagingSessionScope.Fixed(expected.Exact.Span, actual.Exact.Span))
            throw new System.Security.Cryptography.CryptographicException("DID2 SQL/protected journal checkpoint differs; no repair is permitted.");
    }
}
