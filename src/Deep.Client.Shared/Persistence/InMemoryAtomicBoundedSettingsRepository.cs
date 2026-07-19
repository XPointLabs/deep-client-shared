using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

public sealed partial class InMemorySessionStore
{
    private Action<AtomicBoundedSettingsFaultPoint>? atomicBoundedSettingsFaultInjector;

    public Task<AtomicBoundedSettingReadOutcome> ReadAtomicBoundedSettingAsync(
        string key,
        int maximumValueUtf8Bytes,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!AtomicBoundedSettingsEnvelope.IsValidKeyAndLimit(
                key,
                maximumValueUtf8Bytes))
        {
            return Task.FromResult(new AtomicBoundedSettingReadOutcome(
                AtomicBoundedSettingReadResult.Oversized));
        }

        try
        {
            lock (durableStateGate)
            {
                if (!settings.TryGetValue(key, out var stored))
                {
                    return Task.FromResult(new AtomicBoundedSettingReadOutcome(
                        AtomicBoundedSettingReadResult.Missing));
                }

                return Task.FromResult(ReadStoredEnvelope(stored, maximumValueUtf8Bytes));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(
                "Atomic bounded settings operation was canceled.",
                cancellationToken);
        }
        catch
        {
            return Task.FromResult(new AtomicBoundedSettingReadOutcome(
                AtomicBoundedSettingReadResult.DependencyFailure));
        }
    }

    public Task<AtomicBoundedSettingMutationResult> CreateAtomicBoundedSettingAsync(
        string key,
        ReadOnlyMemory<byte> utf8Json,
        int maximumValueUtf8Bytes,
        CancellationToken cancellationToken = default) =>
        MutateAtomicBoundedSettingAsync(
            key,
            expectedRevision: null,
            utf8Json,
            maximumValueUtf8Bytes,
            delete: false,
            create: true,
            cancellationToken);

    public Task<AtomicBoundedSettingMutationResult> ReplaceAtomicBoundedSettingAsync(
        string key,
        AtomicBoundedSettingRevision expectedRevision,
        ReadOnlyMemory<byte> utf8Json,
        int maximumValueUtf8Bytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedRevision);
        return MutateAtomicBoundedSettingAsync(
            key,
            expectedRevision,
            utf8Json,
            maximumValueUtf8Bytes,
            delete: false,
            create: false,
            cancellationToken);
    }

    public Task<AtomicBoundedSettingMutationResult> DeleteAtomicBoundedSettingAsync(
        string key,
        AtomicBoundedSettingRevision expectedRevision,
        int maximumValueUtf8Bytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedRevision);
        return MutateAtomicBoundedSettingAsync(
            key,
            expectedRevision,
            utf8Json: default,
            maximumValueUtf8Bytes,
            delete: true,
            create: false,
            cancellationToken);
    }

    internal void SetAtomicBoundedSettingsFaultInjectorForTests(
        Action<AtomicBoundedSettingsFaultPoint>? faultInjector) =>
        atomicBoundedSettingsFaultInjector = faultInjector;

    private Task<AtomicBoundedSettingMutationResult> MutateAtomicBoundedSettingAsync(
        string key,
        AtomicBoundedSettingRevision? expectedRevision,
        ReadOnlyMemory<byte> utf8Json,
        int maximumValueUtf8Bytes,
        bool delete,
        bool create,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        bool validInput;
        try
        {
            validInput = delete
                ? AtomicBoundedSettingsEnvelope.IsValidKeyAndLimit(
                    key,
                    maximumValueUtf8Bytes)
                : AtomicBoundedSettingsEnvelope.IsValidInput(
                    key,
                    utf8Json,
                    maximumValueUtf8Bytes);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(
                "Atomic bounded settings operation was canceled.",
                cancellationToken);
        }
        catch
        {
            return Task.FromResult(AtomicBoundedSettingMutationResult.DependencyFailure);
        }
        if (!validInput)
        {
            return Task.FromResult(AtomicBoundedSettingMutationResult.TooLarge);
        }

        byte[]? input = null;
        string? replacement = null;
        Exception? afterMutationFault = null;
        try
        {
            if (!delete)
            {
                input = utf8Json.ToArray();
                var revision = AtomicBoundedSettingsEnvelope.CreateRevision();
                replacement = AtomicBoundedSettingsEnvelope.Create(revision, input);
            }

            atomicBoundedSettingsFaultInjector?.Invoke(
                AtomicBoundedSettingsFaultPoint.BeforeCommit);
            // The callback is evaluated before the store lock. Any captured fault is
            // injected only after the live dictionary mutation, so rollback is real
            // without executing test code under the lock.
            try
            {
                atomicBoundedSettingsFaultInjector?.Invoke(
                    AtomicBoundedSettingsFaultPoint.AfterMutationBeforePersistence);
            }
            catch (Exception exception)
            {
                afterMutationFault = exception;
            }
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(
                "Atomic bounded settings operation was canceled.",
                cancellationToken);
        }
        catch
        {
            return Task.FromResult(AtomicBoundedSettingMutationResult.DependencyFailure);
        }

        AtomicBoundedSettingMutationResult result;
        try
        {
            lock (durableStateGate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var exists = settings.TryGetValue(key, out var previous);
                if (!exists)
                {
                    if (!create)
                    {
                        return Task.FromResult(AtomicBoundedSettingMutationResult.Missing);
                    }
                }
                else
                {
                    if (create)
                    {
                        return Task.FromResult(AtomicBoundedSettingMutationResult.Conflict);
                    }
                    var read = AtomicBoundedSettingsEnvelope.TryRead(
                        previous!,
                        maximumValueUtf8Bytes,
                        out var current);
                    if (read == AtomicBoundedEnvelopeReadResult.Oversized)
                    {
                        return Task.FromResult(AtomicBoundedSettingMutationResult.TooLarge);
                    }
                    if (read != AtomicBoundedEnvelopeReadResult.Found
                        || current is null)
                    {
                        return Task.FromResult(AtomicBoundedSettingMutationResult.DependencyFailure);
                    }
                    if (expectedRevision is null
                        || !CryptographicOperations.FixedTimeEquals(
                            current.Revision,
                            expectedRevision.Value))
                    {
                        return Task.FromResult(AtomicBoundedSettingMutationResult.Conflict);
                    }
                }

                try
                {
                    if (delete)
                    {
                        settings.TryRemove(key, out _);
                    }
                    else
                    {
                        settings[key] = replacement!;
                    }
                    if (afterMutationFault is not null)
                    {
                        throw afterMutationFault;
                    }
                    PersistState();
                    result = AtomicBoundedSettingMutationResult.Applied;
                }
                catch (OperationCanceledException) when (
                    cancellationToken.IsCancellationRequested)
                {
                    if (exists)
                    {
                        settings[key] = previous!;
                    }
                    else
                    {
                        settings.TryRemove(key, out _);
                    }
                    throw new OperationCanceledException(
                        "Atomic bounded settings operation was canceled.",
                        cancellationToken);
                }
                catch
                {
                    if (exists)
                    {
                        settings[key] = previous!;
                    }
                    else
                    {
                        settings.TryRemove(key, out _);
                    }
                    return Task.FromResult(AtomicBoundedSettingMutationResult.DependencyFailure);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(
                "Atomic bounded settings operation was canceled.",
                cancellationToken);
        }
        catch
        {
            return Task.FromResult(AtomicBoundedSettingMutationResult.DependencyFailure);
        }

        try
        {
            atomicBoundedSettingsFaultInjector?.Invoke(
                AtomicBoundedSettingsFaultPoint.AfterCommit);
        }
        catch
        {
            return Task.FromResult(AtomicBoundedSettingMutationResult.OutcomeUnknown);
        }

        return Task.FromResult(result);
    }

    private static AtomicBoundedSettingReadOutcome ReadStoredEnvelope(
        string stored,
        int maximumValueUtf8Bytes)
    {
        var result = AtomicBoundedSettingsEnvelope.TryRead(
            stored,
            maximumValueUtf8Bytes,
            out var envelope);
        return result switch
        {
            AtomicBoundedEnvelopeReadResult.Found when envelope is not null =>
                new AtomicBoundedSettingReadOutcome(
                    AtomicBoundedSettingReadResult.Found,
                    AtomicBoundedSettingRevision.FromBytes(envelope.Revision),
                    envelope.Value),
            AtomicBoundedEnvelopeReadResult.Oversized =>
                new AtomicBoundedSettingReadOutcome(
                    AtomicBoundedSettingReadResult.Oversized),
            _ => new AtomicBoundedSettingReadOutcome(
                AtomicBoundedSettingReadResult.DependencyFailure)
        };
    }
}
