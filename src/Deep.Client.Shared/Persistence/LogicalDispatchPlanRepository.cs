using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

internal static class DurableLogicalDispatchPlanCodec
{
    private const int MaximumIdentifierUtf8Bytes = 512;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal sealed record Material(
        byte[] OwnerDigest,
        byte[] SemanticOperationId,
        byte[] PlanDigest,
        long CreatedAtUnixMilliseconds);

    internal static Material Encode(DurableLogicalDispatchPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(plan.Targets);
        if (!Enum.IsDefined(plan.Kind) ||
            plan.Targets.Count is < 1 or > SqliteSessionStore.MaximumScopedMailboxBatchTargets ||
            plan.CreatedAt != TransportOutboxTime.Canonical(plan.CreatedAt))
        {
            throw new ArgumentException("Logical dispatch plan is invalid.", nameof(plan));
        }

        using var ownerHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        ownerHash.AppendData("deep.logical-dispatch.owner.v1"u8);
        AppendString(ownerHash, plan.Sender.Value);
        var owner = ownerHash.GetHashAndReset();

        using var semanticHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        semanticHash.AppendData("deep.logical-dispatch.semantic.v1"u8);
        semanticHash.AppendData(owner);
        semanticHash.AppendData([(byte)plan.Kind]);
        AppendString(semanticHash, plan.SemanticMessageId.Value);
        var semantic = semanticHash.GetHashAndReset()[..16];

        using var planHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        planHash.AppendData("deep.logical-dispatch.plan.v1"u8);
        planHash.AppendData(owner);
        planHash.AppendData(semantic);
        string? previousRecipient = null;
        string? previousWireId = null;
        foreach (var target in plan.Targets)
        {
            ArgumentNullException.ThrowIfNull(target);
            if (!Enum.IsDefined(target.Route) ||
                target.Route == DurableLogicalDispatchRoute.DirectP2p &&
                    !target.CloudScopeId.IsEmpty ||
                target.Route == DurableLogicalDispatchRoute.OfficialCloud &&
                    target.CloudScopeId.Length != 32)
            {
                throw new ArgumentException("Logical dispatch target is invalid.", nameof(plan));
            }
            var recipientOrder = previousRecipient is null
                ? -1
                : string.CompareOrdinal(previousRecipient, target.Recipient.Value);
            if (previousRecipient is not null &&
                (recipientOrder > 0 ||
                 recipientOrder == 0 && string.CompareOrdinal(
                     previousWireId, target.WireMessageId.Value) >= 0))
            {
                throw new ArgumentException(
                    "Logical dispatch targets are not in canonical unique order.", nameof(plan));
            }
            planHash.AppendData([(byte)target.Route]);
            AppendString(planHash, target.Recipient.Value);
            AppendString(planHash, target.WireMessageId.Value);
            planHash.AppendData(target.CloudScopeId.Span);
            previousRecipient = target.Recipient.Value;
            previousWireId = target.WireMessageId.Value;
        }
        return new Material(
            owner,
            semantic,
            planHash.GetHashAndReset(),
            plan.CreatedAt.ToUnixTimeMilliseconds());
    }

    private static void AppendString(IncrementalHash hash, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("Logical dispatch identifier is required.");
        byte[] bytes;
        try
        {
            bytes = StrictUtf8.GetBytes(value);
        }
        catch (EncoderFallbackException exception)
        {
            throw new ArgumentException(
                "Logical dispatch identifier is not valid UTF-8.", exception);
        }
        if (bytes.Length is 0 or > MaximumIdentifierUtf8Bytes)
            throw new ArgumentException("Logical dispatch identifier exceeds its bound.");
        Span<byte> length = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }
}

public sealed partial class InMemorySessionStore
{
    public Task EnsureLogicalDispatchPlanAsync(
        DurableLogicalDispatchPlan plan,
        CancellationToken cancellationToken = default)
    {
        var material = DurableLogicalDispatchPlanCodec.Encode(plan);
        cancellationToken.ThrowIfCancellationRequested();
        var key = "logical-dispatch-plan:" +
            Convert.ToHexString(material.OwnerDigest) + ":" +
            Convert.ToHexString(material.SemanticOperationId);
        var value = Convert.ToHexString(material.PlanDigest);
        lock (durableStateGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (settings.TryGetValue(key, out var stored))
            {
                if (!CryptographicOperations.FixedTimeEquals(
                        Convert.FromHexString(stored), material.PlanDigest))
                    throw new InvalidOperationException(
                        "Semantic message conflicts with its durable dispatch plan.");
                return Task.CompletedTask;
            }
            if (!settings.TryAdd(key, value))
                throw new InvalidOperationException(
                    "Semantic message dispatch plan could not be reserved.");
            try
            {
                PersistState();
            }
            catch
            {
                settings.TryRemove(key, out _);
                throw;
            }
        }
        return Task.CompletedTask;
    }
}

public sealed partial class SqliteSessionStore
{
    public async Task EnsureLogicalDispatchPlanAsync(
        DurableLogicalDispatchPlan plan,
        CancellationToken cancellationToken = default)
    {
        var material = DurableLogicalDispatchPlanCodec.Encode(plan);
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction(deferred: false);
            using var read = connection.CreateCommand();
            read.Transaction = transaction;
            read.CommandText = """
                SELECT plan_digest FROM logical_dispatch_plans
                WHERE owner_digest=$owner AND semantic_operation_id=$semantic;
                """;
            read.Parameters.Add("$owner", SqliteType.Blob).Value = material.OwnerDigest;
            read.Parameters.Add("$semantic", SqliteType.Blob).Value =
                material.SemanticOperationId;
            var stored = read.ExecuteScalar() as byte[];
            if (stored is not null)
            {
                if (!CryptographicOperations.FixedTimeEquals(stored, material.PlanDigest))
                    throw new InvalidOperationException(
                        "Semantic message conflicts with its durable dispatch plan.");
                transaction.Commit();
                return;
            }
            using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO logical_dispatch_plans(
                    owner_digest,semantic_operation_id,plan_digest,created_at)
                VALUES($owner,$semantic,$plan,$created);
                """;
            insert.Parameters.Add("$owner", SqliteType.Blob).Value = material.OwnerDigest;
            insert.Parameters.Add("$semantic", SqliteType.Blob).Value =
                material.SemanticOperationId;
            insert.Parameters.Add("$plan", SqliteType.Blob).Value = material.PlanDigest;
            insert.Parameters.AddWithValue("$created", material.CreatedAtUnixMilliseconds);
            insert.ExecuteNonQuery();
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
        }
        finally
        {
            _databaseGate.Release();
        }
    }
}
