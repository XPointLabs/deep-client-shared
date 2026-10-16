using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    public async Task Did2PreKeyCustody_ReadRejectsMissingOrMalformedPointer(int shape)
    {
        using var storage = new InMemoryDeepSecureStorage();
        var scope = Bytes(32, 0xa1); var initial = Bytes(32, 0xa2);
        var root = new byte[64]; scope.CopyTo(root, 0); initial.CopyTo(root, 32);
        if (shape == 1) Array.Clear(root, 32, 32);
        if (shape == 2) root[0] ^= 1;
        if (shape == 3) root = root[..1];
        if (shape == 4) Array.Clear(root, 0, 32);
        if (shape == 5) root = [.. root, 0];
        if (shape == 6) root[^1] ^= 1; // Exact noninitial entry absent: never use SQL genesis instead.
        if (shape != 0) await storage.WriteBatchAsync([new(ProtectedPreKeyInventoryChain.TipSlot, root)]);
        if (shape is 0 or 6)
            await Assert.ThrowsAsync<InvalidDataException>(() => ProtectedPreKeyInventoryChain.ReadAsync(storage, scope, initial, default));
        else
            await Assert.ThrowsAsync<CryptographicException>(() => ProtectedPreKeyInventoryChain.ReadAsync(storage, scope, initial, default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2PreKeyCustody_AtomicNativeSuccessorsRetainExactSecrets(bool encryptedStorage)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: encryptedStorage);
        await fixture.CheckProtectedPreKeyChainAsync(encryptedStorage);
    }

    private sealed partial class Fixture
    {
        // Native account/device/ML-KEM authoring and actual encrypted storage
        // where requested. A fixture-owned sealing key exercises the custody
        // format, not the unfinished production SQL-key owner integration.
        internal async Task CheckProtectedPreKeyChainAsync(bool encrypted)
        {
            var source = Source();
            var initial = await accounts.EnsureOwnPreKeyInventoryAsync(source);
            await StageAndRecordPairAsync();
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof,
                DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(initial.ExactDca1.Span),
                    checkpoint.Binding, checkpoint.Directory), Boot, Sample);
            using var installed = await storage.ReadOwnedAsync("deep.store.v2.prekey-installed");
            var scopeHash = installed!.Use(value => value.ToArray());
            var initialHash = SHA256.HashData(initial.ExactXpp1.Span);
            var initialService = DeepIdV2PreKeyServiceCodec.Decode(initial.ExactXps1.Span);
            var certificate = checkpoint.Binding.Identity.ActiveDevices.Single().Certificate;
            var scope = new Dpk2PreKeyPersistenceScope(Network, checkpoint.Directory.Record.DeepAccountId.Span,
                checkpoint.Binding.Identity.Account.Certificate.AccountGeneration, certificate.DeviceId.Span,
                certificate.DeviceGeneration, initialService.Field(4).Span);
            using var author = await accounts.OpenLocalPreKeyAuthoringAuthorityAsync();
            var sealKey = RandomNumberGenerator.GetBytes(32);
            using var protector = new Dpk2PreKeyPersistenceProtector(sealKey);
            CryptographicOperations.ZeroMemory(sealKey);
            var originalSql = Assert.Single(Directory.EnumerateFiles(directory, "*.prekeys.pkv2"));
            var sqlHash = SHA256.HashData(File.ReadAllBytes(originalSql));
            using var originalPair = await storage.ReadOwnedAsync("deep.store.v2.prekey-commit-pair-v1");
            var pairBytes = originalPair!.Use(value => value.ToArray());
            try
            {
                using (var empty = await ProtectedPreKeyInventoryChain.ReadAsync(storage, scopeHash, initialHash, default))
                    Assert.Empty(empty.Entries);
                using var first = Make(initialService, initialHash, 0x91);
                using var competing = Make(initialService, initialHash, 0x92);
                CheckIndependentEncoding(first);
                using (var parsed = ProtectedPreKeyInventoryChain.Entry.Decode(first.CopyExact(), scopeHash, first.PublicationHash))
                {
                    Assert.True(parsed.HasAllSecrets);
                    Assert.False(parsed.IsAuthoredCandidate);
                    await Assert.ThrowsAsync<CryptographicException>(() => ProtectedPreKeyInventoryChain.StageAsync(storage, parsed, default));
                }
                Assert.NotEqual(first.PublicationHash.ToArray(), competing.PublicationHash.ToArray());
                using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                    ProtectedPreKeyInventoryChain.StageAsync(storage, first, cancelled.Token));
                using (var unchanged = await ProtectedPreKeyInventoryChain.ReadAsync(storage, scopeHash, initialHash, default))
                    Assert.Empty(unchanged.Entries);

                // Exactly one of two fully sealed candidates wins the actual
                // backend transaction. A loser cannot insert an orphan record.
                var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var raceA = Task.Run(async () => { await start.Task; return await ProtectedPreKeyInventoryChain.StageAsync(storage, first, default); });
                var raceB = Task.Run(async () => { await start.Task; return await ProtectedPreKeyInventoryChain.StageAsync(storage, competing, default); });
                start.SetResult();
                var race = await Task.WhenAll(raceA, raceB);
                Assert.Single(race, value => value);
                var winner = race[0] ? first : competing;
                var loser = race[0] ? competing : first;
                using (var absent = await storage.ReadOwnedAsync(ProtectedPreKeyInventoryChain.EntrySlot(loser.PublicationHash)))
                    Assert.Null(absent);
                Assert.True(await ProtectedPreKeyInventoryChain.StageAsync(storage, winner, default));
                if (encrypted) ColdReopenCompactionStorage();
                using (var reopened = await ProtectedPreKeyInventoryChain.ReadAsync(storage, scopeHash, initialHash, default))
                {
                    Assert.True(CryptographicOperations.FixedTimeEquals(winner.CopyExact(), Assert.Single(reopened.Entries).CopyExact()),
                        "Cold reopen must retain the exact private inventory record.");
                    var publication = DeepIdV2PreKeyPublicationCodec.Decode(reopened.Entries[0].CopyPublication());
                    for (var index = 0; index < winner.SecretCount; index++)
                    {
                        var sealedBytes = reopened.Entries[0].CopySealedSecret(index);
                        var member = index < publication.OneTimeMembers.Count ? publication.OneTimeMembers[index] : publication.LastResortMember;
                        try { using var restored = protector.Restore(Dpk2PreKeyPersistenceBlob.Decode(sealedBytes), member.CanonicalBytes, scope); }
                        finally { CryptographicOperations.ZeroMemory(sealedBytes); }
                    }
                    var damaged = reopened.Entries[0].CopySealedSecret(0);
                    try
                    {
                        damaged[^1] ^= 1;
                        Assert.Throws<CryptographicException>(() => protector.Restore(Dpk2PreKeyPersistenceBlob.Decode(damaged),
                            publication.OneTimeMembers[0].CanonicalBytes, scope));
                    }
                    finally { CryptographicOperations.ZeroMemory(damaged); }
                }

                using var second = Make(DeepIdV2PreKeyServiceCodec.Decode(winner.CopyService()), winner.PublicationHash, 0x93);
                storage.FailAfterPreKeySuccessorInsert = true;
                await Assert.ThrowsAsync<IOException>(() => ProtectedPreKeyInventoryChain.StageAsync(storage, second, default));
                if (encrypted) ColdReopenCompactionStorage();
                Assert.True(await ProtectedPreKeyInventoryChain.StageAsync(storage, second, default));
                using (var recovered = await ProtectedPreKeyInventoryChain.ReadAsync(storage, scopeHash, initialHash, default))
                {
                    Assert.Equal(2, recovered.Entries.Count);
                    Assert.True(CryptographicOperations.FixedTimeEquals(winner.CopyExact(), recovered.Entries[0].CopyExact()), "Prior custody changed.");
                    Assert.True(CryptographicOperations.FixedTimeEquals(second.CopyExact(), recovered.Entries[1].CopyExact()), "Pending custody changed.");
                }
                Assert.Equal(sqlHash, SHA256.HashData(File.ReadAllBytes(originalSql)));
                using var retainedPair = await storage.ReadOwnedAsync("deep.store.v2.prekey-commit-pair-v1");
                Assert.True(retainedPair!.Use(value => CryptographicOperations.FixedTimeEquals(value, pairBytes)), "Initial receipt pair changed.");

                // Hostile local data never causes a historical-generation
                // fallback. Restore these test bytes only after the rejection.
                var slot = ProtectedPreKeyInventoryChain.EntrySlot(winner.PublicationHash);
                await storage.DeleteBatchAsync([slot]);
                await Assert.ThrowsAsync<InvalidDataException>(() => ProtectedPreKeyInventoryChain.ReadAsync(storage, scopeHash, initialHash, default));
                await storage.WriteBatchAsync([new(slot, winner.CopyExact())]);
                var wrongScope = scopeHash.ToArray(); wrongScope[0] ^= 1;
                await Assert.ThrowsAsync<CryptographicException>(() => ProtectedPreKeyInventoryChain.ReadAsync(storage, wrongScope, initialHash, default));

                var changedLink = winner.CopyExact(); second.PublicationHash.CopyTo(changedLink.AsSpan(36));
                Assert.True(await storage.CompareExchangeAsync(slot, winner.CopyExact(), changedLink));
                try { await Assert.ThrowsAsync<InvalidDataException>(() => ProtectedPreKeyInventoryChain.ReadAsync(storage, scopeHash, initialHash, default)); }
                finally { Assert.True(await storage.CompareExchangeAsync(slot, changedLink, winner.CopyExact())); CryptographicOperations.ZeroMemory(changedLink); }

                using var currentRoot = await storage.ReadOwnedAsync(ProtectedPreKeyInventoryChain.TipSlot);
                var exactRoot = currentRoot!.Use(value => value.ToArray());
                var originalRoot = new byte[64]; scopeHash.CopyTo(originalRoot, 0); initialHash.CopyTo(originalRoot, 32);
                storage.AfterPreKeySuccessorRead = async () => Assert.True(await storage.CompareExchangeAsync(
                    ProtectedPreKeyInventoryChain.TipSlot, exactRoot, originalRoot));
                try { await Assert.ThrowsAsync<CryptographicException>(() => ProtectedPreKeyInventoryChain.ReadAsync(storage, scopeHash, initialHash, default)); }
                finally { Assert.True(await storage.CompareExchangeAsync(ProtectedPreKeyInventoryChain.TipSlot, originalRoot, exactRoot)); }

                using var cancelRead = new CancellationTokenSource();
                storage.AfterPreKeySuccessorRead = () => { cancelRead.Cancel(); return Task.CompletedTask; };
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                    ProtectedPreKeyInventoryChain.ReadAsync(storage, scopeHash, initialHash, cancelRead.Token));

                var canonical = second.CopyExact();
                try
                {
                    var firstBlob = ProtectedPreKeyInventoryChain.HeaderBytes + 352 + second.CopyPublication().Length;
                    var firstBlobLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(canonical.AsSpan(firstBlob)));
                    byte[] omitted = [.. canonical.AsSpan(0, firstBlob), 0, 0, 0, 0, .. canonical.AsSpan(firstBlob + 4 + firstBlobLength)];
                    try
                    {
                        using var deleted = ProtectedPreKeyInventoryChain.Entry.Decode(omitted, scopeHash, second.PublicationHash);
                        Assert.False(deleted.HasAllSecrets); // Structural parsing never proves consumption.
                        await Assert.ThrowsAsync<CryptographicException>(() => ProtectedPreKeyInventoryChain.StageAsync(storage, deleted, default));
                    }
                    finally { CryptographicOperations.ZeroMemory(omitted); }
                    foreach (var mutation in new[] { "version", "reserved", "reserved-tail", "scope", "self", "hash", "length", "count", "blob-length", "trailing", "truncated", "service", "oversized" })
                    {
                        var changed = canonical.ToArray();
                        var blobStart = ProtectedPreKeyInventoryChain.HeaderBytes + 352 + second.CopyPublication().Length;
                        switch (mutation)
                        {
                            case "version": changed[0] = 2; break;
                            case "reserved": changed[1] = 1; break;
                            case "reserved-tail": changed[106] = 1; break;
                            case "scope": changed[4] ^= 1; break;
                            case "self": second.PublicationHash.CopyTo(changed.AsSpan(36)); break;
                            case "hash": changed[68] ^= 1; break;
                            case "length": BinaryPrimitives.WriteUInt32BigEndian(changed.AsSpan(100), uint.MaxValue); break;
                            case "count": BinaryPrimitives.WriteUInt16BigEndian(changed.AsSpan(104), ushort.MaxValue); break;
                            case "blob-length": BinaryPrimitives.WriteUInt32BigEndian(changed.AsSpan(blobStart), uint.MaxValue); break;
                            case "trailing": changed = [.. changed, 0]; break;
                            case "truncated": changed = changed[..^1]; break;
                            case "service": initial.ExactXps1.Span.CopyTo(changed.AsSpan(ProtectedPreKeyInventoryChain.HeaderBytes)); break;
                            case "oversized": changed = new byte[DeepSecureStorageRegistration.MaximumValueBytes + 1]; break;
                        }
                        try
                        {
                            var error = Record.Exception(() => { using var invalid = ProtectedPreKeyInventoryChain.Entry.Decode(changed, scopeHash, second.PublicationHash); });
                            Assert.True(error is InvalidDataException or CryptographicException, "Hostile protected inventory must reject with a closed custody error.");
                        }
                        finally { CryptographicOperations.ZeroMemory(changed); }
                    }
                }
                finally { CryptographicOperations.ZeroMemory(canonical); }

                var disposed = await ProtectedPreKeyInventoryChain.ReadAsync(storage, scopeHash, initialHash, default);
                var borrowed = disposed.Entries[0]; disposed.Dispose();
                Assert.Throws<ObjectDisposedException>(() => { _ = disposed.Entries; });
                Assert.Throws<ObjectDisposedException>(() => borrowed.CopyExact());
            }
            finally { CryptographicOperations.ZeroMemory(scopeHash); CryptographicOperations.ZeroMemory(pairBytes); }

            ProtectedPreKeyInventoryChain.Entry Make(ParsedXps1V2 predecessor, ReadOnlySpan<byte> previousHash, byte operation)
            {
                var context = new Dpk2AuthoringContext(ApplicationCoreVerifier.StartDmd1Lineage(checkpoint.Directory).Next,
                    checked(BinaryPrimitives.ReadUInt64BigEndian(predecessor.Field(5).Span) + 1), 1, 1,
                    fresh.Proof.TrustedLowerUnixSeconds, fresh.Proof.TrustedLowerUnixSeconds,
                    checked(BinaryPrimitives.ReadUInt64BigEndian(predecessor.Field(11).Span) + 60));
                var service = author.AuthorPreKeyServiceV2(context, checkpoint.Binding, 32, 1, predecessor.CanonicalBytes.Span);
                var placement = ContactServicePlacementFactory.Create(fresh.Network, ContactServiceRequestKind.PublishPreKeyInventory, service.ServiceCapability);
                var drs = new byte[38]; "DRS1"u8.CopyTo(drs); BinaryPrimitives.WriteUInt16BigEndian(drs.AsSpan(4), 1);
                checkpoint.Binding.Identity.Revocations.Snapshot.CanonicalHash.Span.CopyTo(drs.AsSpan(6));
                using var inventory = author.AuthorInventoryV2(context, checkpoint.Binding, service, drs, new byte[32],
                    Bytes(32, operation), placement.PlacementHash.Span, 32, 1);
                DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(checkpoint.Binding.DeepId, service.ExactXps1.Span,
                    authorization, DeepIdV2PreKeyPublicationCodec.Decode(inventory.ExactXpp1.Span), Boot, Sample);
                return ProtectedPreKeyInventoryChain.Entry.Create(scopeHash, previousHash, service, inventory, protector, scope);
            }

            static void CheckIndependentEncoding(ProtectedPreKeyInventoryChain.Entry entry)
            {
                // Independent concatenation of DR-0130's fixed layout; never
                // log sealed custody/identifiers through byte-array assertions.
                var expected = new List<byte> { 1, 0, 0, 0 };
                expected.AddRange(entry.ScopeHash.ToArray()); expected.AddRange(entry.PredecessorHash.ToArray());
                expected.AddRange(entry.PublicationHash.ToArray());
                var publication = entry.CopyPublication(); var length = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)publication.Length)); expected.AddRange(length);
                var count = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(count, checked((ushort)entry.SecretCount));
                expected.AddRange(count); expected.Add(0); expected.Add(0);
                Assert.Equal(108, expected.Count);
                expected.AddRange(entry.CopyService()); expected.AddRange(publication);
                for (var index = 0; index < entry.SecretCount; index++)
                {
                    var blob = entry.CopySealedSecret(index);
                    BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)blob.Length)); expected.AddRange(length); expected.AddRange(blob);
                    CryptographicOperations.ZeroMemory(blob);
                }
                var exact = entry.CopyExact();
                try { Assert.True(CryptographicOperations.FixedTimeEquals(CollectionsMarshal.AsSpan(expected), exact), "Private inventory encoding differs from the frozen layout."); }
                finally { CryptographicOperations.ZeroMemory(CollectionsMarshal.AsSpan(expected)); CryptographicOperations.ZeroMemory(exact); }
            }
        }
    }
}
