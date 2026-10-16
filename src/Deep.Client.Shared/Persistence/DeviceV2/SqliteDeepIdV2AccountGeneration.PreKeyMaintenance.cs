using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.PreKeyV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    // The actual account lease encloses this entire method. The owner supplies
    // its existing held-lease verifier, never a recursive ordinary store read.
    internal static async Task<StagedDeepIdV2PreKeyPublication> MaintainPreKeyInventoryAsync(
        IDeepSecureStorage storage, string accountStatePath, VerifiedDeepIdV2CurrentAccount current,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        Func<CancellationToken, Task<OnionMonotonicReading>> recheck, CancellationToken ct)
    {
        SqlitePreKeyV2InventoryStore? store = null; byte[]? scope = null;
        try
        {
            using (var installed = await storage.ReadOwnedAsync(PreKeyInstallMarkerSlot, ct).ConfigureAwait(false))
            {
                if (installed is not null)
                {
                    var opened = await OpenPreKeyStoreAsync(storage, accountStatePath, current, false, ct).ConfigureAwait(false);
                    store = opened.Store; scope = opened.ScopeHash;
                }
                else if (PreKeyFileFamilyExists(PreKeyStatePath(accountStatePath)))
                    throw new InvalidDataException("Prekey files exist without their exact protected owner.");
            }
            var local = current.Verified.PublicEvidence;
            var previousExact = store?.ReadStagedPublication();
            var previous = previousExact is null ? null : DeepIdV2PreKeyPublicationCodec.Decode(previousExact);
            var previousService = previous is null ? null : DeepIdV2PreKeyServiceCodec.Decode(store!.ReadStagedService()!);
            (byte[] First, byte[] Second)? pair = null;
            if (previous is not null)
            {
                using var retained = await storage.ReadOwnedAsync(PreKeyPairSlot(store!, SHA256.HashData(previousExact!)), ct).ConfigureAwait(false);
                if (retained is null) return Snapshot(previousExact!, previousService!.CanonicalBytes.Span);
                pair = retained.Use(value => DecodePreKeyCommitPairMarker(value, scope!, previous));
            }

            var reading = await recheck(ct).ConfigureAwait(false);
            var directory = DeepIdV2AccountService.RequireOwnCurrentDirectory(current, fresh.Proof, reading.BootId.Span, reading.SampleSeconds);
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, local.Authorization,
                reading.BootId.Span, reading.SampleSeconds);
            var drs = new byte[38]; "DRS1"u8.CopyTo(drs); BinaryPrimitives.WriteUInt16BigEndian(drs.AsSpan(4), 1);
            local.Binding.Identity.Revocations.Snapshot.CanonicalHash.Span.CopyTo(drs.AsSpan(6));
            var remaining = previous is null ? (OneTimeRemaining: 0, ServiceLastResortExhausted: false) : store!.ReadOwnedReplenishmentState();
            if (previous is not null)
            {
                var placement = ContactServicePlacementFactory.Create(fresh.Network,
                    ContactServiceRequestKind.PublishPreKeyInventory, previous.Manifest.Field(2));
                DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(previous, placement,
                    DeepIdV2PreKeyCommitReceiptCodec.Decode(pair!.Value.First), DeepIdV2PreKeyCommitReceiptCodec.Decode(pair.Value.Second));
                var renew = U64PreKey(previous.Manifest.Field(15).Span) <= authorization.TrustedUpperUnixSeconds ||
                    !previous.Manifest.Field(12).Span.SequenceEqual(local.Directory.Record.RecordHash.Span) ||
                    !previous.Manifest.Field(13).Span.SequenceEqual(drs) || remaining.OneTimeRemaining <= 16 || remaining.ServiceLastResortExhausted;
                if (!renew)
                {
                    DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(local.Binding.DeepId,
                        previousService!.CanonicalBytes.Span, authorization, previous, reading.BootId.Span, reading.SampleSeconds);
                    return Snapshot(previousExact!, previousService.CanonicalBytes.Span);
                }
            }

            var issued = authorization.TrustedLowerUnixSeconds;
            var certificate = local.Binding.Identity.ActiveDevices.Single().Certificate;
            var ceiling = Math.Min(checked(issued + 2_592_000),
                Math.Min(authorization.Authorization.Record.ExpiresAtUnixSeconds, certificate.ExpiresAtUnixSeconds));
            var target = Math.Min(checked(issued + 86_400), ceiling);
            var newService = previous is null || remaining.ServiceLastResortExhausted ||
                U64PreKey(previous.Manifest.Field(7).Span) == 14 ||
                U64PreKey(previousService!.Field(11).Span) <= authorization.TrustedUpperUnixSeconds;
            var generation = previous is null ? 1UL : U64PreKey(previousService!.Field(5).Span);
            var epoch = previous is null || newService ? 1UL : checked(U64PreKey(previous.Manifest.Field(7).Span) + 1);
            var serviceExpires = newService ? target : Math.Min(target, U64PreKey(previousService!.Field(11).Span));
            if (newService && previous is not null)
            {
                generation = checked(generation + 1);
                var required = checked(U64PreKey(previousService!.Field(11).Span) + 1);
                serviceExpires = Math.Min(Math.Max(target, required), ceiling);
                if (serviceExpires < required) throw new CryptographicException("Current authorization cannot extend the exact prekey service.");
            }
            if (serviceExpires <= authorization.TrustedUpperUnixSeconds)
                throw new CryptographicException("New prekey inventory cannot cover authenticated upper time.");
            var minimum = previous is null ? (ushort)32 : BinaryPrimitives.ReadUInt16BigEndian(previousService!.Field(8).Span);
            var reuse = previous is null ? (ushort)1 : BinaryPrimitives.ReadUInt16BigEndian(previousService!.Field(9).Span);
            if (minimum > 32) throw new CryptographicException("Owned prekey policy exceeds its unchanged local inventory budget.");
            var relatives = local.Binding.Identity.ActiveDeviceRelatives;
            if (relatives.Count != 1) throw new CryptographicException("Prekey maintenance requires one exact local device.");
            using var author = current.Verified.DeviceSecrets.CreateDpk2AuthoringAuthority(relatives[0]);
            var context = new Dpk2AuthoringContext(directory, generation, epoch, 1, issued, issued, serviceExpires);
            var service = newService
                ? author.AuthorPreKeyServiceV2(context, local.Binding, minimum, reuse,
                    previousService is null ? default : previousService.CanonicalBytes.Span)
                : author.RestorePreKeyServiceV2(context, local.Binding, previousService!.CanonicalBytes.Span);
            var selected = ContactServicePlacementFactory.Create(fresh.Network,
                ContactServiceRequestKind.PublishPreKeyInventory, service.ServiceCapability);
            var operation = new byte[32]; do RandomNumberGenerator.Fill(operation); while (operation.AsSpan().IndexOfAnyExcept((byte)0) < 0);
            using var inventory = author.AuthorInventoryV2(context, local.Binding, service, drs,
                previous is null || newService ? new byte[32] : previous.Manifest.ExactHash.Span,
                operation, selected.PlacementHash.Span, 32, reuse);
            reading = await recheck(ct).ConfigureAwait(false);
            authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, local.Authorization,
                reading.BootId.Span, reading.SampleSeconds);
            DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(local.Binding.DeepId, service.ExactXps1.Span,
                authorization, DeepIdV2PreKeyPublicationCodec.Decode(inventory.ExactXpp1.Span), reading.BootId.Span, reading.SampleSeconds);
            ct.ThrowIfCancellationRequested();
            if (previous is not null)
                await store!.StageSuccessorAsync(storage, scope!, service, inventory, ct).ConfigureAwait(false);
            else if (store is not null)
            {
                await store.StageInitialAsync(service, inventory, cancellationToken: ct).ConfigureAwait(false);
                await WritePreKeyTipAsync(storage, scope!, SHA256.HashData(inventory.ExactXpp1.Span), ct).ConfigureAwait(false);
            }
            else await StageInitialPreKeyInventoryAsync(storage, accountStatePath, current, service, inventory, ct).ConfigureAwait(false);
            return Snapshot(inventory.ExactXpp1.Span, service.ExactXps1.Span);

            StagedDeepIdV2PreKeyPublication Snapshot(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> xps) =>
                new(exact, local.Binding.DeepId.CanonicalBytes.Span, local.Authorization.Record.CanonicalBytes.Span, xps);
        }
        finally
        {
            if (store is not null) await store.DisposeAsync().ConfigureAwait(false);
            if (scope is not null) CryptographicOperations.ZeroMemory(scope);
        }
    }

    private static ulong U64PreKey(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt64BigEndian(bytes);

    // Historical commit custody only. The owner independently rechecks current
    // complete support and time after these suspended protected reads.
    internal static async Task RequireCommittedOwnPreKeyInventoryAsync(IDeepSecureStorage storage,
        string accountStatePath, VerifiedDeepIdV2CurrentAccount current, StagedDeepIdV2PreKeyPublication staged,
        VerifiedOnionNetworkContext network, CancellationToken ct)
    {
        var opened = await OpenPreKeyStoreAsync(storage, accountStatePath, current, false, ct).ConfigureAwait(false);
        await using var store = opened.Store;
        try
        {
            if (!staged.ExactXpp1.Span.SequenceEqual(store.ReadStagedPublication()) ||
                !staged.ExactXps1.Span.SequenceEqual(store.ReadStagedService()) ||
                !staged.ExactDid2.Span.SequenceEqual(current.Verified.PublicEvidence.Binding.DeepId.CanonicalBytes.Span))
                throw new CryptographicException("Contact support differs from its exact current owned inventory.");
            var publication = DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span);
            using var marker = await storage.ReadOwnedAsync(PreKeyPairSlot(store, SHA256.HashData(staged.ExactXpp1.Span)), ct).ConfigureAwait(false) ??
                throw new CryptographicException("Changed contact support requires its exact committed prekey replica pair.");
            var pair = marker.Use(value => DecodePreKeyCommitPairMarker(value, opened.ScopeHash, publication));
            var placement = ContactServicePlacementFactory.Create(network, ContactServiceRequestKind.PublishPreKeyInventory, publication.Manifest.Field(2));
            DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(publication, placement,
                DeepIdV2PreKeyCommitReceiptCodec.Decode(pair.First), DeepIdV2PreKeyCommitReceiptCodec.Decode(pair.Second));
        }
        finally { CryptographicOperations.ZeroMemory(opened.ScopeHash); }
    }
}
