using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RecordedRouteControl_ActualReceiveColdStoreAckAndFollowingOrdinaryOffset()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        await fixture.RecoverNativeSenderPublicationAsync();
        using var command = await fixture.CreateOwnedRouteUpdate(sender);
        var message = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span);
        var update = Assert.IsType<ContactRouteUpdateDmc2Payload>(message.ParsedPayload);
        Assert.Equal(1, update.RecoveryWitness!.PairCount);
        Assert.Equal(1UL, update.RouteGeneration);
        Assert.Equal(2UL, BinaryPrimitives.ReadUInt64BigEndian(update.Authorization.Field(3).Span));
        byte[] ciphertext;
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId)) ciphertext = sent.ExactEnvelope.ToArray();
        await fixture.CheckLocalHistoryFailureBeforeRecoveredReceiveAsync(receiver, ciphertext);
        var grants = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var terminal = new OwnedReadTerminal(fixture, ciphertext) { LoseAckReply = true };
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.SynchronizeNativeReceiver(grants, terminal));
        byte[] outcome;
        using (var received = await fixture.ReceiveOwnedMessage(receiver, ciphertext))
        { outcome = received.RouteProcessing.ToArray(); Assert.Equal(1, outcome[0]); }
        fixture.ColdReopenReceiverStoreStorage();
        const string text = "reply through independently adopted recovered route";
        var operation = await fixture.QueueNativeText(receiver, text);
        var issuer = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
        var store = new OwnedStoreFixture(fixture, receiver, operation, null, ownerOnPrimary: false);
        var result = await fixture.SendNativeText(receiver, operation, text, issuer, store);
        var exactRoute = await fixture.ReadAttemptOriginalRoute(receiver, operation);
        await fixture.CompactHistoricalPeerRoutePrefix(receiver);
        fixture.ColdReopenReceiverStoreStorage();
        fixture.AdvanceRouteProcessingPast(message.ExpiresAtUnixMilliseconds);
        fixture.AdvanceRouteProcessingRetryClock(); terminal.LoseAckReply = false;
        Assert.Equal(1, (await fixture.SynchronizeNativeReceiver(grants, terminal)).DurableTombstones);
        Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(2, terminal.AckCalls);
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, ciphertext)) Assert.Equal(outcome, replay.RouteProcessing.ToArray());
        var unusedIssuer = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
        var cached = await fixture.SendNativeText(receiver, operation, text, unusedIssuer, store);
        Assert.Equal(result.Cursor, cached.Cursor); Assert.False(cached.IngressDispatched);
        Assert.Equal(0, unusedIssuer.Calls); Assert.Equal(1, store.Calls);
        Assert.Equal(exactRoute, await fixture.ReadAttemptOriginalRoute(receiver, operation));
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 300);
        using var ordinary = await fixture.CreateOwnedRouteUpdate(sender);
        var ordinaryPayload = Assert.IsType<ContactRouteUpdateDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(ordinary.ExactDmc2.Span).ParsedPayload);
        Assert.Null(ordinaryPayload.RecoveryWitness); Assert.Equal(2UL, ordinaryPayload.RouteGeneration);
        Assert.Equal(3UL, BinaryPrimitives.ReadUInt64BigEndian(ordinaryPayload.Authorization.Field(3).Span));
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, ordinary.OperationId))
        using (var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray())) Assert.Equal(1, received.RouteProcessing[0]);
    }

    [Fact]
    public async Task Did2RecordedRouteRecovery_CurrentWrapperClipsToProofAndRejectsExhaustedAuthority()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckRecoveryWrapperCeilingAsync();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckLocalHistoryFailureBeforeRecoveredReceiveAsync(Did2MessagingSessionScope receiver, byte[] ciphertext)
        {
            var saved = new List<(byte[] Operation, byte[] Metadata)>();
            await WithRouteReadSql(receiver, (_, connection) =>
            {
                using (var read = connection.CreateCommand())
                {
                    read.CommandText = "SELECT operation,metadata FROM events ORDER BY ordinal;";
                    using var rows = read.ExecuteReader();
                    while (rows.Read()) saved.Add(((byte[])rows.GetValue(0), (byte[])rows.GetValue(1)));
                }
                Assert.NotEmpty(saved);
                using var damage = connection.CreateCommand();
                damage.CommandText = "UPDATE events SET metadata=zeroblob(672);";
                Assert.Equal(saved.Count, damage.ExecuteNonQuery());
            });
            var before = (await ReadMessagingFloor(receiver)).Exact.ToArray();
            try
            {
                var error = await Record.ExceptionAsync(async () => { using var rejected = await ReceiveOwnedMessage(receiver, ciphertext); });
                Assert.True(error is CryptographicException or InvalidDataException or FormatException,
                    "Lost local authenticated history must fail outside remote route-fault classification; actual=" + (error?.GetType().Name ?? "none"));
                Assert.Equal(before, (await ReadMessagingFloor(receiver)).Exact.ToArray());
            }
            finally
            {
                await WithRouteReadSql(receiver, (_, connection) =>
                {
                    foreach (var row in saved)
                    {
                        using var restore = connection.CreateCommand();
                        restore.CommandText = "UPDATE events SET metadata=$metadata WHERE operation=$operation;";
                        restore.Parameters.AddWithValue("$metadata", row.Metadata); restore.Parameters.AddWithValue("$operation", row.Operation);
                        Assert.Equal(1, restore.ExecuteNonQuery());
                    }
                });
                foreach (var row in saved) { CryptographicOperations.ZeroMemory(row.Operation); CryptographicOperations.ZeroMemory(row.Metadata); }
                CryptographicOperations.ZeroMemory(before);
            }
        }
        internal async Task RecoverNativeSenderPublicationAsync()
        {
            var backend = new RenewalBackend(this) { RecoveryThresholdLifetimeSeconds = 300 };
            using (var state = await RouteState())
                foreach (var entry in state.Entries.Values.Where(entry => entry.Phase == 7))
                    backend.SeedRetainedPublication(entry.Record(9), entry.Record(10));
            var plan = await accounts.ReadOwnPermanentContactPlanAsync(); ulong expires;
            using (var state = await RouteState()) expires = BinaryPrimitives.ReadUInt64BigEndian(
                ContactCodec.Decode("XRA1", state.Entries[Convert.ToHexString(plan.Intent.Span)].Record(1).Span).Field(13).Span);
            var elapsed = checked(expires + 20 - CurrentProofTime); ProofTime += elapsed; Sample += elapsed;
            await SeedShortPendingRenewalAsync(20);
            backend.LoseRouteResponse = true;
            await Assert.ThrowsAsync<IOException>(() => accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend));
            await AdvancePastRecordedPendingAsync(); await backend.PrepareRecoveryAsync();
            Assert.Equal(1UL, (await EnsureRecordedReopenedAsync(backend)).Generation);
        }

        internal async Task CheckRecoveryWrapperCeilingAsync()
        {
            var seeded = await SeedRecordedRenewalAsync();
            using var entry = ProtectedDid2ContactRouteJournal.Entry.Decode(seeded.Pending, Network,
                checkpoint.Directory.Record.DeepAccountId.Span);
            using var device = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage,
                Network, checkpoint.Directory.Record.DeepAccountId.Span)
                .ReadVerifiedAsync(checkpoint.Binding.Identity.ActiveDevices.Single(), default);
            await seeded.Backend.CheckRecoveryWrapperCeilingAsync(ContactRouteAuthorityWireCodec.DecodeRequest(entry.Record(12).Span), device!);
        }
        private async Task CheckRecordedPrivateControlAsync(VerifiedDeepIdV2ContactRouteClosure next,
            VerifiedDeepIdV2ContactRouteClosure previous, ParsedDeepIdV2ContactMailboxRoute initial,
            VerifiedDeepIdV2DirectoryFreshness proof, bool expectedWitness)
        {
            var original = DeepIdV2ContactMailboxRouteCodec.Decode(DeepIdV2ContactMailboxRouteCodec.Encode(previous));
            var hash = Bytes(32, 0xa1); var relationship = Bytes(32, 0xa2); var conversation = Bytes(32, 0xa3);
            var time = new OnionTrustedTimeAuthority(this);
            var authored = await ApplicationCoreCodec.AuthorVerifiedContactRouteUpdateAsync(next, original,
                previous.ExactRouteClosure, hash, relationship, conversation, Bytes(32, 0xa4), 6, time);
            var update = Assert.IsType<ContactRouteUpdateDmc2Payload>(authored.Record.ParsedPayload);
            Assert.Equal(next.ExactRouteClosure.ToArray(), update.ExactRouteClosure.ToArray());
            Assert.Equal(expectedWitness, update.RecoveryWitness is not null);
            await Check(authored.CanonicalBytes);
            if (!expectedWitness) return;
            Assert.Equal(1, update.RecoveryWitness!.PairCount);
            Assert.Equal(previous.ExactXir1V2.ToArray(), update.RecoveryWitness.ExactCompletedAnchorXir1V2.ToArray());
            var payload = update.CanonicalBytes.ToArray(); var witness = update.RecoveryWitness.CanonicalBytes.ToArray();
            var prefixLength = payload.Length - witness.Length - 4;
            var omitted = payload.AsSpan(0, prefixLength).ToArray(); omitted[72] = 6;
            await Reject(ReplaceControlPayload(authored.Record, omitted));
            var wrongAnchor = witness.ToArray(); initial.Invite.CanonicalBytes.Span.CopyTo(wrongAnchor.AsSpan(4, 611));
            await Reject(WithWitness(wrongAnchor));
            var badSignature = witness.ToArray();
            badSignature[4 + FieldOffset(badSignature.AsSpan(4, 611).ToArray(), 17)] ^= 1;
            await Reject(WithWitness(badSignature), malformedSignature: true);
            var foreignFloor = witness.ToArray(); foreignFloor[615 + 40] ^= 1;
            await Reject(WithWitness(foreignFloor));
            var duplicate = new byte[615 + 2 * (witness.Length - 615)]; witness.AsSpan(0, 615).CopyTo(duplicate);
            duplicate[1] = 2; witness.AsSpan(615).CopyTo(duplicate.AsSpan(615)); witness.AsSpan(615).CopyTo(duplicate.AsSpan(witness.Length));
            await Reject(WithWitness(duplicate));
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentSuccessorAsync(
                initial, proof, next.Network, next.NetworkAuthority, time, initial.Route.ExactBytes, hash, relationship, conversation, authored.CanonicalBytes));

            byte[] WithWitness(byte[] tail)
            {
                var changed = new byte[prefixLength + 4 + tail.Length]; payload.AsSpan(0, prefixLength).CopyTo(changed);
                BinaryPrimitives.WriteUInt32BigEndian(changed.AsSpan(prefixLength), checked((uint)tail.Length)); tail.CopyTo(changed, prefixLength + 4);
                return ReplaceControlPayload(authored.Record, changed);
            }
            async Task Check(ReadOnlyMemory<byte> exact)
            {
                var current = await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentSuccessorAsync(original, proof, next.Network,
                    next.NetworkAuthority, time, previous.ExactRouteClosure, hash, relationship, conversation, exact);
                Assert.Equal(next.ExactRouteClosure.ToArray(), current.ExactRouteClosure.ToArray());
                var historical = await DeepIdV2ContactRouteUpdateVerifier.RequireRetainedSuccessorFactsAsync(original, proof,
                    next.Network, next.NetworkAuthority, time, previous.ExactRouteClosure, hash, relationship, conversation, exact);
                Assert.Equal(next.ExactRouteClosure.ToArray(), historical.ExactBytes.ToArray());
            }
            async Task Reject(byte[] exact, bool malformedSignature = false)
            {
                if (malformedSignature)
                {
                    await Assert.ThrowsAsync<ApplicationCoreFormatException>(async () => await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentSuccessorAsync(
                        original, proof, next.Network, next.NetworkAuthority, time, previous.ExactRouteClosure, hash, relationship, conversation, exact));
                    await Assert.ThrowsAsync<ApplicationCoreFormatException>(async () => await DeepIdV2ContactRouteUpdateVerifier.RequireRetainedSuccessorFactsAsync(
                        original, proof, next.Network, next.NetworkAuthority, time, previous.ExactRouteClosure, hash, relationship, conversation, exact));
                    return;
                }
                await Assert.ThrowsAnyAsync<CryptographicException>(async () => await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentSuccessorAsync(
                    original, proof, next.Network, next.NetworkAuthority, time, previous.ExactRouteClosure, hash, relationship, conversation, exact));
                await Assert.ThrowsAnyAsync<CryptographicException>(async () => await DeepIdV2ContactRouteUpdateVerifier.RequireRetainedSuccessorFactsAsync(
                    original, proof, next.Network, next.NetworkAuthority, time, previous.ExactRouteClosure, hash, relationship, conversation, exact));
            }
        }

        private static byte[] ReplaceControlPayload(ParsedDmc2 original, byte[] payload)
        {
            var exact = original.CanonicalBytes.Span; var offset = 12;
            while (BinaryPrimitives.ReadUInt16BigEndian(exact[offset..]) != 12)
                offset += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(exact[(offset + 4)..]));
            var changed = new byte[offset + 8 + payload.Length]; exact[..(offset + 8)].CopyTo(changed);
            BinaryPrimitives.WriteUInt32BigEndian(changed.AsSpan(offset + 4), checked((uint)payload.Length)); payload.CopyTo(changed, offset + 8);
            return changed;
        }
    }

    private sealed partial class RenewalBackend
    {
        internal ulong? RecoveryThresholdLifetimeSeconds;
        internal async Task CheckRecoveryWrapperCeilingAsync(ContactRouteAuthorityWireRequest request, OwnedGenesisDeviceSecrets device)
        {
            // Reuse the actual signed proof near its deadline; do not acquire a
            // replacement or extend any signed directory/network interval.
            var proof = authorization.Freshness;
            RecoveryFixture.Sample = proof.FreshnessDeadlineMonotonicSeconds - 20;
            var wrapper = await DeepIdV2ContactRouteAuthor.AuthorRecoveryRequestAsync(authorization, network, authority,
                device!, DeepIdV2ContactRouteRecoveryMode.ReadRecordedWinner, request, [], time);
            var proofEnd = checked(proof.TrustedLowerUnixSeconds + proof.FreshnessDeadlineMonotonicSeconds - proof.MonotonicSample);
            Assert.Equal(proofEnd, wrapper.ExpiresAtUnixSeconds);
            Assert.True(wrapper.ExpiresAtUnixSeconds < wrapper.IssuedAtUnixSeconds + 120);
            Assert.True(wrapper.ExpiresAtUnixSeconds <= proof.NextProtectedLkg.Head.ValidUntil);
            Assert.Equal(ContactRouteAuthorityWireCodec.EncodeRequest(request), wrapper.ExactBaseRequest.ToArray());
            RecoveryFixture.Sample = proof.FreshnessDeadlineMonotonicSeconds - 10;
            var noInterval = await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.AuthorRecoveryRequestAsync(
                authorization, network, authority, device!, DeepIdV2ContactRouteRecoveryMode.ReadRecordedWinner, request, [], time));
            Assert.Equal("Current authority cannot cover a fresh route recovery interval.", noInterval.Message);
            RecoveryFixture.Sample = proof.FreshnessDeadlineMonotonicSeconds;
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.AuthorRecoveryRequestAsync(
                authorization, network, authority, device!, DeepIdV2ContactRouteRecoveryMode.ReadRecordedWinner, request, [], time));
            Assert.Equal(0, RecoveryReads); Assert.Equal(0, RecoveryIssues);
        }
    }
}
