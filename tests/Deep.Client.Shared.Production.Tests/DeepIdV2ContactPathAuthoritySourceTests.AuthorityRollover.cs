using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CurrentAuthorityRollover_NewContactTextAndLostAckUseCurrentRouteAfterOriginalPolicyExpiry()
        => await CheckOwnedMailboxReceiveAsync(selectedSuccessor: false,
            renewPublicationDuringAck: false, authorityRollover: true);

    private sealed partial class Fixture
    {
        // Same-key routine renewal, not root/witness key rotation. This source
        // fixture uses real signed lineage/heads/views and native account/SQL
        // owners; its in-process services are not production/device evidence.
        internal async Task AdvanceCurrentRoutingAuthorityAsync()
        {
            var before = await Source().VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            Assert.Equal(0UL, before.Authority.AuthorityGeneration);
            var peer = peerAccounts ?? throw new InvalidOperationException("Independent peer is required.");
            _ = await Source(peer).VerifyForOwnPreKeyAuthoringAsync(peer, default);
            await AdvanceNetworkAsync(expiry: 6_000);
            AuthorSignedEpochAdvance();
            var originalEpoch = BinaryPrimitives.ReadUInt64BigEndian(
                ContactCodec.Decode("PMT2", operational.ExactPmt2.Span).Field(6).Span);
            var advancedEpoch = BinaryPrimitives.ReadUInt64BigEndian(
                ContactCodec.Decode("PMT2", epochSuccessorPmt!.Value.Span).Field(6).Span);
            Assert.Equal(checked(originalEpoch + 1), advancedEpoch);
            var delta = checked(2_100UL - CurrentProofTime);
            ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);

            var renewedRoot = await XPointNetworkBootstrapAuthor.AuthorSameKeyRenewalAsync(
                Bytes(32, 0x1a), bootstrap.Authority, [bootstrap.ExactDts1],
                1_500, 1_500, 10_000, 1_500, 10_000, [root]);
            ReadOnlyMemory<byte>[] authorities = [bootstrap.ExactXna1, renewedRoot.ExactXna1];
            ReadOnlyMemory<byte>[] policies = [bootstrap.ExactDts1, renewedRoot.ExactDts1];
            objectHorizonAuthority = XPointNetworkAuthorityVerifier.Verify(bootstrap.GenesisPin, authorities, policies);
            retainedIssuanceHistory ??= new() { [0] = genesis.ProtectedHead };
            retainedIssuanceHistory[head.ProtectedHead.LogGeneration] = head.ProtectedHead;
            var from = checked(CurrentProofTime - 10); var until = checked(CurrentProofTime + 3_600);
            head = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(objectHorizonAuthority, head.ProtectedHead,
                new(head.ExactAllTransitions, [checkpoint, peerCheckpoint!], [], from, until, 2), witnesses);
            retainedIssuanceHistory[head.ProtectedHead.LogGeneration] = head.ProtectedHead;
            var rollovers = nodes.Select((signer, index) => new XPointNetworkOperationalNodeRollover(signer,
                Bytes(32, checked((byte)(0x60 + index))), Bytes(32, checked((byte)(0x68 + index))),
                ScalarMult.Base(Bytes(32, checked((byte)(0x80 + index)))),
                ScalarMult.Base(Bytes(32, checked((byte)(0x88 + index)))))).ToArray();
            var renewed = await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(new(Bytes(32, 0x1b),
                objectHorizonAuthority, [root], witnesses, rollovers, successor!.ExactXvp1, successor.ExactXnd1,
                [operational.ExactXnv1, successor.ExactXnv1], successor.ExactXnh1, successor.ExactPma2,
                epochSuccessorPmt!.Value, XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(successor.ExactXnh1.Span),
                ContactCodec.Decode("PMT2", epochSuccessorPmt.Value.Span).ArtifactHash.Span,
                HeadReference(head.CoreHash.Span), from, from, until));
            objectHorizonClosure = new(authorities, policies,
                [operational.ExactXvp1, successor.ExactXvp1, renewed.ExactXvp1],
                [operational.ExactXnv1, successor.ExactXnv1, renewed.ExactXnv1],
                [operational.ExactXnh1, successor.ExactXnh1, renewed.ExactXnh1], renewed.ExactXnd1,
                [operational.ExactPmt2, epochSuccessorPmt.Value, renewed.ExactPmt2],
                [operational.ExactPma2, successor.ExactPma2, renewed.ExactPma2]);

            var current = await Source().VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            Assert.Equal(1UL, current.Authority.AuthorityGeneration);
            Assert.Equal(bootstrap.ExactXna1.ToArray(), objectHorizonClosure.ExactXna1AuthorityChain[0].ToArray());
            Assert.Equal(renewed.ExactPma2.ToArray(), current.MailboxAuthority.ExactPma2.ToArray());
            // Routine authority renewal must preserve the separately advanced
            // placement epoch, not reset it to a guessed genesis value.
            Assert.Equal(advancedEpoch, BinaryPrimitives.ReadUInt64BigEndian(
                ContactCodec.Decode("PMT2", renewed.ExactPmt2.Span).Field(6).Span));
            Assert.Throws<CryptographicException>(() => MailboxAuthorityV2Verifier.Verify(current.Authority,
                operational.ExactPma2.Span, current.Proof.TrustedLowerUnixSeconds, current.Proof.TrustedUpperUnixSeconds));
        }
    }
}
