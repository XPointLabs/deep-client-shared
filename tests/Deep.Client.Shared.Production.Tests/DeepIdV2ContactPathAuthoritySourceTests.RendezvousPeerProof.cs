using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    // Genuine owned signatures and independent current directory/network
    // consumers, without a native handshake, route adoption or Store claim.
    [Fact]
    public async Task Did2RendezvousPeerProof_IndependentCurrentOwnerNetworkVerifiesExactSignedContinuationAndRejectsForkExpiryCancellation()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.CheckIndependentRendezvousPeerProofAsync();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckIndependentRendezvousPeerProofAsync()
        {
            var authorSource = Source();
            var author = await authorSource.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            using var current = (await SenderCompactionOwner().ReadCurrentAsync(1_000, pq, default))!;
            var scalar = RandomNumberGenerator.GetBytes(32);
            VerifiedDeepIdV2ContactUpdateRendezvous genesis;
            try
            {
                genesis = await DeepIdV2ContactUpdateRendezvousAuthor.AuthorGenesisAsync(author.Proof, author.Network,
                    current.Verified.DeviceSecrets, RandomNumberGenerator.GetBytes(32), DeepIdentityCrypto.DeriveX25519PublicKey(scalar),
                    author.Proof.TrustedLowerUnixSeconds, 1_120, authorSource.RendezvousTrustedTime);
            }
            finally { CryptographicOperations.ZeroMemory(scalar); }
            var first = await DeepIdV2ContactUpdateRendezvousAuthor.AuthorSuccessorAsync(genesis.ExactXur1, author.Proof,
                author.Network, current.Verified.DeviceSecrets, author.Proof.TrustedLowerUnixSeconds, 1_140,
                authorSource.RendezvousTrustedTime);
            var second = await DeepIdV2ContactUpdateRendezvousAuthor.AuthorSuccessorAsync(first.ExactXur1, author.Proof,
                author.Network, current.Verified.DeviceSecrets, author.Proof.TrustedLowerUnixSeconds, 1_160,
                authorSource.RendezvousTrustedTime);
            var branch = await DeepIdV2ContactUpdateRendezvousAuthor.AuthorSuccessorAsync(genesis.ExactXur1, author.Proof,
                author.Network, current.Verified.DeviceSecrets, author.Proof.TrustedLowerUnixSeconds, 1_141,
                authorSource.RendezvousTrustedTime);
            AdvanceControlClockTo(1_106);
            var peerSource = Source(peerAccounts!);
            var peer = await peerSource.VerifyForOwnPreKeyAuthoringAsync(peerAccounts!, default);
            Assert.False(author.Proof.ExactDtt1.Span.SequenceEqual(peer.Proof.ExactDtt1.Span));
            ReadOnlyMemory<byte>[] successors = [first.ExactXur1, second.ExactXur1];
            var accepted = await DeepIdV2ContactUpdateRendezvousVerifier.VerifySuccessorChainAsync(genesis.ExactXur1,
                genesis.ExactXur1, successors, author.Proof, peer.Network, peer.Authority, peerSource.RendezvousTrustedTime);
            Assert.Equal(2UL, BinaryPrimitives.ReadUInt64BigEndian(accepted.Record.Field(4).Span));
            Assert.Equal(second.ExactXur1.ToArray(), accepted.ExactXur1.ToArray());
            _ = await DeepIdV2ContactUpdateRendezvousVerifier.VerifySuccessorChainAsync(genesis.ExactXur1,
                first.ExactXur1, successors, author.Proof, peer.Network, peer.Authority, peerSource.RendezvousTrustedTime);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                _ = await DeepIdV2ContactUpdateRendezvousVerifier.VerifySuccessorChainAsync(genesis.ExactXur1,
                    branch.ExactXur1, successors, author.Proof, peer.Network, peer.Authority, peerSource.RendezvousTrustedTime));
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                _ = await DeepIdV2ContactUpdateRendezvousVerifier.VerifySuccessorChainAsync(genesis.ExactXur1,
                    first.ExactXur1, successors, author.Proof, peer.Network, peer.Authority, peerSource.RendezvousTrustedTime, cancelled.Token));
            AdvanceControlClockTo(1_170);
            authorSource = Source(); author = await authorSource.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            peerSource = Source(peerAccounts!); peer = await peerSource.VerifyForOwnPreKeyAuthoringAsync(peerAccounts!, default);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                _ = await DeepIdV2ContactUpdateRendezvousVerifier.VerifySuccessorChainAsync(genesis.ExactXur1,
                    second.ExactXur1, successors, author.Proof, peer.Network, peer.Authority, peerSource.RendezvousTrustedTime));
            await DeepIdV2ContactUpdateRendezvousVerifier.VerifyRecordedSuccessorChainAsync(genesis.ExactXur1,
                second.ExactXur1, successors, author.Proof, peer.Network, peer.Authority, 1_106,
                peerSource.RendezvousTrustedTime);
        }
    }
}
