using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Client.Shared.Services.ContactV1;
using Sodium;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    private sealed partial class Fixture
    {
        private static async Task CheckExactGrantRouteIntentAsync(
            VerifiedDeepIdV2ContactRouteClosure first, VerifiedDeepIdV2ContactRouteClosure second)
        {
            // Two actual independently device-signed closures sharing the same
            // authenticated threshold/placement. Not publication or node custody.
            Assert.Equal(first.Route.Projection.CanonicalBytes.ToArray(), second.Route.Projection.CanonicalBytes.ToArray());
            Assert.Equal(first.Route.Selection.CanonicalBytes.ToArray(), second.Route.Selection.CanonicalBytes.ToArray());
            Assert.Equal(first.Route.Reachability.Field(10).ToArray(), second.Route.Reachability.Field(10).ToArray());
            Assert.NotEqual(first.Route.ExactHash.ToArray(), second.Route.ExactHash.ToArray());
            using var holder = new GrantHolder();
            var owner = Bytes(32, 0xb2); var locator = Bytes(32, 0xb1);
            var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(first, locator, owner, holder);
            var window = await first.ReadCurrentTimeAsync();
            _ = MailboxGrantRequestVerifier.VerifyRetrieve(request.ExactXmg2.Span, first.Route, owner, window.UpperUnixSeconds);
            Assert.Equal("MailboxGrantRequestRouteBindingMismatch", Assert.Throws<ContactFormatException>(() =>
                MailboxGrantRequestVerifier.VerifyRetrieve(request.ExactXmg2.Span, second.Route, owner, window.UpperUnixSeconds)).Code);
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantRequestAuthor.RestoreRetrieveAsync(
                second, locator, owner, request.HolderPublicKey, request.ExactXmg2));
            var secondRequest = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(second, locator, owner, holder);
            _ = MailboxGrantRequestVerifier.VerifyRetrieve(secondRequest.ExactXmg2.Span, second.Route, owner, window.UpperUnixSeconds);
            Assert.Equal(second.Route.ExactHash.ToArray(), secondRequest.Record.Field(11).ToArray());
        }

        private async Task CheckMailboxGrantRequestsAsync(VerifiedDeepIdV2ContactRouteClosure route)
        {
            var window = await route.ReadCurrentTimeAsync();
            Assert.Empty(typeof(DeepIdV2ContactRouteTimeWindow).GetConstructors());
            var locator = Bytes(32, 0xb1); var owner = Bytes(32, 0xb2);
            var expectedLocator = locator.ToArray(); var expectedOwner = owner.ToArray();
            var seed = RandomNumberGenerator.GetBytes(32);
            var retrieveSeed = RandomNumberGenerator.GetBytes(32);
            try
            {
                using var scoped = ReachabilityMailboxHolderAuthority.OpenRetained(route, locator,
                    route.Route.Reachability.Field(10), MailboxCapabilityDomain.Deposit, seed);
                var narrow = await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, locator, scoped);
                ContactCodec.VerifyMailboxGrantHolderSignature(narrow.Record);
                Assert.Equal(route.Route.ExactHash.ToArray(), narrow.Record.Field(11).ToArray());
                var changedRouteBytes = narrow.ExactXmg2.ToArray();
                Bytes(32, 0xbc).CopyTo(changedRouteBytes, FieldOffset(changedRouteBytes, 11));
                var changedRoute = ContactCodec.Decode("XMG2", changedRouteBytes);
                var untouchedSignature = Enumerable.Repeat((byte)0xdd, 64).ToArray();
                await Assert.ThrowsAsync<CryptographicException>(async () => await scoped.SignMailboxGrantRequestAsync(
                    changedRoute.SignatureInput, untouchedSignature, default));
                Assert.All(untouchedSignature, value => Assert.Equal(0xdd, value));
                await Assert.ThrowsAsync<CryptographicException>(async () => await scoped.SignMailboxGrantRequestAsync(
                    narrow.Record.SignatureInput.ToArray()[..^1], untouchedSignature, default));
                Assert.All(untouchedSignature, value => Assert.Equal(0xdd, value));
                CheckHolderPresentationBindings(scoped, route, window);
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, Bytes(32, 0xb3), scoped));
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(route, locator, owner, scoped));
                await Assert.ThrowsAsync<CryptographicException>(async () => await scoped.SignMailboxGrantRequestAsync(new byte[512], new byte[64], default));
                using var retrieving = ReachabilityMailboxHolderAuthority.OpenRetained(route, locator, owner, MailboxCapabilityDomain.Retrieve, retrieveSeed);
                var ownRequest = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(route, locator, owner, retrieving);
                ContactCodec.VerifyMailboxGrantHolderSignature(ownRequest.Record);
                Assert.Equal(route.Route.ExactHash.ToArray(), ownRequest.Record.Field(11).ToArray());
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(route, locator, Bytes(32, 0xb4), retrieving));
                Assert.Throws<CryptographicException>(() => ReachabilityMailboxHolderAuthority.OpenRetained(route, locator,
                    route.Route.Reachability.Field(10), MailboxCapabilityDomain.Retrieve, seed));
                Assert.Empty(typeof(ReachabilityMailboxHolderAuthority).GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static));
                Assert.Empty(typeof(ReachabilityMailboxHolderAuthority.ReachabilityMailboxHolderSigner).GetConstructors());
                scoped.Dispose();
                Assert.Throws<ObjectDisposedException>(() => scoped.GetEd25519PublicKey());
            }
            finally { CryptographicOperations.ZeroMemory(seed); CryptographicOperations.ZeroMemory(retrieveSeed); }
            using var holder = new GrantHolder();
            var deposit = await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, locator, holder);
            Assert.Equal(435, deposit.ExactXmg2.Length); Assert.Equal(MailboxCapabilityDomain.Deposit, deposit.Domain);
            Assert.Equal(route.Route.ExactHash.ToArray(), deposit.Record.Field(11).ToArray());
            Assert.True(CryptographicOperations.FixedTimeEquals(deposit.Record.Field(4).Span, route.Route.Reachability.Field(10).Span));
            Assert.Equal(window.LowerUnixSeconds, BinaryPrimitives.ReadUInt64BigEndian(deposit.Record.Field(9).Span));
            var expiry = BinaryPrimitives.ReadUInt64BigEndian(deposit.Record.Field(10).Span);
            Assert.True(expiry > window.UpperUnixSeconds && expiry <= window.LowerUnixSeconds + 120);
            Assert.True(expiry <= BinaryPrimitives.ReadUInt64BigEndian(route.Route.Route.Field(18).Span));
            ContactCodec.VerifyMailboxGrantHolderSignature(deposit.Record);
            MailboxGrantRequestVerifier.VerifyDeposit(deposit.ExactXmg2.Span, route.Route, window.UpperUnixSeconds);
            // Inputs and signer key are captured before asynchronous signing.
            holder.BeforeSign = () => { Array.Clear(locator); Array.Clear(owner); holder.ChangeExposedKey(); };
            var retrieve = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(route, locator, owner, holder);
            Assert.Equal(2, holder.KeyReads); // One key capture per call; no post-await substitution.
            Assert.True(CryptographicOperations.FixedTimeEquals(retrieve.Record.Field(3).Span, expectedLocator));
            Assert.True(CryptographicOperations.FixedTimeEquals(retrieve.Record.Field(4).Span, expectedOwner));
            Assert.Equal(MailboxCapabilityDomain.Retrieve, retrieve.Domain);
            MailboxGrantRequestVerifier.VerifyRetrieve(retrieve.ExactXmg2.Span, route.Route, expectedOwner, window.UpperUnixSeconds);
            Assert.ThrowsAny<FormatException>(() =>
                MailboxGrantRequestVerifier.VerifyDeposit(retrieve.ExactXmg2.Span, route.Route, window.UpperUnixSeconds));
            using var never = new GrantHolder();
            await Assert.ThrowsAsync<ArgumentException>(async () => await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, new byte[33], never));
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(
                route, expectedLocator, route.Route.Reachability.Field(10), never));
            Assert.Equal(0, never.Calls);
            using var bad = new GrantHolder { CorruptSignature = true };
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, expectedLocator, bad));
            Assert.Equal(1, bad.Calls);
            using var shortReply = new GrantHolder { ReportedLength = 63 };
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, expectedLocator, shortReply));
            using var cancelled = new CancellationTokenSource();
            using var cancelling = new GrantHolder { BeforeSign = cancelled.Cancel };
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(
                route, expectedLocator, cancelling, cancelled.Token));
            var sampleBefore = Sample;
            using var delayed = new GrantHolder { BeforeSign = () => Sample = route.Recipient.Freshness.FreshnessDeadlineMonotonicSeconds };
            try
            {
                await RequireRouteRejectionAsync(async () => await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, expectedLocator, delayed));
                Assert.Equal(1, delayed.Calls);
                await RequireRouteRejectionAsync(async () => await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, expectedLocator, never));
                Assert.Equal(0, never.Calls);
            }
            finally { Sample = sampleBefore; } // Fixture fault cleanup, no runtime repair.
            using var preCancelled = new CancellationTokenSource(); preCancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(
                route, expectedLocator, never, preCancelled.Token));
            CryptographicOperations.ZeroMemory(expectedOwner);
        }

        private static void CheckHolderPresentationBindings(
            ReachabilityMailboxHolderAuthority.ReachabilityMailboxHolderSigner holder,
            VerifiedDeepIdV2ContactRouteClosure route, DeepIdV2ContactRouteTimeWindow window)
        {
            // Scope-only synthetic MCG3, deliberately NOT issuer/topology evidence.
            var grant = new MailboxAuthenticatedGrant
            {
                Domain = MailboxCapabilityDomain.Deposit, Lifecycle = MailboxCapabilityLifecycle.Active,
                NetworkId = route.Network.NetworkId, Epoch = BinaryPrimitives.ReadUInt64BigEndian(route.Route.Selection.Field(4).Span),
                Generation = 1, Serial = Bytes(16, 0x91), NotBeforeUnixSeconds = window.LowerUnixSeconds,
                ExpiresAtUnixSeconds = window.UpperUnixSeconds + 5, OverlapUntilUnixSeconds = 0,
                PlacementCommitment = MailboxPlacementCommitment.Compute(new BlindedPlacementId(route.Route.Reachability.Field(10).Span)),
                MembershipCommitment = Bytes(32, 0x92), IssuerPublicKey = Bytes(32, 0x93),
                SelectionInput = route.Route.Selection.Field(3),
                HolderPublicKey = holder.Ed25519PublicKey, IssuerSignature = Bytes(64, 0x94)
            };
            var presentation = new MailboxAuthenticatedPresentation
            {
                Operation = MailboxAuthenticatedOperation.Store, OperationId = Bytes(16, 0x95), ReplayCounter = 1,
                RequestDigest = Bytes(32, 0x96), Grant = grant, HolderSignature = Bytes(64, 0x97)
            };
            var input = MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(presentation);
            var signature = holder.SignMailboxPresentation(presentation.Operation, input);
            try { Assert.True(PublicKeyAuth.VerifyDetached(signature, input, holder.Ed25519PublicKey.ToArray())); }
            finally { CryptographicOperations.ZeroMemory(signature); }
            var oldLabel = input.ToArray(); "DEEP-MCP2-STR\0\0\0"u8.CopyTo(oldLabel);
            Assert.Throws<CryptographicException>(() => holder.SignMailboxPresentation(presentation.Operation, oldLabel));
            var oldVersion = input.ToArray(); oldVersion[16 + 4] = 2;
            Assert.Throws<CryptographicException>(() => holder.SignMailboxPresentation(presentation.Operation, oldVersion));
            foreach (var bad in new[] { grant with { Epoch = grant.Epoch + 1 },
                grant with { SelectionInput = Bytes(32, 0x9b) },
                grant with { PlacementCommitment = Bytes(32, 0x98) }, grant with { NetworkId = Bytes(16, 0x99) },
                grant with { HolderPublicKey = Bytes(32, 0x9a) } })
            {
                var changed = MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(presentation with { Grant = bad });
                Assert.Throws<CryptographicException>(() => holder.SignMailboxPresentation(presentation.Operation, changed));
            }
            Assert.Throws<CryptographicException>(() => holder.SignMailboxPresentation(MailboxAuthenticatedOperation.Ack, input));
        }
    }

    // Random role-key fixture only, not protected holder/issuer/socket evidence.
    private sealed class GrantHolder : IReachabilityMailboxHolderSigner, IDisposable
    {
        private readonly byte[] privateKey;
        private readonly byte[] publicKey;
        private byte[] exposed;
        internal Action? BeforeSign { get; set; }
        internal bool CorruptSignature { get; set; }
        internal int ReportedLength { get; set; } = 64;
        internal int Calls { get; private set; }
        internal int KeyReads { get; private set; }
        internal GrantHolder()
        {
            var pair = PublicKeyAuth.GenerateKeyPair();
            privateKey = pair.PrivateKey; publicKey = pair.PublicKey; exposed = publicKey.ToArray();
        }
        public ReadOnlyMemory<byte> Ed25519PublicKey { get { KeyReads++; return exposed; } }
        internal void ChangeExposedKey() => Array.Clear(exposed);
        public async ValueTask<int> SignMailboxGrantRequestAsync(ReadOnlyMemory<byte> input,
            Memory<byte> signature64, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Calls++; await Task.Yield(); BeforeSign?.Invoke();
            var signature = PublicKeyAuth.SignDetached(input.ToArray(), privateKey);
            try { signature.CopyTo(signature64); if (CorruptSignature) signature64.Span[0] ^= 1; return ReportedLength; }
            finally { CryptographicOperations.ZeroMemory(signature); }
        }
        public void Dispose() { CryptographicOperations.ZeroMemory(privateKey); CryptographicOperations.ZeroMemory(exposed); }
    }
}
