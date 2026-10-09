using System.Buffers.Binary;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [Trait("FixturePreflight", "true")]
    public async Task FixturePreflight_SignedWindowsSuccessorOverlapAndColdReopenLease(int variant)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true,
            shortMailboxAuthority: variant == 1, longMailboxWindow: variant >= 2,
            initialMailboxAuthorityExpiry: variant == 3 ? 2_000UL : null);
        await fixture.CheckPreflightWindowsAndLeaseAsync(variant);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckPreflightWindowsAndLeaseAsync(int variant)
        {
            var expectedExpiry = variant switch { 0 => 1_500UL, 1 => 1_200UL, 2 => 6_000UL, 3 => 2_000UL, _ => throw new ArgumentOutOfRangeException(nameof(variant)) };
            var original = ContactCodec.Decode("PMT2", operational.ExactPmt2.Span);
            Assert.Equal(expectedExpiry, BinaryPrimitives.ReadUInt64BigEndian(original.Field(12).Span));
            Assert.Equal(expectedExpiry, BinaryPrimitives.ReadUInt64BigEndian(
                ContactCodec.Decode("PMA2", operational.ExactPma2.Span).Field(12).Span));
            var source = Source();
            var current = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            current.Network.EnsureCurrent();
            var reading = await ReadAsync(default);
            Assert.True(current.Proof.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds));
            var reopened = ReopenAccount();
            Assert.NotNull(await reopened.GetCurrentAsync());
            current.Network.EnsureCurrent();
            var restored = await Source(reopened).VerifyForOwnPreKeyAuthoringAsync(reopened, default);
            restored.Network.EnsureCurrent();
            Assert.Equal(OnionNetworkProtectedHistoryCodec.Encode(current.Network),
                OnionNetworkProtectedHistoryCodec.Encode(restored.Network));
            if (variant == 2) return;

            var successorExpiry = variant == 3 ? 6_000UL : 1_500UL;
            await AdvanceNetworkAsync(successorExpiry);
            var next = ContactCodec.Decode("PMT2", successor!.ExactPmt2.Span);
            var nextStart = BinaryPrimitives.ReadUInt64BigEndian(next.Field(11).Span);
            Assert.True(nextStart < expectedExpiry);
            Assert.Equal(successorExpiry, BinaryPrimitives.ReadUInt64BigEndian(next.Field(12).Span));
            var successorAuthority = await Source(reopened).VerifyForOwnPreKeyAuthoringAsync(reopened, default);
            successorAuthority.Network.EnsureCurrent();
            Assert.True(successorAuthority.Proof.TrustedLowerUnixSeconds >= nextStart);
        }
    }
}
