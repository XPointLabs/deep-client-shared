using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.Identity;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

// Scheduler unit tests only: these metadata selectors/denial hints are not
// proofs, Store receipts, transport fixtures or connected E2E evidence.
public sealed class ContactRouteMaintenanceCycleTests
{
    [Fact]
    public async Task EveryAcceptedOrientationIsVisitedButPendingConsentNeverRefreshes()
    {
        var contacts = new[] { Contact(1, DeepIdV2ContactState.IncomingRequest),
            Contact(2, DeepIdV2ContactState.LocalAcceptanceRetained),
            Contact(3, DeepIdV2ContactState.OutgoingRequest), Contact(4, DeepIdV2ContactState.PeerAcceptanceRetained) };
        var visited = new List<string>();
        var result = await Run(contacts, (_, _) => Task.FromResult(new DeepIdV2ContactRouteHealth(true, false, false)),
            (item, _) => { visited.Add(item.ConversationId); return Task.FromResult(1); });
        Assert.Equal(new[] { contacts[1].Conversation.ConversationId, contacts[3].Conversation.ConversationId }, visited);
        Assert.Equal(new DeepIdV2ContactMaintenanceResult(2, 2, 0, 0, 0, false), result);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public async Task ExpiredOrFaultedPeerIsDeferredWithoutStarvingAnotherContact(bool advertisement, bool fault)
    {
        var contacts = Pair(); var calls = 0;
        var result = await Run(contacts, (item, _) => Task.FromResult(ReferenceEquals(item, contacts[0].Conversation)
                ? new DeepIdV2ContactRouteHealth(advertisement, false, fault) : new(true, true, false)),
            (_, _) => { calls++; return Task.FromResult(1); });
        Assert.Equal(1, calls); Assert.Equal(2, result.AcceptedContacts);
        Assert.Equal(1, result.ControlsStored); Assert.Equal(1, result.DeferredContacts);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnknownOrDuplicateMetadataRejectsBeforeAnyCallback(bool duplicate)
    {
        var contacts = Pair();
        contacts[1] = duplicate ? contacts[0] : Contact(2, (DeepIdV2ContactState)255);
        var calls = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() => Run(contacts,
            (_, _) => { calls++; return Task.FromResult(new DeepIdV2ContactRouteHealth(true, true, false)); },
            (_, _) => { calls++; return Task.FromResult(0); }));
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    public async Task EffectCountCannotExceedTheOriginalOneControlContract(int count) =>
        await Assert.ThrowsAsync<InvalidDataException>(() => Run(Pair(),
            (_, _) => Task.FromResult(new DeepIdV2ContactRouteHealth(true, true, false)), (_, _) => Task.FromResult(count)));

    [Fact]
    public async Task DistinctDeviceScopesInTheSameConversationAreNotDeduplicated()
    {
        var first = Contact(1, DeepIdV2ContactState.PeerAcceptanceRetained);
        var exact = first.Conversation.Scope.Exact.ToArray(); exact[172] ^= 1;
        var second = new DeepIdV2ConversationSnapshot(new(Did2MessagingSessionScope.RestoreMetadata(exact)), first.ContactState);
        Assert.Equal(first.Conversation.ConversationId, second.Conversation.ConversationId);
        var effects = 0;
        var result = await Run([first, second], (_, _) => Task.FromResult(new DeepIdV2ContactRouteHealth(true, true, false)),
            (_, _) => { effects++; return Task.FromResult(1); });
        Assert.Equal(2, effects); Assert.Equal(2, result.ControlsStored);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationBeforeOrAfterDenialReadNeverInvokesAnEffect(bool before)
    {
        using var cancelled = new CancellationTokenSource(); if (before) cancelled.Cancel();
        var effects = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Run(Pair(),
            (_, _) => { cancelled.Cancel(); return Task.FromResult(new DeepIdV2ContactRouteHealth(true, true, false)); },
            (_, _) => { effects++; return Task.FromResult(1); }, cancelled.Token));
        Assert.Equal(0, effects);
    }

    [Fact]
    public async Task APositiveHealthHintNeverSuppressesTheActualEffectOwnersRefusal()
    {
        var refusal = new CryptographicException("Unit-only changed custody."); var effects = 0;
        var actual = await Assert.ThrowsAsync<CryptographicException>(() => Run(Pair(),
            (_, _) => Task.FromResult(new DeepIdV2ContactRouteHealth(true, true, false)),
            (_, _) => { effects++; return Task.FromException<int>(refusal); }));
        Assert.Same(refusal, actual); Assert.Equal(1, effects);
    }

    [Fact]
    public async Task AnotherCycleReentersEveryRealOwnerInsteadOfCachingSuccessfulEffects()
    {
        var effects = 0;
        for (var cycle = 0; cycle < 2; cycle++)
        {
            var result = await Run(Pair(), (_, _) => Task.FromResult(new DeepIdV2ContactRouteHealth(true, true, false)),
                (_, _) => { effects++; return Task.FromResult(0); });
            Assert.Equal(0, result.ControlsStored); Assert.Equal(0, result.DeferredContacts);
        }
        Assert.Equal(4, effects);
    }

    [Fact]
    public async Task ReintroductionStoresOnlyAControlAndDoesNotPromoteAnExpiredPeerRoute()
    {
        var contacts = Pair(); var refreshes = 0; var recoveries = 0;
        var result = await DeepIdV2AccountService.MaintainAcceptedContactRoutesAsync(contacts,
            (item, _) => Task.FromResult(new DeepIdV2ContactRouteHealth(!ReferenceEquals(item, contacts[0].Conversation), false, false)),
            (_, _) => { refreshes++; return Task.FromResult(1); }, default,
            (_, _) => { recoveries++; return Task.FromResult<int?>(1); });
        Assert.Equal(1, refreshes); Assert.Equal(1, recoveries);
        Assert.Equal(2, result.ControlsStored); Assert.Equal(1, result.Reintroductions);
        Assert.Equal(1, result.DeferredContacts); // Only a subsequent actual receive can adopt the peer route.
    }

    [Fact]
    public async Task RetainedFaultCannotUseAnAddressBookAsARecoveryOverride()
    {
        var calls = 0;
        var result = await DeepIdV2AccountService.MaintainAcceptedContactRoutesAsync(Pair(),
            (_, _) => Task.FromResult(new DeepIdV2ContactRouteHealth(false, false, true)),
            (_, _) => { calls++; return Task.FromResult(1); }, default,
            (_, _) => { calls++; return Task.FromResult<int?>(1); });
        Assert.Equal(0, calls); Assert.Equal(2, result.DeferredContacts);
    }

    [Fact]
    public void KnownAddressCollectionIsOwnedBeforeCallbacksAndRejectsCaseAliasesOrOverflow()
    {
        var selector = new string('a', 64);
        var capability = Enumerable.Repeat((byte)2, 16).ToArray();
        var address = DeepPermanentIdV2.FromCredential(DeepIdV2Codec.AuthorDid2(
            Enumerable.Repeat((byte)1, 32).ToArray(), Enumerable.Repeat((byte)3, 1952).ToArray(), capability), capability);
        var input = new Dictionary<string, DeepPermanentIdV2> { [selector] = address };
        var copied = DeepIdV2AccountService.CopyKnownContactAddresses(input);
        input.Clear(); Assert.Same(address, Assert.Single(copied).Value);
        input.Add(selector, address); input.Add(selector.ToUpperInvariant(), address);
        Assert.Throws<ArgumentException>(() => DeepIdV2AccountService.CopyKnownContactAddresses(input));
        var huge = Enumerable.Range(0, DeepIdV2AccountService.MaximumKnownContactAddresses + 1)
            .ToDictionary(index => index.ToString("x64"), _ => address);
        Assert.Throws<ArgumentException>(() => DeepIdV2AccountService.CopyKnownContactAddresses(huge));
    }

    private static Task<DeepIdV2ContactMaintenanceResult> Run(IReadOnlyList<DeepIdV2ConversationSnapshot> contacts,
        Func<DeepIdV2Conversation, CancellationToken, Task<DeepIdV2ContactRouteHealth>> health,
        Func<DeepIdV2Conversation, CancellationToken, Task<int>> effect, CancellationToken ct = default) =>
        DeepIdV2AccountService.MaintainAcceptedContactRoutesAsync(contacts, health, effect, ct);

    private static DeepIdV2ConversationSnapshot[] Pair() =>
        [Contact(1, DeepIdV2ContactState.PeerAcceptanceRetained), Contact(2, DeepIdV2ContactState.LocalAcceptanceRetained)];

    private static DeepIdV2ConversationSnapshot Contact(byte selector, DeepIdV2ContactState state)
    {
        var exact = Did2ContactAcceptCustodyTests.Scope().Exact.ToArray(); exact[244] = selector;
        return new(new(Did2MessagingSessionScope.RestoreMetadata(exact)), state);
    }
}
