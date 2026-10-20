using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class SecureStorageCompareExchangeTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public Task GrammarMemoCannotReplaceActualAuthenticationOrAcceptChangedCanonicalInput(bool group) =>
        CheckGrammarAuthentication(group ? RegistrationGrammarKind.Group : RegistrationGrammarKind.Ordinary);

    [Theory]
    [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)]
    public Task AdditionalRegistrationRootsCannotReplaceActualAuthenticationOrAcceptChangedCanonicalInput(int value) =>
        CheckGrammarAuthentication((RegistrationGrammarKind)value);

    private async Task CheckGrammarAuthentication(RegistrationGrammarKind kind)
    {
        using var f = new Fixture(true); var network = Enumerable.Repeat((byte)1, 16).ToArray();
        var account = Enumerable.Repeat((byte)2, 32).ToArray(); var instance = Enumerable.Repeat((byte)3, 32).ToArray();
        var slot = kind switch
        {
            RegistrationGrammarKind.Group => ProtectedDid2GroupJournal.Slot,
            RegistrationGrammarKind.Ordinary => ProtectedDid2DirectTextJournal.Slot,
            RegistrationGrammarKind.ContactRoutes => ProtectedDid2ContactRouteJournal.Slot,
            RegistrationGrammarKind.MailboxGrants => ProtectedDid2MailboxGrantJournal.Slot,
            RegistrationGrammarKind.MailboxSends => ProtectedDid2MailboxSendJournal.Slot,
            RegistrationGrammarKind.MailboxReads => ProtectedDid2MailboxReadJournal.Slot,
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
        var original = AccountRegistrationGrammarTests.Empty(kind, network, account, instance);
        await f.Store.WriteBatchAsync([new(slot, original)]);
        var grammar = new AccountRegistrationGrammar();
        async Task Read()
        {
            using var root = await f.Store.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
            root.Use(bytes => { grammar.Validate(kind, bytes, network, account, instance); return true; });
        }
        var loads = f.Protector.UnprotectCalls;
        await Read(); await Read();
        Assert.Equal(loads + 2, f.Protector.UnprotectCalls); Assert.Equal(1, grammar.ParserExecutions);
        Assert.True(f.Protector.LastUnprotected!.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        var malformed = original.ToArray(); malformed[0] ^= 0x80;
        Assert.True(await f.Store.CompareExchangeAsync(slot, original, malformed));
        await Assert.ThrowsAnyAsync<Exception>(Read); await Assert.ThrowsAnyAsync<Exception>(Read);
        Assert.Equal(3, grammar.ParserExecutions);
        Assert.True(await f.Store.CompareExchangeAsync(slot, malformed, original));
        await Read(); Assert.Equal(3, grammar.ParserExecutions);
        var tampered = File.ReadAllBytes(f.StatePath); tampered[^1] ^= 1; File.WriteAllBytes(f.StatePath, tampered);
        await Assert.ThrowsAnyAsync<CryptographicException>(Read);
        Assert.Equal(3, grammar.ParserExecutions); // Last good grammar cannot authorize a failed actual read.
    }
}
