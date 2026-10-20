using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class AccountRegistrationGrammarTests
{
    private static byte[] B(int size, byte value) => Enumerable.Repeat(value, size).ToArray();
    internal static byte[] Empty(RegistrationGrammarKind kind, byte[] network, byte[] account, byte[] instance) => kind switch
    {
        RegistrationGrammarKind.Group => ProtectedDid2GroupJournal.Empty(network, account, instance),
        RegistrationGrammarKind.Ordinary => ProtectedDid2DirectTextJournal.Empty(network, account, instance),
        RegistrationGrammarKind.ContactRoutes => ProtectedDid2ContactRouteJournal.Empty(network, account, instance),
        RegistrationGrammarKind.MailboxGrants => ProtectedDid2MailboxGrantJournal.Empty(network, account, instance),
        RegistrationGrammarKind.MailboxSends => ProtectedDid2MailboxSendJournal.Empty(network, account, instance),
        RegistrationGrammarKind.MailboxReads => ProtectedDid2MailboxReadJournal.Empty(network, account, instance),
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)]
    public void OnlyExactSuccessfulCanonicalBytesAndEveryBindingReuseGrammar(int value)
    {
        var kind = (RegistrationGrammarKind)value; var network = B(16, 1); var account = B(32, 2); var instance = B(32, 3);
        var bytes = Empty(kind, network, account, instance); var original = bytes.ToArray(); var grammar = new AccountRegistrationGrammar();
        grammar.Validate(kind, bytes, network, account, instance);
        grammar.Validate(kind, bytes.ToArray(), network, account, instance);
        Assert.Equal(1, grammar.ParserExecutions); Assert.Equal(original, bytes);
        Assert.NotNull(Record.Exception(() => grammar.Validate(kind, bytes, B(16, 4), account, instance)));
        Assert.NotNull(Record.Exception(() => grammar.Validate(kind, bytes, network, B(32, 4), instance)));
        Assert.NotNull(Record.Exception(() => grammar.Validate(kind, bytes, network, account, B(32, 4))));
        Assert.Equal(4, grammar.ParserExecutions);
        grammar.Validate(kind, bytes, network, account, instance); Assert.Equal(4, grammar.ParserExecutions);
        var changed = bytes.ToArray(); changed[0] ^= 0x80;
        Assert.NotNull(Record.Exception(() => grammar.Validate(kind, changed, network, account, instance)));
        Assert.NotNull(Record.Exception(() => grammar.Validate(kind, changed, network, account, instance)));
        Assert.Equal(6, grammar.ParserExecutions); // Failures never populate the memo.
        grammar.Validate(kind, bytes, network, account, instance); Assert.Equal(6, grammar.ParserExecutions);
        var other = Empty(kind, network, account, B(32, 5));
        grammar.Validate(kind, other, network, account, B(32, 5)); Assert.Equal(7, grammar.ParserExecutions);
        grammar.Validate(kind, bytes, network, account, instance); Assert.Equal(8, grammar.ParserExecutions); // one entry per kind
        var anotherOwner = new AccountRegistrationGrammar();
        anotherOwner.Validate(kind, bytes, network, account, instance); Assert.Equal(1, anotherOwner.ParserExecutions);
    }

    [Fact]
    public void KindAndExistingSizeLimitsRejectBeforeMaterializingOrParsing()
    {
        var grammar = new AccountRegistrationGrammar(); var network = B(16, 1); var account = B(32, 2); var instance = B(32, 3);
        Assert.Throws<ArgumentException>(() => grammar.Validate((RegistrationGrammarKind)255, [], network, account, instance));
        Assert.Throws<ArgumentException>(() => grammar.Validate(RegistrationGrammarKind.Group, [], new byte[16], account, instance));
        Assert.Throws<InvalidDataException>(() => grammar.Validate(RegistrationGrammarKind.Group,
            new byte[ProtectedDid2GroupJournal.MaximumBytes + 1], network, account, instance));
        Assert.Throws<InvalidDataException>(() => grammar.Validate(RegistrationGrammarKind.Ordinary,
            new byte[ProtectedDid2DirectTextJournal.MaximumBytes + 1], network, account, instance));
        Assert.Equal(0, grammar.ParserExecutions);
    }
}
