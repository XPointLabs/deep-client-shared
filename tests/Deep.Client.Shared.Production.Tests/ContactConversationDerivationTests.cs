using Deep.Client.Shared.Domain.ContactV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ContactConversationDerivationTests
{
    [Fact]
    public void ContactConversationWrapper_UsesExactProtocolDerivation()
    {
        var network = Enumerable.Repeat((byte)1, 16).ToArray();
        var relationship = ContactRelationshipId32.FromBytes(Enumerable.Repeat((byte)2, 32).ToArray());
        var a = Enumerable.Repeat((byte)3, 32).ToArray();
        var b = Enumerable.Repeat((byte)4, 32).ToArray();
        var derived = ContactConversationId32.Derive(network, relationship, a, b).ToArray();
        Assert.Equal("5DF376969A08E345299DDE6328693EB27830A80C8F17F65EB1C770D3BEBD4E64", Convert.ToHexString(derived));
        Assert.Equal(derived, ApplicationCoreVerifier.ComputeContactConversationId(network, relationship.ToArray(), a, b));
        Assert.Equal(derived, ContactConversationId32.Derive(network, relationship, b, a).ToArray());
    }
}
