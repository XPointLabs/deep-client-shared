using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal enum RegistrationGrammarKind : byte { Group, Ordinary, ContactRoutes, MailboxGrants, MailboxSends, MailboxReads }

// Six bounded PURE grammar results, scoped to one account owner. This does not
// cache a storage read, decoded private state, revision/currentness decision or
// permission. The owner must still read/authenticate actual storage every time.
// Only exact bytes AND every parser binding may reuse canonicality; every
// dynamic owner/SQL/proof/floor/effect check remains outside this component.
internal sealed class AccountRegistrationGrammar
{
    private readonly object gate = new();
    private readonly byte[]?[] latest = new byte[6][];
#if DEEP_TEST_INTERNALS
    internal int ParserExecutions { get; private set; }
#endif
    internal void Validate(RegistrationGrammarKind kind, ReadOnlySpan<byte> bytes,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (kind is < RegistrationGrammarKind.Group or > RegistrationGrammarKind.MailboxReads ||
            network.Length != 16 || account.Length != 32 || instance.Length != 32 ||
            network.IndexOfAnyExcept((byte)0) < 0 || account.IndexOfAnyExcept((byte)0) < 0 || instance.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Registration grammar requires its exact closed binding.");
        var maximum = kind switch
        {
            RegistrationGrammarKind.Group => ProtectedDid2GroupJournal.MaximumBytes,
            RegistrationGrammarKind.Ordinary => ProtectedDid2DirectTextJournal.MaximumBytes,
            RegistrationGrammarKind.ContactRoutes => ProtectedDid2ContactRouteJournal.MaximumBytes,
            RegistrationGrammarKind.MailboxGrants => ProtectedDid2MailboxGrantJournal.MaximumBytes,
            RegistrationGrammarKind.MailboxSends => ProtectedDid2MailboxSendJournal.MaximumBytes,
            RegistrationGrammarKind.MailboxReads => ProtectedDid2MailboxReadJournal.MaximumBytes,
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
        if (bytes.Length > maximum) throw new InvalidDataException("Registration grammar exceeds its existing root bound.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Client/registration-grammar-resource\0"u8); hash.AppendData([(byte)kind]);
        hash.AppendData(network); hash.AppendData(account); hash.AppendData(instance); hash.AppendData(bytes);
        var digest = hash.GetHashAndReset();
        try
        {
            lock (gate)
            {
                if (latest[(int)kind] is { } prior && CryptographicOperations.FixedTimeEquals(prior, digest)) return;
#if DEEP_TEST_INTERNALS
                ParserExecutions++;
#endif
                switch (kind)
                {
                    case RegistrationGrammarKind.Group: { using var decoded = ProtectedDid2GroupJournal.Decode(bytes, network, account, instance); break; }
                    case RegistrationGrammarKind.Ordinary: { using var decoded = ProtectedDid2DirectTextJournal.Decode(bytes, network, account, instance); break; }
                    case RegistrationGrammarKind.ContactRoutes: { using var decoded = ProtectedDid2ContactRouteJournal.Decode(bytes, network, account, instance); break; }
                    case RegistrationGrammarKind.MailboxGrants: { using var decoded = ProtectedDid2MailboxGrantJournal.Decode(bytes, network, account, instance); break; }
                    case RegistrationGrammarKind.MailboxSends: { using var decoded = ProtectedDid2MailboxSendJournal.Decode(bytes, network, account, instance); break; }
                    case RegistrationGrammarKind.MailboxReads: { using var decoded = ProtectedDid2MailboxReadJournal.Decode(bytes, network, account, instance); break; }
                }
                if (latest[(int)kind] is { } previous) CryptographicOperations.ZeroMemory(previous);
                latest[(int)kind] = digest; digest = [];
            }
        }
        finally { CryptographicOperations.ZeroMemory(digest); }
    }
}
