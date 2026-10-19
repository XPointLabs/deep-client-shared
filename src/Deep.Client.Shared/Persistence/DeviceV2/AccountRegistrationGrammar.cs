using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal enum RegistrationGrammarKind : byte { Group, Ordinary }

// Two bounded PURE grammar results, scoped to one account owner. This does not
// cache a storage read, decoded private state, revision/currentness decision or
// permission. The owner must still read/authenticate actual storage every time.
// Only exact bytes AND every parser binding may reuse canonicality; every
// dynamic owner/SQL/proof/floor/effect check remains outside this component.
internal sealed class AccountRegistrationGrammar
{
    private readonly object gate = new();
    private readonly byte[]?[] latest = new byte[2][];
#if DEEP_TEST_INTERNALS
    internal int ParserExecutions { get; private set; }
#endif
    internal void Validate(RegistrationGrammarKind kind, ReadOnlySpan<byte> bytes,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (kind is not (RegistrationGrammarKind.Group or RegistrationGrammarKind.Ordinary) ||
            network.Length != 16 || account.Length != 32 || instance.Length != 32 ||
            network.IndexOfAnyExcept((byte)0) < 0 || account.IndexOfAnyExcept((byte)0) < 0 || instance.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Registration grammar requires its exact closed binding.");
        var maximum = kind == RegistrationGrammarKind.Group ? ProtectedDid2GroupJournal.MaximumBytes : ProtectedDid2DirectTextJournal.MaximumBytes;
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
                if (kind == RegistrationGrammarKind.Group)
                { using var decoded = ProtectedDid2GroupJournal.Decode(bytes, network, account, instance); }
                else
                { using var decoded = ProtectedDid2DirectTextJournal.Decode(bytes, network, account, instance); }
                if (latest[(int)kind] is { } previous) CryptographicOperations.ZeroMemory(previous);
                latest[(int)kind] = digest; digest = [];
            }
        }
        finally { CryptographicOperations.ZeroMemory(digest); }
    }
}
