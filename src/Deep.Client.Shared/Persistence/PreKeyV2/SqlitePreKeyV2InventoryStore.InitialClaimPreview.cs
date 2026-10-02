using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.PreKeyV2;

internal sealed partial class SqlitePreKeyV2InventoryStore
{
    // Called only after account owner rechecks the protected inventory tip.
    // An opaque read-only preview copy is not an inventory reservation/burn.
    internal async ValueTask<(VerifiedDpk2Offering Offering, RestoredDpk2PreKeySecretCapability Secrets)>
        ReadRestoredInitialSecretsAsync(Dph2Record dph2, VerifiedDeepIdV2DirectoryFreshness proof,
            OnionMonotonicReading reading, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        byte[]? exact = null, sealedSecret = null;
        try
        {
            ThrowIfDisposed();
            if (!dph2.NetworkId.Span.SequenceEqual(network) || !dph2.ResponderAccountId.Span.SequenceEqual(account) ||
                !dph2.ResponderDeviceId.Span.SequenceEqual(device) || dph2.ResponderDeviceGeneration != deviceGeneration)
                throw new CryptographicException("The initial preview is outside this protected inventory owner.");
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT exact_dpk2,sealed_secret FROM secrets WHERE exact_dpk2_hash=$hash;";
            Add(command, "$hash", dph2.ExactDpk2Hash.ToArray());
            using var reader = command.ExecuteReader();
            if (!reader.Read()) throw new CryptographicException("The exact initial DPK2 is not retained in this local inventory.");
            exact = (byte[])reader.GetValue(0); sealedSecret = (byte[])reader.GetValue(1);
            var offering = DeepIdV2Dpk2PreClaimVerifier.Verify(exact, proof, reading.BootId.Span, reading.SampleSeconds);
            Dph2Codec.ValidateSelection(dph2, offering);
            ct.ThrowIfCancellationRequested();
            var scope = new Dpk2PreKeyPersistenceScope(network, account, accountGeneration, device, deviceGeneration, dpd1);
            var restored = protector.Restore(Dpk2PreKeyPersistenceBlob.Decode(sealedSecret), exact, scope);
            return (offering, restored);
        }
        finally
        {
            if (exact is not null) CryptographicOperations.ZeroMemory(exact);
            if (sealedSecret is not null) CryptographicOperations.ZeroMemory(sealedSecret);
            gate.Release();
        }
    }
}
