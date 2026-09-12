using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.AccountDirectoryV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;

const string networkIdHex = "edc5dc1516a847a65fc8ba0e690d000d";
const string genesisHashHex =
    "304911104767ae1036a44c71116a5fcdee3449fc71ea1467c09295f89be3a2b7";
const string registryOrigin = "https://registry.xpoint.network/";

var networkId = Convert.FromHexString(networkIdHex);
var genesisHash = Convert.FromHexString(genesisHashHex);
var accountKey = RandomNonzero(32);
var didKey = RandomNonzero(32);
var resolverCapability = RandomNonzero(16);
try
{
    var account = DeepAccountIdentityCapability.FromVerifiedInputs(
        DeepNetworkId16.FromVerifiedBytes(networkId),
        accountGeneration: 1,
        AccountEd25519PublicKey32.FromVerifiedBytes(accountKey));
    var scope = ContactStoreScope.ForCurrentAccount(account.AccountId);
    var contactStore = new InMemoryContactStateStore(scope);
    var importer = new ContactAddressImportService(contactStore, networkId);
    var did = ApplicationCoreCodec.AuthorDid1(didKey, resolverCapability);
    var imported = await importer.ImportAsync(did.Text);
    var clock = new ProbeMonotonicClock();
    var directoryStore = new InMemoryAccountDirectoryStateStore();
    var networkStore = new InMemoryXPointNetworkStateStore();
    var transportFactory = new HttpServiceTransportFactory(
        HttpServiceEndpointPolicy.Production);
    var clientOptions = new HttpServiceClientOptions(
        Timeout: TimeSpan.FromSeconds(20),
        ConnectTimeout: TimeSpan.FromSeconds(5));
    using (var authority = transportFactory
               .CreateProductionContactResolvePathAuthoritySource(
                   registryOrigin,
                   new XPointNetworkGenesisPin(networkId, genesisHash),
                   directoryStore,
                   networkStore,
                   clock,
                   supportedDirectoryReader: 1,
                   clientOptions))
    {
        _ = await authority.MintPlacementContextAsync(
            scope,
            imported.PendingAddress);
    }

    using (var restartedAuthority = transportFactory
               .CreateProductionContactResolvePathAuthoritySource(
                   registryOrigin,
                   new XPointNetworkGenesisPin(networkId, genesisHash),
                   directoryStore,
                   networkStore,
                   clock,
                   supportedDirectoryReader: 1,
                   clientOptions))
    {
        _ = await restartedAuthority.MintPlacementContextAsync(
            scope,
            imported.PendingAddress);
    }
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        schema = "deep-contact-resolve-production-probe.v1",
        status = "verified-after-restart",
        networkId = networkIdHex
    }));
}
finally
{
    CryptographicOperations.ZeroMemory(networkId);
    CryptographicOperations.ZeroMemory(genesisHash);
    CryptographicOperations.ZeroMemory(accountKey);
    CryptographicOperations.ZeroMemory(didKey);
    CryptographicOperations.ZeroMemory(resolverCapability);
}

static byte[] RandomNonzero(int length)
{
    var value = new byte[length];
    do RandomNumberGenerator.Fill(value);
    while (value.AsSpan().IndexOfAnyExcept((byte)0) < 0);
    return value;
}

file sealed class ProbeMonotonicClock : IOnionMonotonicClock
{
    private readonly byte[] bootId = RandomNumberGenerator.GetBytes(16);
    private readonly long started = Stopwatch.GetTimestamp();

    public ValueTask<OnionMonotonicReading> ReadAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var elapsed = Stopwatch.GetElapsedTime(started);
        return ValueTask.FromResult(new OnionMonotonicReading(
            bootId,
            checked((ulong)Math.Floor(elapsed.TotalSeconds))));
    }
}
