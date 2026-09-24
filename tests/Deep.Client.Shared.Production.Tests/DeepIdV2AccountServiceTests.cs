using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2AccountServiceTests
{
    [Fact]
    public async Task PublicServiceCreatesResumesAndDeletesPhraseWithoutV1Fallback()
    {
        if (!SupportedProvider()) return;
        var directory = Path.Combine(Path.GetTempPath(),
            "deep-did2-service-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using var storage = new InMemoryDeepSecureStorage();
            await storage.WriteBatchAsync(
                [new DeepSecureStorageWrite("deep.store.v1.keep", new byte[] { 7 })]);
            var network = Enumerable.Range(1, 16).Select(static value =>
                (byte)value).ToArray();
            var clock = new FrozenClock(
                DateTimeOffset.FromUnixTimeSeconds(1_900_000_000));
            var first = new DeepIdV2AccountService(storage, directory,
                network, 1, clock,
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            Assert.Null(await first.GetCurrentAsync());
            var created = await first.CreateAsync(" Alice ");
            Assert.Equal("Alice", created.DisplayName);
            Assert.Equal(created.PermanentId,
                DeepPermanentIdV2.ParseCanonical(
                    created.PermanentId.CanonicalText));
            Assert.Equal(32, created.AccountId.Length);
            var callerCopy = created.AccountId.ToArray();
            callerCopy.AsSpan().Clear();
            Assert.NotEqual(callerCopy, created.AccountId.ToArray());
            var publicGenesis = await new ProtectedDeepIdV2GenesisContactStore(
                storage, network, created.AccountId.Span).ReadUntrustedAsync(
                default);
            Assert.NotNull(publicGenesis);
            var readCapability = DeepIdV2Codec.DecodeDeepIdText(
                created.PermanentId.CanonicalText).ReadCapability;
            Assert.Equal(-1, publicGenesis!.ExactDid2.Span.IndexOf(
                readCapability));
            Assert.True(DeepIdV2Codec.DecodeDid2(
                publicGenesis.ExactDid2.Span).MatchesResolverReadCapability(
                    readCapability));
            using (var phrase = await first.ReadRetainedRecoveryPhraseAsync())
                Assert.NotNull(phrase);

            var otherNetwork = network.ToArray();
            otherNetwork[0] ^= 1;
            var wrongScope = new DeepIdV2AccountService(storage, directory,
                otherNetwork, 1, clock,
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            await Assert.ThrowsAnyAsync<Exception>(() =>
                wrongScope.GetCurrentAsync());

            var resumed = new DeepIdV2AccountService(storage, directory,
                network, 1, clock,
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            var account = await resumed.GetCurrentAsync();
            Assert.NotNull(account);
            Assert.Equal(created.AccountId.ToArray(), account.AccountId.ToArray());
            Assert.Equal(created.PermanentId, account.PermanentId);
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => resumed.CreateAsync("Second"));

            await resumed.DeleteRetainedRecoveryPhraseAsync();
            Assert.Null(await new DeepIdV2AccountService(storage, directory,
                network, 1, clock,
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess)
                .ReadRetainedRecoveryPhraseAsync());
            Assert.Equal(created.PermanentId,
                (await resumed.GetCurrentAsync())!.PermanentId);
            var afterPhraseDeletion = new DeepIdV2AccountService(storage,
                directory, network, 1, clock,
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            Assert.Equal(created.PermanentId,
                (await afterPhraseDeletion.GetCurrentAsync())!.PermanentId);

            await storage.DeleteBatchAsync(
                ["deep.store.v2.resolver-read-capability"]);
            await Assert.ThrowsAnyAsync<Exception>(() =>
                resumed.GetCurrentAsync());

            await resumed.ResetExplicitlyAsync();
            Assert.Null(await resumed.GetCurrentAsync());
            using var v1 = await storage.ReadOwnedAsync("deep.store.v1.keep");
            Assert.NotNull(v1);
        }
        finally
        {
            foreach (var path in Directory.EnumerateFiles(directory))
                File.Delete(path);
            Directory.Delete(directory);
        }
    }

    private static bool SupportedProvider() =>
        OperatingSystem.IsWindows() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture is
            (System.Runtime.InteropServices.Architecture.X64 or
             System.Runtime.InteropServices.Architecture.Arm64) ||
        OperatingSystem.IsLinux() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
            System.Runtime.InteropServices.Architecture.X64;
}
