using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class DormantSelfHostedProfileVerificationMutationTests
{
    [Fact]
    public async Task EveryFrozenComponentMutationFailsClosedWithoutStorageMutation()
    {
        var original = P14A2TestSupport.Fixture("accepted-eff4523-default.dpf");
        var componentOffsets = ComponentPayloadOffsets(original);
        Assert.Equal(4, componentOffsets.Count);

        foreach (var offset in componentOffsets.Prepend(0))
        {
            var mutated = original.ToArray();
            mutated[offset] ^= 0x01;
            var staging = new StagedSelfHostedProfileService(new InMemorySessionStore());
            var scope = P14A2TestSupport.Scope(0xa0);
            var saved = await staging.SaveAsync(scope, 1, mutated);
            var service = new DormantSelfHostedProfileVerificationService(
                staging,
                new P14A2DeterministicVerifier());

            var outcome = await service.VerifyAsync(
                scope, saved.Candidate!.Id, P14A2TestSupport.Parameters());

            Assert.Contains(outcome.Status, new[]
            {
                DormantSelfHostedProfileVerificationStatus.Malformed,
                DormantSelfHostedProfileVerificationStatus.TrustRejected
            });
            Assert.Equal(mutated,
                (await staging.ExportAsync(scope, saved.Candidate.Id)).GetCandidateBytesCopy());
        }
    }

    private static IReadOnlyList<int> ComponentPayloadOffsets(byte[] payload)
    {
        var offset = 6;
        _ = ReadVarUInt(payload, ref offset);
        var count = payload[5];
        var result = new List<int>(count);
        for (var index = 0; index < count; index++)
        {
            offset++;
            var length = ReadVarUInt(payload, ref offset);
            result.Add(offset + length - 1);
            offset += length;
        }
        return result;
    }

    private static int ReadVarUInt(byte[] source, ref int offset)
    {
        var value = 0;
        var shift = 0;
        byte current;
        do
        {
            current = source[offset++];
            value |= (current & 0x7f) << shift;
            shift += 7;
        } while ((current & 0x80) != 0);
        return value;
    }
}
