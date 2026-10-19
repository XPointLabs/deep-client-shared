using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Reflection;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class SecureStorageCompareExchangeTests
{
    private delegate Dictionary<string, byte[]> DecodeInventory(ReadOnlySpan<byte> bytes, IReadOnlySet<string>? selected);

    [Fact]
    public void SelectedDecodeAvoidsUnrequestedValueBuffersWhileFullMutationDecodeRetainsThem()
    {
        var decode = typeof(JournaledDeepSecureStorage).GetMethod("Decode", BindingFlags.Static | BindingFlags.NonPublic)!
            .CreateDelegate<DecodeInventory>();
        var bytes = EncodeSelectedReadFixture([("a"u8.ToArray(), [1]), ("z"u8.ToArray(), new byte[1024 * 1024])]);
        var selectors = new HashSet<string>(StringComparer.Ordinal) { "a" };
        // Pure synchronous decoder: no awaits, file locks or other-thread
        // allocations enter this structural allocation comparison.
        var start = GC.GetAllocatedBytesForCurrentThread(); var full = decode(bytes, null);
        var fullBytes = GC.GetAllocatedBytesForCurrentThread() - start;
        start = GC.GetAllocatedBytesForCurrentThread(); var selected = decode(bytes, selectors);
        var selectedBytes = GC.GetAllocatedBytesForCurrentThread() - start;
        try
        {
            Assert.Equal(2, full.Count); Assert.Single(selected); Assert.Equal(1, selected["a"][0]);
            Assert.True(fullBytes - selectedBytes >= 1024 * 1024);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            foreach (var value in full.Values.Concat(selected.Values)) CryptographicOperations.ZeroMemory(value);
        }
    }

    [Fact]
    public void VectorizedSlotCharacterValidationMatchesControlAndSurrogatePolicyForEveryUtf16Character()
    {
        var validate = typeof(JournaledDeepSecureStorage).GetMethod("ValidateSlot", BindingFlags.Static | BindingFlags.NonPublic)!
            .CreateDelegate<Action<string>>();
        for (var value = 0; value <= char.MaxValue; value++)
        {
            var ch = (char)value; var error = Record.Exception(() => validate("a" + ch));
            Assert.Equal(char.IsControl(ch) || char.IsSurrogate(ch), error is not null);
        }
    }

    [Theory]
    [InlineData("oversized-unselected")]
    [InlineData("duplicate-unselected")]
    [InlineData("unordered-unselected")]
    [InlineData("invalid-utf8-unselected")]
    [InlineData("control-unselected")]
    [InlineData("empty-unselected")]
    [InlineData("trailing")]
    [InlineData("truncated")]
    public async Task SelectedReadStillRejectsMalformedUnselectedInventoryAndWipesWholePlaintext(string defect)
    {
        using var f = new Fixture(true);
        var entries = new List<(byte[] Slot, byte[] Value)> { ("a"u8.ToArray(), [1]), ("z"u8.ToArray(), [2]) };
        switch (defect)
        {
            case "oversized-unselected": entries[1] = ("z"u8.ToArray(), new byte[1024 * 1024 + 1]); break;
            case "duplicate-unselected": entries.Add(("z"u8.ToArray(), [3])); break;
            case "unordered-unselected": entries.Add(("y"u8.ToArray(), [3])); break;
            case "invalid-utf8-unselected": entries[1] = ([0xff], [2]); break;
            case "control-unselected": entries[1] = ("z\n"u8.ToArray(), [2]); break;
            case "empty-unselected": entries[1] = ("z"u8.ToArray(), []); break;
        }
        var plaintext = EncodeSelectedReadFixture(entries);
        if (defect == "trailing") plaintext = [.. plaintext, 1];
        if (defect == "truncated") plaintext = plaintext[..^1];
        var ciphertext = f.Protector.Protect(plaintext);
        try
        {
            File.WriteAllBytes(f.StatePath, ciphertext);
            await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.ReadOwnedAsync("a"));
            Assert.True(f.Protector.LastUnprotected!.AsSpan().IndexOfAnyExcept((byte)0) < 0);
            await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.ReadOwnedBatchAsync(["absent", "a"]));
            Assert.True(f.Protector.LastUnprotected!.AsSpan().IndexOfAnyExcept((byte)0) < 0);
            Assert.Equal(ciphertext, File.ReadAllBytes(f.StatePath));
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); CryptographicOperations.ZeroMemory(ciphertext); }
    }

    [Fact]
    public async Task SelectedReadReauthenticatesActualFileAndDoesNotLoseUnselectedValuesOnMutation()
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("z", new byte[1024 * 1024])]);
        var before = f.Protector.UnprotectCalls;
        using var first = await f.Store.ReadOwnedAsync("a");
        Assert.Equal(1, first!.Use(bytes => bytes[0]));
        Assert.Equal(before + 1, f.Protector.UnprotectCalls);
        Assert.True(f.Protector.LastUnprotected!.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        Assert.True(await f.Store.CompareExchangeAsync("a", new byte[] { 1 }, new byte[] { 3 }));
        using var current = await f.Store.ReadOwnedBatchAsync(["z", "a", "absent"]);
        Assert.Equal(1024 * 1024, current[0]!.Length); Assert.Equal(3, current[1]!.Use(bytes => bytes[0]));
        Assert.Null(current[2]); Assert.Equal(1, first.Use(bytes => bytes[0]));
        var tampered = File.ReadAllBytes(f.StatePath); tampered[^1] ^= 1; File.WriteAllBytes(f.StatePath, tampered);
        await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.ReadOwnedAsync("a"));
    }

    private static byte[] EncodeSelectedReadFixture(List<(byte[] Slot, byte[] Value)> entries)
    {
        var result = new byte[8 + entries.Sum(row => 6 + row.Slot.Length + row.Value.Length)];
        "DSS1"u8.CopyTo(result); BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), checked((ushort)entries.Count));
        var offset = 8;
        foreach (var entry in entries)
        {
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset), checked((ushort)entry.Slot.Length));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset + 2), checked((uint)entry.Value.Length)); offset += 6;
            entry.Slot.CopyTo(result, offset); offset += entry.Slot.Length;
            entry.Value.CopyTo(result, offset); offset += entry.Value.Length;
        }
        return result;
    }
}
