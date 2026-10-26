using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Reflection;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class SecureStorageCompareExchangeTests
{
    [Fact]
    public async Task SelectedReadLoadsBoundedManifestWithoutUnrequestedObjectPayloads()
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("z", new byte[1024 * 1024])]);
        using (var warm = await f.Store.ReadOwnedAsync("a")) Assert.Equal(1, warm!.Use(value => value[0]));
        var loads = f.Protector.UnprotectCalls;
        using var selected = await f.Store.ReadOwnedBatchAsync(["a", "absent"]);
        Assert.Equal(loads + 1, f.Protector.UnprotectCalls);
        Assert.Equal(1, selected[0]!.Use(value => value[0])); Assert.Null(selected[1]);
        Assert.InRange(new FileInfo(f.StatePath).Length, 1, 2048);
        Assert.True(f.Protector.LastUnprotected!.Length < 2048);
        Assert.True(f.Protector.LastUnprotected.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        Assert.True(await f.Store.CompareExchangeAsync("a", new byte[] { 1 }, new byte[] { 2 }));
        using var large = await f.Store.ReadOwnedAsync("z"); Assert.Equal(1024 * 1024, large!.Length);
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
        await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("z", new byte[] { 2 })]);
        var plaintext = f.Protector.Unprotect(File.ReadAllBytes(f.StatePath));
        var entries = Dss2Entries(plaintext);
        var second = entries[1];
        switch (defect)
        {
            case "oversized-unselected": BinaryPrimitives.WriteUInt32BigEndian(plaintext.AsSpan(second.LengthOffset), 1024 * 1024 + 1); break;
            case "duplicate-unselected": plaintext[second.SlotOffset] = (byte)'a'; break;
            case "unordered-unselected": plaintext[second.SlotOffset] = (byte)'A'; break;
            case "invalid-utf8-unselected": plaintext[second.SlotOffset] = 0xff; break;
            case "control-unselected": plaintext[second.SlotOffset] = (byte)'\n'; break;
            case "empty-unselected": BinaryPrimitives.WriteUInt32BigEndian(plaintext.AsSpan(second.LengthOffset), 0); break;
        }
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
