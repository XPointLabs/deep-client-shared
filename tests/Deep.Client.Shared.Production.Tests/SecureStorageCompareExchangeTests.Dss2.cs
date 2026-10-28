using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Reflection;
using System.Runtime.InteropServices;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Microsoft.Win32.SafeHandles;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class SecureStorageCompareExchangeTests
{
    [Theory]
    [InlineData("missing")] [InlineData("pending")] [InlineData("backup")]
    public async Task Dss2OpenExistingNeverCreatesOrPromotesAnAbsentCommittedRoot(string remnant)
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("a", new byte[] { 7 })]);
        var original = File.ReadAllBytes(f.StatePath);
        if (remnant != "missing") File.WriteAllBytes(f.StatePath + "." + remnant, original);
        File.Delete(f.StatePath);
        using var reopened = f.OpenJournaled();
        await Assert.ThrowsAnyAsync<CryptographicException>(() => reopened.ReadOwnedAsync("a"));
        Assert.False(File.Exists(f.StatePath));
        Assert.NotEmpty(Directory.GetFiles(f.StatePath + ".objects", "*.dvo"));
    }

    [Theory]
    [InlineData("current")] [InlineData("pending")] [InlineData("backup")] [InlineData("object")]
    public async Task Dss2CreateNewRejectsEveryExistingStorageRemnantWithoutEffects(string remnant)
    {
        using var f = new Fixture(false);
        var target = remnant switch
        {
            "current" => f.StatePath,
            "object" => Path.Combine(f.StatePath + ".objects", new string('a', 64) + ".dvo"),
            _ => f.StatePath + "." + remnant
        };
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        byte[] sentinel = [7, 8, 9]; File.WriteAllBytes(target, sentinel);
        using var candidateProtector = f.NewProtector();
        await Assert.ThrowsAsync<InvalidOperationException>(() => JournaledDeepSecureStorage.CreateNewAsync(f.StatePath, candidateProtector));
        Assert.Equal(sentinel, File.ReadAllBytes(target));
        if (remnant != "current") Assert.False(File.Exists(f.StatePath));
    }

    [Fact]
    public async Task Dss2EmptyManifestIsDurableAndOrdinaryReadsRejectDss1()
    {
        using var f = new Fixture(true);
        using (var reopened = f.OpenJournaled())
        using (var empty = await reopened.ReadOwnedBatchAsync(["missing"])) Assert.Null(empty[0]);
        var old = EncodeSelectedReadFixture([("a"u8.ToArray(), [7])]);
        try
        {
            File.WriteAllBytes(f.StatePath, f.Protector.Protect(old));
            await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.ReadOwnedAsync("a"));
        }
        finally { CryptographicOperations.ZeroMemory(old); }
    }

    [Theory]
    [InlineData("missing")] [InlineData("ciphertext")] [InlineData("tag")]
    [InlineData("truncated")] [InlineData("trailing")] [InlineData("swapped")] [InlineData("oversized")]
    public async Task Dss2SelectedObjectCorruptionCannotBecomeAbsenceOrAValue(string defect)
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("a", new byte[] { 7 }), new("z", new byte[] { 9 })]);
        using (var warm = await f.Store.ReadOwnedAsync("a")) Assert.NotNull(warm);
        var descriptors = Dss2ReadEntries(f); var path = Dss2ObjectPath(f, descriptors[0]);
        var original = File.ReadAllBytes(path);
        if (defect == "missing") File.Delete(path);
        else
        {
            var changed = original.ToArray();
            if (defect == "ciphertext") changed[96] ^= 1;
            if (defect == "tag") changed[^1] ^= 1;
            if (defect == "truncated") changed = changed[..^1];
            if (defect == "trailing") changed = [.. changed, 0];
            if (defect == "swapped") changed = File.ReadAllBytes(Dss2ObjectPath(f, descriptors[1]));
            File.WriteAllBytes(path, changed);
            if (defect == "oversized") { using var file = File.OpenWrite(path); file.SetLength(8 * 1024 * 1024); }
        }
        var manifest = File.ReadAllBytes(f.StatePath);
        await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.ReadOwnedAsync("a"));
        await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.ReadOwnedBatchAsync(["absent", "a"]));
        Assert.Equal(manifest, File.ReadAllBytes(f.StatePath));
    }

    [Theory]
    [InlineData("store")] [InlineData("id")] [InlineData("birth")]
    [InlineData("nonce")] [InlineData("tag")] [InlineData("slot")]
    public async Task Dss2AnchoredHashCannotReplaceExactObjectContextAndAead(string defect)
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("a", new byte[] { 7 })]);
        using (var warm = await f.Store.ReadOwnedAsync("a")) Assert.NotNull(warm);
        var plain = f.Protector.Unprotect(File.ReadAllBytes(f.StatePath));
        try
        {
            var entry = Assert.Single(Dss2Entries(plain));
            var path = Dss2ObjectPath(f, entry); var bytes = File.ReadAllBytes(path);
            if (defect == "slot") plain[entry.SlotOffset] = (byte)'b';
            else
            {
                var offset = defect switch { "store" => 8, "id" => 40, "birth" => 79, "nonce" => 84, _ => bytes.Length - 1 };
                bytes[offset] ^= 1; File.WriteAllBytes(path, bytes);
                SHA256.HashData(bytes).CopyTo(plain, entry.HashOffset);
            }
            File.WriteAllBytes(f.StatePath, f.Protector.Protect(plain));
            await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.ReadOwnedAsync(defect == "slot" ? "b" : "a"));
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    [Fact]
    public async Task Dss2WarmSelectionDefersUnusedContentButColdOpenAndAuditReadAllObjects()
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("a", new byte[] { 7 }), new("z", new byte[] { 9 })]);
        using (var warm = await f.Store.ReadOwnedAsync("a")) Assert.NotNull(warm);
        var path = Dss2ObjectPath(f, Dss2ReadEntries(f)[1]);
        var changed = File.ReadAllBytes(path); changed[^1] ^= 1; File.WriteAllBytes(path, changed);
        var loads = f.Protector.UnprotectCalls;
        using (var selected = await f.Store.ReadOwnedBatchAsync(["a", "absent"]))
        { Assert.Equal(7, selected[0]!.Use(value => value[0])); Assert.Null(selected[1]); }
        Assert.Equal(loads + 1, f.Protector.UnprotectCalls);
        await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.ReadOwnedAsync("z"));
        await Assert.ThrowsAnyAsync<CryptographicException>(() => Assert.IsType<JournaledDeepSecureStorage>(f.Store).AuditAsync());
        using var reopened = f.OpenJournaled();
        await Assert.ThrowsAnyAsync<CryptographicException>(() => reopened.ReadOwnedAsync("a"));
    }

    [Theory]
    [InlineData("AfterPendingManifest", false)] [InlineData("AfterObjectStaged", false)]
    [InlineData("BeforeManifestReplace", false)] [InlineData("AfterManifestReplace", true)]
    [InlineData("AfterRetirementTombstone", true)] [InlineData("AfterRetirementUnlink", true)]
    [InlineData("BeforeCleanupManifest", true)] [InlineData("AfterCleanupManifest", true)]
    public async Task Dss2CrashCutpointsKeepOneCompleteInventoryAndResumeExactCleanup(string point, bool committed)
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("guard", new byte[] { 1 }), new("foreign", new byte[] { 9 })]);
        var old = Dss2ReadEntries(f).Single(entry => entry.Slot == "guard");
        using var crash = JournaledDeepSecureStorageTestHooks.PushCrashOnce(Enum.Parse<JournaledDeepSecureStorageFailpoint>(point));
        {
            var error = await Assert.ThrowsAsync<IOException>(() => f.Store.CompareExchangeAndInsertAsync("guard", new byte[] { 1 },
                new byte[] { 2 }, [new("inserted", new byte[] { 3 })]));
            Assert.Equal("Injected DSS2 crash cutpoint.", error.Message);
        }
        Assert.True(crash.Reached);
        using var reopened = f.OpenJournaled();
        using var snapshot = await reopened.ReadOwnedBatchAsync(["guard", "inserted", "foreign"]);
        Assert.Equal(committed ? 2 : 1, snapshot[0]!.Use(value => value[0]));
        if (committed) Assert.Equal(3, snapshot[1]!.Use(value => value[0])); else Assert.Null(snapshot[1]);
        Assert.Equal(9, snapshot[2]!.Use(value => value[0]));
        await reopened.AuditAsync();
        if (committed) Assert.False(File.Exists(Dss2ObjectPath(f, old)));
        Assert.False(File.Exists(f.StatePath + ".pending")); Assert.False(File.Exists(f.StatePath + ".backup"));
        Assert.Equal(Dss2ReadEntries(f).Count, Directory.GetFiles(f.StatePath + ".objects", "*.dvo").Length);
    }

    [Theory]
    [InlineData("BeforeManifestReplace", false)] [InlineData("AfterManifestReplace", true)]
    public async Task Dss2CancellationNeverTurnsAnAdoptedInventoryIntoNoncommit(string point, bool committed)
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 })]);
        using var cancelled = new CancellationTokenSource();
        using var callback = JournaledDeepSecureStorageTestHooks.PushCallbackOnce(Enum.Parse<JournaledDeepSecureStorageFailpoint>(point), cancelled.Cancel);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Store.CompareExchangeAsync("a", new byte[] { 1 }, new byte[] { 2 }, cancelled.Token));
        Assert.True(callback.Reached);
        using var reopened = f.OpenJournaled(); using var current = await reopened.ReadOwnedAsync("a");
        Assert.Equal(committed ? 2 : 1, current!.Use(value => value[0]));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Dss2OutstandingCleanupRepeatsDurableTombstoneEvenForAbsentOrEmptyFile(bool empty)
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 })]);
        var old = Assert.Single(Dss2ReadEntries(f));
        using var crash = JournaledDeepSecureStorageTestHooks.PushCrashOnce(JournaledDeepSecureStorageFailpoint.AfterManifestReplace);
        await Assert.ThrowsAsync<IOException>(() => f.Store.DeleteBatchAsync(["a"]));
        Assert.True(crash.Reached);
        var path = Dss2ObjectPath(f, old); if (empty) File.WriteAllBytes(path, []); else File.Delete(path);
        var tombstones = 0;
        using (JournaledDeepSecureStorageTestHooks.PushCallbackOnce(JournaledDeepSecureStorageFailpoint.AfterRetirementTombstone, () =>
        {
            tombstones++; Assert.True(File.Exists(path)); Assert.Equal(0, new FileInfo(path).Length);
        }))
        using (var reopened = f.OpenJournaled())
        using (var missing = await reopened.ReadOwnedAsync("a")) Assert.Null(missing);
        Assert.Equal(1, tombstones); Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Dss2ProtectCallbackRevocationCannotPublishPreparedSuccessor()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 })]);
        var original = File.ReadAllBytes(f.StatePath);
        f.Protector.AfterProtect = () => f.Protector.FailUnprotect = true;
        try { await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.CompareExchangeAsync("a", new byte[] { 1 }, new byte[] { 2 })); }
        finally { f.Protector.AfterProtect = null; f.Protector.FailUnprotect = false; }
        Assert.Equal(original, File.ReadAllBytes(f.StatePath));
        using var reopened = f.OpenJournaled(); using var current = await reopened.ReadOwnedAsync("a");
        Assert.Equal(1, current!.Use(value => value[0]));
    }

    [Fact]
    public async Task Dss2ReadRejectsActualManifestReplacementDuringUnprotectCallback()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 })]);
        using (var warm = await f.Store.ReadOwnedAsync("a")) Assert.NotNull(warm);
        var changed = File.ReadAllBytes(f.StatePath); changed[^1] ^= 1; var callbackReached = false;
        f.Protector.AfterUnprotect = () => { callbackReached = true; File.WriteAllBytes(f.StatePath, changed); };
        try { await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.ReadOwnedBatchAsync(["a", "absent"])); }
        finally { f.Protector.AfterUnprotect = null; }
        Assert.True(callbackReached); Assert.Equal(changed, File.ReadAllBytes(f.StatePath));
        Assert.True(f.Protector.LastUnprotected!.AsSpan().IndexOfAnyExcept((byte)0) < 0);
    }

    [WindowsStorageFact]
    public async Task Dss2RetirementSharingFailureLeavesCommittedCleanupAndPreservesFilePermissions()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("foreign", new byte[] { 9 })]);
        var retired = Dss2ReadEntries(f).Single(entry => entry.Slot == "a");
        var path = Dss2ObjectPath(f, retired); var bytes = File.ReadAllBytes(path); var attributes = File.GetAttributes(path);
        using (var blocker = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            var failure = await Assert.ThrowsAsync<IOException>(() => f.Store.DeleteBatchAsync(["a"]));
            Assert.Equal("Protected storage operation retry budget exhausted.", failure.Message);
            Assert.Equal(bytes, File.ReadAllBytes(path)); Assert.Equal(attributes, File.GetAttributes(path));
            Assert.DoesNotContain(Dss2ReadEntries(f), entry => entry.Slot == "a");
            var manifest = f.Protector.Unprotect(File.ReadAllBytes(f.StatePath));
            try { Assert.Equal(1U, BinaryPrimitives.ReadUInt32BigEndian(manifest.AsSpan(84))); }
            finally { CryptographicOperations.ZeroMemory(manifest); }
        }
        using var reopened = f.OpenJournaled();
        using var current = await reopened.ReadOwnedBatchAsync(["a", "foreign"]);
        Assert.Null(current[0]); Assert.Equal(9, current[1]!.Use(value => value[0])); Assert.False(File.Exists(path));
    }

    [Theory]
    [InlineData("version")] [InlineData("flags")] [InlineData("store-id")]
    [InlineData("revision")] [InlineData("active-count")] [InlineData("cleanup-count")]
    [InlineData("logical-bytes")] [InlineData("duplicate-id")] [InlineData("birth")]
    public async Task Dss2CompleteManifestRejectsMalformedUnselectedDescriptors(string defect)
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("z", new byte[] { 2 })]);
        var manifest = f.Protector.Unprotect(File.ReadAllBytes(f.StatePath));
        try
        {
            var entries = Dss2Entries(manifest);
            switch (defect)
            {
                case "version": manifest[5] = 3; break;
                case "flags": manifest[7] = 1; break;
                case "store-id": manifest.AsSpan(8, 32).Clear(); break;
                case "revision": manifest.AsSpan(40, 8).Clear(); break;
                case "active-count": BinaryPrimitives.WriteUInt32BigEndian(manifest.AsSpan(80), 1025); break;
                case "cleanup-count": BinaryPrimitives.WriteUInt32BigEndian(manifest.AsSpan(84), 1025); break;
                case "logical-bytes": BinaryPrimitives.WriteUInt64BigEndian(manifest.AsSpan(88), 8 * 1024 * 1024 + 1); break;
                case "duplicate-id": manifest.AsSpan(entries[0].IdOffset, 32).CopyTo(manifest.AsSpan(entries[1].IdOffset, 32)); break;
                case "birth": manifest.AsSpan(entries[1].IdOffset + 32, 8).Clear(); break;
            }
            var changed = f.Protector.Protect(manifest); File.WriteAllBytes(f.StatePath, changed);
            await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.ReadOwnedBatchAsync(["absent", "a"]));
            Assert.Equal(changed, File.ReadAllBytes(f.StatePath));
            Assert.True(f.Protector.LastUnprotected!.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        }
        finally { CryptographicOperations.ZeroMemory(manifest); }
    }

    [Fact]
    public async Task Dss2ProtectedManifestSizeIsBoundedBeforeUnprotect()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 })]);
        var calls = f.Protector.UnprotectCalls;
        using (var file = File.OpenWrite(f.StatePath)) file.SetLength(2 * 1024 * 1024 + 1);
        await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.ReadOwnedAsync("a"));
        Assert.Equal(calls, f.Protector.UnprotectCalls);
    }

    [Fact]
    public async Task Dss2CleanupCannotNameAnyCurrentActiveObject()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 })]);
        var manifest = f.Protector.Unprotect(File.ReadAllBytes(f.StatePath));
        try
        {
            var entry = Assert.Single(Dss2Entries(manifest)); var path = Dss2ObjectPath(f, entry); var original = File.ReadAllBytes(path);
            var changed = new byte[manifest.Length + 32]; manifest.CopyTo(changed, 0);
            try
            {
                manifest.AsSpan(entry.IdOffset, 32).CopyTo(changed.AsSpan(manifest.Length));
                BinaryPrimitives.WriteUInt32BigEndian(changed.AsSpan(84), 1);
                File.WriteAllBytes(f.StatePath, f.Protector.Protect(changed));
                await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.ReadOwnedAsync("a"));
                Assert.Equal(original, File.ReadAllBytes(path));
            }
            finally { CryptographicOperations.ZeroMemory(changed); }
        }
        finally { CryptographicOperations.ZeroMemory(manifest); }
    }

    [Fact]
    public async Task Dss2UnauthenticatedPendingCannotAuthorizeCleanupOrPromotion()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 })]);
        var original = File.ReadAllBytes(f.StatePath); var entry = Assert.Single(Dss2ReadEntries(f));
        var objectPath = Dss2ObjectPath(f, entry); var originalObject = File.ReadAllBytes(objectPath);
        using var crash = JournaledDeepSecureStorageTestHooks.PushCrashOnce(JournaledDeepSecureStorageFailpoint.AfterObjectStaged);
        await Assert.ThrowsAsync<IOException>(() => f.Store.CompareExchangeAsync("a", new byte[] { 1 }, new byte[] { 2 }));
        Assert.True(crash.Reached); var pending = File.ReadAllBytes(f.StatePath + ".pending"); pending[^1] ^= 1;
        File.WriteAllBytes(f.StatePath + ".pending", pending);
        using var reopened = f.OpenJournaled();
        await Assert.ThrowsAnyAsync<CryptographicException>(() => reopened.ReadOwnedAsync("a"));
        Assert.Equal(original, File.ReadAllBytes(f.StatePath)); Assert.Equal(originalObject, File.ReadAllBytes(objectPath));
    }

    [Fact]
    public async Task Dss2ExplicitEnrollmentPreservesEverySlotAndExternalNativeFile()
    {
        using var f = new Fixture(false);
        var values = new List<(byte[] Slot, byte[] Value)>
        {
            ("a.account-instance"u8.ToArray(), RandomNumberGenerator.GetBytes(32)),
            ("b.pending-store-original"u8.ToArray(), RandomNumberGenerator.GetBytes(1024 * 1024)),
            ("c.native-floor"u8.ToArray(), RandomNumberGenerator.GetBytes(196)),
            ("z.ack-original"u8.ToArray(), RandomNumberGenerator.GetBytes(512))
        };
        var source = EncodeSelectedReadFixture(values); var protectedSource = f.Protector.Protect(source);
        var nativePath = f.StatePath + ".native.dsv2"; var nativeKey = RandomNumberGenerator.GetBytes(32);
        try
        {
            // Real existing SQLCipher opener and actual native file. This small
            // structural table is not a fabricated verified account/schema claim.
            using (var sql = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(nativePath, nativeKey, create: true))
            {
                using var write = sql.CreateCommand();
                write.CommandText = "CREATE TABLE retained (id INTEGER PRIMARY KEY, counter INTEGER NOT NULL, exact BLOB NOT NULL); INSERT INTO retained VALUES(1,59,$exact);";
                write.Parameters.AddWithValue("$exact", values[2].Value); write.ExecuteNonQuery();
            }
            var native = File.ReadAllBytes(nativePath); File.WriteAllBytes(f.StatePath, protectedSource);
            using (var ordinary = f.OpenJournaled()) await Assert.ThrowsAnyAsync<CryptographicException>(() => ordinary.ReadOwnedAsync("a.account-instance"));
            using var enrolled = await JournaledDeepSecureStorage.EnrollAggregateAsync(f.StatePath, f.Protector);
            await enrolled.AuditAsync();
            using var actual = await enrolled.ReadOwnedBatchAsync(values.Select(row => Encoding.UTF8.GetString(row.Slot)).ToArray());
            for (var index = 0; index < values.Count; index++) Assert.Equal(values[index].Value, actual[index]!.Use(value => value.ToArray()));
            Assert.Equal(native, File.ReadAllBytes(nativePath));
            using (var sql = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(nativePath, nativeKey, create: false))
            {
                using var read = sql.CreateCommand(); read.CommandText = "SELECT counter,exact FROM retained WHERE id=1;";
                using var row = read.ExecuteReader(); Assert.True(row.Read()); Assert.Equal(59L, row.GetInt64(0));
                Assert.Equal(values[2].Value, row.GetFieldValue<byte[]>(1)); Assert.False(row.Read());
            }
            var manifest = f.Protector.Unprotect(File.ReadAllBytes(f.StatePath));
            try { Assert.Equal(SHA256.HashData(protectedSource), manifest[48..80]); Assert.Equal(1UL, BinaryPrimitives.ReadUInt64BigEndian(manifest.AsSpan(40))); }
            finally { CryptographicOperations.ZeroMemory(manifest); }
            Assert.False(File.Exists(f.StatePath + ".backup")); Assert.False(File.Exists(f.StatePath + ".pending"));
        }
        finally { CryptographicOperations.ZeroMemory(source); CryptographicOperations.ZeroMemory(nativeKey); foreach (var row in values) CryptographicOperations.ZeroMemory(row.Value); }
    }

    [Fact]
    public async Task Dss2InterruptedEnrollmentResumesOnlyThroughExplicitEnrollment()
    {
        using var f = new Fixture(false);
        var source = EncodeSelectedReadFixture([("a"u8.ToArray(), [1]), ("z"u8.ToArray(), [9])]);
        var protectedSource = f.Protector.Protect(source); File.WriteAllBytes(f.StatePath, protectedSource);
        try
        {
            using var firstProtector = f.NewProtector();
            using var crash = JournaledDeepSecureStorageTestHooks.PushCrashOnce(JournaledDeepSecureStorageFailpoint.AfterObjectStaged);
            await Assert.ThrowsAsync<IOException>(() => JournaledDeepSecureStorage.EnrollAggregateAsync(f.StatePath, firstProtector));
            Assert.True(crash.Reached); Assert.Equal(protectedSource, File.ReadAllBytes(f.StatePath));
            using (var ordinary = f.OpenJournaled()) await Assert.ThrowsAnyAsync<CryptographicException>(() => ordinary.ReadOwnedAsync("a"));
            using var enrolled = await JournaledDeepSecureStorage.EnrollAggregateAsync(f.StatePath, f.NewProtector());
            using var current = await enrolled.ReadOwnedBatchAsync(["a", "z"]);
            Assert.Equal(1, current[0]!.Use(value => value[0])); Assert.Equal(9, current[1]!.Use(value => value[0]));
            Assert.Equal(2, Directory.GetFiles(f.StatePath + ".objects", "*.dvo").Length);
            Assert.False(File.Exists(f.StatePath + ".pending"));
        }
        finally { CryptographicOperations.ZeroMemory(source); }
    }

    [Fact]
    public async Task Dss2EnrollmentRejectsActualSourceReplacementAfterProtectorCallback()
    {
        using var f = new Fixture(false);
        var source = EncodeSelectedReadFixture([("a"u8.ToArray(), [1])]);
        var replacement = EncodeSelectedReadFixture([("a"u8.ToArray(), [2])]);
        var protectedSource = f.Protector.Protect(source); var protectedReplacement = f.Protector.Protect(replacement);
        File.WriteAllBytes(f.StatePath, protectedSource); var changed = false;
        using var candidateProtector = f.NewProtector();
        candidateProtector.AfterProtect = () => { changed = true; File.WriteAllBytes(f.StatePath, protectedReplacement); };
        try
        {
            await Assert.ThrowsAnyAsync<CryptographicException>(() => JournaledDeepSecureStorage.EnrollAggregateAsync(f.StatePath, candidateProtector));
            Assert.True(changed); Assert.Equal(protectedReplacement, File.ReadAllBytes(f.StatePath));
        }
        finally { candidateProtector.AfterProtect = null; CryptographicOperations.ZeroMemory(source); CryptographicOperations.ZeroMemory(replacement); }
    }

    [Fact]
    public async Task Dss2MutationRejoinsActualGuardAfterProtectEvenWhenReplacementManifestAuthenticates()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 })]);
        var predecessor = File.ReadAllBytes(f.StatePath);
        var oldObject = Assert.Single(Dss2ReadEntries(f)); var oldPath = Dss2ObjectPath(f, oldObject); var oldBytes = File.ReadAllBytes(oldPath);
        Assert.True(await f.Store.CompareExchangeAsync("a", new byte[] { 1 }, new byte[] { 2 }));
        // An authentic older manifest is still not the exact actual CAS source.
        // Restoring it here is fault injection, never an owner recovery path.
        var changed = false;
        f.Protector.AfterProtect = () => { changed = true; File.WriteAllBytes(oldPath, oldBytes); File.WriteAllBytes(f.StatePath, predecessor); };
        try
        {
            await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.CompareExchangeAsync("a", new byte[] { 2 }, new byte[] { 3 }));
            Assert.True(changed); Assert.Equal(predecessor, File.ReadAllBytes(f.StatePath));
        }
        finally { f.Protector.AfterProtect = null; }
    }

    [Fact]
    public async Task Dss2CreationCannotOverwriteRootMaterializedDuringFinalProtectorAdmission()
    {
        using var f = new Fixture(false); using var candidateProtector = f.NewProtector();
        byte[]? appearedRoot = null;
        using var boundary = JournaledDeepSecureStorageTestHooks.PushCallbackOnce(JournaledDeepSecureStorageFailpoint.BeforeCreationPolicyAdmission, () =>
        {
            candidateProtector.AfterUnprotect = () =>
            {
                candidateProtector.AfterUnprotect = null;
                var plaintext = candidateProtector.LastUnprotected!.ToArray();
                try { appearedRoot = f.Protector.Protect(plaintext); File.WriteAllBytes(f.StatePath, appearedRoot); }
                finally { CryptographicOperations.ZeroMemory(plaintext); }
            };
        });
        try
        {
            await Assert.ThrowsAnyAsync<CryptographicException>(() => JournaledDeepSecureStorage.CreateNewAsync(f.StatePath, candidateProtector));
            Assert.True(boundary.Reached); Assert.NotNull(appearedRoot);
            Assert.Equal(appearedRoot, File.ReadAllBytes(f.StatePath));
        }
        finally { candidateProtector.AfterUnprotect = null; }
    }

    [Fact]
    public async Task Dss2EnrollmentResumeRejectsUntrackedObjectWithoutDeletingIt()
    {
        using var f = new Fixture(false);
        var source = EncodeSelectedReadFixture([("a"u8.ToArray(), [1]), ("z"u8.ToArray(), [9])]);
        var exact = f.Protector.Protect(source); File.WriteAllBytes(f.StatePath, exact);
        try
        {
            using var firstProtector = f.NewProtector();
            using var crash = JournaledDeepSecureStorageTestHooks.PushCrashOnce(JournaledDeepSecureStorageFailpoint.AfterObjectStaged);
            await Assert.ThrowsAsync<IOException>(() => JournaledDeepSecureStorage.EnrollAggregateAsync(f.StatePath, firstProtector));
            Assert.True(crash.Reached); Assert.True(File.Exists(f.StatePath + ".pending"));
            string unknownPath;
            do { unknownPath = Path.Combine(f.StatePath + ".objects", Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)) + ".dvo"); }
            while (File.Exists(unknownPath));
            byte[] unknown = [0x71, 0x72, 0x73]; File.WriteAllBytes(unknownPath, unknown); var cleanupReached = 0;
            using var resumeProtector = f.NewProtector();
            using (JournaledDeepSecureStorageTestHooks.PushCallbackOnce(JournaledDeepSecureStorageFailpoint.AfterRetirementTombstone, () => cleanupReached++))
                await Assert.ThrowsAnyAsync<CryptographicException>(() => JournaledDeepSecureStorage.EnrollAggregateAsync(f.StatePath, resumeProtector));
            Assert.True(cleanupReached > 0); Assert.False(File.Exists(f.StatePath + ".pending"));
            Assert.Equal(exact, File.ReadAllBytes(f.StatePath)); Assert.Equal(unknown, File.ReadAllBytes(unknownPath));
            Assert.Equal(unknownPath, Assert.Single(Directory.GetFiles(f.StatePath + ".objects", "*.dvo")));
        }
        finally { CryptographicOperations.ZeroMemory(source); }
    }

    [WindowsStorageFact]
    public async Task Dss2RetirementRetryRejectsChangedTombstoneAndRetainsCleanupObligation()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("foreign", new byte[] { 9 })]);
        var retired = Dss2ReadEntries(f).Single(entry => entry.Slot == "a");
        var path = Dss2ObjectPath(f, retired); var original = File.ReadAllBytes(path); var tombstone = path + ".tombstone";
        var retryReached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var admissions = 0;
        using var cancelled = new CancellationTokenSource();
        var blocker = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        f.Protector.AfterUnprotect = () =>
        {
            // Two fresh current-policy reads while the zero source exists
            // prove the real MoveFileEx sharing failure crossed a retry wait.
            if (File.Exists(tombstone) && Interlocked.Increment(ref admissions) == 2)
            { File.WriteAllBytes(tombstone, new byte[] { 7, 8, 9 }); retryReached.TrySetResult(); }
        };
        var deletion = Task.Run(() => f.Store.DeleteBatchAsync(["a"], cancelled.Token));
        try
        {
            await retryReached.Task.WaitAsync(TimeSpan.FromSeconds(10)); blocker.Dispose();
            await Assert.ThrowsAnyAsync<CryptographicException>(() => deletion.WaitAsync(TimeSpan.FromSeconds(10)));
            Assert.True(admissions >= 2); Assert.Equal(original, File.ReadAllBytes(path));
            Assert.Equal(new byte[] { 7, 8, 9 }, File.ReadAllBytes(tombstone));
            var manifest = f.Protector.Unprotect(File.ReadAllBytes(f.StatePath));
            try { Assert.Equal(1U, BinaryPrimitives.ReadUInt32BigEndian(manifest.AsSpan(84))); Assert.DoesNotContain(Dss2Entries(manifest), entry => entry.Slot == "a"); }
            finally { CryptographicOperations.ZeroMemory(manifest); }
        }
        finally
        {
            f.Protector.AfterUnprotect = null; cancelled.Cancel(); blocker.Dispose();
            try { await deletion.WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (OperationCanceledException) { }
            catch (CryptographicException) { }
            catch (System.ComponentModel.Win32Exception) { }
        }
    }

    [WindowsStorageFact]
    public async Task Dss2LocalApplicationDataCreateEnrollAndReopenKeepExactValues()
    {
        // The real LocalApplicationData namespace is important: packaged
        // Windows hosts may resolve it to a physical parent different from
        // its lexical path. An unpackaged host proves only its own binding.
        using (var created = new Fixture(true, localApplicationData: true))
        {
            await created.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("foreign", new byte[] { 9 })]);
            using var reopened = created.OpenJournaled();
            using var current = await reopened.ReadOwnedBatchAsync(["foreign", "a", "absent"]);
            Assert.Equal(9, current[0]!.Use(value => value[0])); Assert.Equal(1, current[1]!.Use(value => value[0])); Assert.Null(current[2]);
            Assert.True(await reopened.CompareExchangeAsync("a", new byte[] { 1 }, new byte[] { 2 }));
            await reopened.AuditAsync();
        }
        using var enrolled = new Fixture(false, localApplicationData: true);
        var source = EncodeSelectedReadFixture([("a"u8.ToArray(), [3]), ("z"u8.ToArray(), [7])]);
        try
        {
            File.WriteAllBytes(enrolled.StatePath, enrolled.Protector.Protect(source));
            using (var adopted = await JournaledDeepSecureStorage.EnrollAggregateAsync(enrolled.StatePath, enrolled.NewProtector()))
            {
                using var selected = await adopted.ReadOwnedBatchAsync(["z", "a"]);
                Assert.Equal(7, selected[0]!.Use(value => value[0])); Assert.Equal(3, selected[1]!.Use(value => value[0]));
            }
            using var reopened = enrolled.OpenJournaled(); using var actual = await reopened.ReadOwnedAsync("a");
            Assert.Equal(3, actual!.Use(value => value[0])); await reopened.AuditAsync();
        }
        finally { CryptographicOperations.ZeroMemory(source); }
    }

    [WindowsStorageFact]
    public async Task Dss2OpenedPathRejectsSameLeafUnderAnotherExistingCanonicalParent()
    {
        using var actual = new Fixture(false, localApplicationData: true);
        using var other = new Fixture(false, localApplicationData: true);
        File.WriteAllBytes(actual.StatePath, new byte[] { 1 }); File.WriteAllBytes(other.StatePath, new byte[] { 9 });
        Assert.Equal(Path.GetFileName(actual.StatePath), Path.GetFileName(other.StatePath));
        var require = typeof(JournaledDeepSecureStorage).GetMethod("RequireOpenedPath", BindingFlags.NonPublic | BindingFlags.Static)!
            .CreateDelegate<Action<SafeFileHandle, string>>();
        using var file = new FileStream(actual.StatePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        require(file.SafeFileHandle, actual.StatePath); // A real existing-parent positive, not only a refusal witness.
        Assert.Throws<CryptographicException>(() => require(file.SafeFileHandle, other.StatePath));
        // Exercise the optimized instance branch under a real acquired lease,
        // rather than relying only on the standalone static path validator.
        using var owner = actual.OpenJournaled();
        var begin = typeof(JournaledDeepSecureStorage).GetMethod("BeginOperationAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var acquiring = (Task)begin.Invoke(owner, [CancellationToken.None])!; await acquiring;
        using var operation = (IDisposable)acquiring.GetType().GetProperty("Result")!.GetValue(acquiring)!;
        var requireOwned = typeof(JournaledDeepSecureStorage).GetMethod("RequireOwnedOpenedPath", BindingFlags.NonPublic | BindingFlags.Instance)!
            .CreateDelegate<Action<SafeFileHandle, string>>(owner);
        requireOwned(file.SafeFileHandle, actual.StatePath);
        Assert.Throws<CryptographicException>(() => requireOwned(file.SafeFileHandle, other.StatePath));
        requireOwned(file.SafeFileHandle, actual.StatePath); // The refusal grants no authority for another parent.
        Assert.Equal(new byte[] { 1 }, File.ReadAllBytes(actual.StatePath)); Assert.Equal(new byte[] { 9 }, File.ReadAllBytes(other.StatePath));
    }

    [WindowsStorageFact]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public void Dss2WindowsHandlePathGrowsForActualLongPathAndStillRejectsWrongParent()
    {
        using var f = new Fixture(false);
        var parent = Path.Combine(Path.GetDirectoryName(f.StatePath)!, new string('a', 160), new string('b', 160), new string('c', 160));
        var otherParent = Path.Combine(parent, "other");
        static string Extended(string value) => value.StartsWith("\\\\?\\", StringComparison.Ordinal) ? value :
            value.StartsWith("\\\\", StringComparison.Ordinal) ? "\\\\?\\UNC\\" + value[2..] : "\\\\?\\" + value;
        Directory.CreateDirectory(Extended(otherParent));
        var actual = Extended(Path.Combine(parent, "bound.bin")); var other = Extended(Path.Combine(otherParent, "bound.bin"));
        File.WriteAllBytes(actual, new byte[] { 1 }); File.WriteAllBytes(other, new byte[] { 9 });
        using var file = new FileStream(actual, FileMode.Open, FileAccess.Read, FileShare.Read);

        // Actual OS result: a 512-character buffer is insufficient. The large
        // independent reference is test-only, not a replacement storage policy.
        var small = new StringBuilder(512);
        var required = Dss2GetFinalPathNameByHandle(file.SafeFileHandle, small, checked((uint)small.Capacity), 0);
        Assert.InRange(required, 513U, 32768U);
        var reference = new StringBuilder(32768);
        var length = Dss2GetFinalPathNameByHandle(file.SafeFileHandle, reference, checked((uint)reference.Capacity), 0);
        Assert.InRange(length, 513U, 32767U); Assert.Equal(checked((int)length), reference.Length);
        var expected = reference.ToString();
        if (expected.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase)) expected = "\\\\" + expected[8..];
        else if (expected.StartsWith("\\\\?\\", StringComparison.Ordinal)) expected = expected[4..];

        var read = typeof(JournaledDeepSecureStorage).GetMethod("ReadWindowsHandlePath", BindingFlags.NonPublic | BindingFlags.Static)!
            .CreateDelegate<Func<SafeFileHandle, string>>();
        Assert.Equal(expected, read(file.SafeFileHandle));
        var require = typeof(JournaledDeepSecureStorage).GetMethod("RequireOpenedPath", BindingFlags.NonPublic | BindingFlags.Static)!
            .CreateDelegate<Action<SafeFileHandle, string>>();
        require(file.SafeFileHandle, actual);
        Assert.Throws<CryptographicException>(() => require(file.SafeFileHandle, other));
        Assert.Equal(new byte[] { 1 }, File.ReadAllBytes(actual)); Assert.Equal(new byte[] { 9 }, File.ReadAllBytes(other));
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint Dss2GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint length, uint flags);

    [Theory]
    [InlineData("protect")] [InlineData("candidate-unprotect")]
    public async Task Dss2ClosedCleanupRetiresSavedObjectRestoredByCandidateCallbacks(string edge)
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 })]);
        var old = Assert.Single(Dss2ReadEntries(f)); var path = Dss2ObjectPath(f, old); var saved = File.ReadAllBytes(path);
        using (var crash = JournaledDeepSecureStorageTestHooks.PushCrashOnce(JournaledDeepSecureStorageFailpoint.AfterRetirementUnlink))
        {
            await Assert.ThrowsAsync<IOException>(() => f.Store.DeleteBatchAsync(["a"]));
            Assert.True(crash.Reached);
        }
        Assert.False(File.Exists(path));
        using var observer = f.NewProtector(); var restored = false; var protects = 0;
        void Restore()
        { Assert.False(File.Exists(path)); File.WriteAllBytes(path, saved); Assert.Equal(saved, File.ReadAllBytes(path)); restored = true; }
        if (edge == "protect") f.Protector.AfterProtect = () => { if (++protects == 1) Restore(); };
        else f.Protector.AfterUnprotect = () =>
        {
            if (!restored && BinaryPrimitives.ReadUInt32BigEndian(f.Protector.LastUnprotected!.AsSpan(84)) == 0 &&
                Dss2ObserveCleanupCount(f, observer) != 0) Restore();
        };
        try { using var missing = await f.Store.ReadOwnedAsync("a"); Assert.Null(missing); }
        finally { f.Protector.AfterProtect = null; f.Protector.AfterUnprotect = null; }
        Assert.True(restored); Assert.False(File.Exists(path)); Assert.Equal(0U, Dss2ObserveCleanupCount(f, observer));
    }

    [Fact]
    public async Task Dss2ClosedCleanupReplaysEarlierIdsAfterLaterUnlinkCallback()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("z", new byte[] { 9 })]);
        var old = Dss2ReadEntries(f).OrderBy(entry => entry.Id, StringComparer.Ordinal).ToArray();
        var first = Dss2ObjectPath(f, old[0]); var saved = File.ReadAllBytes(first);
        var store = Assert.IsType<JournaledDeepSecureStorage>(f.Store); var before = store.ReadWorkSnapshot();
        using var callback = JournaledDeepSecureStorageTestHooks.PushCallbackOnce(JournaledDeepSecureStorageFailpoint.AfterRetirementUnlink, () =>
        {
            Assert.False(File.Exists(first)); File.WriteAllBytes(first, saved); Assert.Equal(saved, File.ReadAllBytes(first));
        }, occurrence: 2);
        await f.Store.DeleteBatchAsync(["a", "z"]);
        Assert.True(callback.Reached); Assert.Equal(2, callback.SeenOccurrences);
        Assert.Equal(4L, store.ReadWorkSnapshot().CleanupTombstones - before.CleanupTombstones);
        Assert.All(old, entry => Assert.False(File.Exists(Dss2ObjectPath(f, entry))));
        using var observer = f.NewProtector(); Assert.Equal(0U, Dss2ObserveCleanupCount(f, observer));
    }

    [WindowsStorageFact]
    public async Task Dss2ClosedCleanupReplaysEarlierIdsAfterLaterNativeSharingRetry()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("z", new byte[] { 9 })]);
        var old = Dss2ReadEntries(f).OrderBy(entry => entry.Id, StringComparer.Ordinal).ToArray();
        var first = Dss2ObjectPath(f, old[0]); var second = Dss2ObjectPath(f, old[1]); var saved = File.ReadAllBytes(first);
        var store = Assert.IsType<JournaledDeepSecureStorage>(f.Store); var before = store.ReadWorkSnapshot();
        var blocker = new FileStream(second, FileMode.Open, FileAccess.Read, FileShare.ReadWrite); var restored = false;
        f.Protector.AfterUnprotect = () =>
        {
            if (restored || File.Exists(first) || !File.Exists(second + ".tombstone")) return;
            File.WriteAllBytes(first, saved); Assert.Equal(saved, File.ReadAllBytes(first)); restored = true; blocker.Dispose();
        };
        try { await f.Store.DeleteBatchAsync(["a", "z"]).WaitAsync(TimeSpan.FromSeconds(10)); }
        finally { f.Protector.AfterUnprotect = null; blocker.Dispose(); }
        Assert.True(restored); Assert.Equal(3L, store.ReadWorkSnapshot().CleanupTombstones - before.CleanupTombstones);
        Assert.All(old, entry => Assert.False(File.Exists(Dss2ObjectPath(f, entry))));
        using var observer = f.NewProtector(); Assert.Equal(0U, Dss2ObserveCleanupCount(f, observer));
    }

    [Theory]
    [InlineData("delete")] [InlineData("selected")] [InlineData("null")] [InlineData("batch")] [InlineData("audit")]
    public async Task Dss2ClosedCleanupHasNoProviderCallbackAfterObligationsDisappear(string entry)
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("kept", new byte[] { 9 })]);
        var old = Dss2ReadEntries(f).Single(item => item.Slot == "a"); var path = Dss2ObjectPath(f, old); var saved = File.ReadAllBytes(path);
        if (entry != "delete")
        {
            using var crash = JournaledDeepSecureStorageTestHooks.PushCrashOnce(JournaledDeepSecureStorageFailpoint.AfterManifestReplace);
            await Assert.ThrowsAsync<IOException>(() => f.Store.DeleteBatchAsync(["a"])); Assert.True(crash.Reached);
        }
        var originalRoot = File.ReadAllBytes(f.StatePath);
        using var observer = f.NewProtector(); var sawCleanup = false; var callbackAfterClear = false; var providers = 0;
        f.Protector.AfterUnprotect = () =>
        {
            providers++;
            var cleanup = Dss2ObserveCleanupCount(f, observer);
            if (entry == "delete" && !File.ReadAllBytes(f.StatePath).AsSpan().SequenceEqual(originalRoot))
            { callbackAfterClear = true; File.WriteAllBytes(path, saved); }
            if (cleanup != 0) sawCleanup = true;
            else if (sawCleanup) { callbackAfterClear = true; File.WriteAllBytes(path, saved); }
        };
        try
        {
            if (entry == "delete") await f.Store.DeleteBatchAsync(["a"]);
            else if (entry == "audit") await Assert.IsType<JournaledDeepSecureStorage>(f.Store).AuditAsync();
            else if (entry == "batch")
            {
                using var values = await f.Store.ReadOwnedBatchAsync(["a", "kept"]);
                Assert.Null(values[0]); Assert.Equal(9, values[1]!.Use(value => value[0]));
            }
            else
            {
                using var value = await f.Store.ReadOwnedAsync(entry == "null" ? "a" : "kept");
                if (entry == "null") Assert.Null(value); else Assert.Equal(9, value!.Use(bytes => bytes[0]));
            }
        }
        finally { f.Protector.AfterUnprotect = null; }
        Assert.True(providers > 0);
        if (entry != "delete") Assert.True(sawCleanup);
        Assert.False(callbackAfterClear); Assert.False(File.Exists(path));
        Assert.Equal(0U, Dss2ObserveCleanupCount(f, observer));
        using var deleted = await f.Store.ReadOwnedAsync("a"); Assert.Null(deleted);
    }

    [Theory]
    [InlineData("null")] [InlineData("selected")] [InlineData("batch")] [InlineData("all-absent")] [InlineData("audit")]
    public async Task Dss2ClosedReadUsesOneUnprotectAndOneFinalSourceRejoin(string result)
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 })]);
        var store = Assert.IsType<JournaledDeepSecureStorage>(f.Store); var before = store.ReadWorkSnapshot();
        await Dss2ReadResultAsync(store, result, default);
        var after = store.ReadWorkSnapshot();
        Assert.Equal(1L, after.UnprotectCalls - before.UnprotectCalls);
        Assert.Equal(2L, after.ManifestReads - before.ManifestReads);
        Assert.True(f.Protector.LastUnprotected!.AsSpan().IndexOfAnyExcept((byte)0) < 0);
    }

    [Theory]
    [InlineData("null")] [InlineData("selected")] [InlineData("batch")] [InlineData("all-absent")] [InlineData("audit")]
    public async Task Dss2ClosedReadEveryReturnRejectsActualSourceReplacement(string result)
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 })]);
        var changed = File.ReadAllBytes(f.StatePath); changed[^1] ^= 1; var reached = false;
        f.Protector.AfterUnprotect = () => { reached = true; File.WriteAllBytes(f.StatePath, changed); };
        try { await Assert.ThrowsAnyAsync<CryptographicException>(() => Dss2ReadResultAsync(Assert.IsType<JournaledDeepSecureStorage>(f.Store), result, default)); }
        finally { f.Protector.AfterUnprotect = null; }
        Assert.True(reached); Assert.Equal(changed, File.ReadAllBytes(f.StatePath));
        Assert.True(f.Protector.LastUnprotected!.AsSpan().IndexOfAnyExcept((byte)0) < 0);
    }

    [Theory]
    [InlineData("null")] [InlineData("selected")] [InlineData("batch")] [InlineData("all-absent")] [InlineData("audit")]
    public async Task Dss2ClosedReadEveryReturnHonorsCancellationAfterProvider(string result)
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 })]);
        using var cancelled = new CancellationTokenSource(); var original = File.ReadAllBytes(f.StatePath); var reached = false;
        f.Protector.AfterUnprotect = () => { reached = true; cancelled.Cancel(); };
        try { await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Dss2ReadResultAsync(Assert.IsType<JournaledDeepSecureStorage>(f.Store), result, cancelled.Token)); }
        finally { f.Protector.AfterUnprotect = null; }
        Assert.True(reached); Assert.Equal(original, File.ReadAllBytes(f.StatePath));
        Assert.True(f.Protector.LastUnprotected!.AsSpan().IndexOfAnyExcept((byte)0) < 0);
    }

    [Fact]
    public async Task Dss2ClosedReadFailedFinalFenceDoesNotConsumeColdAudit()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("z", new byte[] { 9 })]);
        var replacement = f.Protector.Unprotect(File.ReadAllBytes(f.StatePath));
        try
        {
            var second = Dss2Entries(replacement)[1]; var id = RandomNumberGenerator.GetBytes(32);
            id.CopyTo(replacement, second.IdOffset); var invalidObject = new byte[113];
            RandomNumberGenerator.Fill(invalidObject);
            File.WriteAllBytes(Path.Combine(f.StatePath + ".objects", Convert.ToHexStringLower(id) + ".dvo"), invalidObject);
            SHA256.HashData(invalidObject).CopyTo(replacement, second.HashOffset);
            var changed = f.Protector.Protect(replacement); using var coldProtector = f.NewProtector();
            using var cold = new JournaledDeepSecureStorage(f.StatePath, coldProtector); var reached = false;
            coldProtector.AfterUnprotect = () => { reached = true; File.WriteAllBytes(f.StatePath, changed); };
            var before = cold.ReadWorkSnapshot();
            try
            {
                var error = await Assert.ThrowsAnyAsync<CryptographicException>(() => cold.ReadOwnedAsync("a"));
                Assert.Contains("changed", error.Message, StringComparison.OrdinalIgnoreCase);
            }
            finally { coldProtector.AfterUnprotect = null; }
            Assert.True(reached);
            Assert.True(cold.ReadWorkSnapshot().ObjectPlaintextBytesDecrypted - before.ObjectPlaintextBytesDecrypted >= 2);
            // The old inventory's complete object audit succeeded. Only its
            // final source fence failed; a new selected read must audit again.
            await Assert.ThrowsAnyAsync<CryptographicException>(() => cold.ReadOwnedAsync("a"));
        }
        finally { CryptographicOperations.ZeroMemory(replacement); }
    }

    [Fact]
    public async Task Dss2ClosedMutationAdmissionsDoNotScaleWithObjectCount()
    {
        var inserts = new List<int>(); var deletes = new List<int>();
        var registrations = new List<int>(); var guardedDeletes = new List<int>();
        foreach (var count in new[] { 1, 3, 18 })
        {
            using var f = new Fixture(true); var store = Assert.IsType<JournaledDeepSecureStorage>(f.Store);
            var writes = Enumerable.Range(0, count).Select(index => new DeepSecureStorageWrite("value-" + index, new byte[] { 1 })).ToArray();
            var before = store.ReadWorkSnapshot(); var calls = f.Protector.UnprotectCalls;
            await f.Store.WriteBatchAsync(writes); inserts.Add(f.Protector.UnprotectCalls - calls);
            Assert.Equal((long)count, store.ReadWorkSnapshot().ObjectWrites - before.ObjectWrites);
            Assert.Equal(count, Dss2ReadEntries(f).Count);
            before = store.ReadWorkSnapshot(); calls = f.Protector.UnprotectCalls;
            await f.Store.DeleteBatchAsync(writes.Select(write => write.Slot).ToArray()); deletes.Add(f.Protector.UnprotectCalls - calls);
            Assert.Equal((long)count, store.ReadWorkSnapshot().CleanupTombstones - before.CleanupTombstones);
            Assert.Empty(Directory.GetFiles(f.StatePath + ".objects", "*.dvo"));
            await f.Store.WriteBatchAsync([new("guard", new byte[] { 1 }), new("foreign", new byte[] { 9 })]);
            before = store.ReadWorkSnapshot(); calls = f.Protector.UnprotectCalls;
            Assert.True(await f.Store.CompareExchangeAndInsertAsync("guard", new byte[] { 1 }, new byte[] { 2 }, writes));
            registrations.Add(f.Protector.UnprotectCalls - calls);
            // New values plus the guard replacement and its empty tombstone.
            Assert.Equal((long)count + 2, store.ReadWorkSnapshot().ObjectWrites - before.ObjectWrites);
            Assert.Equal(1L, store.ReadWorkSnapshot().CleanupTombstones - before.CleanupTombstones);
            before = store.ReadWorkSnapshot(); calls = f.Protector.UnprotectCalls;
            Assert.True(await f.Store.CompareAndDeleteAsync("guard", new byte[] { 2 }, writes.Select(write => write.Slot).ToArray()));
            guardedDeletes.Add(f.Protector.UnprotectCalls - calls);
            Assert.Equal((long)count, store.ReadWorkSnapshot().CleanupTombstones - before.CleanupTombstones);
            using var kept = await f.Store.ReadOwnedBatchAsync(["guard", "foreign"]);
            Assert.Equal(2, kept[0]!.Use(value => value[0])); Assert.Equal(9, kept[1]!.Use(value => value[0]));
        }
        Assert.True(inserts[0] > 0); Assert.True(deletes[0] > 0);
        Assert.All(inserts, calls => Assert.Equal(inserts[0], calls)); Assert.All(deletes, calls => Assert.Equal(deletes[0], calls));
        Assert.True(registrations[0] > 0); Assert.True(guardedDeletes[0] > 0);
        Assert.All(registrations, calls => Assert.Equal(registrations[0], calls));
        Assert.All(guardedDeletes, calls => Assert.Equal(guardedDeletes[0], calls));
    }

    [Fact]
    public async Task Dss2ClosedMutationRejectsActualStagedObjectTamperAfterCallback()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("guard", new byte[] { 1 })]);
        var before = File.ReadAllBytes(f.StatePath);
        var existing = Directory.GetFiles(f.StatePath + ".objects", "*.dvo").ToHashSet(StringComparer.OrdinalIgnoreCase);
        using var callback = JournaledDeepSecureStorageTestHooks.PushCallbackOnce(JournaledDeepSecureStorageFailpoint.AfterObjectStaged, () =>
        {
            var staged = Assert.Single(Directory.GetFiles(f.StatePath + ".objects", "*.dvo"), path => !existing.Contains(path));
            var changed = File.ReadAllBytes(staged); changed[^1] ^= 1; File.WriteAllBytes(staged, changed);
            Assert.Equal(changed, File.ReadAllBytes(staged));
        });
        await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.WriteBatchAsync(
            [new("new-1", new byte[] { 2 }), new("new-2", new byte[] { 3 }), new("new-3", new byte[] { 4 })]));
        Assert.True(callback.Reached); Assert.Equal(before, File.ReadAllBytes(f.StatePath));
        using var reopened = f.OpenJournaled(); using var guard = await reopened.ReadOwnedAsync("guard");
        Assert.Equal(1, guard!.Use(bytes => bytes[0]));
        using var absent = await reopened.ReadOwnedAsync("new-1"); Assert.Null(absent);
    }

    [Fact]
    public async Task Dss2ClosedMutationRejectsNinthImmediateCallbackBeforeInvocation()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("guard", new byte[] { 1 })]);
        var original = File.ReadAllBytes(f.StatePath); var callbacks = 0; var registrations = new List<IDisposable>();
        Action invalidate = null!;
        invalidate = () =>
        {
            callbacks++;
            registrations.Add(JournaledDeepSecureStorageTestHooks.PushCallbackOnce(JournaledDeepSecureStorageFailpoint.BeforeManifestReplace, invalidate));
        };
        registrations.Add(JournaledDeepSecureStorageTestHooks.PushCallbackOnce(JournaledDeepSecureStorageFailpoint.BeforeManifestReplace, invalidate));
        try
        {
            var error = await Assert.ThrowsAsync<IOException>(() => f.Store.CompareExchangeAsync("guard", new byte[] { 1 }, new byte[] { 2 }));
            Assert.Equal("Protected storage callback invalidation budget exhausted.", error.Message);
            Assert.Equal(8, callbacks); Assert.Equal(original, File.ReadAllBytes(f.StatePath));
        }
        finally { for (var index = registrations.Count - 1; index >= 0; index--) registrations[index].Dispose(); }
        using var reopened = f.OpenJournaled(); using var guard = await reopened.ReadOwnedAsync("guard");
        Assert.Equal(1, guard!.Use(bytes => bytes[0]));
    }

    private static async Task Dss2ReadResultAsync(JournaledDeepSecureStorage store, string result, CancellationToken ct)
    {
        if (result == "audit") { await store.AuditAsync(ct); return; }
        if (result is "null" or "selected")
        {
            using var value = await store.ReadOwnedAsync(result == "null" ? "absent" : "a", ct);
            if (result == "null") Assert.Null(value); else Assert.Equal(1, value!.Use(bytes => bytes[0]));
            return;
        }
        using var batch = await store.ReadOwnedBatchAsync(result == "all-absent" ? ["absent", "another-absent"] : ["absent", "a"], ct);
        Assert.Null(batch[0]);
        if (result == "all-absent") Assert.Null(batch[1]); else Assert.Equal(1, batch[1]!.Use(bytes => bytes[0]));
    }

    private static uint Dss2ObserveCleanupCount(Fixture f, Protector observer)
    {
        var manifest = observer.Unprotect(File.ReadAllBytes(f.StatePath));
        try { return BinaryPrimitives.ReadUInt32BigEndian(manifest.AsSpan(84)); }
        finally { CryptographicOperations.ZeroMemory(manifest); }
    }

    private sealed record Dss2Entry(string Slot, string Id, int SlotOffset, int IdOffset, int LengthOffset, int HashOffset);

    private static List<Dss2Entry> Dss2ReadEntries(Fixture f)
    {
        var plaintext = f.Protector.Unprotect(File.ReadAllBytes(f.StatePath));
        try { return Dss2Entries(plaintext); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static List<Dss2Entry> Dss2Entries(byte[] plaintext)
    {
        Assert.True(plaintext.AsSpan(0, 4).SequenceEqual("DSS2"u8));
        var count = BinaryPrimitives.ReadUInt32BigEndian(plaintext.AsSpan(80)); var offset = 96;
        var result = new List<Dss2Entry>();
        for (var index = 0U; index < count; index++)
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(plaintext.AsSpan(offset)); offset += 2;
            var slotOffset = offset; var slot = Encoding.UTF8.GetString(plaintext, offset, length); offset += length;
            var idOffset = offset; var id = Convert.ToHexStringLower(plaintext.AsSpan(offset, 32));
            result.Add(new(slot, id, slotOffset, idOffset, offset + 40, offset + 48)); offset += 112;
        }
        return result;
    }

    private static string Dss2ObjectPath(Fixture f, Dss2Entry entry) => Path.Combine(f.StatePath + ".objects", entry.Id + ".dvo");
}
