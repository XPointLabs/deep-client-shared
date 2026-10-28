using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Deep.Client.Shared.Persistence;
using Microsoft.Win32.SafeHandles;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class SecureStorageCompareExchangeTests
{
    [WindowsStorageFact]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task Dss2ParentAccessRevocationDuringProtectRejectsBeforeAnyCommitAndPreservesExactAcl()
    {
        using var f = new Fixture(false);
        var statePath = Path.Combine(Path.GetDirectoryName(f.StatePath)!, "owned", "protected.bin");
        using var store = await JournaledDeepSecureStorage.CreateNewAsync(statePath, f.Protector);
        await store.WriteBatchAsync([new("guard", new byte[] { 1 }), new("foreign", new byte[] { 9 })]);
        var originalRoot = File.ReadAllBytes(statePath);
        var objectPaths = Directory.GetFiles(statePath + ".objects", "*.dvo").Order(StringComparer.Ordinal).ToArray();
        var directory = new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(statePath))!);
        using (var parent = Dss2OpenDirectoryAttributes(directory.FullName, 0x80, 7, IntPtr.Zero, 3, 0x00200000 | 0x02000000, IntPtr.Zero))
        using (var leaf = new FileStream(statePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            Assert.False(parent.IsInvalid);
            var resolve = typeof(JournaledDeepSecureStorage).GetMethod("ReadWindowsHandlePath", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
                .CreateDelegate<Func<SafeFileHandle, string>>();
            var actualParent = resolve(parent);
            Assert.Equal(actualParent, Path.GetDirectoryName(resolve(leaf.SafeFileHandle)), ignoreCase: true);
            directory = new DirectoryInfo(actualParent);
        }
        var originalAcl = directory.GetAccessControl(AccessControlSections.Access);
        var originalDescriptor = originalAcl.GetSecurityDescriptorBinaryForm();
        var originalSddl = originalAcl.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        var container = directory.Parent!; // The unique fixture-owned directory, never the shared temp parent.
        var containerAcl = container.GetAccessControl(AccessControlSections.Access);
        var containerDescriptor = containerAcl.GetSecurityDescriptorBinaryForm();
        var containerSddl = containerAcl.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        using var identity = WindowsIdentity.GetCurrent(); var user = identity.User!;
        var denied = new DirectorySecurity(); denied.SetSecurityDescriptorBinaryForm(originalDescriptor, AccessControlSections.Access);
        denied.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.ReadAttributes, AccessControlType.Deny));
        var containerDenied = new DirectorySecurity(); containerDenied.SetSecurityDescriptorBinaryForm(containerDescriptor, AccessControlSections.Access);
        containerDenied.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.ListDirectory, AccessControlType.Deny));
        var reached = false;
        f.Protector.AfterProtect = () =>
        {
            f.Protector.AfterProtect = null;
            directory.SetAccessControl(denied); container.SetAccessControl(containerDenied); reached = true;
            // Prove that the real OS rejects the same metadata access used by
            // directory admission. Windows also grants attributes through the
            // containing directory's LIST_DIRECTORY, so deny that fallback only
            // on our unique fixture container. Both exact ACLs are restored.
            using var refused = Dss2OpenDirectoryAttributes(directory.FullName, 0x80, 7, IntPtr.Zero, 3, 0x00200000 | 0x02000000, IntPtr.Zero);
            var error = Marshal.GetLastPInvokeError();
            Assert.True(refused.IsInvalid); Assert.Equal(5, error);
        };
        try
        {
            var error = await Assert.ThrowsAsync<IOException>(() => store.CompareExchangeAsync("guard", new byte[] { 1 }, new byte[] { 2 }));
            Assert.Equal("Owned storage directory cannot be pinned.", error.Message);
            Assert.Equal(5, Assert.IsType<Win32Exception>(error.InnerException).NativeErrorCode);
            Assert.True(reached);
        }
        finally
        {
            f.Protector.AfterProtect = null;
            var restoredContainer = new DirectorySecurity(); restoredContainer.SetSecurityDescriptorBinaryForm(containerDescriptor, AccessControlSections.Access);
            var restored = new DirectorySecurity(); restored.SetSecurityDescriptorBinaryForm(originalDescriptor, AccessControlSections.Access);
            try { container.SetAccessControl(restoredContainer); }
            finally { directory.SetAccessControl(restored); }
        }
        Assert.Equal(originalSddl, directory.GetAccessControl(AccessControlSections.Access).GetSecurityDescriptorSddlForm(AccessControlSections.Access));
        Assert.Equal(containerSddl, container.GetAccessControl(AccessControlSections.Access).GetSecurityDescriptorSddlForm(AccessControlSections.Access));
        Assert.Equal(originalRoot, File.ReadAllBytes(statePath)); Assert.False(File.Exists(statePath + ".pending"));
        Assert.Equal(objectPaths, Directory.GetFiles(statePath + ".objects", "*.dvo").Order(StringComparer.Ordinal).ToArray());
        using var reopenProtector = f.NewProtector(); using var reopened = new JournaledDeepSecureStorage(statePath, reopenProtector);
        using var current = await reopened.ReadOwnedBatchAsync(["guard", "foreign"]);
        Assert.Equal(1, current[0]!.Use(value => value[0])); Assert.Equal(9, current[1]!.Use(value => value[0]));
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle Dss2OpenDirectoryAttributes(string path, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);

    [Fact]
    public void Dss2CallbackSelectionConsumesOneShotBeforeInvokingCode()
    {
        const JournaledDeepSecureStorageFailpoint selected = JournaledDeepSecureStorageFailpoint.AfterRetirementUnlink;
        var calls = 0;
        using var callback = JournaledDeepSecureStorageTestHooks.PushCallbackOnce(selected, () =>
        {
            calls++;
            if (calls == 1) JournaledDeepSecureStorageTestHooks.Hit(selected);
        }, occurrence: 2);
        JournaledDeepSecureStorageTestHooks.Hit(JournaledDeepSecureStorageFailpoint.AfterObjectStaged);
        JournaledDeepSecureStorageTestHooks.Hit(selected);
        Assert.False(callback.Reached); Assert.Equal(1, callback.SeenOccurrences); Assert.Equal(0, calls);
        JournaledDeepSecureStorageTestHooks.Hit(selected);
        Assert.True(callback.Reached); Assert.Equal(2, callback.SeenOccurrences); Assert.Equal(1, calls);
        JournaledDeepSecureStorageTestHooks.Hit(selected);
        Assert.Equal(2, callback.SeenOccurrences); Assert.Equal(1, calls);
    }

    [Fact]
    public void Dss2FinalCleanupPublicationCannotInvokeAnArbitraryHook()
    {
        var called = false;
        Assert.Throws<ArgumentException>(() => JournaledDeepSecureStorageTestHooks.PushCallbackOnce(
            JournaledDeepSecureStorageFailpoint.AfterCleanupManifest, () => called = true));
        Assert.False(called);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Dss2ClosedCleanupReplaysEveryIdIncludingAbsentOrEmptyAfterLaterCallback(bool empty)
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("m", new byte[] { 2 }), new("z", new byte[] { 3 })]);
        var old = Dss2ReadEntries(f).OrderBy(entry => entry.Id, StringComparer.Ordinal).ToArray();
        var first = Dss2ObjectPath(f, old[0]); var middle = Dss2ObjectPath(f, old[1]);
        var saved = File.ReadAllBytes(middle);
        var store = Assert.IsType<JournaledDeepSecureStorage>(f.Store); var before = store.ReadWorkSnapshot();
        using var callback = JournaledDeepSecureStorageTestHooks.PushCallbackOnce(
            JournaledDeepSecureStorageFailpoint.AfterRetirementUnlink, () =>
            {
                Assert.All(old, entry => Assert.False(File.Exists(Dss2ObjectPath(f, entry))));
                if (empty) File.WriteAllBytes(first, []);
                File.WriteAllBytes(middle, saved); Assert.Equal(saved, File.ReadAllBytes(middle));
            }, occurrence: 3);
        await f.Store.DeleteBatchAsync(["a", "m", "z"]);
        Assert.True(callback.Reached); Assert.Equal(3, callback.SeenOccurrences);
        Assert.Equal(6L, store.ReadWorkSnapshot().CleanupTombstones - before.CleanupTombstones);
        Assert.All(old, entry => Assert.False(File.Exists(Dss2ObjectPath(f, entry))));
        using var observer = f.NewProtector(); Assert.Equal(0U, Dss2ObserveCleanupCount(f, observer));
    }

    [Theory]
    [InlineData("source")] [InlineData("guard")] [InlineData("policy")]
    public async Task Dss2ClosedStagingReauthenticatesSourceGuardAndPolicyAfterActualHook(string change)
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("guard", new byte[] { 1 })]);
        var original = File.ReadAllBytes(f.StatePath);
        var guard = Assert.Single(Dss2ReadEntries(f)); var guardPath = Dss2ObjectPath(f, guard);
        byte[]? changedSource = null; byte[]? changedGuard = null;
        using var callback = JournaledDeepSecureStorageTestHooks.PushCallbackOnce(
            JournaledDeepSecureStorageFailpoint.AfterObjectStaged, () =>
            {
                if (change == "policy") { f.Protector.FailUnprotect = true; return; }
                if (change == "source")
                {
                    // Authentic bytes with the same complete map still replace
                    // the exact predecessor and cannot authorize this mutation.
                    using var observer = f.NewProtector();
                    var manifest = observer.Unprotect(original);
                    try { changedSource = observer.Protect(manifest); File.WriteAllBytes(f.StatePath, changedSource); }
                    finally { CryptographicOperations.ZeroMemory(manifest); }
                }
                else
                {
                    changedGuard = File.ReadAllBytes(guardPath); changedGuard[^1] ^= 1;
                    File.WriteAllBytes(guardPath, changedGuard);
                }
            });
        try
        {
            await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.CompareExchangeAndInsertAsync(
                "guard", new byte[] { 1 }, new byte[] { 2 }, [new("inserted", new byte[] { 3 })]));
        }
        finally { f.Protector.FailUnprotect = false; }
        Assert.True(callback.Reached);
        Assert.Equal(changedSource ?? original, File.ReadAllBytes(f.StatePath));
        if (changedGuard is not null) Assert.Equal(changedGuard, File.ReadAllBytes(guardPath));
        using var observerAfter = f.NewProtector(); var final = observerAfter.Unprotect(File.ReadAllBytes(f.StatePath));
        try
        {
            Assert.Equal(0U, BinaryPrimitives.ReadUInt32BigEndian(final.AsSpan(84)));
            Assert.Equal(guard.Id, Assert.Single(Dss2Entries(final)).Id);
        }
        finally { CryptographicOperations.ZeroMemory(final); }
    }

    [WindowsStorageFact]
    public async Task Dss2CleanupHookAndLaterNativeSharingWaitUseOneOperationRetryBudget()
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("z", new byte[] { 2 })]);
        var old = Dss2ReadEntries(f).OrderBy(entry => entry.Id, StringComparer.Ordinal).ToArray();
        var laterPath = Dss2ObjectPath(f, old[1]);
        var blocker = new FileStream(laterPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        Task? release = null;
        using var callback = JournaledDeepSecureStorageTestHooks.PushCallbackOnce(
            JournaledDeepSecureStorageFailpoint.AfterRetirementUnlink, () =>
            {
                // The hook starts the operation budget. A per-file reset would
                // survive this later release and incorrectly return success.
                Thread.Sleep(1100);
                release = Task.Run(async () => { await Task.Delay(1300); blocker.Dispose(); });
            });
        try
        {
            var error = await Assert.ThrowsAsync<IOException>(() => f.Store.DeleteBatchAsync(["a", "z"]));
            Assert.Equal("Protected storage operation retry budget exhausted.", error.Message);
            Assert.True(callback.Reached); Assert.NotNull(release);
            using var observer = f.NewProtector(); Assert.Equal(2U, Dss2ObserveCleanupCount(f, observer));
        }
        finally { blocker.Dispose(); if (release is not null) await release; }
        using var reopened = f.OpenJournaled();
        using var missing = await reopened.ReadOwnedBatchAsync(["a", "z"]);
        Assert.Null(missing[0]); Assert.Null(missing[1]);
        Assert.All(old, entry => Assert.False(File.Exists(Dss2ObjectPath(f, entry))));
    }

    [Fact]
    public async Task Dss2RecoveredCleanupAndNewMutationShareTheOutermostFinalBoundary()
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("retired", new byte[] { 1 }), new("guard", new byte[] { 2 })]);
        var old = Dss2ReadEntries(f).Single(entry => entry.Slot == "retired");
        var path = Dss2ObjectPath(f, old); var saved = File.ReadAllBytes(path);
        using (var crash = JournaledDeepSecureStorageTestHooks.PushCrashOnce(JournaledDeepSecureStorageFailpoint.AfterRetirementUnlink))
        {
            await Assert.ThrowsAsync<IOException>(() => f.Store.DeleteBatchAsync(["retired"]));
            Assert.True(crash.Reached);
        }
        Assert.False(File.Exists(path));
        using var observer = f.NewProtector(); var restored = false; var providerAfterClosure = false;
        void Observe()
        {
            if (Dss2ObserveCleanupCount(f, observer) == 0) providerAfterClosure = true;
        }
        f.Protector.AfterProtect = () =>
        {
            Observe();
            if (restored) return;
            Assert.False(File.Exists(path)); File.WriteAllBytes(path, saved);
            Assert.Equal(saved, File.ReadAllBytes(path)); restored = true;
        };
        f.Protector.AfterUnprotect = Observe;
        try { Assert.True(await f.Store.CompareExchangeAsync("guard", new byte[] { 2 }, new byte[] { 3 })); }
        finally { f.Protector.AfterProtect = null; f.Protector.AfterUnprotect = null; }
        Assert.True(restored); Assert.False(providerAfterClosure); Assert.False(File.Exists(path));
        Assert.Equal(0U, Dss2ObserveCleanupCount(f, observer));
        using var current = await f.Store.ReadOwnedBatchAsync(["retired", "guard"]);
        Assert.Null(current[0]); Assert.Equal(3, current[1]!.Use(value => value[0]));
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData("BeforeManifestReplace", false)]
    [InlineData("AfterManifestReplace", true)]
    public async Task Dss2CleanupOverflowPreservesBoundedDurableObligationsAndNeverReportsFalse(string? crashPoint, bool committed)
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("retired", new byte[] { 1 }), new("guard", new byte[] { 2 })]);
        var retired = Dss2ReadEntries(f).Single(entry => entry.Slot == "retired");
        var retiredPath = Dss2ObjectPath(f, retired); var saved = File.ReadAllBytes(retiredPath);
        await f.Store.DeleteBatchAsync(["retired"]);
        Assert.False(File.Exists(retiredPath));
        var cleanup = Dss2InstallMaximumCleanupFixture(f, retired.Id);
        var restored = false;
        f.Protector.AfterProtect = () =>
        {
            if (restored) return;
            Assert.False(File.Exists(retiredPath)); File.WriteAllBytes(retiredPath, saved);
            Assert.Equal(saved, File.ReadAllBytes(retiredPath)); restored = true;
        };
        try
        {
            if (crashPoint is null)
                Assert.True(await f.Store.CompareExchangeAsync("guard", new byte[] { 2 }, new byte[] { 3 }));
            else
            {
                using var crash = JournaledDeepSecureStorageTestHooks.PushCrashOnce(Enum.Parse<JournaledDeepSecureStorageFailpoint>(crashPoint));
                var error = await Assert.ThrowsAsync<IOException>(() => f.Store.CompareExchangeAsync("guard", new byte[] { 2 }, new byte[] { 3 }));
                Assert.Equal("Injected DSS2 crash cutpoint.", error.Message); Assert.True(crash.Reached);
            }
        }
        finally { f.Protector.AfterProtect = null; }
        Assert.True(restored);
        using (var observer = f.NewProtector())
        {
            var count = Dss2ObserveCleanupCount(f, observer);
            // The overflow path first adopts a cleanup-free metadata root.
            // A later pre-primary crash keeps the old logical guard value.
            Assert.Equal(crashPoint is not null && committed ? 1U : 0U, count);
            var plain = observer.Unprotect(File.ReadAllBytes(f.StatePath));
            try { Assert.Single(Dss2Entries(plain)); }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        Assert.All(cleanup, id => Assert.False(File.Exists(Path.Combine(f.StatePath + ".objects", id + ".dvo"))));
        using var reopened = f.OpenJournaled();
        using var current = await reopened.ReadOwnedAsync("guard");
        Assert.Equal(committed ? 3 : 2, current!.Use(value => value[0]));
        Assert.All(cleanup, id => Assert.False(File.Exists(Path.Combine(f.StatePath + ".objects", id + ".dvo"))));
        using var finalObserver = f.NewProtector(); Assert.Equal(0U, Dss2ObserveCleanupCount(f, finalObserver));
    }

    private static string[] Dss2InstallMaximumCleanupFixture(Fixture f, string retiredId)
    {
        // Build one canonical authenticated inventory directly. Absent cleanup
        // names are legal outstanding obligations and must still be retired.
        // This avoids 1,024 independent public mutations in the test setup.
        var exact = File.ReadAllBytes(f.StatePath); var plain = f.Protector.Unprotect(exact);
        try
        {
            Assert.Equal(0U, BinaryPrimitives.ReadUInt32BigEndian(plain.AsSpan(84)));
            var active = Dss2Entries(plain).Select(entry => entry.Id).ToHashSet(StringComparer.Ordinal);
            var names = new HashSet<string>(StringComparer.Ordinal) { retiredId };
            while (names.Count < 1024)
            {
                var id = RandomNumberGenerator.GetBytes(32);
                if (id.AsSpan().IndexOfAnyExcept((byte)0) < 0) continue;
                var name = Convert.ToHexStringLower(id); if (!active.Contains(name)) names.Add(name);
            }
            var ordered = names.Order(StringComparer.Ordinal).ToArray();
            var fixture = new byte[plain.Length + ordered.Length * 32]; plain.CopyTo(fixture, 0);
            try
            {
                BinaryPrimitives.WriteUInt64BigEndian(fixture.AsSpan(40), checked(BinaryPrimitives.ReadUInt64BigEndian(plain.AsSpan(40)) + 1));
                SHA256.HashData(exact).CopyTo(fixture, 48);
                BinaryPrimitives.WriteUInt32BigEndian(fixture.AsSpan(84), 1024);
                for (var index = 0; index < ordered.Length; index++)
                    Convert.FromHexString(ordered[index]).CopyTo(fixture, plain.Length + index * 32);
                File.WriteAllBytes(f.StatePath, f.Protector.Protect(fixture));
            }
            finally { CryptographicOperations.ZeroMemory(fixture); }
            return ordered;
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    [Fact]
    public async Task Dss2AbandonedPendingAndNewMutationPrepareBeforeTheOldDescriptorIsRemoved()
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("guard", new byte[] { 1 })]);
        var active = Assert.Single(Dss2ReadEntries(f)); var activePath = Dss2ObjectPath(f, active);
        using (var crash = JournaledDeepSecureStorageTestHooks.PushCrashOnce(JournaledDeepSecureStorageFailpoint.AfterObjectStaged))
        {
            await Assert.ThrowsAsync<IOException>(() => f.Store.CompareExchangeAndInsertAsync(
                "guard", new byte[] { 1 }, new byte[] { 2 }, [new("orphan", new byte[] { 3 })]));
            Assert.True(crash.Reached);
        }
        var abandonedPath = Assert.Single(Directory.GetFiles(f.StatePath + ".objects", "*.dvo"), path => path != activePath);
        var saved = File.ReadAllBytes(abandonedPath); var oldPending = File.ReadAllBytes(f.StatePath + ".pending");
        var pendingPlain = f.Protector.Unprotect(oldPending); int targetUnlink;
        try
        {
            var stagedIds = Dss2Entries(pendingPlain).Select(entry => entry.Id).Order(StringComparer.Ordinal).ToArray();
            var targetIndex = Array.IndexOf(stagedIds, Path.GetFileNameWithoutExtension(abandonedPath));
            Assert.InRange(targetIndex, 0, stagedIds.Length - 1);
            // Recovery retires each sorted ID's .dvo and .pending names.
            targetUnlink = checked(targetIndex * 2 + 1);
        }
        finally { CryptographicOperations.ZeroMemory(pendingPlain); }
        using (var crash = JournaledDeepSecureStorageTestHooks.PushCrashOnce(
            JournaledDeepSecureStorageFailpoint.AfterRetirementUnlink, occurrence: targetUnlink))
        {
            await Assert.ThrowsAsync<IOException>(() => f.Store.ReadOwnedAsync("guard"));
            Assert.True(crash.Reached); Assert.Equal(targetUnlink, crash.SeenOccurrences);
        }
        Assert.False(File.Exists(abandonedPath)); Assert.Equal(oldPending, File.ReadAllBytes(f.StatePath + ".pending"));
        var restored = false; var callbackAfterDescriptorRemoval = false;
        void Observe()
        {
            if (!File.Exists(f.StatePath + ".pending") || !File.ReadAllBytes(f.StatePath + ".pending").AsSpan().SequenceEqual(oldPending))
                callbackAfterDescriptorRemoval = true;
        }
        f.Protector.AfterProtect = () =>
        {
            Observe();
            if (restored) return;
            Assert.False(File.Exists(abandonedPath)); File.WriteAllBytes(abandonedPath, saved);
            Assert.Equal(saved, File.ReadAllBytes(abandonedPath)); restored = true;
        };
        f.Protector.AfterUnprotect = Observe;
        try { Assert.True(await f.Store.CompareExchangeAsync("guard", new byte[] { 1 }, new byte[] { 4 })); }
        finally { f.Protector.AfterProtect = null; f.Protector.AfterUnprotect = null; }
        Assert.True(restored); Assert.False(callbackAfterDescriptorRemoval); Assert.False(File.Exists(abandonedPath));
        Assert.False(File.Exists(f.StatePath + ".pending"));
        using var reopened = f.OpenJournaled(); using var current = await reopened.ReadOwnedBatchAsync(["guard", "orphan"]);
        Assert.Equal(4, current[0]!.Use(value => value[0])); Assert.Null(current[1]);
    }
}
