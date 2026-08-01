using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class ProtectedMailboxFileReaderTests
{
    [Fact]
    [UnsupportedOSPlatform("windows")]
    public void Unix_protected_file_is_read_from_openat_handle()
    {
        if (!(OperatingSystem.IsLinux() || OperatingSystem.IsAndroid())) return;
        using var fixture = UnixFixture.Create();
        var directory = fixture.ProtectedDirectory("generation");
        var path = fixture.ProtectedFile(directory, "bundle.json", [7, 8, 9]);

        Assert.Equal(
            new byte[] { 7, 8, 9 },
            ProtectedMailboxFileReader.ReadBounded(fixture.Root, path, 3));
    }

    [Fact]
    [UnsupportedOSPlatform("windows")]
    public void Unix_weak_mode_and_intermediate_symlink_are_rejected()
    {
        if (!(OperatingSystem.IsLinux() || OperatingSystem.IsAndroid())) return;
        using var fixture = UnixFixture.Create();
        var weak = Path.Combine(fixture.Root, "weak.json");
        File.WriteAllBytes(weak, [0x31]);
        File.SetUnixFileMode(
            weak,
            UnixFileMode.UserRead | UnixFileMode.UserWrite |
            UnixFileMode.GroupRead);
        Assert.Throws<InvalidDataException>(() =>
            ProtectedMailboxFileReader.ReadBounded(fixture.Root, weak, 1));

        var outside = fixture.OutsideDirectory("outside-generation");
        _ = fixture.ProtectedFile(outside, "bundle.json", [0x32]);
        var link = Path.Combine(fixture.Root, "linked-generation");
        Directory.CreateSymbolicLink(link, outside);
        Assert.ThrowsAny<Exception>(() =>
            ProtectedMailboxFileReader.ReadBounded(
                fixture.Root, Path.Combine(link, "bundle.json"), 1));
    }

    [Fact]
    [UnsupportedOSPlatform("windows")]
    public void Unix_empty_file_is_rejected()
    {
        if (!(OperatingSystem.IsLinux() || OperatingSystem.IsAndroid())) return;
        using var fixture = UnixFixture.Create();
        var path = fixture.ProtectedFile(fixture.Root, "empty.json", []);

        Assert.Throws<InvalidDataException>(() =>
            ProtectedMailboxFileReader.ReadBounded(fixture.Root, path, 1));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void Windows_protected_file_is_read_from_its_exact_handle()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = WindowsFixture.Create();
        var directory = fixture.ProtectedDirectory("generation");
        var path = fixture.ProtectedFile(directory, "bundle.json", [1, 2, 3, 4]);

        var actual = ProtectedMailboxFileReader.ReadBounded(
            fixture.Root, path, maxBytes: 4);

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, actual);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void Windows_inherited_or_weak_file_dacl_is_rejected()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = WindowsFixture.Create();
        var path = Path.Combine(fixture.Root, "weak.json");
        File.WriteAllBytes(path, [0x41]);

        Assert.Throws<InvalidDataException>(() =>
            ProtectedMailboxFileReader.ReadBounded(fixture.Root, path, 1));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void Windows_final_symbolic_link_is_rejected_when_privilege_is_available()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = WindowsFixture.Create();
        var target = fixture.OutsideFile("target.json", [0x42]);
        var link = Path.Combine(fixture.Root, "linked.json");
        try
        {
            File.CreateSymbolicLink(link, target);
        }
        catch (Exception exception) when (exception is
            UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return;
        }

        Assert.ThrowsAny<Exception>(() =>
            ProtectedMailboxFileReader.ReadBounded(fixture.Root, link, 1));
        Assert.Equal(new byte[] { 0x42 }, File.ReadAllBytes(target));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void Windows_intermediate_junction_escape_is_rejected_when_available()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = WindowsFixture.Create();
        var outsideDirectory = fixture.OutsideDirectory("outside-generation");
        var outside = fixture.ProtectedFile(
            outsideDirectory, "bundle.json", [0x51]);
        var junction = Path.Combine(fixture.Root, "junction");
        if (!TryCreateJunction(junction, outsideDirectory)) return;

        Assert.ThrowsAny<Exception>(() =>
            ProtectedMailboxFileReader.ReadBounded(
                fixture.Root,
                Path.Combine(junction, "bundle.json"),
                1));
        Assert.Equal(new byte[] { 0x51 }, File.ReadAllBytes(outside));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void Windows_bound_is_enforced_on_the_opened_file()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = WindowsFixture.Create();
        var path = fixture.ProtectedFile(
            fixture.Root, "oversized.json", [0x61, 0x62]);

        Assert.Throws<InvalidDataException>(() =>
            ProtectedMailboxFileReader.ReadBounded(fixture.Root, path, 1));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void Windows_empty_file_is_rejected()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = WindowsFixture.Create();
        var path = fixture.ProtectedFile(fixture.Root, "empty.json", []);

        Assert.Throws<InvalidDataException>(() =>
            ProtectedMailboxFileReader.ReadBounded(fixture.Root, path, 1));
    }

    private static bool TryCreateJunction(string junction, string target)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/d /c mklink /J \"{junction}\" \"{target}\"",
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        });
        if (process is null) return false;
        process.WaitForExit();
        return process.ExitCode == 0 && Directory.Exists(junction);
    }

    [UnsupportedOSPlatform("windows")]
    private sealed class UnixFixture : IDisposable
    {
        private readonly string owner;
        private UnixFixture(string owner, string root, string outsideRoot)
        {
            this.owner = owner;
            Root = root;
            OutsideRoot = outsideRoot;
        }

        public string Root { get; }
        public string OutsideRoot { get; }

        public static UnixFixture Create()
        {
            var owner = Path.Combine(
                Path.GetTempPath(),
                "deep-protected-reader-" + Guid.NewGuid().ToString("N"));
            var root = Path.Combine(owner, "protected");
            var outside = Path.Combine(owner, "outside");
            Directory.CreateDirectory(root);
            Directory.CreateDirectory(outside);
            ProtectDirectory(root);
            ProtectDirectory(outside);
            return new UnixFixture(owner, root, outside);
        }

        public string ProtectedDirectory(string name)
        {
            var path = Path.Combine(Root, name);
            Directory.CreateDirectory(path);
            ProtectDirectory(path);
            return path;
        }

        public string OutsideDirectory(string name)
        {
            var path = Path.Combine(OutsideRoot, name);
            Directory.CreateDirectory(path);
            ProtectDirectory(path);
            return path;
        }

        public string ProtectedFile(
            string directory,
            string name,
            ReadOnlySpan<byte> bytes)
        {
            var path = Path.Combine(directory, name);
            File.WriteAllBytes(path, bytes);
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
            return path;
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(owner))
                    Directory.Delete(owner, recursive: true);
            }
            catch
            {
            }
        }

        private static void ProtectDirectory(string path) =>
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite |
                UnixFileMode.UserExecute);
    }

    [SupportedOSPlatform("windows")]
    private sealed class WindowsFixture : IDisposable
    {
        private readonly string owner;
        private WindowsFixture(string owner, string root, string outsideRoot)
        {
            this.owner = owner;
            Root = root;
            OutsideRoot = outsideRoot;
        }

        public string Root { get; }
        public string OutsideRoot { get; }

        public static WindowsFixture Create()
        {
            var owner = Path.Combine(
                Path.GetTempPath(),
                "deep-protected-reader-" + Guid.NewGuid().ToString("N"));
            var root = Path.Combine(owner, "protected");
            var outside = Path.Combine(owner, "outside");
            Directory.CreateDirectory(root);
            Directory.CreateDirectory(outside);
            Protect(root, directory: true);
            Protect(outside, directory: true);
            return new WindowsFixture(owner, root, outside);
        }

        public string ProtectedDirectory(string name)
        {
            var path = Path.Combine(Root, name);
            Directory.CreateDirectory(path);
            Protect(path, directory: true);
            return path;
        }

        public string OutsideDirectory(string name)
        {
            var path = Path.Combine(OutsideRoot, name);
            Directory.CreateDirectory(path);
            Protect(path, directory: true);
            return path;
        }

        public string ProtectedFile(
            string directory,
            string name,
            ReadOnlySpan<byte> bytes)
        {
            var path = Path.Combine(directory, name);
            File.WriteAllBytes(path, bytes);
            Protect(path, directory: false);
            return path;
        }

        public string OutsideFile(string name, ReadOnlySpan<byte> bytes) =>
            ProtectedFile(OutsideRoot, name, bytes);

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(owner))
                    Directory.Delete(owner, recursive: true);
            }
            catch
            {
                // Test cleanup is best-effort; assertions never depend on deletion.
            }
        }

        private static void Protect(string path, bool directory)
        {
            var current = WindowsIdentity.GetCurrent().User
                ?? throw new InvalidOperationException(
                    "The current Windows test identity has no SID.");
            var system = new SecurityIdentifier(
                WellKnownSidType.LocalSystemSid, null);
            var administrators = new SecurityIdentifier(
                WellKnownSidType.BuiltinAdministratorsSid, null);
            FileSystemSecurity security = directory
                ? new DirectorySecurity()
                : new FileSecurity();
            security.SetOwner(current);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var sid in new[] { current, system, administrators })
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    sid,
                    FileSystemRights.FullControl,
                    directory
                        ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
                        : InheritanceFlags.None,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }

            if (directory)
                new DirectoryInfo(path).SetAccessControl((DirectorySecurity)security);
            else
                new FileInfo(path).SetAccessControl((FileSecurity)security);
        }
    }
}
