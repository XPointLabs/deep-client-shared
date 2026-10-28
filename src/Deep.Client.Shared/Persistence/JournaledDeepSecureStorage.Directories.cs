using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Deep.Client.Shared.Persistence;

public sealed partial class JournaledDeepSecureStorage
{
    private DirectoryScope? directories;

    private void DropDirectories() { directories?.Dispose(); directories = null; }

    private void RequireNoRedirectedAncestors(string directory)
    {
        if (OperatingSystem.IsWindows() && operation is not null)
        {
            (directories ??= new DirectoryScope()).Get(directory);
            return;
        }
        CheckDirectoryAncestors(directory);
    }

    private static void CheckDirectoryAncestors(string directory)
    {
        for (DirectoryInfo? node = new(directory); node is not null; node = node.Parent)
            if (node.Exists && (node.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException("Secure-storage directory redirection is forbidden.");
    }

    // Windows handles deny delete sharing: a parent (and every logical/physical
    // ancestor) cannot be renamed/replaced while this synchronous segment owns it.
    // Every leaf still joins its own current handle identity and exact handle path.
    private sealed class DirectoryScope : IDisposable
    {
        private readonly Dictionary<string, PinnedDirectory> parents = new(StringComparer.OrdinalIgnoreCase);

        [SupportedOSPlatform("windows")]
        internal PinnedDirectory Get(string directory)
        {
            directory = Path.GetFullPath(directory);
            if (parents.TryGetValue(directory, out var pinned)) { pinned.Check(); return pinned; }
            var ancestor = Path.GetDirectoryName(directory.TrimEnd(Path.DirectorySeparatorChar));
            if (!string.IsNullOrEmpty(ancestor) && !string.Equals(ancestor, directory, StringComparison.OrdinalIgnoreCase)) Get(ancestor);
            var handle = CreateFile(directory, 0x80, 3, IntPtr.Zero, 3, 0x00200000 | 0x02000000, IntPtr.Zero);
            if (handle.IsInvalid)
            { var error = Marshal.GetLastPInvokeError(); handle.Dispose(); throw new IOException("Owned storage directory cannot be pinned.", new Win32Exception(error)); }
            try
            {
                if (!GetFileInformationByHandle(handle, out var identity) ||
                    (identity.FileAttributes & (uint)FileAttributes.Directory) == 0 ||
                    (identity.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
                    throw new CryptographicException("Owned storage directory is redirected.");
                var physical = ReadWindowsHandlePath(handle);
                pinned = new PinnedDirectory(handle, identity, physical);
                parents.Add(directory, pinned); handle = null!;
                // Packaged hosts may map a logical directory to a different
                // physical chain. Pin that chain too; neither prefix nor suffix
                // matching grants permission to a virtualized location.
                if (!string.Equals(directory, physical, StringComparison.OrdinalIgnoreCase))
                    pinned.RequireSameIdentity(Get(physical));
                return pinned;
            }
            finally { handle?.Dispose(); }
        }

        public void Dispose() { foreach (var item in parents.Values) item.Dispose(); parents.Clear(); }
    }

    private sealed class PinnedDirectory(SafeFileHandle handle, FileInformation identity, string physical) : IDisposable
    {
        private FileInformation Identity { get; } = identity;
        internal string Physical { get; } = physical;
        internal uint Volume => Identity.VolumeSerialNumber;
        internal void RequireSameIdentity(PinnedDirectory other)
        {
            if (Identity.VolumeSerialNumber != other.Identity.VolumeSerialNumber ||
                Identity.FileIndexHigh != other.Identity.FileIndexHigh || Identity.FileIndexLow != other.Identity.FileIndexLow)
                throw new CryptographicException("Logical and physical storage directory identities differ.");
        }
        [SupportedOSPlatform("windows")]
        internal void Check()
        {
            if (!GetFileInformationByHandle(handle, out var actual) ||
                actual.VolumeSerialNumber != Identity.VolumeSerialNumber || actual.FileIndexHigh != Identity.FileIndexHigh ||
                actual.FileIndexLow != Identity.FileIndexLow ||
                (actual.FileAttributes & (uint)FileAttributes.Directory) == 0 ||
                (actual.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException("Pinned storage directory identity changed.");
        }
        public void Dispose() => handle.Dispose();
    }
}
