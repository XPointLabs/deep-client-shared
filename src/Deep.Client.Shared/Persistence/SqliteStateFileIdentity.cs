using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Deep.Client.Shared.Persistence;

/// <summary>
/// Stable identity of the opened SQLite file, independent of lexical path aliases.
/// The coordinator uses this key only after schema initialization created the file.
/// </summary>
internal static class SqliteStateFileIdentity
{
    internal static string Resolve(string path)
    {
        using var handle = File.OpenHandle(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            FileOptions.None);
        if (OperatingSystem.IsWindows())
        {
            if (!GetFileInformationByHandle(handle, out var information))
                throw new IOException(
                    "Unable to resolve the SQLite state file identity.",
                    Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
            var index = ((ulong)information.FileIndexHigh << 32) |
                information.FileIndexLow;
            return $"win:{information.VolumeSerialNumber:x8}:{index:x16}";
        }

        if (OperatingSystem.IsLinux() || OperatingSystem.IsAndroid()
            || OperatingSystem.IsMacOS() || OperatingSystem.IsMacCatalyst()
            || OperatingSystem.IsIOS())
        {
            var stat = Marshal.AllocHGlobal(256);
            try
            {
                for (var offset = 0; offset < 256; offset++)
                    Marshal.WriteByte(stat, offset, 0);
                if (FStat(checked((int)handle.DangerousGetHandle()), stat) != 0)
                    throw new IOException(
                        "Unable to resolve the SQLite state file identity.",
                        Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
                var device = OperatingSystem.IsMacOS() || OperatingSystem.IsMacCatalyst()
                    || OperatingSystem.IsIOS()
                    ? unchecked((uint)Marshal.ReadInt32(stat, 0))
                    : unchecked((ulong)Marshal.ReadInt64(stat, 0));
                var inode = unchecked((ulong)Marshal.ReadInt64(stat, 8));
                if (device == 0 || inode == 0)
                    throw new InvalidDataException(
                        "SQLite state file identity is unavailable.");
                return $"unix:{device:x16}:{inode:x16}";
            }
            finally
            {
                Marshal.FreeHGlobal(stat);
            }
        }

        throw new PlatformNotSupportedException(
            "SQLite state identity requires Windows, Linux, Android, macOS, Mac Catalyst, or iOS.");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [DllImport("libc", EntryPoint = "fstat", SetLastError = true)]
    private static extern int FStat(int descriptor, IntPtr stat);
}
