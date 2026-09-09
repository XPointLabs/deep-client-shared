using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Reads a bounded provisioning artifact from a protected tree without ever reopening the
/// payload by name. Directory handles fence Windows replacement, while Unix traversal uses
/// openat(2) from already verified parent descriptors.
/// </summary>
internal static class ProtectedMailboxFileReader
{
    private const uint GenericRead = 0x80000000;
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint BackupSemantics = 0x02000000;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint SecurityDescriptorRevision = 1;
    private const int SeFileObject = 1;

    private const int UnixReadOnly = 0;
    private const int LinuxNonBlock = 0x00000800;
    private const int LinuxCloseOnExec = 0x00080000;
    private const int DarwinNonBlock = 0x00000004;
    private const int DarwinCloseOnExec = 0x01000000;
    private const int DarwinGetPath = 50;
    private const int UnixRegularFile = 0x00008000;
    private const int UnixFileTypeMask = 0x0000f000;

    internal static byte[] ReadBounded(
        string protectedRoot,
        string path,
        int maxBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (maxBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxBytes));

        var root = Canonical(protectedRoot);
        var requested = Canonical(path);
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (!IsStrictChild(root, requested, comparison))
            throw Invalid("Protected mailbox input is outside its exact root.");

        var relative = Path.GetRelativePath(root, requested);
        var segments = relative.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0 || segments.Any(static segment =>
                segment is "." or ".." || segment.IndexOf('\0') >= 0))
            throw Invalid("Protected mailbox input path is invalid.");

        if (OperatingSystem.IsWindows())
            return ReadWindows(root, requested, segments, maxBytes);
        if (OperatingSystem.IsLinux() || OperatingSystem.IsAndroid()
            || OperatingSystem.IsMacOS() || OperatingSystem.IsMacCatalyst()
            || OperatingSystem.IsIOS())
            return ReadUnix(root, requested, segments, maxBytes);
        throw new PlatformNotSupportedException(
            "Protected mailbox handle reads require Windows, Linux, Android, macOS, Mac Catalyst, or iOS.");
    }

    [SupportedOSPlatform("windows")]
    private static byte[] ReadWindows(
        string root,
        string requested,
        IReadOnlyList<string> segments,
        int maxBytes)
    {
        if (segments.Any(static segment => segment.Contains(':')))
            throw Invalid("Windows alternate data streams are not accepted.");

        var heldDirectories = new List<(SafeFileHandle Handle, string PhysicalPath)>(
            segments.Count);
        SafeFileHandle? file = null;
        try
        {
            var rootHandle = OpenWindows(
                root, directory: true, ShareRead | ShareWrite);
            var physicalRoot = ValidateWindowsHandle(
                rootHandle, expectedPhysicalPath: null, directory: true);
            heldDirectories.Add((rootHandle, physicalRoot));

            var current = root;
            var physicalCurrent = physicalRoot;
            for (var index = 0; index < segments.Count - 1; index++)
            {
                current = Canonical(Path.Combine(current, segments[index]));
                physicalCurrent = Canonical(Path.Combine(
                    physicalCurrent, segments[index]));
                var directory = OpenWindows(
                    current, directory: true, ShareRead | ShareWrite);
                ValidateWindowsHandle(
                    directory, physicalCurrent, directory: true);
                heldDirectories.Add((directory, physicalCurrent));
            }

            file = OpenWindows(requested, directory: false, ShareRead);
            var physicalRequested = Canonical(Path.Combine(
                physicalRoot, Path.Combine(segments.ToArray())));
            ValidateWindowsHandle(file, physicalRequested, directory: false);
            var bytes = ReadExactBounded(file, maxBytes);
            ValidateWindowsHandle(file, physicalRequested, directory: false);
            foreach (var directory in heldDirectories)
                ValidateWindowsHandle(
                    directory.Handle, directory.PhysicalPath, directory: true);
            return bytes;
        }
        finally
        {
            file?.Dispose();
            for (var index = heldDirectories.Count - 1; index >= 0; index--)
                heldDirectories[index].Handle.Dispose();
        }
    }

    [SupportedOSPlatform("windows")]
    private static SafeFileHandle OpenWindows(
        string path,
        bool directory,
        uint shareMode)
    {
        var handle = CreateFile(
            path,
            GenericRead,
            shareMode,
            IntPtr.Zero,
            OpenExisting,
            OpenReparsePoint | (directory ? BackupSemantics : 0),
            IntPtr.Zero);
        if (!handle.IsInvalid) return handle;
        var error = Marshal.GetLastPInvokeError();
        handle.Dispose();
        throw Win32("Unable to bind protected mailbox input.", error);
    }

    [SupportedOSPlatform("windows")]
    private static string ValidateWindowsHandle(
        SafeFileHandle handle,
        string? expectedPhysicalPath,
        bool directory)
    {
        if (!GetFileInformationByHandle(handle, out var information))
            throw Win32("Unable to inspect protected mailbox input.");
        var attributes = information.FileAttributes;
        if ((attributes & FileAttributeReparsePoint) != 0 ||
            ((attributes & FileAttributeDirectory) != 0) != directory)
            throw Invalid("Protected mailbox input contains a reparse point or wrong object type.");
        var physicalPath = FinalWindowsPath(handle);
        if (expectedPhysicalPath is not null && !string.Equals(
                physicalPath,
                Canonical(expectedPhysicalPath),
                StringComparison.OrdinalIgnoreCase))
            throw Invalid("Protected mailbox handle resolved to a different final path.");
        ValidateWindowsSecurity(handle, directory);
        return physicalPath;
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateWindowsSecurity(
        SafeFileHandle handle,
        bool directory)
    {
        var result = GetSecurityInfo(
            handle,
            SeFileObject,
            OwnerSecurityInformation | DaclSecurityInformation,
            out _, out _, out _, out _, out var descriptor);
        if (result != 0)
            throw Win32("Unable to inspect protected mailbox ACL.", checked((int)result));
        try
        {
            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(
                    descriptor,
                    SecurityDescriptorRevision,
                    OwnerSecurityInformation | DaclSecurityInformation,
                    out var encoded,
                    out _))
                throw Win32("Unable to canonicalize protected mailbox ACL.");
            try
            {
                var sddl = Marshal.PtrToStringUni(encoded)
                    ?? throw Invalid("Protected mailbox ACL is unavailable.");
                var security = new CommonSecurityDescriptor(
                    isContainer: directory,
                    isDS: false,
                    sddl);
                var current = WindowsIdentity.GetCurrent().User
                    ?? throw Invalid("The current Windows identity has no SID.");
                var system = new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid, null);
                var administrators = new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid, null);
                if (security.Owner is not SecurityIdentifier owner ||
                    !current.Equals(owner) ||
                    (security.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 ||
                    !security.IsDiscretionaryAclCanonical ||
                    security.DiscretionaryAcl is null)
                    throw Invalid("Protected mailbox owner or DACL is not exact and protected.");

                var allowed = new Dictionary<string, int>(StringComparer.Ordinal)
                {
                    [current.Value] = 0,
                    [system.Value] = 0,
                    [administrators.Value] = 0
                };
                foreach (GenericAce ace in security.DiscretionaryAcl)
                {
                    if (ace is not CommonAce common ||
                        common.AceQualifier != AceQualifier.AccessAllowed ||
                        (common.AceFlags & AceFlags.Inherited) != 0 ||
                        !allowed.ContainsKey(common.SecurityIdentifier.Value))
                        throw Invalid("Protected mailbox DACL contains a non-allowlisted ACE.");
                    allowed[common.SecurityIdentifier.Value] |= common.AccessMask;
                }

                var fullControl = unchecked((int)FileSystemRights.FullControl);
                if (allowed.Values.Any(mask => (mask & fullControl) != fullControl))
                    throw Invalid(
                        "Current user, SYSTEM, and Administrators require protected full control.");
            }
            finally
            {
                _ = LocalFree(encoded);
            }
        }
        finally
        {
            _ = LocalFree(descriptor);
        }
    }

    [SupportedOSPlatform("windows")]
    private static string FinalWindowsPath(SafeFileHandle handle)
    {
        var buffer = new char[32768];
        var length = GetFinalPathNameByHandle(
            handle, buffer, checked((uint)buffer.Length), 0);
        if (length == 0)
            throw Win32("Unable to resolve protected mailbox handle path.");
        if (length >= buffer.Length)
            throw Invalid("Protected mailbox handle path is too long.");
        return Canonical(new string(buffer, 0, checked((int)length)));
    }

    [UnsupportedOSPlatform("windows")]
    private static byte[] ReadUnix(
        string root,
        string requested,
        IReadOnlyList<string> segments,
        int maxBytes)
    {
        var pathFlags = UnixPathFlags(RuntimeInformation.ProcessArchitecture);
        var closeOnExec = IsDarwin() ? DarwinCloseOnExec : LinuxCloseOnExec;
        var nonBlock = IsDarwin() ? DarwinNonBlock : LinuxNonBlock;
        var handles = new List<SafeFileHandle>(segments.Count + 1);
        try
        {
            var rootHandle = OpenUnix(
                root,
                UnixReadOnly | pathFlags.Directory |
                pathFlags.NoFollow | closeOnExec);
            handles.Add(rootHandle);
            var physicalRoot = ValidateUnixHandle(
                rootHandle, expectedPhysicalPath: null, directory: true);

            var physicalCurrent = physicalRoot;
            var parent = rootHandle;
            for (var index = 0; index < segments.Count - 1; index++)
            {
                physicalCurrent = Canonical(Path.Combine(
                    physicalCurrent, segments[index]));
                var child = OpenAtUnix(
                    parent,
                    segments[index],
                    UnixReadOnly | pathFlags.Directory |
                    pathFlags.NoFollow | closeOnExec);
                handles.Add(child);
                ValidateUnixHandle(child, physicalCurrent, directory: true);
                parent = child;
            }

            var file = OpenAtUnix(
                parent,
                segments[^1],
                UnixReadOnly | nonBlock |
                pathFlags.NoFollow | closeOnExec);
            handles.Add(file);
            var physicalRequested = Canonical(Path.Combine(
                physicalRoot, Path.Combine(segments.ToArray())));
            ValidateUnixHandle(file, physicalRequested, directory: false);
            var bytes = ReadExactBounded(file, maxBytes);
            ValidateUnixHandle(file, physicalRequested, directory: false);
            return bytes;
        }
        finally
        {
            for (var index = handles.Count - 1; index >= 0; index--)
                handles[index].Dispose();
        }
    }

    [UnsupportedOSPlatform("windows")]
    private static SafeFileHandle OpenUnix(string path, int flags)
    {
        var descriptor = Open(path, flags, 0);
        if (descriptor >= 0)
            return new SafeFileHandle(new IntPtr(descriptor), ownsHandle: true);
        throw Win32("Unable to bind protected mailbox input.");
    }

    [UnsupportedOSPlatform("windows")]
    private static SafeFileHandle OpenAtUnix(
        SafeFileHandle parent,
        string segment,
        int flags)
    {
        var descriptor = OpenAt(
            checked((int)parent.DangerousGetHandle()), segment, flags, 0);
        if (descriptor >= 0)
            return new SafeFileHandle(new IntPtr(descriptor), ownsHandle: true);
        throw Win32("Unable to traverse protected mailbox input.");
    }

    [UnsupportedOSPlatform("windows")]
    private static string ValidateUnixHandle(
        SafeFileHandle handle,
        string? expectedPhysicalPath,
        bool directory)
    {
        var descriptor = checked((int)handle.DangerousGetHandle());
        var stat = Marshal.AllocHGlobal(256);
        int nativeMode;
        try
        {
            for (var offset = 0; offset < 256; offset++)
                Marshal.WriteByte(stat, offset, 0);
            if (FStat(descriptor, stat) != 0)
                throw Win32("Unable to inspect protected mailbox input.");
            var (modeOffset, ownerOffset) = IsDarwin()
                ? (4, 16)
                : RuntimeInformation.ProcessArchitecture switch
                {
                    Architecture.X64 => (24, 28),
                    Architecture.Arm64 => (16, 24),
                    _ => throw new PlatformNotSupportedException(
                        "Protected mailbox Unix ownership checks require x64 or arm64.")
                };
            nativeMode = Marshal.ReadInt32(stat, modeOffset);
            var owner = unchecked((uint)Marshal.ReadInt32(stat, ownerOffset));
            if (owner != GetEffectiveUserId())
                throw Invalid("Protected mailbox input is not owned by the current euid.");
            if (!directory && (nativeMode & UnixFileTypeMask) != UnixRegularFile)
                throw Invalid("Protected mailbox input is not a regular file.");
        }
        finally
        {
            Marshal.FreeHGlobal(stat);
        }

        var finalPath = FinalUnixPath(descriptor);
        if (expectedPhysicalPath is not null &&
            !string.Equals(Canonical(finalPath), Canonical(expectedPhysicalPath),
                StringComparison.Ordinal))
            throw Invalid("Protected mailbox descriptor resolved to a different final path.");
        var expectedMode = directory
            ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            : UnixFileMode.UserRead | UnixFileMode.UserWrite;
        if ((UnixFileMode)(nativeMode & 0x1ff) != expectedMode)
            throw Invalid("Protected mailbox modes must be exact directory 0700 and file 0600.");
        return Canonical(finalPath);
    }

    [UnsupportedOSPlatform("windows")]
    private static string FinalUnixPath(int descriptor)
    {
        var buffer = new byte[32 * 1024];
        if (IsDarwin())
        {
            if (Fcntl(descriptor, DarwinGetPath, buffer) != 0)
                throw Win32("Unable to resolve protected mailbox descriptor path.");
            var terminator = Array.IndexOf(buffer, (byte)0);
            if (terminator <= 0)
                throw Invalid("Protected mailbox descriptor path is unavailable.");
            return Encoding.UTF8.GetString(buffer, 0, terminator);
        }
        var length = ReadLink(
            $"/proc/self/fd/{descriptor}", buffer, checked((nuint)buffer.Length));
        if (length < 0)
            throw Win32("Unable to resolve protected mailbox descriptor path.");
        if (length == buffer.Length)
            throw Invalid("Protected mailbox descriptor path is too long.");
        return Encoding.UTF8.GetString(buffer, 0, checked((int)length));
    }

    internal static (int Directory, int NoFollow) UnixPathFlags(
        Architecture architecture)
    {
        if (IsDarwin())
            return (0x00100000, 0x00000100);
        return architecture switch
        {
            // Android's ARM UAPI retains the historical ARM flag assignments,
            // while x64 Linux uses the asm-generic assignments.
            Architecture.Arm or Architecture.Arm64 => (0x00004000, 0x00008000),
            Architecture.X64 => (0x00010000, 0x00020000),
            _ => throw new PlatformNotSupportedException(
                $"Protected mailbox Unix path flags do not support {architecture}.")
        };
    }

    private static bool IsDarwin() =>
        OperatingSystem.IsMacOS() || OperatingSystem.IsMacCatalyst()
        || OperatingSystem.IsIOS();

    private static byte[] ReadExactBounded(SafeFileHandle handle, int maxBytes)
    {
        var length = RandomAccess.GetLength(handle);
        if (length <= 0 || length > maxBytes || length > int.MaxValue)
            throw Invalid("Protected mailbox input size is outside its bound.");
        var bytes = new byte[checked((int)length)];
        var read = 0;
        while (read < bytes.Length)
        {
            var count = RandomAccess.Read(handle, bytes.AsSpan(read), read);
            if (count == 0)
                throw Invalid("Protected mailbox input was truncated during its exact read.");
            read += count;
        }
        Span<byte> extra = stackalloc byte[1];
        if (RandomAccess.Read(handle, extra, length) != 0 ||
            RandomAccess.GetLength(handle) != length)
            throw Invalid("Protected mailbox input changed during its exact read.");
        return bytes;
    }

    private static bool IsStrictChild(
        string root,
        string candidate,
        StringComparison comparison)
    {
        if (string.Equals(root, candidate, comparison)) return false;
        var prefix = root.EndsWith(Path.DirectorySeparatorChar) ||
            root.EndsWith(Path.AltDirectorySeparatorChar)
                ? root
                : root + Path.DirectorySeparatorChar;
        return candidate.StartsWith(prefix, comparison);
    }

    private static string Canonical(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                path = @"\\" + path[8..];
            else if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                path = path[4..];
            if (path.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith(@"GLOBALROOT\", StringComparison.OrdinalIgnoreCase))
                throw Invalid("Windows device paths are not accepted.");
        }
        var full = Path.GetFullPath(path);
        var pathRoot = Path.GetPathRoot(full);
        return string.Equals(
                full,
                pathRoot,
                OperatingSystem.IsWindows()
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal)
            ? full
            : full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static InvalidDataException Invalid(string message) => new(message);

    private static IOException Win32(string message) =>
        Win32(message, Marshal.GetLastPInvokeError());

    private static IOException Win32(string message, int error) =>
        new($"{message} Native error {error}.", new Win32Exception(error));

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

    [SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        [Out] char[] path,
        uint pathLength,
        uint flags);

    [SupportedOSPlatform("windows")]
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(
        SafeFileHandle handle,
        int objectType,
        uint securityInformation,
        out IntPtr owner,
        out IntPtr group,
        out IntPtr dacl,
        out IntPtr sacl,
        out IntPtr securityDescriptor);

    [SupportedOSPlatform("windows")]
    [DllImport("advapi32.dll", EntryPoint =
        "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
        IntPtr securityDescriptor,
        uint requestedRevision,
        uint securityInformation,
        out IntPtr stringSecurityDescriptor,
        out uint stringSecurityDescriptorLength);

    [SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [UnsupportedOSPlatform("windows")]
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags, uint mode);

    [UnsupportedOSPlatform("windows")]
    [DllImport("libc", EntryPoint = "openat", SetLastError = true)]
    private static extern int OpenAt(int directory, string path, int flags, uint mode);

    [UnsupportedOSPlatform("windows")]
    [DllImport("libc", EntryPoint = "fstat", SetLastError = true)]
    private static extern int FStat(int descriptor, IntPtr stat);

    [UnsupportedOSPlatform("windows")]
    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();

    [UnsupportedOSPlatform("windows")]
    [DllImport("libc", EntryPoint = "readlink", SetLastError = true)]
    private static extern nint ReadLink(string path, byte[] buffer, nuint size);

    [DllImport("libc", EntryPoint = "fcntl", SetLastError = true)]
    private static extern int Fcntl(int descriptor, int command, byte[] buffer);
}
