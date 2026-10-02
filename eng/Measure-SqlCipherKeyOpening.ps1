param([Parameter(Mandatory = $true)][string]$NativeLibraryPath)
$ErrorActionPreference = 'Stop'
$resolvedLibrary = (Resolve-Path -LiteralPath $NativeLibraryPath).Path
if ([System.IO.Path]::GetFileName($resolvedLibrary) -ne 'e_sqlcipher.dll') {
    throw 'The approved SQLCipher library file is required.'
}

# Isolated performance diagnostic. No account file, identifier or existing key
# is read. All random keys and their native-key encodings are owned and wiped.
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

public static class DeepSqlCipherKeyOpeningProbe
{
    [DllImport("deep_sqlcipher_key_probe", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_open_v2([MarshalAs(UnmanagedType.LPUTF8Str)] string file, out IntPtr db, int flags, IntPtr vfs);
    [DllImport("deep_sqlcipher_key_probe", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_key(IntPtr db, byte[] key, int length);
    [DllImport("deep_sqlcipher_key_probe", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_exec(IntPtr db, [MarshalAs(UnmanagedType.LPUTF8Str)] string sql, IntPtr callback, IntPtr argument, IntPtr error);
    [DllImport("deep_sqlcipher_key_probe", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_close(IntPtr db);

    public static string Run(string nativeLibrary)
    {
        var library = NativeLibrary.Load(nativeLibrary);
        NativeLibrary.SetDllImportResolver(typeof(DeepSqlCipherKeyOpeningProbe).Assembly,
            (name, assembly, search) => name == "deep_sqlcipher_key_probe" ? library : IntPtr.Zero);
        var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "deep-sqlcipher-key-probe-" + Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(root);
        var binaryPath = Path.Combine(root, "binary.db");
        var rawPath = Path.Combine(root, "raw.db");
        var key = RandomNumberGenerator.GetBytes(32);
        var raw = new byte[67]; raw[0] = (byte)'x'; raw[1] = raw[66] = (byte)'\'';
        ReadOnlySpan<byte> alphabet = "0123456789abcdef"u8;
        for (var i = 0; i < key.Length; i++) { raw[2 + i * 2] = alphabet[key[i] >> 4]; raw[3 + i * 2] = alphabet[key[i] & 15]; }
        try
        {
            var binaryCreate = Open(binaryPath, key, true);
            var rawCreate = Open(rawPath, raw, true);
            var binaryRead = Open(binaryPath, key, false);
            var rawRead = Open(rawPath, raw, false);
            RequireEncrypted(binaryPath); RequireEncrypted(rawPath);
            RequireOtherModeRejects(binaryPath, raw); RequireOtherModeRejects(rawPath, key);
            return $"binary_create_ms={binaryCreate}; binary_reopen_ms={binaryRead}; raw_create_ms={rawCreate}; raw_reopen_ms={rawRead}; encrypted_and_wrong_mode_rejection=passed";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(raw);
            foreach (var file in new[] { binaryPath, rawPath, binaryPath + "-journal", rawPath + "-journal" })
            {
                var target = Path.GetFullPath(file);
                if (!string.Equals(Path.GetDirectoryName(target), root, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Probe cleanup escaped its exact temporary directory.");
                File.Delete(target);
            }
            Directory.Delete(root, false);
        }
    }

    private static long Open(string file, byte[] key, bool create)
    {
        var watch = Stopwatch.StartNew(); IntPtr db = IntPtr.Zero;
        try
        {
            Check(sqlite3_open_v2(file, out db, create ? 6 : 2, IntPtr.Zero));
            Check(sqlite3_key(db, key, key.Length));
            Check(sqlite3_exec(db, create
                ? "PRAGMA journal_mode=DELETE; PRAGMA secure_delete=ON; CREATE TABLE probe(value INTEGER); INSERT INTO probe VALUES(1);"
                : "SELECT value FROM probe;", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero));
            return watch.ElapsedMilliseconds;
        }
        finally { if (db != IntPtr.Zero) Check(sqlite3_close(db)); }
    }
    private static void RequireOtherModeRejects(string file, byte[] key)
    {
        IntPtr db = IntPtr.Zero;
        try
        {
            Check(sqlite3_open_v2(file, out db, 2, IntPtr.Zero)); Check(sqlite3_key(db, key, key.Length));
            if (sqlite3_exec(db, "SELECT value FROM probe;", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero) == 0)
                throw new CryptographicException("An incompatible key mode was accepted.");
        }
        finally { if (db != IntPtr.Zero) Check(sqlite3_close(db)); }
    }
    private static void RequireEncrypted(string file)
    {
        Span<byte> prefix = stackalloc byte[16]; using var input = File.OpenRead(file); input.ReadExactly(prefix);
        if (prefix.SequenceEqual("SQLite format 3\0"u8)) throw new CryptographicException("Probe database is plaintext.");
    }
    private static void Check(int code) { if (code != 0) throw new InvalidOperationException("SQLCipher probe rejected an operation (code " + code + ")."); }
}
'@
[DeepSqlCipherKeyOpeningProbe]::Run($resolvedLibrary)
