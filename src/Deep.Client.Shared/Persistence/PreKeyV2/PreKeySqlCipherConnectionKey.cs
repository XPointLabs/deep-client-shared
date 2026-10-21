using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.PreKeyV2;

// Computation reuse only, owned by ONE verified current-account read. It does
// not retain a connection, verified rows, floor, publication or permission.
// Existing PKV2 files keep exactly their original SQLCipher4 password-derived
// key: PBKDF2-HMAC-SHA512(password, actual file salt, 256000, 32).
internal sealed class PreKeySqlCipherConnectionKey : IDisposable
{
    private readonly object gate = new();
    private byte[]? password, salt, encoded;
    private string? path;
    private bool disposed;
    internal int Derivations { get; private set; }

    internal void ApplyExisting(SqliteConnection connection, string statePath, ReadOnlySpan<byte> key)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (key.Length != 32 || key.IndexOfAnyExcept((byte)0) < 0)
                throw new CryptographicException("Pre-key SQL requires its original nonzero account-derived key.");
            // Establish a codec context, without reading an encrypted page or
            // paying native PBKDF2. SQLCipher derives lazily on first page use.
            var original = key.ToArray();
            try
            {
                if (SQLitePCL.raw.sqlite3_key(connection.Handle, original) != SQLitePCL.raw.SQLITE_OK)
                    throw new CryptographicException("SQLCipher rejected the original pre-key context.");
            }
            finally { CryptographicOperations.ZeroMemory(original); }
            RequireDefault(connection, "kdf_iter", "256000");
            RequireDefault(connection, "cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512");
            Span<byte> actualSalt = stackalloc byte[16];
            using (var file = new FileStream(statePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                file.ReadExactly(actualSalt);
            var fullPath = Path.GetFullPath(statePath);
            if (encoded is null)
            {
                Span<byte> derived = stackalloc byte[32];
                try
                {
                    Rfc2898DeriveBytes.Pbkdf2(key, actualSalt, derived, 256000, HashAlgorithmName.SHA512);
                    var result = new byte[67];
                    result[0] = (byte)'x'; result[1] = result[66] = (byte)'\'';
                    ReadOnlySpan<byte> alphabet = "0123456789abcdef"u8;
                    for (var i = 0; i < derived.Length; i++)
                    {
                        result[2 + i * 2] = alphabet[derived[i] >> 4];
                        result[3 + i * 2] = alphabet[derived[i] & 15];
                    }
                    password = key.ToArray(); salt = actualSalt.ToArray(); path = fullPath;
                    encoded = result; Derivations++;
                }
                finally { CryptographicOperations.ZeroMemory(derived); }
            }
            else if (!string.Equals(path, fullPath, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) ||
                !CryptographicOperations.FixedTimeEquals(password!, key) ||
                !CryptographicOperations.FixedTimeEquals(salt!, actualSalt))
                throw new CryptographicException("Pre-key SQL key, file or salt changed within the verified account read.");
            // No SQL string/key diagnostic or fallback. Every fresh connection
            // still authenticates actual encrypted pages and complete custody.
            if (SQLitePCL.raw.sqlite3_key(connection.Handle, encoded) != SQLitePCL.raw.SQLITE_OK)
                throw new CryptographicException("SQLCipher rejected the exact derived pre-key key.");
        }
    }

    private static void RequireDefault(SqliteConnection connection, string pragma, string expected)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA " + pragma + ";";
        if (!string.Equals(Convert.ToString(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture), expected, StringComparison.Ordinal))
            throw new CryptographicException("Pre-key SQLCipher derivation settings differ from the current format.");
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return; disposed = true;
            foreach (var bytes in new[] { password, salt, encoded })
                if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
            password = salt = encoded = null; path = null;
        }
    }
}
