using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain;
using Sodium;

namespace Deep.Client.Shared.Services;

internal sealed class SessionIdentityMaterial : IDisposable
{
    private readonly byte[] ed25519PublicKey;
    private readonly byte[] ed25519PrivateKey;
    private readonly byte[] x25519PublicKey;
    private readonly byte[] x25519PrivateKey;
    private int disposed;

    private SessionIdentityMaterial(
        SessionId sessionId,
        byte[] ed25519PublicKey,
        byte[] ed25519PrivateKey,
        byte[] x25519PublicKey,
        byte[] x25519PrivateKey)
    {
        SessionId = sessionId;
        this.ed25519PublicKey = ed25519PublicKey;
        this.ed25519PrivateKey = ed25519PrivateKey;
        this.x25519PublicKey = x25519PublicKey;
        this.x25519PrivateKey = x25519PrivateKey;
    }

    public SessionId SessionId { get; }

    public byte[] Ed25519PublicKey
    {
        get
        {
            ThrowIfDisposed();
            return ed25519PublicKey;
        }
    }

    public byte[] Ed25519PrivateKey
    {
        get
        {
            ThrowIfDisposed();
            return ed25519PrivateKey;
        }
    }

    public byte[] X25519PublicKey
    {
        get
        {
            ThrowIfDisposed();
            return x25519PublicKey;
        }
    }

    public byte[] X25519PrivateKey
    {
        get
        {
            ThrowIfDisposed();
            return x25519PrivateKey;
        }
    }

    public string Ed25519PublicKeyHex
    {
        get
        {
            ThrowIfDisposed();
            return Convert.ToHexString(ed25519PublicKey).ToLowerInvariant();
        }
    }

    public static SessionIdentityMaterial FromRecoveryPhrase(string recoveryPhrase)
    {
        var normalized = NormalizeRecoveryPhrase(recoveryPhrase);
        byte[]? mnemonicBytes = null;
        byte[]? salt = null;
        byte[]? seed = null;
        byte[]? ed25519PublicKey = null;
        byte[]? ed25519PrivateKey = null;
        byte[]? x25519PublicKey = null;
        byte[]? x25519PrivateKey = null;

        try
        {
            mnemonicBytes = Encoding.UTF8.GetBytes(normalized.Normalize(NormalizationForm.FormKD));
            salt = Encoding.UTF8.GetBytes("mnemonic");
            seed = Rfc2898DeriveBytes.Pbkdf2(
                mnemonicBytes,
                salt,
                2048,
                HashAlgorithmName.SHA512,
                32);

            var ed25519KeyPair = PublicKeyAuth.GenerateKeyPair(seed);
            ed25519PublicKey = ed25519KeyPair.PublicKey;
            ed25519PrivateKey = ed25519KeyPair.PrivateKey;
            x25519PublicKey = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(ed25519PublicKey);
            x25519PrivateKey = PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(ed25519PrivateKey);
            var sessionId = new SessionId($"05{Convert.ToHexString(x25519PublicKey).ToLowerInvariant()}");

            var material = new SessionIdentityMaterial(
                sessionId,
                ed25519PublicKey,
                ed25519PrivateKey,
                x25519PublicKey,
                x25519PrivateKey);

            ed25519PublicKey = null;
            ed25519PrivateKey = null;
            x25519PublicKey = null;
            x25519PrivateKey = null;
            return material;
        }
        finally
        {
            Zero(mnemonicBytes);
            Zero(salt);
            Zero(seed);
            Zero(ed25519PublicKey);
            Zero(ed25519PrivateKey);
            Zero(x25519PublicKey);
            Zero(x25519PrivateKey);
        }
    }

    public string SignPushSubscribe(
        long timestamp,
        bool wantData,
        IReadOnlyList<int> namespaces,
        string service,
        string deviceToken,
        string encryptionKey,
        string appId,
        string appVersion)
    {
        ThrowIfDisposed();
        var message = Encoding.UTF8.GetBytes(PushSubscriptionCanonicalFormat.CreateSubscribe(
            SessionId.Value,
            timestamp,
            wantData,
            namespaces,
            service,
            deviceToken,
            encryptionKey,
            appId,
            appVersion));
        try
        {
            return Convert.ToBase64String(PublicKeyAuth.SignDetached(message, ed25519PrivateKey));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message);
        }
    }

    public string SignPushUnsubscribe(long timestamp, string service, string deviceToken)
    {
        ThrowIfDisposed();
        var message = Encoding.UTF8.GetBytes(PushSubscriptionCanonicalFormat.CreateUnsubscribe(
            SessionId.Value,
            timestamp,
            service,
            deviceToken));
        try
        {
            return Convert.ToBase64String(PublicKeyAuth.SignDetached(message, ed25519PrivateKey));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message);
        }
    }

    public byte[] SignDetached(byte[] message)
    {
        ThrowIfDisposed();
        return PublicKeyAuth.SignDetached(message, ed25519PrivateKey);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        Zero(ed25519PrivateKey);
        Zero(x25519PrivateKey);
        Zero(ed25519PublicKey);
        Zero(x25519PublicKey);
    }

    public static string NormalizeRecoveryPhrase(string phrase) =>
        string.Join(' ', phrase
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(word => word.ToLowerInvariant()));

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(disposed != 0, this);

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

}

internal static class PushSubscriptionCanonicalFormat
{
    public const int SignatureVersion = 2;

    public static string CreateSubscribe(
        string pubkey,
        long timestamp,
        bool wantData,
        IReadOnlyList<int> namespaces,
        string service,
        string deviceToken,
        string encryptionKey,
        string appId,
        string appVersion) =>
        Create(
            "subscribe",
            ("pubkey", pubkey),
            ("sig_ts", timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ("service", service),
            ("device_token", deviceToken),
            ("enc_key", encryptionKey),
            ("want_data", wantData ? "1" : "0"),
            ("namespaces", string.Join(',', namespaces.OrderBy(static value => value).Select(static value => value.ToString(System.Globalization.CultureInfo.InvariantCulture)))),
            ("app_id", appId),
            ("app_version", appVersion));

    public static string CreateUnsubscribe(
        string pubkey,
        long timestamp,
        string service,
        string deviceToken) =>
        Create(
            "unsubscribe",
            ("pubkey", pubkey),
            ("sig_ts", timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ("service", service),
            ("device_token", deviceToken));

    private static string Create(string operation, params (string Name, string Value)[] fields)
    {
        var builder = new StringBuilder($"deep.push/{operation}/v{SignatureVersion}\n");
        foreach (var (name, value) in fields)
        {
            ArgumentException.ThrowIfNullOrEmpty(value, name);
            builder.Append(name)
                .Append('=')
                .Append(Encoding.UTF8.GetByteCount(value).ToString(System.Globalization.CultureInfo.InvariantCulture))
                .Append(':')
                .Append(value)
                .Append('\n');
        }

        return builder.ToString();
    }
}
