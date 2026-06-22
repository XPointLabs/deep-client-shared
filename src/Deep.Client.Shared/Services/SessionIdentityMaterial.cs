using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain;
using Sodium;

namespace Deep.Client.Shared.Services;

internal sealed class SessionIdentityMaterial
{
    private SessionIdentityMaterial(
        SessionId sessionId,
        byte[] ed25519PublicKey,
        byte[] ed25519PrivateKey,
        byte[] x25519PublicKey)
    {
        SessionId = sessionId;
        Ed25519PublicKey = ed25519PublicKey;
        Ed25519PrivateKey = ed25519PrivateKey;
        X25519PublicKey = x25519PublicKey;
    }

    public SessionId SessionId { get; }

    public byte[] Ed25519PublicKey { get; }

    public byte[] Ed25519PrivateKey { get; }

    public byte[] X25519PublicKey { get; }

    public string Ed25519PublicKeyHex => Convert.ToHexString(Ed25519PublicKey).ToLowerInvariant();

    public static SessionIdentityMaterial FromRecoveryPhrase(string recoveryPhrase)
    {
        var normalized = NormalizeRecoveryPhrase(recoveryPhrase);
        var mnemonicBytes = Encoding.UTF8.GetBytes(normalized.Normalize(NormalizationForm.FormKD));
        var salt = Encoding.UTF8.GetBytes("mnemonic");
        var seed = Rfc2898DeriveBytes.Pbkdf2(
            mnemonicBytes,
            salt,
            2048,
            HashAlgorithmName.SHA512,
            32);

        var ed25519KeyPair = PublicKeyAuth.GenerateKeyPair(seed);
        var x25519PublicKey = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(ed25519KeyPair.PublicKey);
        var sessionId = new SessionId($"05{Convert.ToHexString(x25519PublicKey).ToLowerInvariant()}");

        return new SessionIdentityMaterial(
            sessionId,
            ed25519KeyPair.PublicKey,
            ed25519KeyPair.PrivateKey,
            x25519PublicKey);
    }

    public string SignPushSubscribe(long timestamp, bool wantData, IReadOnlyList<int> namespaces)
    {
        var sortedNamespaces = namespaces.OrderBy(static value => value).ToArray();
        var message = Encoding.UTF8.GetBytes(
            $"MONITOR{SessionId.Value}{timestamp}{(wantData ? '1' : '0')}{string.Join(',', sortedNamespaces)}");

        return Convert.ToBase64String(PublicKeyAuth.SignDetached(message, Ed25519PrivateKey));
    }

    public string SignPushUnsubscribe(long timestamp)
    {
        var message = Encoding.UTF8.GetBytes($"UNSUBSCRIBE{SessionId.Value}{timestamp}");
        return Convert.ToBase64String(PublicKeyAuth.SignDetached(message, Ed25519PrivateKey));
    }

    public static string NormalizeRecoveryPhrase(string phrase) =>
        string.Join(' ', phrase
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(word => word.ToLowerInvariant()));
}