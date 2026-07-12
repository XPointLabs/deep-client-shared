using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Sodium;

namespace Deep.Client.Shared.Services;

public sealed class SessionIdentityProvider : IDisposable
{
    private const int Ed25519PublicKeySize = 32;
    private const int Ed25519PrivateKeySize = 64;
    private const int X25519KeySize = 32;

    private readonly object gate = new();
    private SessionIdentityMaterial? material;

    public SessionIdentityProvider(string recoveryPhrase)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(recoveryPhrase);
        material = SessionIdentityMaterial.FromRecoveryPhrase(recoveryPhrase);

        try
        {
            ValidateMaterial(material);
            SessionId = material.SessionId;
        }
        catch
        {
            ClearMaterial(material);
            material = null;
            throw;
        }
    }

    public SessionId SessionId { get; }

    public byte[] GetEd25519PublicKey()
    {
        lock (gate)
        {
            return GetMaterial().Ed25519PublicKey.ToArray();
        }
    }

    public E2eeEnvelopeCodec CreateEnvelopeCodec() => new(this);

    internal IdentityPublicSnapshot GetPublicSnapshot()
    {
        lock (gate)
        {
            var current = GetMaterial();
            return new IdentityPublicSnapshot(
                current.SessionId,
                current.Ed25519PublicKey.ToArray(),
                current.X25519PublicKey.ToArray());
        }
    }

    public byte[] SignDetached(ReadOnlySpan<byte> message)
    {
        var messageBytes = message.ToArray();
        lock (gate)
        {
            try
            {
                return PublicKeyAuth.SignDetached(messageBytes, GetMaterial().Ed25519PrivateKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(messageBytes);
            }
        }
    }

    internal byte[] OpenSealedBox(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        lock (gate)
        {
            var current = GetMaterial();
            return SealedPublicKeyBox.Open(ciphertext, current.X25519PrivateKey, current.X25519PublicKey);
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (material is null)
            {
                return;
            }

            ClearMaterial(material);
            material = null;
        }
    }

    private SessionIdentityMaterial GetMaterial() =>
        material ?? throw new ObjectDisposedException(nameof(SessionIdentityProvider));

    private static void ValidateMaterial(SessionIdentityMaterial value)
    {
        if (value.Ed25519PublicKey.Length != Ed25519PublicKeySize ||
            value.Ed25519PrivateKey.Length != Ed25519PrivateKeySize ||
            value.X25519PublicKey.Length != X25519KeySize ||
            value.X25519PrivateKey.Length != X25519KeySize)
        {
            throw new CryptographicException("Session identity contains an invalid key length.");
        }

        var parsedSessionId = SessionId.Parse(value.SessionId.Value);
        if (!parsedSessionId.Value.StartsWith("05", StringComparison.Ordinal))
        {
            throw new CryptographicException("E2EE v1 requires a standard 05 Session ID.");
        }

        var sessionIdBytes = Convert.FromHexString(parsedSessionId.Value);
        var convertedPublicKey = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(value.Ed25519PublicKey);
        var x25519PublicKeyFromPrivate = ScalarMult.Base(value.X25519PrivateKey);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(convertedPublicKey, value.X25519PublicKey) ||
                !CryptographicOperations.FixedTimeEquals(sessionIdBytes.AsSpan(1), value.X25519PublicKey) ||
                !CryptographicOperations.FixedTimeEquals(x25519PublicKeyFromPrivate, value.X25519PublicKey) ||
                !CryptographicOperations.FixedTimeEquals(value.Ed25519PrivateKey.AsSpan(32), value.Ed25519PublicKey))
            {
                throw new CryptographicException("Session identity keys are not bound to its Session ID.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(convertedPublicKey);
            CryptographicOperations.ZeroMemory(x25519PublicKeyFromPrivate);
            CryptographicOperations.ZeroMemory(sessionIdBytes);
        }
    }

    private static void ClearMaterial(SessionIdentityMaterial value)
    {
        CryptographicOperations.ZeroMemory(value.Ed25519PrivateKey);
        CryptographicOperations.ZeroMemory(value.X25519PrivateKey);
        CryptographicOperations.ZeroMemory(value.Ed25519PublicKey);
        CryptographicOperations.ZeroMemory(value.X25519PublicKey);
    }
}

internal sealed record IdentityPublicSnapshot(
    SessionId SessionId,
    byte[] Ed25519PublicKey,
    byte[] X25519PublicKey);
