using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed class Did2OwnedPermanentContactPlan
{
    private readonly byte[] intent;
    internal Did2OwnedPermanentContactPlan(ReadOnlySpan<byte> intent, string profile)
    { this.intent = intent.ToArray(); Profile = profile; }
    internal ReadOnlyMemory<byte> Intent => intent.ToArray();
    internal string Profile { get; }
    internal bool Matches(Did2OwnedPermanentContactPlan other) =>
        string.Equals(Profile, other.Profile, StringComparison.Ordinal) &&
        CryptographicOperations.FixedTimeEquals(intent, other.intent);

    internal static Did2ContactRouteConfiguration Configuration() => new(1024, 2,
        SHA256.HashData("Deep/Client/ContactV2/anti-spam/bounded-unsolicited-v1"u8));
}

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<Did2OwnedPermanentContactPlan> ReadPermanentContactPlanAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            return CreatePermanentContactPlan(current, instance);
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }

    private void RequirePermanentContactPlan(Did2OwnedPermanentContactPlan? expected,
        VerifiedDeepIdV2CurrentAccount current, ReadOnlySpan<byte> instance, ReadOnlySpan<byte> intent)
    {
        if (expected is null) return; // Internal phase callers still own their existing explicit intent.
        if (!expected.Matches(CreatePermanentContactPlan(current, instance)) ||
            !CryptographicOperations.FixedTimeEquals(expected.Intent.Span, intent))
            throw new CryptographicException("Permanent-contact bootstrap no longer belongs to this protected account instance.");
    }

    private Did2OwnedPermanentContactPlan CreatePermanentContactPlan(
        VerifiedDeepIdV2CurrentAccount current, ReadOnlySpan<byte> instance)
    {
        var profile = Domain.DeepDisplayName.Normalize(current.DisplayName, nameof(current.DisplayName));
        var name = Encoding.UTF8.GetBytes(profile);
        if (name.Length > 128)
            throw new ArgumentException("Permanent-contact profile exceeds its UTF-8 bound.");
        ReadOnlySpan<byte> label = "Deep/Client/DID2/permanent-contact-bootstrap/v1"u8;
        var transcript = new byte[label.Length + 1 + 16 + 32 + 32 + 4 + name.Length];
        try
        {
            label.CopyTo(transcript); var offset = label.Length + 1;
            networkId.CopyTo(transcript, offset); offset += 16;
            current.AccountId.Span.CopyTo(transcript.AsSpan(offset)); offset += 32;
            instance.CopyTo(transcript.AsSpan(offset)); offset += 32;
            BinaryPrimitives.WriteUInt16BigEndian(transcript.AsSpan(offset), deploymentProfileId); offset += 2;
            BinaryPrimitives.WriteUInt16BigEndian(transcript.AsSpan(offset), checked((ushort)name.Length)); offset += 2;
            name.CopyTo(transcript, offset);
            var intent = SHA256.HashData(transcript);
            try { return new(intent, profile); }
            finally { CryptographicOperations.ZeroMemory(intent); }
        }
        finally { CryptographicOperations.ZeroMemory(transcript); }
    }
}
