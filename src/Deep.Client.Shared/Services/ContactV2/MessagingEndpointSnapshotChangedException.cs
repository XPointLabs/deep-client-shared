using System.Security.Cryptography;

namespace Deep.Client.Shared.Services.ContactV2;

// Scheduling-only refusal before an ACK endpoint set is captured. Not a reason
// to retry an effect, reinterpret a proof or splice snapshots inside a set.
internal sealed class MessagingEndpointSnapshotChangedException() : CryptographicException(
    "Refreshed messaging endpoints no longer bind owned network custody.");
