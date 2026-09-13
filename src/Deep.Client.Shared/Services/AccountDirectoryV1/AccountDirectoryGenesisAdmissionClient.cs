using System.Net;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Services;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Client.Shared.Services.AccountDirectoryV1;

public sealed class AccountDirectoryGenesisAdmissionClient : IDisposable
{
    public const string EndpointPath =
        "/api/v1/account-directory/genesis-admissions";
    private const string OperationDomain =
        "Deep/AccountDirectory/V1/genesis-admission-operation";
    private readonly HttpServiceRequestTransport transport;
    private int disposed;

    internal AccountDirectoryGenesisAdmissionClient(
        HttpServiceRequestTransport transport) =>
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));

    public static AccountDirectoryGenesisAdmissionWireRequest CreateRequest(
        DeepGenesisDeviceActivation activation)
    {
        ArgumentNullException.ThrowIfNull(activation);
        var checkpoint = activation.DirectoryCheckpoint;
        if (checkpoint.Checkpoint.CheckpointGeneration != 0 ||
            checkpoint.Checkpoint.PredecessorCheckpointHash.Span
                .IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidOperationException(
                "Genesis admission requires an exact generation-zero checkpoint.");
        if (checkpoint.RevokedDcaAuthorizationCount != 0)
            throw new InvalidOperationException(
                "Genesis admission cannot begin with revoked contact authorizations.");
        var identity = checkpoint.Binding.Identity;
        var exactAdc = AccountDirectoryAdc1Codec.Encode(checkpoint.Checkpoint);
        var operationId = OperationId(exactAdc);
        return new AccountDirectoryGenesisAdmissionWireRequest(
            operationId,
            new AccountDirectoryGenesisAdmissionRequest(
                identity.Account.Certificate.CanonicalBytes.Span,
                identity.Revocations.Snapshot.CanonicalBytes.Span,
                identity.ActiveDevices
                    .OrderBy(static value => value.Certificate.DeviceId.ToArray(),
                        ByteArrayComparer.Instance)
                    .Select(static value => value.Certificate.CanonicalBytes)
                    .ToArray(),
                checkpoint.Binding.DeepId.CanonicalBytes.Span,
                checkpoint.Binding.Record.CanonicalBytes.Span,
                checkpoint.Directory.Record.CanonicalBytes.Span,
                exactAdc,
                []));
    }

    public async ValueTask<AccountDirectoryGenesisAdmissionReceipt> AdmitAsync(
        DeepGenesisDeviceActivation activation,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        var request = CreateRequest(activation);
        var encoded = AccountDirectoryGenesisAdmissionWireCodec.EncodeRequest(request);
        try
        {
            using var response = await transport.PostAsync(
                    EndpointPath, encoded, cancellationToken)
                .ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.Conflict)
                throw new CryptographicException(
                    "The account-directory authority rejected a conflicting genesis admission.");
            if (response.StatusCode is HttpStatusCode.TooManyRequests or
                HttpStatusCode.ServiceUnavailable)
                throw new IOException(
                    "The account-directory authority is temporarily unavailable.");
            if (response.StatusCode != HttpStatusCode.OK)
                throw new InvalidDataException(
                    "The account-directory authority rejected the genesis admission.");
            var receipt = AccountDirectoryGenesisAdmissionWireCodec.DecodeReceipt(
                response.Body.Span);
            if (!Fixed(receipt.OperationId.Span, request.OperationId.Span) ||
                !Fixed(
                    receipt.DirectoryLeafKey.Span,
                    activation.DirectoryCheckpoint.Checkpoint.DirectoryLeafKey.Span))
                throw new CryptographicException(
                    "The account-directory admission receipt is not bound to this account.");
            var head = AccountDirectoryAdh1Codec.Decode(receipt.ExactAdh1.Span);
            if (!Fixed(
                    head.NetworkId.Span,
                    activation.DirectoryCheckpoint.Checkpoint.NetworkId.Span))
                throw new CryptographicException(
                    "The account-directory admission receipt belongs to another network.");
            return receipt;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
            transport.Dispose();
    }

    private static byte[] OperationId(ReadOnlySpan<byte> exactAdc1)
    {
        var domain = Encoding.ASCII.GetBytes(OperationDomain);
        var input = new byte[checked(domain.Length + exactAdc1.Length)];
        domain.CopyTo(input, 0);
        exactAdc1.CopyTo(input.AsSpan(domain.Length));
        try
        {
            var result = SHA256.HashData(input);
            if (result.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                throw new CryptographicException(
                    "The genesis admission operation ID is invalid.");
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) =>
            left.AsSpan().SequenceCompareTo(right);
    }
}
