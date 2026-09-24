using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Services.AccountDirectoryV2;

/// <summary>
/// Bounded DID2-only first-admission exchange. A DGR1 response is untrusted
/// transport evidence; consumers must obtain an independently verified,
/// rollback-protected directory proof before treating the account as admitted.
/// </summary>
public sealed class DeepIdV2GenesisAdmissionClient : IDisposable
{
    public const string EndpointPath = "/api/v2/account-directory/genesis-admissions";
    public static readonly TimeSpan DefaultRequestTimeout = TimeSpan.FromSeconds(30);

    private readonly HttpServiceRequestTransport transport;
    private int disposed;

    public DeepIdV2GenesisAdmissionClient(HttpServiceRequestTransport transport) =>
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));

    public static HttpServiceRequestTransportOptions CreateTransportOptions(
        string registryBaseUrl, TimeSpan requestTimeout = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(registryBaseUrl);
        var timeout = requestTimeout == default ? DefaultRequestTimeout : requestTimeout;
        if (timeout <= TimeSpan.Zero || timeout > DefaultRequestTimeout)
            throw new ArgumentOutOfRangeException(nameof(requestTimeout),
                "The DID2 genesis admission timeout must be 30 seconds or less.");
        return new HttpServiceRequestTransportOptions(
            registryBaseUrl.Trim(), [EndpointPath],
            DeepIdV2GenesisAdmissionWireCodec.RequestMediaType,
            DeepIdV2GenesisAdmissionWireCodec.ResponseMediaType,
            DeepIdV2GenesisAdmissionWireCodec.MaximumRequestLength,
            DeepIdV2GenesisAdmissionWireCodec.MaximumResponseLength,
            timeout);
    }

    public async ValueTask<DeepIdV2GenesisAdmissionReceipt> AdmitAsync(
        ReadOnlyMemory<byte> exactDga1, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        var request = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(exactDga1.Span);
        var checkpoint = DeepIdV2AccountDirectoryCodec.Decode(
            request.Admission.ExactAdc1V2.Span);
        var did = DeepIdV2Codec.DecodeDid2(request.Admission.ExactDid2.Span);
        if (!Fixed(checkpoint.DirectoryLeafKey.Span,
                DeepIdV2AccountDirectoryCodec.ComputeDirectoryLeafKey(
                    checkpoint.NetworkId.Span, did)))
            throw new CryptographicException(
                "The DID2 admission request has a mismatched directory leaf.");

        using var response = await transport.PostAsync(EndpointPath, exactDga1,
            cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.Conflict)
            throw new CryptographicException(
                "The DID2 directory rejected a conflicting genesis admission.");
        if (response.StatusCode is HttpStatusCode.TooManyRequests or
            HttpStatusCode.ServiceUnavailable)
            throw new IOException("The DID2 directory is temporarily unavailable.");
        if (response.StatusCode != HttpStatusCode.OK)
            throw new InvalidDataException(
                "The DID2 directory rejected the genesis admission.");

        var receipt = DeepIdV2GenesisAdmissionWireCodec.DecodeReceipt(
            response.Body.Span);
        var head = AccountDirectoryAdh1Codec.Decode(receipt.ExactAdh1.Span);
        if (!Fixed(receipt.OperationId.Span, request.OperationId.Span) ||
            !Fixed(receipt.DirectoryLeafKey.Span,
                checkpoint.DirectoryLeafKey.Span) ||
            !Fixed(head.NetworkId.Span, checkpoint.NetworkId.Span))
            throw new CryptographicException(
                "The untrusted DID2 receipt does not match this admission.");
        return receipt;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
            transport.Dispose();
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
