using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Client.Shared.Services.AccountDirectoryV2;

// One catchup's read-only transport budget, never history/proof authority.
// Only an explicit bounded HTTPS503 Retry-After permits one exact read repeat.
internal sealed class DirectoryHistoryReadScope(HttpServiceRequestTransport transport)
{
    private bool retryAvailable = true;

    internal async ValueTask<HttpServiceResponse> ReadAsync(ReadOnlyMemory<byte> request, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        DeepIdV2DirectoryHistoryWireCodec.ValidateRequest(request.Span);
        var exact = request.ToArray();
        try
        {
            DeepIdV2DirectoryHistoryWireCodec.ValidateRequest(exact);
            var response = await SendAsync().ConfigureAwait(false);
            try
            {
                ct.ThrowIfCancellationRequested();
                if (retryAvailable && response.StatusCode == HttpStatusCode.ServiceUnavailable &&
                    response.RetryAfter is { } delay && delay > TimeSpan.Zero && delay <= TimeSpan.FromSeconds(5))
                {
                    retryAvailable = false;
                    response.Dispose(); // Never hold the failed response across the wait.
                    await Task.Delay(delay, ct).ConfigureAwait(false);
                    return await SendAsync().ConfigureAwait(false);
                }
                return response;
            }
            catch { response.Dispose(); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(exact); }

        ValueTask<HttpServiceResponse> SendAsync() => new(DeepIdV2DirectoryProofClient.AwaitBoundedResponseAsync(
            transport.PostAsync("/api/v2/account-directory/history", exact, ct).AsTask(), ct));
    }
}
