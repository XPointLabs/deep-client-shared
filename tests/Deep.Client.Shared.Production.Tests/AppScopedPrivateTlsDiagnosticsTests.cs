using System.Net.Security;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Production.Tests;

public sealed class AppScopedPrivateTlsDiagnosticsTests
{
    [Theory]
    [InlineData("Cleartext HTTP traffic to private.invalid is not permitted", "RevocationStatusUnknown CleartextBlocked")]
    [InlineData("No CRLs found for private certificate", "RevocationStatusUnknown CrlUnavailable")]
    [InlineData("Could not determine revocation status for private certificate", "RevocationStatusUnknown RevocationUndetermined")]
    [InlineData("private certificate and request contents", "RevocationStatusUnknown")]
    public void ProviderDetailsBecomeOnlyClosedCategories(string detail, string expected)
    {
        Assert.Equal(expected, HttpServiceTransportFactory.ClassifyPrivateCertificateFailure([
            new() { Status = X509ChainStatusFlags.RevocationStatusUnknown, StatusInformation = detail }]));
        Assert.Equal("PartialChain", HttpServiceTransportFactory.ClassifyPrivateCertificateFailure([
            new() { Status = X509ChainStatusFlags.PartialChain, StatusInformation = detail }]));
    }

    [Fact]
    public void OversizedUnknownAndRepeatedDetailsNeverEscapeOrGrowOutput()
    {
        Assert.Equal("RevocationStatusUnknown", HttpServiceTransportFactory.ClassifyPrivateCertificateFailure([
            new() { Status = X509ChainStatusFlags.RevocationStatusUnknown, StatusInformation = new string('x', 4096) + " cleartext" }]));
        Assert.Equal("OtherChainError", HttpServiceTransportFactory.ClassifyPrivateCertificateFailure([
            new() { Status = X509ChainStatusFlags.InvalidBasicConstraints, StatusInformation = "private" }]));
        Assert.Equal("Revoked", HttpServiceTransportFactory.ClassifyPrivateCertificateFailure([
            new() { Status = X509ChainStatusFlags.Revoked }, new() { Status = X509ChainStatusFlags.Revoked }]));
    }

    [Fact]
    public void FactoryStillRejectsMissingCertificateAndNameMismatchWithClosedCause()
    {
        using var root = Root();
        var callback = Callback(root);
        var missing = Assert.Throws<AuthenticationException>(() => callback(new object(), null, null, SslPolicyErrors.RemoteCertificateNotAvailable));
        Assert.Equal("App-scoped TLS rejected (RemoteCertificateNotAvailable).", missing.Message);
        var mismatch = Assert.Throws<AuthenticationException>(() => callback(new object(), root, null, SslPolicyErrors.RemoteCertificateNameMismatch));
        Assert.Equal("App-scoped TLS rejected (RemoteCertificateNameMismatch).", mismatch.Message);
    }

    [Fact]
    public void AnUnrelatedRootCannotBeAcceptedByTheAppScopedValidator()
    {
        using var root = Root(); using var unrelated = Root();
        var error = Assert.Throws<AuthenticationException>(() =>
            Callback(root)(new object(), unrelated, null, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.StartsWith("App-scoped TLS rejected (", error.Message);
        Assert.DoesNotContain(root.Subject, error.Message);
        Assert.DoesNotContain(unrelated.Thumbprint, error.Message);
    }

    private static RemoteCertificateValidationCallback Callback(X509Certificate2 root)
    {
        var factory = new HttpServiceTransportFactory(HttpServiceEndpointPolicy.Production)
            .WithAppScopedPrivateCertificateAuthority(root.RawData);
        // Test-only observation of an existing private hook; no delegate or
        // mutable handler is exposed by the production API.
        var hooks = Assert.IsType<HttpServiceNetworkHooks>(typeof(HttpServiceTransportFactory)
            .GetField("networkHooks", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(factory));
        return Assert.IsType<RemoteCertificateValidationCallback>(hooks.ServerCertificateValidationCallback);
    }

    private static X509Certificate2 Root()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Synthetic closed-diagnostic root", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(10));
    }
}
