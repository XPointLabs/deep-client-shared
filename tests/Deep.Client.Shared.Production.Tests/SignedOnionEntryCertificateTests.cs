using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Production.Tests;

public sealed class SignedOnionEntryCertificateTests
{
    [Theory]
    [InlineData(SslPolicyErrors.None)]
    [InlineData(SslPolicyErrors.RemoteCertificateChainErrors)]
    public void ExactSignedSpki_AllowsValidSelfSignedLeaf(SslPolicyErrors errors)
    {
        using var certificate = CreateCertificate();
        Assert.True(Validate(certificate, errors, Pin(certificate)));
    }

    [Theory]
    [InlineData(SslPolicyErrors.RemoteCertificateNameMismatch)]
    [InlineData(SslPolicyErrors.RemoteCertificateNotAvailable)]
    [InlineData(SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateChainErrors)]
    public void ExactPin_DoesNotOverrideNameOrCertificateFailure(SslPolicyErrors errors)
    {
        using var certificate = CreateCertificate();
        Assert.False(Validate(certificate, errors, Pin(certificate)));
    }

    [Fact]
    public void MissingWrongZeroOrMalformedPin_Rejects()
    {
        using var certificate = CreateCertificate();
        using var other = CreateCertificate();
        Assert.False(Validate(null, SslPolicyErrors.None, Pin(certificate)));
        Assert.False(Validate(certificate, SslPolicyErrors.None, Pin(other)));
        Assert.False(Validate(certificate, SslPolicyErrors.None, new byte[32]));
        Assert.False(Validate(certificate, SslPolicyErrors.None, new byte[31]));
    }

    [Theory]
    [InlineData(-3, -2)]
    [InlineData(1, 2)]
    public void ExactPin_DoesNotOverrideValidity(int notBeforeDays, int notAfterDays)
    {
        using var certificate = CreateCertificate(notBeforeDays, notAfterDays);
        Assert.False(Validate(certificate, SslPolicyErrors.RemoteCertificateChainErrors, Pin(certificate)));
    }

    [Theory]
    [InlineData("1.3.6.1.5.5.7.3.2", X509KeyUsageFlags.DigitalSignature)]
    [InlineData("1.3.6.1.5.5.7.3.1", X509KeyUsageFlags.KeyAgreement)]
    public void ExactPin_DoesNotOverrideExplicitWrongUsage(string eku, X509KeyUsageFlags keyUsage)
    {
        using var certificate = CreateCertificate(eku: eku, keyUsage: keyUsage);
        Assert.False(Validate(certificate, SslPolicyErrors.RemoteCertificateChainErrors, Pin(certificate)));
    }

    private static bool Validate(X509Certificate? certificate, SslPolicyErrors errors, byte[] pin) =>
        PrivacyManagedIngressHttpTransport.ValidateSignedNodeCertificate(certificate, errors, pin);

    private static byte[] Pin(X509Certificate2 certificate) =>
        SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo());

    private static X509Certificate2 CreateCertificate(int notBeforeDays = -1, int notAfterDays = 1,
        string eku = "1.3.6.1.5.5.7.3.1", X509KeyUsageFlags keyUsage = X509KeyUsageFlags.DigitalSignature)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=onion-entry-test", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid(eku) }, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, critical: true));
        var now = DateTimeOffset.UtcNow;
        // Keep only the public certificate. Attaching an ECDSA private key to
        // a deliberately key-agreement-only leaf is rejected by Windows before
        // our validator can inspect the hostile usage extension.
        return request.Create(request.SubjectName, X509SignatureGenerator.CreateForECDsa(key),
            now.AddDays(notBeforeDays), now.AddDays(notAfterDays), RandomNumberGenerator.GetBytes(16));
    }
}
