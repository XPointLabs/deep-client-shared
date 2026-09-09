using System.Reflection;
using Deep.Client.Shared.Persistence.PreKeyV1;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Tests.Persistence.PreKeyV1;

public sealed class OpaquePreKeyV1StoreSurfaceTests
{
    [Fact]
    public void SchemaV4StoresOnlyCanonicalSealedPreKeyMaterial()
    {
        var owner = typeof(SqlitePreKeyV1SecretOwner);
        var generation = (int)owner.GetField(
            "SchemaGeneration", BindingFlags.Static | BindingFlags.NonPublic)!.GetRawConstantValue()!;
        var ddl = (string)owner.GetField(
            "SchemaDdl", BindingFlags.Static | BindingFlags.NonPublic)!.GetRawConstantValue()!;

        Assert.Equal(4, generation);
        Assert.Contains("sealed_secret", ddl, StringComparison.Ordinal);
        Assert.DoesNotContain("signed_x25519_scalar", ddl, StringComparison.Ordinal);
        Assert.DoesNotContain("x25519_scalar", ddl, StringComparison.Ordinal);
        Assert.DoesNotContain("mlkem_secret", ddl, StringComparison.Ordinal);
    }

    [Fact]
    public void ProductionStoreBoundaryCarriesOpaqueProtocolCapabilitiesOnly()
    {
        var methods = typeof(SqlitePreKeyV1SecretOwner).GetMethods(
            BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
        Assert.DoesNotContain(methods.Where(static method => !method.IsPrivate), static method =>
            method.Name.Contains("ReadSecrets", StringComparison.Ordinal) ||
            method.GetParameters().Any(parameter =>
                typeof(Delegate).IsAssignableFrom(parameter.ParameterType)));
        Assert.Contains(methods, static method =>
            method.ReturnType == typeof(PreKeyV1ProvisioningCapability) &&
            method.GetParameters().Single().ParameterType == typeof(AuthoredDpk2Offering));
    }

    [Fact]
    public void ProvisioningPayloadContainsNoRawPrivateKeySlots()
    {
        var payload = typeof(PreKeyV1ProvisioningCapability).GetNestedType(
            "Payload", BindingFlags.NonPublic)!;
        var properties = payload.GetProperties(
            BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
        Assert.Equal(
            ["ExactDpk2", "SealedSecret"],
            properties.Select(static property => property.Name).Order().ToArray());
    }
}
