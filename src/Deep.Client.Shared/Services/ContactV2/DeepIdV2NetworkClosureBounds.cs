namespace Deep.Client.Shared.Services.ContactV2;

/// <summary>Structural bounds only; validated raw closures never mint verification authority.</summary>
internal static class DeepIdV2NetworkClosureBounds
{
    internal const int MaximumChainArtifacts = 4_096;
    internal const int MaximumSingleArtifactBytes = 16 * 1024 * 1024;
    internal const long MaximumPackageBytes = 68L * 1024 * 1024;

    internal static long ValidateChain(IReadOnlyList<ReadOnlyMemory<byte>> values,
        string name, int maximumCount)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count is 0 || values.Count > maximumCount)
            throw new ArgumentException($"{name} must contain 1..{maximumCount} artifacts.", name);
        var total = 0L;
        foreach (var value in values)
        {
            if (value.IsEmpty || value.Length > MaximumSingleArtifactBytes)
                throw new ArgumentException($"{name} entries must contain 1..{MaximumSingleArtifactBytes} bytes.", name);
            total = checked(total + value.Length);
        }
        return total;
    }
}
