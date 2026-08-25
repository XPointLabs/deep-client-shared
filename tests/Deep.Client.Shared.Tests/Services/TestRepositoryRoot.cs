namespace Deep.Client.Shared.Tests.Services;

internal static class TestRepositoryRoot
{
    internal static string Find()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(
                    current.FullName,
                    "src",
                    "Deep.Client.Shared",
                    "Deep.Client.Shared.csproj")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException(
            "Could not locate the deep-client-shared repository root.");
    }
}
