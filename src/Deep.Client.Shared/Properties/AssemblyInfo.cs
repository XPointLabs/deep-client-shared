using System.Runtime.CompilerServices;

#if DEEP_TEST_INTERNALS
[assembly: InternalsVisibleTo("Deep.Client.Maui.Core")]
[assembly: InternalsVisibleTo("Deep.Client.Shared.Tests")]
[assembly: InternalsVisibleTo("Deep.Client.Maui.ViewModels.Tests")]
[assembly: InternalsVisibleTo("Deep.ReleaseCompositionVerifier")]
#endif
