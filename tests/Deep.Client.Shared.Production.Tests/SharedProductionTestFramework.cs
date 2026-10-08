using System.Reflection;
using Xunit.Abstractions;
using Xunit.Sdk;

[assembly: TestFramework("Deep.Client.Shared.Production.Tests.SharedProductionTestFramework",
    "Deep.Client.Shared.Production.Tests")]

namespace Deep.Client.Shared.Production.Tests;

public sealed class SharedProductionTestFramework(IMessageSink diagnosticMessageSink)
    : XunitTestFramework(diagnosticMessageSink)
{
    protected override ITestFrameworkExecutor CreateExecutor(AssemblyName assemblyName) =>
        new Executor(assemblyName, SourceInformationProvider, DiagnosticMessageSink);

    private sealed class Executor(AssemblyName assemblyName,
        ISourceInformationProvider sourceInformationProvider, IMessageSink diagnosticMessageSink)
        : XunitTestFrameworkExecutor(assemblyName, sourceInformationProvider, diagnosticMessageSink)
    {
        protected override async void RunTestCases(IEnumerable<IXunitTestCase> testCases,
            IMessageSink executionMessageSink, ITestFrameworkExecutionOptions executionOptions)
        {
            using var runner = new AssemblyRunner(TestAssembly, testCases,
                DiagnosticMessageSink, executionMessageSink, executionOptions);
            await runner.RunAsync();
        }
    }

    private sealed class AssemblyRunner(ITestAssembly testAssembly,
        IEnumerable<IXunitTestCase> testCases, IMessageSink diagnosticMessageSink,
        IMessageSink executionMessageSink, ITestFrameworkExecutionOptions executionOptions)
        : XunitTestAssemblyRunner(testAssembly, testCases, diagnosticMessageSink,
            executionMessageSink, executionOptions)
    {
        private readonly int methodParallelism = ContactPathTestScheduling.Parallelism(
            executionOptions.DisableParallelizationOrDefault(),
            executionOptions.MaxParallelThreadsOrDefault());

        protected override Task<RunSummary> RunTestCollectionAsync(IMessageBus messageBus,
            ITestCollection testCollection, IEnumerable<IXunitTestCase> testCases,
            CancellationTokenSource cancellationTokenSource)
        {
            var collectionDisabled = testCollection.CollectionDefinition?
                .GetCustomAttributes(typeof(CollectionDefinitionAttribute))
                .FirstOrDefault()?.GetNamedArgument<bool>("DisableParallelization") == true;
            if (methodParallelism == 1 || collectionDisabled)
                return base.RunTestCollectionAsync(messageBus, testCollection, testCases,
                    cancellationTokenSource);

            return new CollectionRunner(testCollection, testCases, DiagnosticMessageSink,
                messageBus, TestCaseOrderer, new ExceptionAggregator(Aggregator),
                cancellationTokenSource, methodParallelism).RunAsync();
        }
    }

    private sealed class CollectionRunner(ITestCollection testCollection,
        IEnumerable<IXunitTestCase> testCases, IMessageSink diagnosticMessageSink,
        IMessageBus messageBus, ITestCaseOrderer testCaseOrderer,
        ExceptionAggregator aggregator, CancellationTokenSource cancellationTokenSource,
        int methodParallelism)
        : XunitTestCollectionRunner(testCollection, testCases, diagnosticMessageSink,
            messageBus, testCaseOrderer, aggregator, cancellationTokenSource)
    {
        protected override Task<RunSummary> RunTestClassAsync(ITestClass testClass,
            IReflectionTypeInfo @class, IEnumerable<IXunitTestCase> testCases)
        {
            if (@class.Type != typeof(DeepIdV2ContactPathAuthoritySourceTests) ||
                methodParallelism == 1 || CollectionFixtureMappings.Count != 0 ||
                !ContactPathTestScheduling.IsIsolated(@class.Type))
                return base.RunTestClassAsync(testClass, @class, testCases);

            return new ClassRunner(testClass, @class, testCases, DiagnosticMessageSink,
                MessageBus, TestCaseOrderer, new ExceptionAggregator(Aggregator),
                CancellationTokenSource, CollectionFixtureMappings, methodParallelism).RunAsync();
        }
    }

    private sealed class ClassRunner(ITestClass testClass, IReflectionTypeInfo @class,
        IEnumerable<IXunitTestCase> testCases, IMessageSink diagnosticMessageSink,
        IMessageBus messageBus, ITestCaseOrderer testCaseOrderer,
        ExceptionAggregator aggregator, CancellationTokenSource cancellationTokenSource,
        IDictionary<Type, object> collectionFixtureMappings, int methodParallelism)
        : XunitTestClassRunner(testClass, @class, testCases, diagnosticMessageSink,
            messageBus, testCaseOrderer, aggregator, cancellationTokenSource,
            collectionFixtureMappings)
    {
        protected override async Task<RunSummary> RunTestMethodsAsync()
        {
            var constructorArguments = CreateTestClassConstructorArguments();
            var methods = TestCaseOrderer.OrderTestCases(TestCases)
                .GroupBy(testCase => testCase.TestMethod, TestMethodComparer.Instance);
            var results = await ContactPathTestScheduling.RunAsync(methods, async cases =>
            {
                if (CancellationTokenSource.IsCancellationRequested)
                    return new RunSummary();
                // Keep xUnit's method/theory runners, reporting and fault handling.
                return await RunTestMethodAsync(cases.Key,
                    (IReflectionMethodInfo)cases.Key.Method, cases, constructorArguments);
            }, methodParallelism);
            var summary = new RunSummary();
            foreach (var result in results) summary.Aggregate(result);
            return summary;
        }
    }
}

internal static class ContactPathTestScheduling
{
    internal static int Parallelism(bool disabled, int maximumThreads) =>
        disabled || maximumThreads == 1 ? 1 : 2;

    internal static bool IsIsolated(Type testClass) =>
        testClass.GetInterfaces().Length == 0 &&
        testClass.GetFields(BindingFlags.Instance | BindingFlags.Public |
            BindingFlags.NonPublic).Length == 0;

    internal static async Task<RunSummary[]> RunAsync<T>(IEnumerable<T> methods,
        Func<T, Task<RunSummary>> run, int parallelism)
    {
        ArgumentNullException.ThrowIfNull(methods);
        ArgumentNullException.ThrowIfNull(run);
        if (parallelism is < 1 or > 2)
            throw new ArgumentOutOfRangeException(nameof(parallelism));

        var work = methods.ToArray();
        using var gate = new SemaphoreSlim(parallelism, parallelism);
        // SQLCipher setup may run synchronously through completed awaits.
        // Separate tasks avoid serializing that work before the second method starts.
        var tasks = work.Select(method => Task.Run(async () =>
        {
            await gate.WaitAsync().ConfigureAwait(false);
            try { return await run(method).ConfigureAwait(false); }
            finally { gate.Release(); }
        })).ToArray();
        return await Task.WhenAll(tasks).ConfigureAwait(false);
    }
}
