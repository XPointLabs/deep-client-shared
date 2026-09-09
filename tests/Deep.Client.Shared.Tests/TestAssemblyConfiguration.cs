using Xunit;

// Several persistence suites intentionally reset Microsoft.Data.Sqlite's process-wide
// native pool while validating reopen, corruption, and crash-recovery behavior. Those
// global resets cannot safely overlap another SQLite test in the same process.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
