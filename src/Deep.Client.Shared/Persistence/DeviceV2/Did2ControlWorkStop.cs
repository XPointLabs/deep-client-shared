namespace Deep.Client.Shared.Persistence.DeviceV2;

// Local terminal metadata, not authority for stop, deletion, audit or transport.
internal static class Did2ControlWorkStop
{
    // Lower UTC seconds prove a millisecond expiry only at the ceiling second.
    // This conversion is not time/stop authority. Zero denotes no expiry.
    internal static ulong ProvenExpirySecond(ulong expiryMilliseconds) => expiryMilliseconds == 0
        ? ulong.MaxValue
        : checked(expiryMilliseconds / 1_000 + (expiryMilliseconds % 1_000 == 0 ? 0UL : 1UL));

    internal static void RequireCanonical(byte reason, byte audit, ulong stoppedAtUpper, bool payloadRetired,
        ulong firstSuccessfulStoreUpper = 0)
    {
        if (reason == 0 && (firstSuccessfulStoreUpper != 0 || payloadRetired))
        {
            if (stoppedAtUpper != 0 || audit > 2 ||
                (!payloadRetired ? audit != 0 : audit == 0) ||
                (audit == 2 ? firstSuccessfulStoreUpper != 0 : firstSuccessfulStoreUpper is 0 or > long.MaxValue - 2_592_000))
                throw new InvalidDataException("Successful control work has noncanonical terminal/audit metadata.");
            return;
        }
        if (firstSuccessfulStoreUpper != 0)
            throw new InvalidDataException("Successful control work cannot overwrite a first stop.");
        if (reason > (byte)ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired || audit > 2 ||
            (reason == 0 ? audit != 0 || stoppedAtUpper != 0 :
                !payloadRetired ? audit != 0 || stoppedAtUpper is 0 or > long.MaxValue - 2_592_000 :
                audit == 0 || (audit == 2 ? stoppedAtUpper != 0 : stoppedAtUpper is 0 or > long.MaxValue - 2_592_000)))
            throw new InvalidDataException("Control work has noncanonical terminal/audit metadata.");
    }
}
