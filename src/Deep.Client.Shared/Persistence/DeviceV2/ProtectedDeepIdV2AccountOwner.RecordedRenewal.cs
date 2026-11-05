using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private async Task<byte[]> ResolveRenewalIntentAsync(ProtectedDid2ContactRouteJournal.State state,
        byte[] originalIntent, ReadOnlyMemory<byte> account, byte[] instance, CancellationToken ct)
    {
        var intent = originalIntent.ToArray();
        byte[]? expectedRequestHash = null;
        try
        {
            for (var count = 0; ; count++)
            {
                if (state.Entries.TryGetValue(Convert.ToHexString(intent), out var active))
                {
                    if (expectedRequestHash is not null && !FixedRoute(expectedRequestHash, SHA256.HashData(active.Record(12).Span)))
                        throw new CryptographicException("Recorded renewal forward link differs from its exact active proposal.");
                    return intent;
                }
                using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactRenewalClosure.ClosedSlot(intent),ct).ConfigureAwait(false);
                if (raw is null)
                { if(count==0)return intent; throw new InvalidDataException("Recorded renewal lost its next protected proposal."); }
                if(count==3)throw new IOException("Recorded renewal history capacity is exhausted.");
                using var closure=raw.Use(bytes=>ProtectedDid2ContactRenewalClosure.Decode(bytes,networkId,account.Span,instance));
                if(!FixedRoute(closure.OldIntent.Span,intent))throw new CryptographicException("Recorded renewal forward link changed its old intent.");
                if (expectedRequestHash is not null)
                {
                    using var old = ProtectedDid2ContactRouteJournal.Entry.Decode(closure.ExactOldPhase1.Span, networkId, account.Span);
                    if (!FixedRoute(expectedRequestHash, SHA256.HashData(old.Record(12).Span)))
                        throw new CryptographicException("Recorded renewal forward links changed their exact proposal.");
                    CryptographicOperations.ZeroMemory(expectedRequestHash);
                }
                expectedRequestHash = closure.NextRequestHash.ToArray();
                CryptographicOperations.ZeroMemory(intent);intent=closure.NextIntent.ToArray();
            }
        }
        catch { CryptographicOperations.ZeroMemory(intent); throw; }
        finally { if (expectedRequestHash is not null) CryptographicOperations.ZeroMemory(expectedRequestHash); }
    }

    private async Task<VerifiedDeepIdV2ContactRouteRecordedHistory?> ReadRecordedRenewalHistoryAsync(
        ProtectedDid2ContactRouteJournal.Entry entry, DeepIdV2CurrentContactAuthorization authorization,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, DeepIdV2ContactPathAuthoritySource source,
        CancellationToken ct)
    {
        var account=authorization.Authorization.Record.DeepAccountId;
        var instance=await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage,networkId,account,ct).ConfigureAwait(false);
        var closures=new List<ProtectedDid2ContactRenewalClosure>();
        var request=entry.Record(12).ToArray(); var latestNextIntent=Array.Empty<byte>();
        try
        {
            for(var count=0;;count++)
            {
                var requestHash=SHA256.HashData(request);
                using var origin=await storage.ReadOwnedAsync(ProtectedDid2ContactRenewalClosure.OriginSlot(requestHash),ct).ConfigureAwait(false);
                if(origin is null)break;
                if(count==3)throw new IOException("Recorded renewal history capacity is exhausted.");
                var originBytes=origin.Use(bytes=>bytes.ToArray());
                try
                {
                    if(originBytes.Length!=ProtectedDid2ContactRenewalClosure.OriginBytes)throw new InvalidDataException("Recorded renewal origin is truncated.");
                    using var raw=await storage.ReadOwnedAsync(ProtectedDid2ContactRenewalClosure.ClosedSlot(originBytes.AsSpan(120,32)),ct).ConfigureAwait(false)??throw new InvalidDataException("Recorded renewal origin has no closure.");
                    var closure=raw.Use(bytes=>ProtectedDid2ContactRenewalClosure.Decode(bytes,networkId,account.Span,instance));closures.Add(closure);
                    closure.RequireOrigin(originBytes,requestHash);
                    if(count==0)latestNextIntent=closure.NextIntent.ToArray();
                    using var old=ProtectedDid2ContactRouteJournal.Entry.Decode(closure.ExactOldPhase1.Span,networkId,account.Span);
                    var previousRequest = old.Record(12).ToArray();
                    CryptographicOperations.ZeroMemory(request); request = previousRequest;
                }
                finally{CryptographicOperations.ZeroMemory(originBytes);}
            }
            if(closures.Count==0)return null;
            var oldest=closures[^1];
            if(closures.Any(value=>!FixedRoute(value.PermanentIntent.Span,oldest.PermanentIntent.Span)||!FixedRoute(value.CompletedBaseEntryHash.Span,oldest.CompletedBaseEntryHash.Span)))
                throw new CryptographicException("Recorded renewal origins changed their completed anchor.");
            using var journal=await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot,ct).ConfigureAwait(false)??throw new InvalidDataException("Recorded renewal journal is absent.");
            using var state=journal.Use(bytes=>ProtectedDid2ContactRouteJournal.Decode(bytes,networkId,account.Span,instance));
            await HydratePublicationArchiveAsync(state, journal, account, instance, ct, selectedIntent: Convert.ToHexString(latestNextIntent)).ConfigureAwait(false);
            ProtectedDid2ContactRouteJournal.Entry? completed=null;
            foreach(var locator in new[]{oldest.PermanentIntent.ToArray(),latestNextIntent})
            {
                if(!state.Entries.TryGetValue(Convert.ToHexString(locator),out var candidate)||candidate.Phase!=7)continue;
                var normalized=candidate.Exact.ToArray();
                try{oldest.PermanentIntent.Span.CopyTo(normalized);if(FixedRoute(SHA256.HashData(normalized),oldest.CompletedBaseEntryHash.Span)){completed=candidate;break;}}
                finally{CryptographicOperations.ZeroMemory(normalized);}
            }
            if(completed is null)throw new CryptographicException("Recorded renewal lost its exact completed base custody.");
            var predecessor=await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(authorization,fresh.Network,fresh.Authority,completed.Record(5),completed.Record(6),source.RendezvousTrustedTime,ct).ConfigureAwait(false);
            var pairs=new List<DeepIdV2ContactRouteRecordedPair>();
            foreach(var closure in closures.AsEnumerable().Reverse())
            { using var old=ProtectedDid2ContactRouteJournal.Entry.Decode(closure.ExactOldPhase1.Span,networkId,account.Span);pairs.Add(new(old.Record(12).Span,closure.ExactRecordedResponse.Span)); }
            return await DeepIdV2ContactRouteVerifier.VerifyRecordedHistoryAsync(authorization,fresh.Network,fresh.Authority,predecessor,pairs,source.RendezvousTrustedTime,ct).ConfigureAwait(false);
        }
        finally{CryptographicOperations.ZeroMemory(request);CryptographicOperations.ZeroMemory(instance);CryptographicOperations.ZeroMemory(latestNextIntent);foreach(var closure in closures)closure.Dispose();}
    }
}
