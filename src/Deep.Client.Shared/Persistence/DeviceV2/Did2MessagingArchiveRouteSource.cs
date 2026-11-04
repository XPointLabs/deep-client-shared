using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static class Did2MessagingArchiveRouteSource
{
    internal static (ParsedXir1V2 Invite, ParsedContactRouteClosure Route) Completed(Did2RouteHistorySource source,
        Func<Did2MessagingArchiveReference, ReadOnlyMemory<byte>> original)
    {
        var message = ApplicationCoreCodec.DecodeDmc2(original(source.Reference).Span);
        if (source.AtomIndex == 0)
        {
            var package = message.ParsedPayload switch
            {
                ContactHelloDmc2Payload hello => hello.MailboxRoute,
                ContactAcceptDmc2Payload accept => accept.MailboxRoute,
                _ => throw new CryptographicException("Historical C seed is not its actual original relationship anchor.")
            };
            return (package.Invite, package.Route);
        }
        var atom = Atom(source, message);
        if (!atom.IsCompleted) throw new CryptographicException("Historical C names a proposal-only atom.");
        return (DeepIdV2InviteRendezvousCodec.Decode(atom.ExactCompletedXir1V2.Span), ContactRouteClosureCodec.Decode(atom.ExactCompletedRoute.Span));
    }

    internal static (ContactRecord Xra, ContactRecord Xrc, ContactRecord Xss) Proposal(Did2RouteHistorySource source,
        Func<Did2MessagingArchiveReference, ReadOnlyMemory<byte>> original)
    {
        var message = ApplicationCoreCodec.DecodeDmc2(original(source.Reference).Span);
        if (source.AtomIndex == 0)
        {
            var package = message.ParsedPayload switch
            {
                ContactHelloDmc2Payload hello => hello.MailboxRoute,
                ContactAcceptDmc2Payload accept => accept.MailboxRoute,
                _ => throw new CryptographicException("Historical P seed is not its actual original relationship anchor.")
            };
            return (package.Route.Authorization, package.Route.Route, package.Route.Successor);
        }
        var atom = Atom(source, message);
        return (ContactCodec.Decode("XRA1", atom.ExactXra1.Span),
            ContactCodec.Decode("XRC1", atom.ExactXrc1.Span), ContactCodec.Decode("XSS1", atom.ExactXss1.Span));
    }

    internal static ParsedDeepIdV2ContactRouteHistoryAtom Atom(Did2RouteHistorySource source, ParsedDmc2 message)
    {
        if (message.ParsedPayload is not ContactRouteHistoryDmc2Payload page || source.AtomIndex == 0 || source.AtomIndex > page.Atoms.Count)
            throw new CryptographicException("Historical source names an absent count8 atom.");
        return page.Atoms[source.AtomIndex - 1];
    }
    internal static ulong Generation(ContactRecord record) => BinaryPrimitives.ReadUInt64BigEndian(record.Field(3).Span);
}
