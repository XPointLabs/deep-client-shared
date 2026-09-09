using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Client.Shared.Services.GroupV1;
using Deep.Protocol.GroupV1;
using Deep.Protocol.Identity;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.GroupV1;

public sealed class GroupClientStateStoreTests : IDisposable
{
    private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "deep-group-client-" + Guid.NewGuid().ToString("N"));
    private readonly byte[] key = Bytes(32, 0xC1);
    public GroupClientStateStoreTests() => Directory.CreateDirectory(directory);

    [Fact]
    public async Task GenesisExactReplayConflictAndRecipientChunkCursorAreAtomic()
    {
        var fixture = Genesis(); var service = new GroupClientStateService();
        var chunks = Chunks(fixture.Package); var recipient = GroupRecipientKey32.FromOpaqueBytes(Bytes(32, 0x91));
        var plan = service.PrepareVerifiedTransition(Scope(), Operation(1), null, fixture.Transition, fixture.Package, chunks, recipient);
        using var options = Options(Scope()); using var store = new SqliteGroupStateStore(options);

        var applied = await store.CommitVerifiedTransitionAsync(plan);
        Assert.Equal(GroupCommitDisposition.Applied, applied.Disposition);
        Assert.Equal((ulong)1, applied.Head!.Revision); Assert.Equal((ulong)0, applied.Head.Epoch);
        Assert.Single(applied.Head.ControlCursors); Assert.Equal(fixture.Package.ArtifactHash.ToArray(), applied.Head.PackageHash.ToArray());
        Assert.Equal(fixture.Commit.ArtifactHash.ToArray(), applied.Head.CommitHash.ToArray());
        Assert.Equal(fixture.Commit.CanonicalBytes.ToArray(), applied.Head.ExactCanonicalCommit.ToArray());
        Assert.Equal(fixture.Transition.ExactVerifiedGcp1Sha256.ToArray(), applied.Head.ExactVerifiedGcp1Sha256.ToArray());

        Assert.Equal(GroupCommitDisposition.Idempotent, (await store.CommitVerifiedTransitionAsync(plan)).Disposition);
        var conflicting = service.PrepareVerifiedTransition(Scope(), Operation(1), null, fixture.Transition,
            fixture.Package, chunks, GroupRecipientKey32.FromOpaqueBytes(Bytes(32, 0x92)));
        Assert.Equal(GroupCommitDisposition.Conflict, (await store.CommitVerifiedTransitionAsync(conflicting)).Disposition);
        Assert.Single((await store.ReadHeadAsync(GroupId32.FromBytes(fixture.Commit.Field(2).Span)))!.ControlCursors);
    }

    [Fact]
    public async Task SuccessorPersistsCryptographicallyBoundProposalAndInvitationArtifactsAcrossRestart()
    {
        var genesis = Genesis(); var successor = SuccessorWithInvite(genesis.Commit); var service = new GroupClientStateService(); var scope = Scope();
        using (var options = Options(scope))
        using (var store = new SqliteGroupStateStore(options))
        {
            Assert.Equal(GroupCommitDisposition.Applied, (await store.CommitVerifiedTransitionAsync(
                service.PrepareVerifiedTransition(scope, Operation(2), null, genesis.Transition, genesis.Package, Chunks(genesis.Package)))).Disposition);
            var result = await store.CommitVerifiedTransitionAsync(service.PrepareVerifiedTransition(scope, Operation(3), 1,
                successor.Transition, successor.Package, Chunks(successor.Package)));
            Assert.Equal(GroupCommitDisposition.Applied, result.Disposition); Assert.Equal((ulong)2, result.Head!.Revision);
            Assert.Equal(3, result.Head.Artifacts.Count); Assert.Contains(result.Head.Artifacts, x => x.Magic == "DGP1");
            Assert.Contains(result.Head.Artifacts, x => x.Magic == "GIV1"); Assert.Contains(result.Head.Artifacts, x => x.Magic == "GIA1");
        }

        using var reopenOptions = Options(scope, allowCreate: false); using var reopened = new SqliteGroupStateStore(reopenOptions);
        var restored = Assert.Single(await reopened.ReadHeadsAsync());
        Assert.Equal((ulong)1, restored.Epoch); Assert.Equal((ulong)2, restored.Revision); Assert.Equal(3, restored.Artifacts.Count);
        Assert.Equal(successor.Package.CanonicalBytes.ToArray(), restored.ExactCanonicalPackage.ToArray());
        Assert.Equal(successor.Transition.ExactVerifiedGcp1Sha256.ToArray(), restored.ExactVerifiedGcp1Sha256.ToArray());
    }

    [Fact]
    public async Task DistinctSiblingPermanentlyForkLatchesAndRetainsHeadAcrossRestart()
    {
        var genesis = Genesis(); var first = SuccessorWithInvite(genesis.Commit, "first"); var sibling = SuccessorWithInvite(genesis.Commit, "sibling");
        var service = new GroupClientStateService(); var scope = Scope();
        using (var options = Options(scope))
        using (var store = new SqliteGroupStateStore(options))
        {
            await store.CommitVerifiedTransitionAsync(service.PrepareVerifiedTransition(scope, Operation(10), null, genesis.Transition, genesis.Package, Chunks(genesis.Package)));
            await store.CommitVerifiedTransitionAsync(service.PrepareVerifiedTransition(scope, Operation(11), 1, first.Transition, first.Package, Chunks(first.Package)));
            var fork = await store.CommitVerifiedTransitionAsync(service.PrepareVerifiedTransition(scope, Operation(12), 2, sibling.Transition, sibling.Package, Chunks(sibling.Package)));
            Assert.Equal(GroupCommitDisposition.ForkLatched, fork.Disposition); Assert.True(fork.Head!.ForkLatched);
            Assert.Equal(first.Commit.ArtifactHash.ToArray(), fork.Head.CommitHash.ToArray());
        }
        using var reopenOptions = Options(scope, false); using var reopened = new SqliteGroupStateStore(reopenOptions);
        var restored = Assert.Single(await reopened.ReadHeadsAsync()); Assert.True(restored.ForkLatched);
        var blocked = await reopened.CommitVerifiedTransitionAsync(service.PrepareVerifiedTransition(scope, Operation(13), 2, sibling.Transition, sibling.Package, Chunks(sibling.Package)));
        Assert.Equal(GroupCommitDisposition.ForkLatched, blocked.Disposition);
    }

    [Fact]
    public async Task WrongKeyWrongAccountGenerationAndSemanticCorruptionRejectOnOpen()
    {
        var fixture = Genesis(); var scope = Scope(); var service = new GroupClientStateService();
        using (var options = Options(scope)) using (var store = new SqliteGroupStateStore(options))
            await store.CommitVerifiedTransitionAsync(service.PrepareVerifiedTransition(scope, Operation(20), null, fixture.Transition, fixture.Package, Chunks(fixture.Package)));

        using (var wrongKey = new SqliteGroupStateStoreOptions(DbPath(), Bytes(32, 0xEE), scope, false))
            Assert.Throws<GroupStateStoreOpenException>(() => new SqliteGroupStateStore(wrongKey));
        var otherGeneration = new GroupStoreScope(scope.AccountId, 2, GroupStoreScope.CurrentStoreGeneration);
        using (var wrongScope = Options(otherGeneration, false))
        {
            var error = Assert.Throws<GroupStateStoreOpenException>(() => new SqliteGroupStateStore(wrongScope));
            Assert.Equal(GroupStateStoreOpenFailure.ScopeMismatch, error.Reason);
        }

        MutateEncrypted("UPDATE group_heads SET canonical_commit=x'01';");
        using var corrupt = Options(scope, false);
        var corruptError = Assert.Throws<GroupStateStoreOpenException>(() => new SqliteGroupStateStore(corrupt));
        Assert.Equal(GroupStateStoreOpenFailure.Corrupt, corruptError.Reason);
    }

    [Fact]
    public void ProductionSurfaceRequiresVerifiedCapabilityAndHasNoAuthoringOrVerifierCallbacks()
    {
        var method = Assert.Single(typeof(GroupClientStateService).GetMethods(BindingFlags.Instance | BindingFlags.Public), x => x.Name == nameof(GroupClientStateService.PrepareVerifiedTransition));
        Assert.Contains(method.GetParameters(), x => x.ParameterType == typeof(VerifiedGroupTransition));
        Assert.Contains(method.GetParameters(), x => x.ParameterType == typeof(GroupCommitPackageRecord));
        Assert.DoesNotContain(method.GetParameters(), x => typeof(Delegate).IsAssignableFrom(x.ParameterType));
        Assert.Empty(typeof(VerifiedGroupTransition).GetConstructors());
        Assert.DoesNotContain(typeof(GroupClientStateService).GetMethods(), x => x.Name.Contains("Author", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ConcurrentIdenticalSuccessorUsesOneCasCommitAndOneIdempotentObservation()
    {
        var genesis = Genesis(); var successor = SuccessorWithInvite(genesis.Commit); var service = new GroupClientStateService(); var scope = Scope();
        using var options = Options(scope); using var store = new SqliteGroupStateStore(options);
        await store.CommitVerifiedTransitionAsync(service.PrepareVerifiedTransition(scope, Operation(30), null, genesis.Transition, genesis.Package, Chunks(genesis.Package)));
        var first = service.PrepareVerifiedTransition(scope, Operation(31), 1, successor.Transition, successor.Package, Chunks(successor.Package));
        var second = service.PrepareVerifiedTransition(scope, Operation(32), 1, successor.Transition, successor.Package, Chunks(successor.Package));
        var results = await Task.WhenAll(store.CommitVerifiedTransitionAsync(first).AsTask(), store.CommitVerifiedTransitionAsync(second).AsTask());
        Assert.Contains(results, x => x.Disposition == GroupCommitDisposition.Applied);
        Assert.Contains(results, x => x.Disposition == GroupCommitDisposition.Idempotent);
        Assert.All(results, x => Assert.Equal((ulong)2, x.Head!.Revision));
    }

    [Fact]
    public void PackageArtifactsAndChunksMustBeExactlyBoundToVerifiedCommit()
    {
        var genesis = Genesis(); var successor = SuccessorWithInvite(genesis.Commit); var service = new GroupClientStateService(); var scope = Scope();
        Assert.Throws<ArgumentException>(() => service.PrepareVerifiedTransition(scope, Operation(40), null,
            genesis.Transition, genesis.Package, Chunks(successor.Package)));

        var extraProposal = (GroupProposalRecord)Record("DGP1", [genesis.Commit.Field(1).ToArray(),genesis.Commit.Field(2).ToArray(),U64(0),genesis.Commit.ArtifactHash.ToArray(),Bytes(32,61),Bytes(32,2),Bytes(32,3),Ref("DPD1",4),U16(6),Join(U16(1),Encoding.UTF8.GetBytes("x"),new byte[]{0},U32(60)),U64(1),U64(2),Bytes(64,62)]);
        var unbound = Package(genesis.Commit, [extraProposal], []);
        Assert.Throws<ArgumentException>(() => service.PrepareVerifiedTransition(scope, Operation(41), null,
            genesis.Transition, unbound));
    }

    [Fact]
    public async Task ChangedGcp1FailsBeforeStateOrReplayMutation()
    {
        var genesis = Genesis(); var service = new GroupClientStateService(); var scope = Scope();
        var changed = Assert.IsType<GroupCommitPackageRecord>(Record("GCP1",
            Enumerable.Range(1, 10).Select(tag => genesis.Package.Field(tag).ToArray())
                .Append(new byte[] { 1 }).ToArray()));

        Assert.False(genesis.Transition.BindsExactGcp1(changed.CanonicalBytes.Span));
        Assert.Throws<ArgumentException>(() => service.PrepareVerifiedTransition(scope, Operation(42), null,
            genesis.Transition, changed));

        using var options = Options(scope); using var store = new SqliteGroupStateStore(options);
        var changedBytePlan = service.PrepareVerifiedTransition(scope, Operation(42), null,
            genesis.Transition, genesis.Package);
        var storedBytes = Assert.IsType<byte[]>(typeof(GroupTransitionCommitPlan)
            .GetField("canonicalPackage", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(changedBytePlan));
        storedBytes[^1] ^= 0x01;
        await Assert.ThrowsAsync<ArgumentException>(() =>
            store.CommitVerifiedTransitionAsync(changedBytePlan).AsTask());
        Assert.Empty(await store.ReadHeadsAsync());
        var applied = await store.CommitVerifiedTransitionAsync(service.PrepareVerifiedTransition(scope,
            Operation(42), null, genesis.Transition, genesis.Package));
        Assert.Equal(GroupCommitDisposition.Applied, applied.Disposition);
    }

    private (GroupCommitRecord Commit, GroupCommitPackageRecord Package, VerifiedGroupTransition Transition) Genesis()
    {
        var commit = Commit(0, new byte[32], "genesis", []);
        var package = Package(commit, [], []); return (commit, package, Verified(commit, null, package));
    }

    private (GroupCommitRecord Commit, GroupCommitPackageRecord Package, VerifiedGroupTransition Transition) SuccessorWithInvite(GroupCommitRecord predecessor, string name = "group")
    {
        var network = predecessor.Field(1).ToArray(); var group = predecessor.Field(2).ToArray(); var inviteId = Bytes(32, 0x31);
        var invitation = (GroupInvitationRecord)Record("GIV1", [network, group, inviteId, U64(0), predecessor.ArtifactHash.ToArray(), Bytes(32, 2), Bytes(32, 3), Ref("DPD1", 4), Bytes(32, 5), new byte[]{2}, Ref("ADC1",6), Ref("ADH1",7), Bytes(32,8), Bytes(32,9), Ref("DRS1",10), U64(1), U64(2), Bytes(64,11)]);
        var acceptance = (GroupInvitationAcceptanceRecord)Record("GIA1", [network, group, inviteId, Ref("GIV1", invitation.ArtifactHash.Span), Bytes(32,5), Bytes(32,12), Ref("DPD1",13), Ref("ADC1",6), Ref("ADH1",7), Bytes(32,8), Bytes(32,9), Ref("DRS1",10), U64(1), U64(2), Bytes(64,14)]);
        var payload = Join(Ref("GIV1", invitation.ArtifactHash.Span), Ref("GIA1", acceptance.ArtifactHash.Span), Bytes(32,5), new byte[]{2}, Ref("ADC1",6), Ref("ADH1",7), Bytes(32,8), Bytes(32,9), Ref("DRS1",10));
        var proposal = (GroupProposalRecord)Record("DGP1", [network, group, U64(0), predecessor.ArtifactHash.ToArray(), Bytes(32,15), Bytes(32,2), Bytes(32,3), Ref("DPD1",4), U16(1), payload, U64(1), U64(2), Bytes(64,16)]);
        var commit = Commit(1, predecessor.ArtifactHash.ToArray(), name, [proposal.ArtifactHash.ToArray()]);
        var package = Package(commit, [proposal], [(invitation, acceptance)]); return (commit, package, Verified(commit, predecessor, package));
    }

    private static GroupCommitRecord Commit(ulong epoch, byte[] predecessor, string name, byte[][] proposals)
    {
        var members = Member(Bytes(32,2), Bytes(32,3));
        return (GroupCommitRecord)Record("DGC1", [Bytes(16,1),Bytes(32,20),U16(1),U64(epoch),predecessor,Bytes(32,2),Bytes(32,3),Ref("DPD1",4),U16((ushort)proposals.Length),proposals.SelectMany(x=>x).ToArray(),U16(1),members,Encoding.UTF8.GetBytes(name),new byte[]{0},U32(60),U64(epoch+1),Bytes(64,(byte)(30+epoch))]);
    }
    private static byte[] Member(byte[] account, byte[] device)
    {
        var body = Join(account,new byte[]{1},Ref("ADC1",21),Ref("ADH1",22),Bytes(32,23),U64(1),Bytes(32,24),Ref("DRS1",25),new byte[]{1},device,Ref("DPD1",4));
        return Join(U16((ushort)body.Length),body);
    }
    private static GroupCommitPackageRecord Package(GroupCommitRecord commit, GroupProposalRecord[] proposals, (GroupInvitationRecord Invitation, GroupInvitationAcceptanceRecord Acceptance)[] pairs)
    {
        var proposalBytes = proposals.SelectMany(x => Lp(x.CanonicalBytes.Span)).ToArray();
        var pairBytes = pairs.SelectMany(x => Join(Ref("GIV1",x.Invitation.ArtifactHash.Span),Lp(x.Invitation.CanonicalBytes.Span),Ref("GIA1",x.Acceptance.ArtifactHash.Span),Lp(x.Acceptance.CanonicalBytes.Span))).ToArray();
        return (GroupCommitPackageRecord)Record("GCP1", [commit.Field(1).ToArray(),commit.Field(2).ToArray(),commit.Field(4).ToArray(),Lp(commit.CanonicalBytes.Span),U16((ushort)proposals.Length),proposalBytes,U32(0),Array.Empty<byte>(),U16((ushort)pairs.Length),pairBytes,Array.Empty<byte>()]);
    }
    private static GroupCommitChunkRecord[] Chunks(GroupCommitPackageRecord package)
    {
        var bytes = package.CanonicalBytes.ToArray(); return [(GroupCommitChunkRecord)Record("GCF1", [package.ArtifactHash.ToArray(),U32((uint)bytes.Length),U32(24576),U32(0),U32(1),SHA256.HashData(bytes),Lp(bytes)])];
    }
    private static VerifiedGroupTransition Verified(GroupCommitRecord commit, GroupCommitRecord? predecessor,
        GroupCommitPackageRecord package)
    {
        var implementation = typeof(VerifiedGroupTransition).Assembly.GetType("Deep.Protocol.GroupV1.GroupCodec+VerifiedGroupTransitionImpl", throwOnError: true)!;
        var transition = (VerifiedGroupTransition)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(implementation);
        var capability = typeof(VerifiedGroupTransition);
        capability.GetField("<Commit>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(transition, commit);
        capability.GetField("<Predecessor>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(transition, predecessor);
        capability.GetField("exactVerifiedGcp1Sha256", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(transition, SHA256.HashData(package.CanonicalBytes.Span));
        return transition;
    }
    private static GroupRecord Record(string magic, IReadOnlyList<byte[]> fields)
    {
        var length = 12 + fields.Sum(x => 8 + x.Length); var bytes = new byte[length]; Encoding.ASCII.GetBytes(magic).CopyTo(bytes,0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4),1); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6),0x0201); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8),(ushort)fields.Count);
        var at=12; for(var i=0;i<fields.Count;i++){BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(at),(ushort)(i+1));BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(at+4),(uint)fields[i].Length);at+=8;fields[i].CopyTo(bytes,at);at+=fields[i].Length;} return GroupCodec.Decode(magic,bytes);
    }
    private GroupStoreScope Scope(byte marker = 0x71) { var capability = DeepAccountIdentityCapability.FromVerifiedInputs(DeepNetworkId16.FromVerifiedBytes(Bytes(16,1)),1,AccountEd25519PublicKey32.FromVerifiedBytes(Bytes(32,marker))); return GroupStoreScope.ForCurrentAccount(capability.AccountId, capability.AccountGeneration); }
    private SqliteGroupStateStoreOptions Options(GroupStoreScope scope, bool allowCreate = true) => new(DbPath(), key, scope, allowCreate);
    private string DbPath() => System.IO.Path.Combine(directory,"groups.dgv1");
    private void MutateEncrypted(string sql) { SQLitePCL.Batteries_V2.Init(); using var db = new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=DbPath(),Pooling=false}.ToString()); db.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK,SQLitePCL.raw.sqlite3_key(db.Handle,key)); using var cmd=db.CreateCommand();cmd.CommandText=sql;cmd.ExecuteNonQuery(); }
    private static GroupOperationId32 Operation(int value) => GroupOperationId32.FromBytes(SHA256.HashData(BitConverter.GetBytes(value)));
    private static byte[] Ref(string magic, byte marker) => Ref(magic, Bytes(32,marker));
    private static byte[] Ref(string magic, ReadOnlySpan<byte> hash){var b=new byte[38];Encoding.ASCII.GetBytes(magic).CopyTo(b,0);b[5]=1;hash.CopyTo(b.AsSpan(6));return b;}
    private static byte[] Lp(ReadOnlySpan<byte> value)=>Join(U32((uint)value.Length),value.ToArray());
    private static byte[] U16(ushort value){var b=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(b,value);return b;}
    private static byte[] U32(uint value){var b=new byte[4];BinaryPrimitives.WriteUInt32BigEndian(b,value);return b;}
    private static byte[] U64(ulong value){var b=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(b,value);return b;}
    private static byte[] Bytes(int length, byte value)=>Enumerable.Repeat(value,length).ToArray();
    private static byte[] Join(params byte[][] values)=>values.SelectMany(x=>x).ToArray();
    public void Dispose(){try{Directory.Delete(directory,true);}catch(IOException){}catch(UnauthorizedAccessException){}}
}
