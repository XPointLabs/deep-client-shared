# Deep Client Shared

Portable .NET account, protocol-custody, persistence and service code for the
Windows and Android Deep clients. The MAUI app references
`src/Deep.Client.Shared/Deep.Client.Shared.Production.csproj`.

The DID2 clean-break is in progress. The production assembly may contain
historically named `*V1` components when their exact wire type is still part of
the DID2 profile (for example DMD1 or XPS1); that name alone is not permission
to accept DID1/DAB1 or the old `05…` account alias. The old Session-derived
client project and tests are not release evidence and will be removed as their
remaining useful coverage is moved to the production test project.

The current `DPH2` session ID is a 32-byte cryptographic ratchet/dedup value,
not the retired user-facing Session address. Initial messaging is fail-closed
until the exact DID2 sender, V2 contact/prekey publication, authenticated
ContactHello, durable inbox and ACK path are one verified graph.

The DID2 account service can now begin a DPH2 claim from its own exact
current DAB2/DMD1 proof and complete it against a verified DPK2 through the
protected, one-use current-device agreement ledger. Both operations recheck
the proof's nonce window and exact protected directory floor; an older proof
cannot be reused after another lookup advances that floor. Completion returns
only Protocol's single-use preparation, not a private key or a delivery
receipt. MAUI publication/claim transport, session persistence and receive
composition remain separate release gates.

## Verify

```powershell
dotnet test Deep.Client.Shared.Production.slnx --configuration Release -m:1
```

See [`AGENTS.md`](AGENTS.md) for repository boundaries and test requirements.
