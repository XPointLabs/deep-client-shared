# Required producer contract for P03

P01 defines observable properties and gates only. It does not select or design a cryptographic primitive.

P03 must provide a versioned contract with:

1. Separate opaque deposit and retrieval capabilities. Neither value may be a raw Session ID, public key, provider token or deterministic transform that a service can reverse or join without additional secret material.
2. Sender authentication and abuse controls that do not reveal a stable sender identity to storage.
3. Capability expiry, bounded replay behavior, revocation and explicit authenticated failure semantics.
4. Rotation epochs with bounded overlap. Values from different epochs, accounts and transports must not be linkable by equality.
5. Multi-device and offline recovery rules, including how a newly linked device obtains current capabilities without falling back to a raw-account lookup.
6. A storage API in which deposit and retrieve requests do not repeat sender or recipient inside managed outer JSON.
7. A push API using rotating handles rather than raw account keys, with overlap, retry, unregister and account-switch behavior.
8. Domain separation between storage deposit, storage retrieve and push handles.
9. Test vectors and an independent security review before the P01 finding status can become `resolved`.
10. A migration profile that can read legacy data during a bounded transition but never silently downgrades a strict release client.

Required negative tests:

- storage cannot join deposit to retrieve by equality of a stable account value;
- ingress+storage cannot recover a raw sender-recipient pair from managed payloads;
- storage+push cannot join records by raw account or a shared stable handle;
- replay outside the defined window fails;
- expired, revoked, wrong-domain and wrong-epoch capabilities fail closed;
- account switch, logout and device-token rotation cannot reuse the prior handle.

Candidate systems may be reviewed for established constructions, but they are references rather than a design decision:

- [RFC 9458: Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458)
- [Signal sealed sender overview](https://signal.org/blog/sealed-sender/)
- [libsignal](https://github.com/signalapp/libsignal)
- [Session Android](https://github.com/session-foundation/session-android)
- [Session Desktop](https://github.com/session-foundation/session-desktop)

Any adopted construction needs a written threat model and external cryptographic review. Passing P01 requires evidence of the producer properties above, not a construction name.
