# P01 observer and collusion matrix

Status: current-state characterization; not a privacy claim. Owner for human decisions: Mr. X.

## Current data flow

`client -> network ingress -> routed hop 1 -> routed hop 2 -> storage exit -> storage`

Push is a separate flow:

`client -> push service -> platform provider`

The routed transport encrypts each onion layer, but the final storage layer still contains the current storage RPC. DPE1 protects content, while its authenticated header contains clear sender and recipient identifiers. The current storage wrapper also repeats sender and recipient in managed JSON.

## Single observers

| Observer | Direct storage mode | Three-hop routed mode | Push flow |
|---|---|---|---|
| Client device / local database | Account, contacts, clear content, timestamps, sizes, route configuration | Same, plus selected route snapshot | Raw account, provider token, notification key and subscription state |
| Access network / ISP | Source IP, storage destination, timing, byte counts | Source IP, router destination, timing, byte counts | Source IP, push destination, timing, byte counts |
| Ingress / first router | Source IP, request timing and size | Source IP, route RPC, first onion envelope, next-hop relationship after layer removal; no final storage body from onion encryption alone | Not in path |
| Middle router | Not applicable | Previous and next hop, timing and size; no client IP unless topology or collusion reveals it | Not in path |
| Storage exit / final router | Not applicable | Previous hop, storage destination, timing, size, and decrypted final storage RPC | Not in path |
| Storage service | Raw recipient `pubkey`, namespace, timestamp, TTL, stable idempotency key and base64 managed payload containing sender and recipient; DPE1 clear header remains inspectable when the managed body carries DPE1 | Same final storage fields after onion exit; onion routing does not hide these from storage | Can correlate only if it obtains push data |
| Push service | Not applicable | Not applicable | Raw account public key, Ed25519 public key, namespaces, stable provider token, application metadata and subscription timing |
| Platform push provider | Not applicable | Not applicable | Provider token, source service, delivery timing/size and device/account metadata held by the platform provider; Deep content remains separately encrypted |
| Crash/log collector | Depends on host app capture | Depends on host app capture | Depends on host app capture |
| Global passive observer | Source/destination timing, volume and IP-level relationship | Client-to-ingress and inter-node/storage timing, sizes and endpoints; padding/mixing is not implemented | Client/push/provider timing and volume |

The shared library currently has no general logging dependency. That is not proof that MAUI, Windows, server, OS crash reporting or provider telemetry is safe. P01 therefore uses synthetic managed-log fixtures and does not change production logging defaults.

## Collusion

| Colluding observers | Current inference |
|---|---|
| Ingress + storage | In routed mode, ingress supplies source IP/timing/size while storage supplies raw recipient and a managed sender-recipient pair. Matching timing and sizes enables high-confidence source-to-account and conversation correlation. |
| Storage + push | Exact raw account public key joins storage retrieval/deposit activity to a provider token and notification subscription. This is a deterministic join, not merely timing inference. |
| Ingress + push | Source network activity can be aligned with raw-account subscription and delivery events. |
| First + middle + final routed hops | Full route reconstruction and timing correlation; final hop exposes the storage RPC. |
| Storage + crash/log collector | Any raw Session ID, provider token, idempotency key or server hash captured by the application can deterministically reinforce storage observations. |
| Global passive observer | Can correlate endpoints, timing, direction and byte counts across all paths. Current code provides no cover traffic, batching, padding or radio-layer protection. |

## Residual channels separate from content secrecy

- Timing: send, retrieve, retry, subscription and notification cadence.
- Size: DPE1 length reveals plaintext length plus fixed overhead; outer JSON/base64 adds a predictable transform.
- IP/topology: access network sees ingress; routed relays see adjacent hops; storage sees the exit.
- Radio and device state: cellular/Wi-Fi association, wakeups, background activity and platform push telemetry.
- Availability behavior: retry intervals, route failover and offline/online transitions.

These channels remain even after opaque capabilities unless later packages add audited padding, batching, mixing, cover traffic and power-aware scheduling.
