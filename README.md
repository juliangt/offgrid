# Off-Grid DTN Messaging System

Asynchronous, end-to-end encrypted (E2EE) messaging that works with **no Internet, no cellular network and no satellites**. It is a delay-tolerant network (DTN) built from two moving parts:

- **Fixed dead-drop nodes** — Raspberry Pi Zero 2 W boards running an open Wi-Fi access point with a captive portal and a self-contained HTTP daemon (Go + SQLite). Nodes are *blind mailboxes*: they store and serve opaque encrypted envelopes without ever seeing plaintext, keys or sender identities.
- **Mobile data mules** — ordinary users' phone browsers. While moving between nodes, a mule's browser carries other people's encrypted envelopes in its `IndexedDB` (capacity 100 envelopes) and drops them off at the next portal it reaches.

All cryptography happens on the client (X25519 + XSalsa20-Poly1305 for confidentiality, Ed25519 for identity/signatures, via an embedded `tweetnacl.js`). The envelope format is designed from day one to migrate, without rewriting the data structure, to BLE L2CAP (Phase 2) and LoRa P2P (Phase 3).

## How a message travels

1. Alice registers once on the portal: alias + key pairs generated on her device; private keys never leave her browser's `IndexedDB`.
2. She picks Bob from the node's public directory and writes a message (up to 128 bytes). Her client signs, encrypts, addresses the envelope with a blind `dest_hint` and computes its `id`.
3. The envelope enters a node via `POST /api/v1/sync` — the node only sees random bytes and a truncated key hash.
4. Any syncing user becomes a mule: unknown envelopes ride along in their `transit_queue`.
5. At the next node the mule pushes the envelope; the nodes never talk to each other.
6. Bob syncs, recognizes his own `dest_hint`, decrypts, verifies Alice's Ed25519 signature, and the message lands in his inbox.

## Phase 1 components

| Module | Scope | Location |
|---|---|---|
| **A — Node network configuration** | `hostapd` (open AP), `dnsmasq` (DHCP + wildcard DNS), `iptables` (captive-portal redirects, client isolation), power optimizations for solar + LiFePO4 | `raspberry/` |
| **B — Node daemon** | Single static Go binary: HTTP API, SQLite storage (`WAL`), canonical-host middleware, 15-minute cleanup worker, `index.html` embedded via `embed.FS` | `node/` |
| **C — SPA + crypto engine** | Single-file `web/index.html` (inline HTML/CSS/JS) with `tweetnacl.js` embedded, IndexedDB store (`identity`, `inbox`, `transit_queue`), mule sync engine | `node/web/` |
| **D — Protocol evolution mapping** | How the universal Envelope maps to BLE L2CAP CoC with `hop_count <= 7` (Phase 2) and to LoRa SX1262 at 915 MHz in CBOR within a 222-byte MTU (Phase 3) | `docs/protocolo.md` |

## Documentation

- **`docs/protocolo.md`** — the *normative* protocol specification: envelope format, canonical serialization, key derivations (`id`, `dest_hint`), crypto primitives, binding limits, node SQLite schema and API behavior, threat model and the Phase 2/3 evolution mapping. If you implement Modules B or C, start there.
- **`PLAN_DESARROLLO.md`** — binding development plan (in Spanish): design decisions, architecture, sprint breakdown and acceptance criteria.
- **`prompt_maestro_de_desarrollo.md`** — original master specification (in Spanish, source of truth for requirements).

## Repository layout

```
offgrid/
├── docs/            # normative protocol spec, build and hardware docs
├── node/            # Module B: Go daemon (internal: storage, api, cleanup, envelope; web/: SPA)
├── raspberry/       # Module A: hostapd, dnsmasq, firewall, power, systemd configs
└── tests/           # crypto round-trip (Node) and E2E sync (curl) tests
```

## Status

Development follows five sprints (see `PLAN_DESARROLLO.md` §5):

| Sprint | Scope | Status |
|---|---|---|
| 0 | Protocol & scaffolding: `.gitignore`, repo structure, README, normative `docs/protocolo.md`, threat model | **Complete** |
| 1 | Module B: Go node daemon (storage, API, cleanup, embedded SPA host) | **Complete** |
| 2 | Module C: SPA + crypto engine + mule engine | **Complete** |
| 3 | Module A: Raspberry Pi infrastructure | **Complete** |
| 4 | E2E integration, Module D final docs, build/deploy guide | Pending |

Sprint 2 delivered the single-file SPA (`node/web/index.html`) with the
tweetnacl crypto engine embedded inline: registration with seed backup/import,
directory-driven composition with a 128-byte UTF-8 counter, inbox, mule
telemetry panel, the captive "open in your full browser" banner, the IndexedDB
store (`dtn_local_store` v1) and the full mule sync engine (push/pull with
FIFO transit capacity 100). The engine is verified by
`node tests/crypto_roundtrip.mjs` (spec §6 test vectors included).

Sprint 3 delivered the Module A network infrastructure in `raspberry/`: an
open-AP `hostapd.conf` (channel 6, `ap_isolate=1`), `dnsmasq.conf` (DHCP pool
10.42.0.50–250 with options 3/6 pointing at the node, wildcard DNS +
`portal.red.local`), an idempotent firewall script (TCP/80 → 8080 REDIRECT,
FORWARD policy DROP as the L3 half of client isolation), power trim
(`config.txt` snippet + `dtn-power.service`, ~1 W target), a hardened
`dtn-node.service` with sd_notify watchdog support (`internal/sdnotify`, pure
Go) and a strictly idempotent `provision.sh` that switches Bookworm from
NetworkManager to the classic ifupdown + hostapd + dnsmasq + iptables stack
and never starts services mid-run — a reboot is the activation step.
