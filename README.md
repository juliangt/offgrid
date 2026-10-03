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
| 1 | Module B: Go node daemon (storage, API, cleanup, embedded SPA host) | Pending |
| 2 | Module C: SPA + crypto engine + mule engine | Pending |
| 3 | Module A: Raspberry Pi infrastructure | Pending |
| 4 | E2E integration, Module D final docs, build/deploy guide | Pending |
