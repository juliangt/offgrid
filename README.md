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
| **D — Protocol evolution mapping** | How the universal Envelope maps to BLE L2CAP CoC with `hop_count <= 7` (Phase 2) and to LoRa SX1262 at 915 MHz in CBOR within a 222-byte MTU (Phase 3) | `docs/protocol.md` |

## Documentation

- **`docs/protocol.md`** — the *normative* protocol specification: envelope format, canonical serialization, key derivations (`id`, `dest_hint`), crypto primitives, binding limits, node SQLite schema and API behavior, threat model and the Phase 2/3 evolution mapping (§14, with §14.4 listing where each mapping lives in the code). If you implement Modules B or C, start there.
- **`docs/BUILD.md`** — step-by-step build, run, test and Raspberry Pi deployment guide, with troubleshooting.
- **`docs/hardware.md`** — solar + LiFePO4 sizing math, wiring, SD/enclosure guidance and the node assembly checklist.
- **`DEVELOPMENT_PLAN.md`** — binding development plan: design decisions, architecture, sprint breakdown and acceptance criteria.
- **`MASTER_DEVELOPMENT_PROMPT.md`** — original master specification (source of truth for requirements).

## Repository layout

```
offgrid/
├── docs/            # normative protocol spec, build and hardware docs
├── node/            # Module B: Go daemon (internal: storage, api, cleanup, envelope; web/: SPA)
├── raspberry/       # Module A: hostapd, dnsmasq, firewall, power, systemd configs
└── tests/           # crypto round-trip (Node) and E2E sync (curl) tests
```

## Architecture recap

One self-contained static Go binary (`node/`, with the single-file SPA embedded via `go:embed`) serves, behind a canonical-host redirect that forces every browser onto the shared origin `http://portal.red.local:8080`, a blind SQLite dead-drop API: clients do all cryptography (X25519 + XSalsa20-Poly1305 boxes, Ed25519 signatures, sign-then-encrypt — tweetnacl embedded in `node/web/index.html`), so nodes store and serve opaque envelopes deduplicated by client-computed ids, TTL-filtered, and swept by a 15-minute janitor. Phones are the transport: each portal visit pushes what a mule carries and pulls what it does not know into a 100-envelope `IndexedDB` transit queue, and physical movement between identical nodes delivers mail — the same envelope format maps, without rewrites, onto BLE L2CAP (Phase 2) and LoRa CBOR (Phase 3) per `docs/protocol.md` §14. See `docs/` for the normative protocol, the build/deploy guide and the hardware design.

## Verification

From the repository root (expected outputs in `docs/BUILD.md` §4):

```bash
cd node && go test ./... -count=1 && cd ..   # Go unit tests (storage, api, envelope, main, sdnotify)
node tests/crypto_roundtrip.mjs              # 44 assertions against the SPA's embedded crypto engine
bash tests/sync_e2e.sh                       # 31 assertions: two real daemons + mule walk, curl only
```

All three must pass; `bash tests/sync_e2e.sh` additionally simulates the full Alice → node A → mule → node B → Bob journey and asserts payload byte integrity (sha256) through the mule, dedup, TTL filtering, the 1 MiB/400 rejections and the canonical-host/captive-probe redirect pair.

## Acceptance traceability

Translation of `DEVELOPMENT_PLAN.md` §8 — every master-prompt acceptance criterion and where it is implemented:

| Master-prompt criterion | Where implemented |
|---|---|
| `/etc/hostapd/hostapd.conf` (open AP, channel 6, `ap_isolate=1`) | `raspberry/hostapd/hostapd.conf`, installed by `raspberry/provision.sh` |
| `/etc/dnsmasq.conf` (DHCP 10.42.0.50–250, GW/DNS 10.42.0.1, wildcard DNS) | `raspberry/dnsmasq/dnsmasq.conf` |
| `iptables` (80→8080 redirect, captive probes) | `raspberry/firewall/iptables.sh` + probe endpoints `node/internal/api/handlers.go` (`handleProbe`) and their redirect exemption in `node/internal/api/middleware.go` |
| Power optimization (HDMI, LEDs, solar/LiFePO4) | `raspberry/power/config.txt.snippet`, `raspberry/power/dtn-power.service`, sizing in `docs/hardware.md` |
| SQLite: exact tables, columns and indexes | `node/internal/storage/storage.go` (`schema`, pragmas, single connection) |
| Exact API endpoints (`GET /`, probes, directory GET/POST, sync) | `node/internal/api/handlers.go` (routes + limits), served from `node/main.go` |
| 15-minute cleanup worker | `node/internal/cleanup/cleanup.go` (+ startup sweep), wired in `node/main.go` |
| `embed.FS` with a single `index.html` | `node/main.go` (`webFS`, `//go:embed web`) |
| X25519+Ed25519 client-side, server without keys | `node/web/index.html` (embedded tweetnacl engine), verified by `tests/crypto_roundtrip.mjs` |
| `dtn_local_store`: identity / inbox / transit_queue (capacity 100) | `node/web/index.html` (IndexedDB layer, `TRANSIT_CAPACITY`) |
| Sync on page load + own/foreign envelope classification | `node/web/index.html` (mule sync engine), exercised E2E by `tests/sync_e2e.sh` |
| UI: registration, directory, composer with byte counter, inbox, mule telemetry | `node/web/index.html` (sections 6+) |
| bitchat L2CAP mapping (`hop_count ≤ 7`) and LoRa CBOR within 222 B | `docs/protocol.md` §14 (+ §14.4 anchors table), mirrored in `node/internal/envelope/envelope.go` and above `buildEnvelope` in `node/web/index.html` |
| Complete code without `TODO` placeholders | repo-wide; `gofmt`/`go vet` clean, no placeholders in any shipped file |
| Step-by-step build/run/test instructions | `docs/BUILD.md` |

## Status

Development follows five sprints (see `DEVELOPMENT_PLAN.md` §5):

| Sprint | Scope | Status |
|---|---|---|
| 0 | Protocol & scaffolding: `.gitignore`, repo structure, README, normative `docs/protocol.md`, threat model | **Complete** |
| 1 | Module B: Go node daemon (storage, API, cleanup, embedded SPA host) | **Complete** |
| 2 | Module C: SPA + crypto engine + mule engine | **Complete** |
| 3 | Module A: Raspberry Pi infrastructure | **Complete** |
| 4 | E2E integration, Module D final docs, build/deploy guide | **Complete** |

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

Sprint 4 closed the plan: `tests/sync_e2e.sh` reproduces the complete mule
journey without hardware (two real daemons, the §3.2 spec envelope parsed
verbatim from `docs/protocol.md`, byte-integrity assertions through the
mule, dedup/TTL/limit/redirect negatives); the Module D Phase 2/3 mapping is
anchored on all three surfaces (Go `Envelope` doc-comment, SPA
`buildEnvelope` comment, spec §14.4); `docs/BUILD.md` and
`docs/hardware.md` document the whole build→deploy→verify path; and a
hardening pass added the cold-start `-db` directory bootstrap plus the
5000-envelope anti-abuse node cap (`429 node_full`, spec §8.1). Remaining
manual items require physical hardware (two-node walk test and captive
mini-browser on real Android/iOS) — see `docs/BUILD.md` §5 and §7 for
the on-site checklists.
