# Off-Grid DTN Messaging System

Asynchronous, end-to-end encrypted (E2EE) messaging that works with **no Internet, no cellular network and no satellites** — just Wi-Fi access points, ordinary phone browsers, and people walking between them.

## Initial inspiration

The project combines three ideas:

- **Delay-tolerant networking (DTN) / store-and-forward** — messages are atomic envelopes that sit in untrusted mailboxes until a path to the recipient shows up. Nodes never talk to each other; *physical human movement is the transport layer*.
- **Sneakernet / data mules** — anyone who opens the portal at one node and later at another carries other people's encrypted envelopes in their browser, extending the network wherever its users go.
- **bitchat and Nostr** — the envelope format follows their model of small, self-contained, signed events (~180–250 bytes), so the same data structure can later migrate, without rewrites, to Bluetooth LE (Phase 2) and LoRa point-to-point radio (Phase 3).

## Objective

Enable asynchronous, private communication between people in zones without connectivity — rural areas, remote trails, disaster response, community networks — using commodity hardware:

- **Fixed dead-drop nodes** — Raspberry Pi boards (baseline: the **Pi Zero W**; every model with on-board Wi-Fi works, and the rest through an AP-capable USB adapter — see [`docs/pi-models.md`](docs/pi-models.md)) broadcasting an open Wi-Fi access point with a captive portal. Each node is a **blind mailbox**: one self-contained Go binary with SQLite that stores and serves opaque encrypted envelopes without ever seeing plaintext, keys or sender identities.
- **Mobile data mules** — ordinary users' phone browsers. While moving between nodes, a mule's browser carries other people's encrypted envelopes in its `IndexedDB` (capacity: 100 envelopes) and drops them off at the next portal it reaches.

All cryptography happens on the client: X25519 + XSalsa20-Poly1305 for confidentiality, Ed25519 for identity and signatures (via a vendored `tweetnacl.js`). Private keys never leave the browser.

## Architecture

```
   Alice ──► Node A ──► mule (any phone in transit) ──► Node B ──► Bob
        Wi-Fi       encrypted envelopes ride in             Wi-Fi
     (captive       the mule's IndexedDB queue           (captive
      portal)                                             portal)
```

Key design decisions:

- **Same-origin trick** — every node serves the portal at the same URL, `http://offgrid.local:8080` (gateway `10.42.0.1`, wildcard DNS), so a phone's `IndexedDB` keeps one identity and one transit queue across all nodes.
- **Zero-trust intermediaries** — envelopes are sign-then-encrypt, addressed to a truncated key hash (`dest_hint`). Nodes and mules see only random bytes and a truncated key hash — never content, sender identity or the full recipient key.
- **Self-contained nodes** — a single static Go binary serves the API and the whole SPA (embedded via `go:embed`). No CDNs, no cloud calls, nothing external; everything is served from the Pi.
- **Lightweight envelope** — JSON/Base64 in Phase 1 within binding limits (128-byte plaintext, 1 MiB envelope cap, 5000-envelope node cap, per-envelope TTL with a 15-minute janitor), designed to map onto BLE L2CAP and LoRa CBOR frames in later phases.

### How a message travels

1. Alice registers once on the portal: alias + key pairs generated on her device; private keys never leave her browser's `IndexedDB`.
2. She picks Bob from the node's public directory and writes a message (up to 128 bytes). Her client signs, encrypts, addresses the envelope with a blind `dest_hint` and computes its `id`.
3. The envelope enters a node via `POST /api/v1/sync` — the node only sees random bytes and a truncated key hash.
4. Any syncing user becomes a mule: unknown envelopes ride along in their `transit_queue`.
5. At the next node the mule pushes the envelope; the nodes never talk to each other.
6. Bob syncs, recognizes his own `dest_hint`, decrypts, verifies Alice's Ed25519 signature, and the message lands in his inbox.

## Installation

### Raspberry Pi node (one command)

On a fresh Raspberry Pi OS **Lite** install (Zero W or newer — the per-model matrix, including which OS image and binary each board needs, is [`docs/pi-models.md`](docs/pi-models.md)):

```bash
curl -fsSL https://raw.githubusercontent.com/juliangt/offgrid/main/raspberry/install.sh \
  | sudo bash -s -- --country AR
```

The installer detects the board, fetches the matching release binary (checksum-verified) plus the provisioning tree, runs the verified `provision.sh`, and asks to reboot — the reboot is the activation step. The node then announces the open `offgrid-messages` access point with the captive portal on its own.

**No Internet at the deployment site?** Copy a release's assets onto a USB stick or the SD card's FAT partition and run:

```bash
sudo ./install.sh --offline /media/usb --country AR
```

The full manual path (build + copy) is in [`docs/BUILD.md`](docs/BUILD.md) §5. Prebuilt binaries for armv6/armv7/arm64 plus `SHA256SUMS` are attached to every release tag.

### Hardware

For solar-powered deployment (~1 W continuous target): solar + LiFePO4 sizing math, wiring, SD card and enclosure guidance are in [`docs/hardware.md`](docs/hardware.md).

## Usage

Each node broadcasts the open Wi-Fi network `offgrid-messages`. Anyone in range:

1. **Joins the network** — the captive portal opens automatically (or browse to `http://offgrid.local:8080`).
2. **Registers once** — picks an alias; key pairs are generated on the device and stay there (with an optional seed backup).
3. **Writes messages** — picks a recipient from the public directory (alias + public key) and sends up to 128 bytes of UTF-8 text.
4. **Syncs automatically on page load** — pushes what it carries, pulls what's addressed to it into the inbox, and keeps unknown envelopes (up to 100) in the transit queue for the next node. A telemetry panel shows what the phone is carrying: *"Foreign envelopes in transit: X / Capacity: Y"*.

That's the whole interaction: sending is leaving a note at one mailbox, receiving is walking past another. Envelopes expire via TTL and are swept every 15 minutes, so the network self-cleans.

## Building and testing from source

Requirements: Go 1.26+ and Node.js (tests only). From the repository root:

```bash
cd node && ./build.sh && cd ..     # cross-compiles arm64/armv7/armv6 + dev binary
cd node && go test ./... -count=1 && cd ..
node tests/crypto_roundtrip.mjs    # 44 assertions against the SPA crypto engine
node tests/spa_structure.mjs       # 91 assertions on the SPA layout, CSP and API surface
bash tests/sync_e2e.sh             # 31 assertions: two real daemons + full mule walk (curl only)
```

`tests/sync_e2e.sh` simulates the complete Alice → node A → mule → node B → Bob journey and asserts payload byte integrity (sha256) through the mule, dedup, TTL filtering, limit rejections and the captive-portal redirects. Expected outputs: [`docs/BUILD.md`](docs/BUILD.md) §4.

## Repository layout

```
offgrid/
├── .github/         # release workflow: binaries + per-model DEPLOY.md per tag
├── docs/            # protocol spec, build/hardware docs, per-model matrix
├── node/            # Go daemon (internal: storage, api, cleanup, envelope; web/: SPA)
├── raspberry/       # install.sh, provision.sh, hostapd, dnsmasq, firewall, power, systemd
└── tests/           # crypto round-trip (Node), SPA structure, E2E sync (bash/curl)
```

## Documentation

| Document | Contents |
|---|---|
| [`docs/protocol.md`](docs/protocol.md) | **Normative protocol spec**: envelope format, canonical serialization, key derivations, crypto primitives, binding limits, node schema and API, threat model, Phase 2 (BLE) / Phase 3 (LoRa) mapping |
| [`docs/BUILD.md`](docs/BUILD.md) | Build, run locally, test and deploy to a Pi (online / offline / manual), plus troubleshooting and on-site checklists |
| [`docs/pi-models.md`](docs/pi-models.md) | Support matrix for every Raspberry Pi model: OS image, binary, Wi-Fi caveats, performance and power notes |
| [`docs/hardware.md`](docs/hardware.md) | Solar + LiFePO4 sizing math, bill of materials, wiring diagram, assembly checklist |
| [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md) | Design decisions and rationale (same-origin trick, threat model, byte budgets, OS choices) |
| [`docs/MASTER_DEVELOPMENT_PROMPT.md`](docs/MASTER_DEVELOPMENT_PROMPT.md) | Original master specification (source of truth for requirements) |

## Status and roadmap

- **Phase 1 (this repository) — complete**: Wi-Fi dead-drop nodes + browser data mules over HTTP, covered by the automated test suite above. The remaining manual item is on-hardware acceptance with a physical Pi Zero W (see [`docs/BUILD.md`](docs/BUILD.md) §5 and §7).
- **Phase 2 — BLE**: direct phone-to-phone transfer over BLE L2CAP connection-oriented channels with `hop_count ≤ 7`; the envelope format and the code-level mapping are already defined in [`docs/protocol.md`](docs/protocol.md) §14.
- **Phase 3 — LoRa**: long-range radio backhaul between zones, envelope packed as CBOR within the 222-byte SX1262 MTU at 915 MHz (same spec section).
