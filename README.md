# Off-Grid DTN Messaging System

Asynchronous, end-to-end encrypted (E2EE) messaging that works with **no Internet, no cellular network and no satellites** — just Wi-Fi access points, ordinary phone browsers, and people walking between them.

## Initial inspiration

The project combines three ideas:

- **Delay-tolerant networking (DTN) / store-and-forward** — messages are atomic envelopes that sit in untrusted mailboxes until a path to the recipient shows up. Nodes never talk to each other; *physical human movement is the transport layer*. This follows the DTN **architecture** of RFC 4838 (store-carry-forward, endpoint naming, message lifetimes) — not the IETF Bundle Protocol wire format (RFC 5050/9171); the concept-by-concept alignment audit is [`docs/rfc4838-alignment.md`](docs/rfc4838-alignment.md).
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
- **Zero-trust intermediaries** — envelopes are sign-then-encrypt, addressed to a truncated key hash (`dest_hint`). Since spec 1.6.0 the hint ROTATES per 24-hour epoch (HKDF of the key with the epoch salt) — rotation raises the work factor and bounds retroactive linking after a late key acquisition, but a directory-holding operator can still link envelopes to aliases permanently (protocol §13.3). Nodes and mules see only random bytes and an opaque hint — never content, sender identity or the full recipient key.
- **Self-contained nodes** — a single static Go binary serves the API and the whole SPA (embedded via `go:embed`). No CDNs, no cloud calls, nothing external; everything is served from the Pi.
- **Lightweight envelope** — JSON/Base64 in Phase 1 within binding limits (128-byte plaintext per envelope — longer texts are split client-side into several ordinary envelopes and reassembled transparently, 1 MiB envelope cap, 5000-envelope node cap, per-envelope TTL with a 15-minute janitor), designed to map onto BLE L2CAP and LoRa CBOR frames in later phases.

### How a message travels

1. Alice registers once on the portal: alias + key pairs generated on her device; private keys never leave her browser's `IndexedDB`.
2. She picks Bob from the node's public directory (or from her saved in-person contacts — see the QR exchange in Usage) and writes a message (up to 128 bytes per envelope; her client splits longer texts into several envelopes — 16 at most — and Bob's reassembles them into one message). Her client signs, encrypts, addresses each envelope with a blind `dest_hint` and computes its `id`.
3. The envelope enters a node via `POST /api/v1/sync` — the node only sees random bytes and an opaque (rotating, per-epoch) hint.
4. Any syncing user becomes a mule: unknown envelopes ride along in their `transit_queue`.
5. At the next node the mule pushes the envelope; the nodes never talk to each other.
6. Bob syncs, recognizes his own `dest_hint` (his client tries the legacy static hint, the current epoch's hint and the previous one), decrypts, verifies Alice's Ed25519 signature, and the message lands in his inbox. If delivery confirmations are on, his device answers with one small signed, encrypted acknowledgment that travels back the same way — and Alice sees her message as *delivered*.

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

**Already provisioned?** Upgrade in place — no reflash, no data loss: `sudo ./install.sh --upgrade --offline /media/usb` (or `--ref vX.Y.Z` online); the node backs up the store + previous binary first, and a health gate rolls everything back automatically if the new release does not come up healthy. See [`docs/BUILD.md`](docs/BUILD.md) §5 Path 4 and the runbook [`docs/RUNBOOK.md`](docs/RUNBOOK.md) §4.8.

### Hardware

For solar-powered deployment (~1 W continuous target): the step-by-step builder's guide — component shopping with budget tiers, battery and panel choices, bench assembly, and per-environment deployment (forest, mountain, desert, coastal) — is [`docs/install-node.md`](docs/install-node.md); the solar + LiFePO4 sizing math, wiring, SD card and enclosure guidance it links to are in [`docs/hardware.md`](docs/hardware.md).

## Usage

Each node broadcasts the open Wi-Fi network `offgrid-messages`. Anyone in range:

1. **Joins the network** — the captive portal opens automatically (or browse to `http://offgrid.local:8080`).
2. **Registers once** — picks an alias; key pairs are generated on the device and stay there (with an optional seed backup).
3. **Exchanges contacts in person (optional)** — two people who meet can flash their identity QR codes at each other (Contacts tab): scanning the other person's code — or pasting the payload text it displays — saves their alias and public keys as a contact, with the payload signed by their Ed25519 key and checksummed so a tampered or damaged code is visibly rejected. Contacts appear in the composer even when the node's directory is unreachable; when both are available the fresh directory data is used for sending.
4. **Writes messages** — picks a recipient from the merged directory + contacts list and writes UTF-8 text: up to 128 bytes per envelope, and the composer splits anything longer into at most 16 envelopes (with the envelope count shown before sending).
5. **Syncs automatically on page load** — pushes what it carries, pulls what's addressed to it into the inbox, and keeps unknown envelopes (up to 100) in the transit queue for the next node. A telemetry panel shows what the phone is carrying: *"Foreign envelopes in transit: X / Capacity: Y"*.

That's the whole interaction: sending is leaving a note at one mailbox, receiving is walking past another. Envelopes expire via TTL and are swept every 15 minutes, so the network self-cleans.

**For field pilots:** a printable, non-technical end-user guide lives in [`docs/quick-start.md`](docs/quick-start.md) and is served by every node itself at `http://offgrid.local:8080/guide` (linked as "Guide" from the portal footer) — hand it out on paper or show it on a phone.

### Keep an Offgrid icon on your home screen

Instead of typing `http://offgrid.local:8080` every time, pin the portal — the node ships a web app manifest and an icon (all self-hosted, no internet needed). While on the node's Wi-Fi in your **full browser**:

- **Android (Chrome):** tap the browser menu (⋮) → **Add to Home screen** → confirm. Chrome may also show a banner offering it.
- **iOS (Safari):** tap the **Share** button → **Add to Home Screen** → confirm.

The portal then shows the "Offgrid" icon with the standalone (app-like) look, opens straight to your inbox, and always lands on the canonical origin — the same one across every node, so your identity and messages carry over as usual. Honest boundary: **the icon is a shortcut, not an offline app** — it opens the portal when you are on the node's Wi-Fi; without it there is nothing to load (there is deliberately no offline mode — see protocol §12.1).

### Delivery feedback (best-effort)

The composer can track each sent message locally: **queued** (waiting for the next sync) → **sent** (a node holds it; a mule may be carrying it) → **delivered** (the recipient's device confirmed receipt). The confirmation is one small signed, encrypted acknowledgment envelope that travels back exactly like any other mail — nodes and mules stay blind, it costs at most one envelope per message, and acknowledgments are never acknowledged (no storms). Honesty notes: it is **best-effort**, not a read receipt — the ack itself travels by mule, can arrive late, and can expire or be evicted like any envelope, so silence means *unknown*; it can only be emitted when the recipient's device can resolve your public key from a node directory. Delivery confirmations can be turned off in the Identity tab, and you choose per message whether to track delivery (the sent list lives only on your device).

## Building and testing from source

Requirements: Go 1.26+ and Node.js (tests only). From the repository root:

```bash
cd node && ./build.sh && cd ..     # cross-compiles arm64/armv7/armv6 + dev binary
cd node && go test ./... -count=1 && cd ..
node tests/crypto_roundtrip.mjs    # 44 assertions against the SPA crypto engine
node tests/qr_identity.mjs         # 73 assertions on the §4.7 identity QR (payload vectors, tamper rejection, QR encoder round-trips)
node tests/spa_structure.mjs       # 262 assertions on the SPA layout, CSP, API surface and the /guide page
node tests/pwa_assets.mjs          # 46 assertions on the §12.1 PWA-lite assets (manifest, icons, zero external URLs)
bash tests/sync_e2e.sh             # 383 assertions: five real daemons + full mule walk (curl only)
bash tests/node_plane_e2e.sh       # 25 assertions: three daemons in a line topology exchanging bundles over TCPCLv4 (issue #33)
sh esp32/components/dtn_core/host/run_tests.sh   # the ESP32 firmware's portable core, host-tested (issue #39 + #33)
go run ./cmd/capsuletool --help    # from node/: the offline identity/capsule/admin ceremony tool (issue #33)
```

`tests/sync_e2e.sh` simulates the complete Alice → node A → mule → node B → Bob journey and asserts payload byte integrity (sha256) through the mule, dedup, TTL filtering, limit rejections and the captive-portal redirects. `make test` runs the full documented suite in one command (including the two E2Es, the dtn_core host suite and the node-plane E2E); `make chaos` and `make fuzz` cover the failure-injection and parser-fuzzing suites. Expected outputs: [`docs/BUILD.md`](docs/BUILD.md) §4.

## Repository layout

```
offgrid/
├── .github/         # release workflow: binaries + per-model DEPLOY.md per tag
├── docs/            # protocol + node-network specs, build/hardware docs, per-model matrix
├── esp32/           # optional ESP32 node firmware (issue #39): dtn_core (C99, host-tested) + dtn_node
├── node/            # Go daemon (internal: storage, api, envelope, bundle, nodeid, link, tcpcl, forward, mgmt, capsule, directory; web/: SPA)
├── raspberry/       # install.sh, provision.sh, hostapd, dnsmasq, firewall, power, systemd
├── tests/           # crypto round-trip (Node), SPA structure, E2E sync + node-plane E2E (bash/curl), shared crypto/format vectors
└── tools/           # gen_icons.mjs — deterministic regeneration of the §12.1 PWA icons
```

## Documentation

| Document | Contents |
|---|---|
| [`docs/protocol.md`](docs/protocol.md) | **Normative protocol spec**: envelope format, canonical serialization, key derivations, crypto primitives, binding limits, node schema and API, threat model, Phase 2 (BLE) / Phase 3 (LoRa) mapping |
| [`docs/node-network.md`](docs/node-network.md) | **Normative node-plane spec** (issue #33 Phase 3): the two-plane model — the user plane of `protocol.md` stays byte-frozen — with node identity and anchor-signed role certificates (roles, authority levels L0–L3, revocation without a server), the Offgrid BPv7 profile (an RFC 9171 subset) with measured byte budgets, the LoRa radio plan and link-security spec (EDHOC-shaped sessions, persisted anti-replay), epidemic forwarding with contact budgets, the management plane (signed admin commands, telemetry replies), updates and directory federation over the plane, the threat-model delta and the conformance matrix |
| [`docs/rfc4838-alignment.md`](docs/rfc4838-alignment.md) | **RFC 4838 alignment audit** (issue #40): the DTN architecture claim validated concept-by-concept against RFC 4838 — 16-row mapping table, verdicts, deviation register (intentional vs unintentional) and what Bundle-Protocol conformance would mean (informational) |
| [`docs/security-audit.md`](docs/security-audit.md) | **Security audit report** (issue #14, FINAL v1.0.0): five-phase audit — node daemon, SPA + crypto engine, protocol/threat model, Pi network stack, supply chain — 30 findings by severity with reproductions and fixes, the §13 claim-by-claim threat-model verdict table, and the consolidated register of accepted residuals and deferred follow-ups |
| [`docs/known-limitations.md`](docs/known-limitations.md) | **Known limitations** (issue #14): the residual risks accepted by design, in plain language — no TLS, node-served app code, permanent directory-holder linkability, unauthenticated directory entries, replay after expiry, store-fill censorship, shared devices, SD-card extraction, unsigned release hashes, mule withholding — each citing its spec section and audit finding |
| [`docs/BUILD.md`](docs/BUILD.md) | Build, run locally, test and deploy to a Pi (online / offline / manual), plus troubleshooting and on-site checklists |
| [`docs/pi-models.md`](docs/pi-models.md) | Support matrix for every Raspberry Pi model: OS image, binary, Wi-Fi caveats, performance and power notes |
| [`docs/hardware.md`](docs/hardware.md) | Solar + LiFePO4 sizing math, bill of materials, wiring diagram, assembly checklist |
| [`docs/install-node.md`](docs/install-node.md) | **From-scratch node installation guide** (issue #35): component shopping in three budget tiers with substitution rules, battery chemistry + runtime tables, build alternatives, step-by-step bench assembly, per-environment outdoor deployment (forest, mountain, desert, coastal), maintenance, troubleshooting and printable checklists — links to `hardware.md` for all the math |
| [`docs/hardening.md`](docs/hardening.md) | Defensive hardening design (issue #16): adversarial assumptions, the four defense tracks with their regression tests, deliberate non-defenses, the shed → survive → self-recover contract |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Field operator runbook: reading the counters-only telemetry, detecting abuse, restoring a node in minutes (quarantine, remount cycle, reflash), upgrading a deployed node + rollback, escalation |
| [`docs/quick-start.md`](docs/quick-start.md) | **End-user quick-start guide** (issue #23): the printable, translatable one-pager a field pilot hands out — join the Wi-Fi, open the full browser, register, back up the seed, send, be a mule — also served by every node at `http://offgrid.local:8080/guide` |
| [`docs/field-test.md`](docs/field-test.md) | **Field acceptance protocol + report** (issue #20): the executable T1–T10 cases for the on-hardware session (two-node mule walk, device matrix, seed restore, isolation, cold start, coexistence, power draw) with PENDING results matrices, a defect log and an empty sign-off — plus the software-verifiable half automated as `tests/field_equiv.mjs` — extended (issue #33 P3.9) with the §15 node-plane session N1–N14 (bench + field tiers, 72 h solar soak; execution pending the radio hardware bring-up) |
| [`docs/offline-maintenance.md`](docs/offline-maintenance.md) | **Offline island maintenance design** (issue #37): the complete design for mule-delivered signed release capsules (byte-exact format, offline signing ritual, staging endpoint, anti-rollback policy, apply via the #22 machinery) and directory federation (signed identity cards, merge policy, privacy accounting) — **design record only**: the staging/federation endpoints are not yet implemented; the unknown-recipient conformance pin it carries is already normative and tested in `docs/protocol.md` §10.5 |
| [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md) | Design decisions and rationale (same-origin trick, threat model, byte budgets, OS choices) |
| [`docs/MASTER_DEVELOPMENT_PROMPT.md`](docs/MASTER_DEVELOPMENT_PROMPT.md) | Original master specification (source of truth for requirements) |

## Status and roadmap

- **Security audit — complete** (issue #14): all five phases done across the node daemon, client, protocol, Pi network stack and supply chain — no critical or high findings; fixes, spec corrections and accepted residuals are documented in [`docs/security-audit.md`](docs/security-audit.md), with the user/operator-facing residual list in [`docs/known-limitations.md`](docs/known-limitations.md).
- **Phase 1 (this repository) — software complete**: Wi-Fi dead-drop nodes + browser data mules over HTTP, covered by the automated test suite above. The remaining manual item is on-hardware acceptance with physical Pis and phones: the executable protocol and report scaffold are [`docs/field-test.md`](docs/field-test.md) (T1–T10, every result PENDING until executed — `make field-kit` prints the session checklist).
- **Phase 2 — BLE**: direct phone-to-phone transfer over BLE L2CAP connection-oriented channels with `hop_count ≤ 7`; the envelope format and the code-level mapping are already defined in [`docs/protocol.md`](docs/protocol.md) §14.
- **Phase 3 — node-to-node network — software complete** (issue #33, spec [`docs/node-network.md`](docs/node-network.md)): nodes are now identified, authenticated DTN peers on a dedicated node plane that leaves the user plane byte-frozen — a frozen BPv7 profile (RFC 9171 subset) as the bundle layer, TCPCLv4 over TLS 1.3 on the Wi-Fi plane today with the LoRa convergence layer (EDHOC-shaped encrypted link sessions, SX1262 MAC, window reassembly) host-tested and awaiting the radio hardware bring-up, controlled-epidemic forwarding with contact budgets, anchor-signed role certificates with management levels L0–L3 (island-wide revocation without any server), software capsules and signed directory cards riding the same plane. The physical acceptance — bench radio tests, multi-km links, the 72 h solar repeater soak — is the executable protocol of [`docs/field-test.md`](docs/field-test.md) §15 (N1–N14, results PENDING until the hardware session).
