# Master Development Prompt: Off-Grid DTN Messaging System (Phase 1 + Phase 2/3 Roadmap)

---

## 1. Assistant Context and Role

Act as a **Senior Software Engineer in Distributed Systems, Embedded Networks and Applied Cryptography**. Your goal is to generate the code, infrastructure configurations and technical architecture for an **asynchronous, disconnected (off-grid), decentralized, delay-tolerant messaging system (DTN / Store-and-Forward)**.

The system must operate with no Internet, satellite or cellular network access. It uses fixed Wi-Fi access points on **Raspberry Pi Zero 2 W** boards (with a captive portal) as blind mailboxes (*dead drops*), and leverages users who physically move between zones as **data mules (*sneakernet*)** using only the mobile web browser and `IndexedDB`.

---

## 2. Strict Design Guidelines

1. **Zero Internet Dependency:** External CDNs, cloud API calls, or libraries requiring public DNS resolution are not allowed. Every asset, script or font must be served locally from the Raspberry Pi.
2. **Zero Trust in the Infrastructure (Zero-Trust Intermediaries):** The fixed nodes (Raspberry Pi) and transit cellphones are blind, untrusted channels. They must not learn the content, the real sender, or the full identity of the recipient.
3. **Cross-Node Persistence (Same Web Origin):** All Raspberry Pi boards must force the same local virtual FQDN (`http://portal.red.local:8080`) and the same gateway IP (`10.42.0.1`) to guarantee that `IndexedDB` keeps the same logical origin as the user moves from one node to another.
4. **bitchat / Nostr Protocol-Compatible Format:** Messages must serialize as atomic, independent events/envelopes (max ~180-250 bytes in the standard payload) to allow their future direct migration to **BLE L2CAP CoC** and **LoRa P2P (SX1262)** packets without rewriting the data structure.

---

## 3. Required Deliverables

### Module A: Network Configuration on Raspberry Pi OS Lite
Generate the Linux configuration files and provisioning commands:
* **`/etc/hostapd/hostapd.conf`**: Configure `wlan0` as an open Access Point (`SSID: Red-Comunitaria`, channel 6, `ap_isolate=1`).
* **`/etc/dnsmasq.conf`**: DHCP server on range `10.42.0.50` to `10.42.0.250`, DNS/Gateway assignment `10.42.0.1` and wildcard DNS spoofing (`address=/#/10.42.0.1` and `address=/portal.red.local/10.42.0.1`).
* **Firewall Rules (`iptables`)**: Bash script redirecting port 80 to 8080 on `wlan0` and capturing the Android (`/generate_204`) and iOS (`/hotspot-detect.html`) connectivity-check endpoints.
* **Power optimizations for the Raspberry Pi Zero 2 W**: Disable the HDMI output and activity LEDs for operation on a solar panel and LiFePO4 battery.

---

### Module B: Node Backend Daemon (Go)
Develop a self-contained HTTP server in **Go**, statically compilable (`CGO_ENABLED=1` or a pure-Go embedded SQLite driver such as `modernc.org/sqlite`):
1. **SQLite Database (`node_storage.db`):**
   * `envelopes` table: `id` (TEXT PRIMARY KEY), `dest_hint` (TEXT), `created_at` (INTEGER), `ttl` (INTEGER), `payload` (TEXT).
   * `directory` table: `pubkey` (TEXT PRIMARY KEY), `alias` (TEXT), `last_seen` (INTEGER).
   * Indexes on `dest_hint` and `(created_at, ttl)`.
2. **API Endpoints:**
   * `GET /`: Serve the static `index.html` file embedded (via `embed.FS`).
   * `GET /generate_204`, `GET /hotspot-detect.html`: Answer with an HTTP 302 redirect toward `http://portal.red.local:8080/`.
   * `GET /api/v1/directory`: Return the list of known users (alias + pubkey + last_seen).
   * `POST /api/v1/directory`: Register or refresh a user on the node.
   * `POST /api/v1/sync`:
     * **Input JSON:** `{ "known_ids": [...], "push_envelopes": [...], "limit": 50 }`.
     * **Action:** `INSERT OR IGNORE` of the `push_envelopes`. Query of up to `limit` live envelopes not present in `known_ids`.
     * **Output JSON:** `{ "status": "ok", "pull_envelopes": [...] }`.
3. **Cleanup Worker:** Goroutine with `time.Ticker` that deletes, every 15 minutes, envelopes with `created_at + ttl < now()`.

---

### Module C: Web SPA Frontend + Cryptographic Engine (Vanilla JS / Web Crypto)
Generate a single `index.html` file (HTML + inline CSS + JS) operating as the user interface on the captive portal:
1. **Cryptographic Handling (E2EE Client-Side):**
   * Use `window.crypto.subtle` (or an embedded implementation of `tweetnacl.js` injected directly into the file) for the **X25519** key pair (encryption) and **Ed25519** (signature/identity).
   * The server never has access to the private keys.
2. **Local Storage (`IndexedDB`):**
   * Database `dtn_local_store` with the stores:
     * `identity`: The user's keys and alias.
     * `inbox`: Successfully decrypted messages addressed to the current user.
     * `transit_queue`: **The Mule's Buffer.** Foreign envelopes in transit (max 50-100 envelopes).
3. **Automatic Exchange Flow (Data Mule):**
   * On page load, run `POST /api/v1/sync`:
     * Send the envelopes accumulated in `transit_queue` and the list of known ids.
     * Receive `pull_envelopes`. If an envelope matches the user's `dest_hint`, attempt to decrypt it and move it to `inbox`; if it does not match, store it in `transit_queue` to carry it to the next node.
4. **User Interface (Minimalist Responsive UI):**
   * Alias registration screen and cryptographic identity initialization.
   * Recipient selector driven by the node's public directory.
   * Message composition and send field.
   * Inbox with decrypted messages.
   * Mule telemetry panel: *"Foreign envelopes in transit carried: X / Capacity: Y"*.

---

### Module D: Abstraction Interfaces for Phase 2 (BLE) and Phase 3 (LoRa)
Document in the code how the universal envelope (`Envelope`) must be mapped:
1. **bitchat alignment (Phase 2):** Structure of the L2CAP CoC binary data channel and hop control (`hop_count <= 7`) for Capacitor/Ionic.
2. **LoRa P2P SX1262 alignment (Phase 3):** Binary packing (CBOR) that keeps the payload below the 222-byte MTU per radio frame at 915 MHz.

---

## 4. Acceptance Criteria
* The code must be fully written, production-ready (no `// TODO: implement here` style placeholders).
* It must include precise step-by-step build, run and test instructions.
