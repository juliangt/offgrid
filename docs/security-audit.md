# Security Audit — off-grid DTN messaging (issue #14)

| | |
|---|---|
| **Version** | 0.1.0 (Phase 1 appended) |
| **Date** | 2026-10-06 |
| **Status** | DRAFT — Phases 2–5 pending; this document is the master report that each audit phase appends to. Phase 1 (node daemon) is complete as of this revision. |
| **Tracker** | GitHub issue #14 ("Security audit"), branch `feat/14-security-audit` |
| **Normative baseline** | `docs/protocol.md` (wire contract — nothing here overrides it), `docs/hardening.md` (defense tracks A1–A8), `tests/chaos/FAILURE_MATRIX.md` (failure contract) |

## Scope and phase status

| # | Audit area | Primary material | Phase status |
|---|---|---|---|
| 1 | **Node daemon** — Go HTTP API + SQLite storage (`node/main.go`, `node/internal/…`) | this document, §1 | **Phase 1 — complete (this revision)** |
| 2 | SPA / client crypto (`node/web/` — tweetnacl usage, IndexedDB, CSP, key handling, §4.6/§4.7 verification duties) | — | pending |
| 3 | Protocol / crypto design (envelope format, §5 canonical forms, §6 derivations, §13 threat model, forward secrecy) | — | pending |
| 4 | Raspberry Pi / network (`raspberry/` — hostapd, dnsmasq, iptables, systemd, hardening scripts) | — | pending |
| 5 | Supply chain / build (`go.mod`/`go.sum` in depth, vendored JS provenance, `node/build.sh`, release stamping) | — | pending (dependency hygiene of the node module was spot-checked in Phase 1, §1.4) |

## Methodology

- **Manual code review with file:line evidence.** Every claim below cites the exact source location in the state of branch `feat/14-security-audit` at this revision. Nothing is asserted from documentation alone: each `docs/protocol.md` guarantee that bears on security was traced to the code that enforces it.
- **Dynamic tests where possible.** The existing regression suites were re-run against the audited tree, and new regression tests were added for every confirmed vulnerability class that a Go test can cover (see each finding). Commands run, all green at this revision:
  - `cd node && go test ./... -count=1` — all 10 packages pass (including the seed corpora of the two native fuzz targets `FuzzSyncHandler`, `FuzzParseEnvelope`);
  - `cd node && go vet ./...`, `gofmt -l .` — clean;
  - `bash tests/sync_e2e.sh` — 383 assertions passed, 0 failed (two real daemons, curl-driven);
  - `bash tests/chaos/run_all.sh` — 57 assertions passed, 0 skipped-in-failure (kill-mid-sync, corrupt-DB quarantine, full disk, restart-under-load, janitor-under-flood, parser fuzzing).
- **Existing adversarial suites reused, not duplicated.** `node/internal/api/flood_test.go` (flood/sabotage rows), `node/internal/api/fuzz_test.go` + `node/internal/envelope/fuzz_test.go` (parser fuzzing; fuzz session driven by `tests/chaos/chaos_fuzz_parsers.sh`), `tests/chaos/*` (failure-injection matrix), `node/main_test.go`, `node/internal/api/api_test.go`, `health_test.go`, `status_page_test.go`, `unknown_recipient_test.go`, `node/internal/storage/storage_test.go` were treated as prior evidence and spot-verified against the code they claim to pin.
- **Adversarial assumptions.** The review assumes `docs/hardening.md` §1 A1–A8 — above all A1 (*every client is an attacker*: the AP is open, so the API surface is reachable by anyone in radio range with zero credentials) and A3 (*clients WILL flood and sabotage*).

## Severity scale

| Severity | One-line definition |
|---|---|
| **Critical** | Remote, unauthenticated compromise of the node process, or break of the blind-node/E2EE core claim (plaintext or key exposure). |
| **High** | Unauthenticated attacker causes service-wide outage, persistent data loss, or meaningful plaintext/metadata compromise with no practical mitigation in the shipped deployment. |
| **Medium** | A confirmed weakness an unauthenticated attacker can exploit with real (but bounded or recoverable) impact — degradation, poisoning, resource exhaustion — or one requiring specific positioning/conditions. |
| **Low** | Real but low-impact or heavily-mitigated weakness; defense-in-depth gaps against assumptions the layered deployment already answers. |
| **Info** | Accepted design risks, hardening notes, and documentation findings. No code change required now. |

## Findings index

| ID | Severity | Component | Title | Status |
|---|---|---|---|---|
| NODE-01 | Medium | node daemon (storage + API) | Unauthenticated, unbounded directory-table growth — persistent disk-fill DoS | **Fixed in this PR** |
| NODE-02 | Low | node daemon (HTTP server) | No read/write/idle timeouts — slow-body drip and idle-socket hoarding hold connections indefinitely | **Fixed in this PR** |
| NODE-03 | Low | node daemon (HTTP surface) | Missing baseline security headers (nosniff, framing protection, referrer) | **Fixed in this PR** |
| NODE-04 | Medium | node daemon + protocol | Directory upsert has no proof-of-possession: any station can hijack any identity's entry (x25519/prekeys swap) | Documented / accepted risk (protocol-inherent; client-side verification is the mitigation) |
| NODE-05 | Info | transport | Plaintext HTTP transport — TLS intentionally absent | Documented / accepted risk |
| NODE-06 | Info | node daemon (parser) | Bytes after the top-level JSON value are silently ignored | Documented / accepted risk |
| NODE-07 | Info | node daemon (read path) | GET endpoints are unbudgeted; worst-case directory GET ≈ 1 MiB per hit | Already mitigated (protocol-assigned to the Track 1 shields) |

Note on disclosure: the three fixed findings (NODE-01..03) and this report land in the same merge, so there is no window between fix and disclosure.

---

## 1. Node daemon

Audited: `node/main.go`, `node/internal/api/` (handlers.go, middleware.go, ratelimit.go, health.go), `node/internal/storage/storage.go`, `node/internal/envelope/envelope.go`, `node/internal/cleanup/cleanup.go`, `node/internal/health/health.go`, `node/internal/status/` (engine.go, activity.go), `node/internal/sysres/`, `node/go.mod`/`go.sum` (hygiene only). Out of scope here: `node/web/` SPA internals (Phase 2), `node/internal/power/` and `sdnotify/` hardware plumbing (reviewed only for request-path impact — none: both run off-request-path).

### 1.1 The core claim, verified end to end

The claim under audit — **"nodes only ever handle opaque envelopes; all crypto happens on the client"** — holds in the code:

- **No cryptography exists in the daemon.** A source scan of `node/` finds zero imports of `crypto/*` (beyond stdlib hashing-free plumbing), `golang.org/x/crypto`, nacl/box, or any signature/decryption call outside comments. The storage layer stores the payload string verbatim (`storage.go` `InsertEnvelopes`, line 582) and returns it verbatim (`PullEnvelopes`, line 634); envelope admission is shape-only (`envelope.go` `Validate`, line 190: version set, hex id/hint regexes, timestamp window, TTL bounds, strict-Base64 payload decode for a [248, 400]-byte length check). The node never recomputes `id` (§6.2), never verifies signatures, never consults the directory on the push path (`handlers.go` `handleSync`, line 658 — the §10.5 unknown-recipient guarantee, pinned by `unknown_recipient_test.go`).
- **Round-trip fidelity is tested**: payload bytes survive a store/pull cycle byte-identical (`TestSyncPushPullDedup`, `tests/sync_e2e.sh` §3–4), and served envelopes never carry admission-time `meta` (§15.3, `TestSyncV2AdmissionDedupAndServing`).

### 1.2 Findings

#### NODE-01 — Medium — Unauthenticated, unbounded directory-table growth (persistent disk-fill DoS)

- **Severity:** Medium
- **Affected component (pre-fix):** `node/internal/storage/storage.go` `UpsertDirectory` (no cap) + `node/internal/api/handlers.go` `handlePostDirectory`; the §10.6 janitor (`cleanup.go` `sweep`) reaps only `envelopes`.
- **Description.** `POST /api/v1/directory` is unauthenticated and every accepted request permanently inserts or updates one `directory` row. Before this fix the table had **no row cap and no TTL** (the code itself noted "directory rows are never auto-deleted in Phase 1"). Every other persistent surface is bounded: envelopes have the 5000-row §8.1 cap; counters and rate-limit state are RAM-only. The directory was therefore the one unbounded, attacker-writable disk resource: at ~150 B per bare entry and ~2.2 KiB with a max-size §4.6 prekeys bundle, sustained registrations (the §10.1 request budget permits ~30/min per IP indefinitely; colluding stations multiply) grow the SQLite file without bound until the SD card fills — after which every envelope push sheds `507 storage_unavailable` (the clean shed keeps the daemon alive, but the mailbox stops accepting mail) and the card keeps wearing. The janitor never recovers it: operator intervention (deleting rows) would be required on a node class with no SSH (A8). `GET /api/v1/health` would show `disk_free_low` and growing `db_size_bytes`, but nothing stops the growth.
- **Reproduction (pre-fix):**
  ```bash
  # from any station on the open Wi-Fi (repeat per colluding station):
  while :; do
    curl -s -X POST http://10.42.0.1:8080/api/v1/directory \
      -H 'Host: offgrid.local:8080' -H 'Content-Type: application/json' \
      -d "{\"alias\":\"j$RANDOM\",\"pubkey\":\"$(head -c 32 /dev/urandom | base64)\",\"x25519\":\"$(head -c 32 /dev/urandom | base64)\"}"
    sleep 2   # stays under the §10.1 request budget forever
  done
  # rows accumulate permanently; watch db_size_bytes climb in /api/v1/health.
  ```
- **Fix (in this PR):** a per-node directory cap mirroring the envelope cap's design:
  - `storage.go`: new `maxDirectoryEntries` var (5000, the §8.1 envelope-cap class; test hook, exported via `MaxDirectoryEntries()`, line 149/471). `UpsertDirectory` (line 713) first probes pubkey existence (cheap indexed lookup); an **existing** pubkey always refreshes — a full directory never locks registered users out of their own republication — while a **new** pubkey at/over the cap is rejected whole with `ErrCapacity` (fail closed; nothing stored). The exists-then-count order keeps the refresh path cheap and pays the `COUNT(*)` only for genuinely new rows; as with envelopes, the check and insert are separate statements, so a race may overshoot the cap by a couple of rows — irrelevant at a 5000-row bound and identical to the envelope path's documented ≤100 tolerance.
  - `handlers.go` `handlePostDirectory` (line 592): maps `ErrCapacity` to `429 {"error":"node_full"}` (line 616) — the same capacity shed `POST /api/v1/sync` already answers at envelope capacity, and a status class this endpoint already answers under the §10.1 request budget. No documented API shape changes; a valid registration below the cap behaves exactly as before (pinned by `TestDirectoryBelowCapAcceptsNewRegistrations`).
- **Regression tests:** `node/internal/storage/storage_test.go` `TestDirectoryUpsertCapacityGuard` (cap sheds new, refresh survives at cap, deleting a row re-opens capacity), `TestDirectoryUpsertDefaultCap` (5000 accepted / 5001st rejected / refresh at full cap); `node/internal/api/security_test.go` `TestDirectoryCapShedsNewRegistrationsWithNodeFull` (end-to-end: 429 node_full, nothing stored, existing entry refreshes 200), `TestDirectoryBelowCapAcceptsNewRegistrations`.
- **Status:** Fixed in this PR.

#### NODE-02 — Low — HTTP server missing read/write/idle timeouts (slow-body drip, idle-socket hoarding)

- **Severity:** Low (defense-in-depth: the reference deployment's Track 1 firewall connlimits — 32/source, 20 stations — bound the same attack; but the Track 2 premise is that the daemon must shed by itself when the shields are bypassed, `docs/hardening.md` §3)
- **Affected component (pre-fix):** `node/main.go` — the `http.Server` literal set only `ReadHeaderTimeout: 5s`; `ReadTimeout`, `WriteTimeout`, `IdleTimeout` were unset (net/http's zero value = no timeout).
- **Description.** `http.MaxBytesReader` bounds request-body *size* (1 MiB → 413, `middleware.go` `limitBody`, line 82) but not *time*. Pre-fix, a hostile station could (a) open a connection, send valid headers, then drip the body one byte per minute indefinitely — each drip connection holds a server goroutine and its buffers forever; or (b) complete one request per socket and then idle forever — keep-alive sockets were never reaped (`IdleTimeout` 0). Neither is stopped by the body cap, the per-IP request budget (which spends one token per *request*, not per open socket), or the 1 MiB header cap (431). On the Pi-class target this is connection/goroutine hoarding toward `MemoryMax=192M` and fd exhaustion; the daemon alone had no time bound on any of it.
- **Reproduction (pre-fix):**
  ```bash
  # slow-body drip — headers valid, body dribbled; pre-fix the connection
  # (and goroutine) is held indefinitely; post-fix ReadTimeout closes it at 60 s:
  { printf 'POST /api/v1/sync HTTP/1.1\r\nHost: offgrid.local:8080\r\nContent-Type: application/json\r\nContent-Length: 1000000\r\n\r\n{';
    while :; do printf 'A'; sleep 55; done; } | nc 10.42.0.1 8080
  # idle hoarding — complete one request, then hold the socket:
  exec 3<>/dev/tcp/10.42.0.1/8080   # pre-fix: held forever; post-fix: reaped at 120 s
  ```
- **Fix (in this PR):** `main.go` now builds the server through `newHTTPServer` (line 111) with the full timeout set: `ReadHeaderTimeout` 5 s (unchanged), `ReadTimeout` 60 s (whole request lifetime — orders of magnitude above any legitimate phone interaction on the node's own AP), `WriteTimeout` 60 s (covers the ~1 MiB worst-case directory GET at captive-portal speeds), `IdleTimeout` 120 s (above browser keep-alive habits). Sized to be invisible to honest clients — `tests/sync_e2e.sh` (383 assertions, real daemons) stays green.
- **Regression tests:** `node/main_test.go` `TestNewHTTPServerTimeouts` — pins all four fields and their sanity ordering, so a regression that silently drops one fails the suite.
- **Status:** Fixed in this PR.

#### NODE-03 — Low — Missing baseline security headers (nosniff, framing protection, referrer)

- **Severity:** Low
- **Affected component (pre-fix):** `node/internal/api/middleware.go` (no header middleware; the wrapper chain was `canonicalHost(limitBody(mux))`, `handlers.go` `NewWithCounters`).
- **Description.** The daemon set no security headers. Consequences, in increasing order of concern:
  1. **No `X-Content-Type-Options: nosniff`.** All bodies carry exact §10.1 Content-Types, but the directory GET serves client-controlled JSON verbatim inside `prekeys` (unknown bundle members are ignored and stored as-published, `handlers.go` `validatePrekeysBundle` line 539; served verbatim, `storage.go` `GetDirectory`) and `writeJSON` serializes with `SetEscapeHTML(false)` (`handlers.go`, `writeJSON`). With legacy UA MIME-sniffing in the picture, response re-interpretation was one browser quirk away; `nosniff` closes the class outright.
  2. **No framing protection.** The portal, guide and §10.7 operator status page ship their CSP as `<meta>` tags — and `frame-ancestors` is *ignored inside a meta policy*, so pre-fix clickjacking protection (relevant at least for the operator view, which displays operational detail) rested on nothing.
  3. **No `Referrer-Policy` header.** The pages set `<meta name="referrer" content="no-referrer">`; the header extends the guarantee to every response and to clients that ignore meta.
- **Reproduction (pre-fix):** `curl -sI -H 'Host: offgrid.local:8080' http://10.42.0.1:8080/ | grep -Ei 'nosniff|x-frame|referrer'` → no output.
- **Fix (in this PR):** new `secureHeaders` middleware (`middleware.go` line 53) sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` on every response, wired outermost — `secureHeaders(canonicalHost(limitBody(mux)))`, `handlers.go` `NewWithCounters` — so 200s, the §10.2 301, the probe 302 and all error shapes carry them. A header-level Content-Security-Policy is deliberately NOT introduced: the per-page meta CSPs are the normative policies and a header copy would be a drifting second CSP; frame protection — the one directive meta cannot express — is delivered by `X-Frame-Options`. Non-breaking: the portal is a top-level destination and never legitimately framed.
- **Regression tests:** `node/internal/api/security_test.go` `TestSecurityHeadersOnEveryResponse` — asserts all three headers on 200 HTML, 200 JSON, 200 asset, 404, 405, 400, the canonical-host 301 and the captive-probe 302.
- **Status:** Fixed in this PR.

#### NODE-04 — Medium — Directory upsert has no proof-of-possession: any station can hijack any identity's entry

- **Severity:** Medium
- **Affected component:** `node/internal/api/handlers.go` `handlePostDirectory` (line 592) + `node/internal/storage/storage.go` `UpsertDirectory` (line 713); inherent to the §10.3 wire contract.
- **Description.** Directory registration is keyed by the Ed25519 **public key alone**, with no signature, challenge, or any proof that the poster holds the matching private key. The public key is public data — the same node's `GET /api/v1/directory` serves it. A hostile station can therefore republish a victim's `pubkey` bound to the **attacker's** `x25519` key (and attacker prekeys): every subsequent sender who picks the victim from the directory encrypts to the attacker's key and addresses the matching hint; the victim silently stops receiving mail while the attacker decrypts it. E2EE does not help — the attacker *holds* the key material the mail was encrypted to.
  - This is **protocol-inherent, not a coding error**: a blind node cannot demand proof-of-possession, because verifying a signature over the registration body is exactly the cryptography §1 forbids the node from doing ("never verifies signatures — clients verify"). `docs/protocol.md` §13.5 (bundle paragraph) already acknowledges the hole for the malicious-**node** case: "the signature does NOT close the pre-existing hole that the node can swap any entry's `x25519` member (directory entries are not authenticated end-to-end in Phase 1); closing that (key transparency) is out of scope."
  - **Audit nuance (recorded for Phases 2–3):** the unauthenticated POST widens that documented hole from *a malicious node operator* to *any station in radio range* — strictly cheaper to exploit than the documented variant. Mitigations that exist are all client-side and must be verified in Phase 2: §4.6 `spk_sig` client verification (defeats swapped *bundles*, and a failed verification must downgrade to identity addressing with a UI warning), the §4.7 identity-QR in-person exchange (trust-on-sight), and — open question — the §1.8.0 changelog wording that the merged recipient picker lets "the directory supply the fresh key material when an entry exists", which, if it means directory x25519 overrides QR-pinned contacts, would extend this finding's reach to QR-verified contacts. Phase 2 must pin the picker's precedence.
- **Reproduction:**
  ```bash
  # 1. Victim's entry is public on the same node:
  curl -s -H 'Host: offgrid.local:8080' http://10.42.0.1:8080/api/v1/directory
  # 2. Republish the victim's pubkey bound to the attacker's key material:
  curl -s -X POST http://10.42.0.1:8080/api/v1/directory \
    -H 'Host: offgrid.local:8080' -H 'Content-Type: application/json' \
    -d '{"alias":"<victim alias>","pubkey":"<victim ed25519 pubkey, public>",
         "x25519":"<attacker x25519 pubkey>","prekeys":<attacker-signed bundle>}'
  # -> 200 {"status":"ok"}; future directory-trusting senders encrypt to the attacker.
  ```
- **Recommended fix (not auto-applied — breaking, and it crosses the blindness invariant):** any node-side closure requires either (a) node-side signature verification over a proof-of-possession member (a wire/protocol change and a §1 exception to be designed with extreme care — a *limited*, purpose-bound verification that never touches envelopes), or (b) a key-transparency layer (log/audit of directory history clients can check), both explicitly out of scope for Phase 1 per the protocol. Interim client-side duties for Phase 2: verify bundle signatures before prekey addressing (normative already), surface trust warnings on first-seen key changes, and resolve the QR-vs-directory precedence question above.
- **Status:** Documented / accepted risk (protocol-inherent; already partially acknowledged in `docs/protocol.md` §13.5; client-side mitigation obligations tracked for Phase 2).

#### NODE-05 — Info — Plaintext HTTP transport (TLS intentionally absent)

- **Severity:** Info
- **Affected component:** transport layer; `node/internal/api/middleware.go` `CanonicalHost` (line 14) and the `http://` redirect targets (`middleware.go` line 70, `handlers.go` line 415).
- **Description.** Every byte between client and node — API payloads, directory listings, the captive-portal redirect chain — rides plaintext HTTP on the open Wi-Fi. Any associated station can passively observe all traffic metadata (who syncs, when, how much, which endpoints) and the full directory; an active attacker positioned as the AP (evil twin, A6) can serve anything. This is a **normative design decision**, documented in `docs/protocol.md` §12 ("TLS is intentionally absent" — no CA will issue for `offgrid.local` on a shared static IP, and offline PKI would break the captive flow) and justified by §13: confidentiality rests entirely on the E2EE envelope, which TLS would not strengthen. The audit accepts the reasoning and records the residual exposure honestly: traffic analysis and directory harvesting by any station are possible and unprotected by design (consistent with §13.2's "Network observer" row and §13.5's traffic-analysis acceptance); NODE-04 is the one place where network-level tampering escalates beyond metadata. The `301`-based canonicalization also means browsers cache the redirect per original origin — an operator changing `CanonicalHost` would strand cached clients (operational note, not a vulnerability).
- **Recommended action:** none in the daemon (adding TLS is forbidden by the design). Keep the §13.4/§12 client-side guidance current (canonical-URL banner, E2EE, QR exchange).
- **Status:** Documented / accepted risk.

#### NODE-06 — Info — Bytes after the top-level JSON value are silently ignored

- **Severity:** Info
- **Affected component:** `node/internal/api/handlers.go` `decodeJSON` (line 424): `json.Decoder.Decode` consumes exactly one JSON value; trailing bytes after it are never read or rejected.
- **Description.** A body like `{"limit":50} garbage` parses as a valid sync request. This is harmless in this deployment: the daemon is a single HTTP/1.1 hop with no proxy in the path (no request-smuggling surface), `net/http` owns all framing, and `MaxBytesReader` caps the socket work. Enforcing strictness (read-all + re-validate, or `DisallowUnknownFields`) would buy nothing and would collide with the §15.4 unknown-member tolerance that versioning depends on.
- **Reproduction:** `curl -s -X POST http://10.42.0.1:8080/api/v1/sync -H 'Host: offgrid.local:8080' -H 'Content-Type: application/json' -d '{} trailing-garbage'` → `200 {"status":"ok",…}`.
- **Recommended action:** none; record the behavior here so it is a decision, not an accident.
- **Status:** Documented / accepted risk.

#### NODE-07 — Info — GET endpoints are unbudgeted; worst-case directory GET ≈ 1 MiB per hit

- **Severity:** Info
- **Affected component:** `node/internal/api/handlers.go` `handleGetDirectory` (line 470), `handleSync` pull path; by design per §10.1.
- **Description.** Only the two POST endpoints and the diagnostics surface carry per-IP budgets; `GET /api/v1/directory` and sync pulls are unlimited at the daemon. The worst legitimate answer is bounded — 500 directory entries × ≤2 KiB bundles ≈ 1 MiB (documented §8.1 NOTE) and pulls ≤ 200 envelopes × ≤ ~530 B — but an unbudgeted repeater can force repeated SQLite reads and large responses from a Pi-class CPU. This allocation of responsibility is deliberate and documented: §10.1 assigns read-path floods to the Track 1 shields, which answer exactly this (per-source NEW-connection hashlimit 30/min + burst 60, connlimit 32/source, CAKE 25 mbit per-host fairness, 20-station ceiling — `docs/hardening.md` §2.1).
- **Reproduction:** `while :; do curl -s -H 'Host: offgrid.local:8080' http://10.42.0.1:8080/api/v1/directory >/dev/null; done` — daemon keeps serving; airtime/CPU load bounded only by the AP-layer shields.
- **Recommended action:** none now. If a future phase ever drops the Track 1 shields from a deployment profile, revisit a small read budget mirroring `healthBudget`.
- **Status:** Already mitigated (protocol-assigned control cited: §10.1 + `docs/hardening.md` §2.1).

### 1.3 Checklist coverage — what was verified as OK

Every item of the issue's checklist was checked; the following were verified **sound with evidence** (not merely un-tested):

1. **Input validation on every endpoint — covered.**
   `POST /api/v1/sync`: Content-Type enforced (`handlers.go` `decodeJSON` line 424, 400 otherwise), 1 MiB body cap → 413 (`middleware.go` `limitBody` line 82 + `MaxBodyBytes` line 18; `MaxBytesError` mapped in `decodeJSON`), `limit` ∈ [1, 200] with pointer-distinct default 50, `known_ids` ≤ 500 each matching `^[0-9a-f]{64}$` (`handlers.go` `isHex64`), `push_envelopes` ≤ 100, and every envelope run through the full §10.5/§15.3 matrix (`envelope.go` `Validate` line 190: version set {1,2}, per-version meta rules line 234, id/hint regexes, `created_at ∈ (0, now+300]`, TTL [3600, 2592000], strict padded Base64 payload decoding to [248, 400] bytes, CRLF rejection). Fail-closed: any single violation rejects the whole batch before any insert (`TestSyncInvalidEnvelopes`, `TestSyncDefaultsAndLimits`). `POST /api/v1/directory`: alias regex, both keys Base64→exactly 32 B, §4.6 bundle blind-shape validation with a 2048-byte member cap checked *before* any parse (`validatePrekeysBundle`). `GET /api/v1/directory?limit=` clamped into [1, 500]. Arbitrary bytes through the whole stack can only produce 200/400/413 — never 5xx, never a panic — per the `FuzzSyncHandler` property (seed corpus green; fuzz session via `tests/chaos/chaos_fuzz_parsers.sh` passes).
2. **DoS resistance — covered (gaps found are NODE-01/02/07).** Body limit (above); oversized headers → 431 with survival (`TestFloodOversizedRequestHeaderServerSurvives`); per-IP request budget checked *before the body is read* and per-IP atomic envelope budget (`ratelimit.go` `allow` line 121, wired at `handlers.go` lines 244–245), honest-IP isolation and Retry-After pinned (`TestFloodSyncStormSingleStationIsolated`, `TestFloodPerIPEnvelopeQuotaIsolation`); the 15-minute janitor is a single indexed `DELETE` on a table capped at 5000 rows over one serialized connection — bounded under flood (`chaos_janitor_flood.sh` PASS, 10/10); full disk sheds clean `507 storage_unavailable` and recovers without restart (`TestFloodStorageUnavailableMapsTo507`, `chaos_full_disk.sh` PASS); corrupt-DB quarantine + rebuild with sidecars-moved-first (`storage.go` `Open`/`quarantineCorruptDatabase` line 330, `chaos_corrupt_db.sh` PASS 15/15); WAL bounded by `wal_autocheckpoint(1000)` with a 64 MiB sidecar warning (`storage.go` lines 235–286).
3. **Rate limiting cannot be bypassed via `X-Forwarded-For` — verified.** Bucket keys derive from the kernel-set `RemoteAddr` only (`ratelimit.go` `clientKey` line 208); forwarding headers are never consulted, and the behavioral test proves a rotated XFF mints no fresh bucket (`TestRateLimiterIgnoresForwardedFor`). The bucket map itself is bounded (lazy eviction at 4096 entries, 10-min idle TTL, `ratelimit.go` lines 75–76; `TestRateLimiterIdleBucketEviction`), so a spoofed-source flood cannot grow RAM without bound.
4. **Deduplication by client-computed `id` cannot overwrite, evict, or poison other users' envelopes — verified.** Storage is insert-only for clients: `INSERT OR IGNORE` keyed by `id` (first-write-wins; `storage.go` `InsertEnvelopes` line 582); there is **no** UPDATE and no DELETE on the envelope table outside the TTL janitor's exclusive-boundary sweep (`DeleteExpired` line 784). To displace a victim's envelope an attacker would need its 64-hex id, which is the SHA-256 of the canonical envelope bytes (§5.2) — i.e. the exact ciphertext — infeasible without the key; and even then `INSERT OR IGNORE` keeps the *first* row. No cross-tenant eviction exists: at the 5000 cap the store rejects the *newest* writers (`429 node_full`) and keeps the oldest mail servable (the "reject newest, keep oldest" policy, `storage.go` lines ~107–125; `TestFloodJunkEnvelopesStoreCapHolds` proves the cap holds exactly under a 10 000-envelope flood while another IP keeps syncing). TTL is server-fenced: `created_at ≤ now+300` and `ttl ≤ 30 d` mean attacker junk expires within at most ~30 days. Anyone may *pull* all envelopes — that is the blind dead-drop by design; confidentiality rests on E2EE and the exposure is documented (§13.2).
5. **SQL injection — none; storage layer correct — verified.** Every user-reachable value is bound through `?` placeholders; the only dynamically assembled SQL is the `NOT IN` chunking whose interpolations are generated `?` markers with numeric bounds (`placeholders` line 682, chunk size 900 < SQLite's parameter limits), and `PRAGMA user_version = <strconv.Itoa(int)>` (operator-internal). Queries match the §10.4 contract including the inclusive-servability/exclusive-cleanup boundary pair and the deterministic `created_at DESC, id ASC` ordering (`PullEnvelopes` line 634); WAL engagement is *verified* at open, not assumed (`storage.go` journal-mode check); the single-connection policy (`SetMaxOpenConns(1)`) removes write contention; kill-mid-sync atomicity is proven (`chaos_kill_mid_sync.sh` PASS).
6. **HTTP security headers, canonical-host and captive-portal logic — one gap (NODE-03, fixed).** Host handling is sound: the canonical redirect target is the compile-time constant origin + request URI (`middleware.go` line 70), the probe redirect is a constant absolute URL (`handlers.go` line 415), no handler reflects the Host header or any user input into a response header, and Go's header writer neutralizes control characters — no open redirect, no header injection. Exemptions match §10.2 exactly (probes answer 302 with any Host, never 204: `TestCanonicalHostRedirect`, `TestCaptiveProbesExemptFromCanonicalRedirect`, E2E §7). Static serving cannot traverse: assets are served from an in-memory map keyed by exact path, populated once from the compile-time embed (`handlers.go` `loadStaticAssets`/`handleStatic` line 396); unknown paths, `/index.html`, `/guide.html` and `..` variants all land on the JSON 404 / mux-cleaned handlers (`TestStaticAssets`, `TestIndexServed`).
7. **Absence of TLS — documented (NODE-05).**
8. **Error hygiene and privacy — verified.** Client-visible errors are fixed short codes only; internal error strings are never written to responses (`writeError`; storage failures surface as 507/429, `TestFloodStorageUnavailableMapsTo507`). The diagnostics surface is aggregates-only by construction (`health.go` header contract; store figures from pure COUNT/pragma queries), the active-clients tracker exposes exactly one integer and its keys never leave it (`status/activity.go` lines 1–17), counters are RAM-only atomics (`internal/health`), system sampling happens once a minute off the request path (`internal/status` engine, `internal/sysres`), and nothing per-client is ever persisted or logged (checked: the only log lines carry counts and paths). Pinned by `TestHealthPrivacy` and the E2E privacy assertions.
9. **Dependency hygiene (spot-check only; deep dive = Phase 5).** `node/go.mod` is minimal: direct deps are `modernc.org/sqlite v1.60.1` (pure-Go SQLite, no CGO — the single supply-chain-critical dependency) and `golang.org/x/sys v0.48.0`; eight indirect deps, all from the sqlite/libc family or golang.org/x. No `replace` directives, go 1.26.0 toolchain pin. Phase 5 should add: version freshness/vuln-database sweep and the vendored-JS provenance chain (`node/web/js/vendor/`).

### 1.4 Phase 1 quality gates (executed at this revision)

| Gate | Result |
|---|---|
| `cd node && go test ./... -count=1` | PASS — 10/10 packages |
| `cd node && go vet ./...` | PASS — clean |
| `cd node && test -z "$(gofmt -l .)"` | PASS — clean |
| `bash tests/sync_e2e.sh` | PASS — 383 assertions, 0 failed |
| `bash tests/chaos/run_all.sh` (extra, storage/handler changes) | PASS — 57 assertions, 0 failed |

---

*(Phases 2–5 append below as they complete.)*
