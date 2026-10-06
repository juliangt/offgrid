# Known limitations — residual risks accepted by design (issue #14)

Offgrid keeps its promises by construction (end-to-end encryption, blind nodes) and accepts a specific list of things it does **not** protect against; this page states each one in plain language, with the authoritative source. Nothing here is a surprise or a bug: every item was found and accepted by the security audit ([`docs/security-audit.md`](security-audit.md), issue #14, final report v1.0.0, 2026-10-06), and the normative wording lives in [`docs/protocol.md`](protocol.md) (spec 1.12.2) and [`docs/offline-maintenance.md`](offline-maintenance.md).

| Limitation | What it means for you | Where it's specified |
|---|---|---|
| No TLS — the portal is plain HTTP | Traffic metadata (who syncs, when, how much) and the directory are readable by anyone on the node's Wi-Fi; message content is not. | protocol §12; audit NODE-05 |
| The node serves the app itself | A malicious node operator can serve a modified app that steals the identity of anyone who registers on it. | protocol §12/§13.5; audit SPA-04, PROTO-04 |
| A directory holder can link mail to aliases — permanently | Whoever holds a node's directory can recompute every user's receiving code and match stored envelopes to aliases, for any date, forever. | protocol §6.1/§13.3; audit PROTO-01 |
| Directory entries carry no proof of ownership | Any device on the open Wi-Fi can republish someone's directory entry with attacker keys and silently receive their mail. | protocol §13.5; audit NODE-04, PROTO-06 |
| Replayed mail after expiry | A captured envelope can be re-injected after it left the store; a fresh or restored device may see an old message as new mail. | protocol §13.5; audit PROTO-02 |
| Filling the store is censorship | A hostile station can hold a node's mailbox shut to NEW mail for up to 30 days per fill, within its rate budget; mules can be stuffed the same way. | protocol §13.6/§8.1; audit PROTO-03, NODE-01 |
| A shared or unlocked device is the identity | Anyone holding your unlocked browser (or the seed) is you: keys, sent list and decrypted inbox are on the device. | protocol §13.1/§13.5; audit SPA-05 |
| An extracted SD card is readable | Whoever holds a node's card reads the whole directory in plaintext and all ciphertext envelopes; no at-rest encryption. | protocol §13.2; audit PI-03 |
| Release hashes are unsigned; `curl \| bash` trusts the channel | The checksums ride the same channel as the files they pin; an attacker controlling that channel can re-sign in the same stroke. | audit SUPPLY-02; offline-maintenance §2 |
| Mules can withhold or drop mail | A mule (or hostile node) can refuse to carry mail; the protocol guarantees blindness, not delivery — silence is indistinguishable from loss. | protocol §13.2/§13.6; audit SPA-03 |
| The signed-release design is not built yet | The capsule-signing closure for the row above exists as a complete design record with zero implementation. | offline-maintenance §2 (design record) |

## 1. No TLS: the portal is plain HTTP

The captive portal and the API speak unencrypted HTTP by design: no certificate authority issues certificates for `offgrid.local` on a shared static IP, and an offline PKI would break the captive flow (protocol §12). What that means in practice: any device on the node's Wi-Fi can observe *that* you sync, when, how much, and read the public directory — while message content stays protected by the end-to-end encryption, which TLS would not strengthen. An attacker who positions themselves as the access point (evil twin) can also serve their own content; see §2 below. (Audit NODE-05.)

## 2. The node serves the app itself (evil-twin trust)

Every byte of the web app arrives from the node you are connected to — there is no out-of-band code channel. A malicious or compromised node can therefore serve a modified app that captures the seed and keys of everyone who registers, imports a seed, or unlocks on it; the app's own cryptography cannot defend against the app having been replaced (protocol §13.5 "the node serves the client code"; audit SPA-04, PROTO-04). Practical check: the shipped crypto engine carries recorded SHA-256 hashes with a one-command offline re-verification recipe (audit SPA-01), so a swapped engine is detectable from any terminal; registering only on nodes whose operator you trust is the real control, and signed/native distribution is the structural closure reserved for protocol §14.

## 3. A directory holder can link envelopes to aliases — permanently

This is the audit's headline correction, stated honestly. An earlier revision of the spec claimed that the rotating per-epoch address (`dest_hint`) confined a directory-holding operator's ability to match envelopes to aliases to the current epoch. That was wrong: the epoch counter is public, the derivation input is the user's public directory key, and every envelope carries its creation time in plaintext — so the operator can recompute a user's address for any epoch, past or future, and link every stored envelope to its alias permanently (protocol §13.3, corrected in spec 1.12.2; audit PROTO-01). What rotation actually buys: each match needs fresh per-epoch work instead of one computation forever, and mail deposited before an operator later acquires the directory only becomes linkable once they do the recomputation. Within a single node — where the operator holds the directory from day one — treat envelope↔alias linkage by the operator as permanent and accepted.

## 4. Directory entries have no proof of ownership

Registering on a node's directory proves nothing: the entry is keyed by a public key alone, with no signature or challenge, because demanding proof would force the blind node to do cryptography (protocol §13.5; audit NODE-04). Consequence: any device on the open Wi-Fi — not just the node operator — can republish a victim's entry bound to attacker-controlled keys, and later senders encrypt to the attacker while the victim silently stops receiving mail. Note the precise limit of the in-person QR exchange: it authenticates a contact's *identity* key, but when the visited node's directory also lists that identity, the directory's encryption key silently wins (audit PROTO-05; protocol §4.7/§13.5) — the pin-and-warn refinement that makes such a divergence visible is specified in [`offline-maintenance.md`](offline-maintenance.md) §3.5 and not yet built.

## 5. Replayed mail after expiry

The node's duplicate check covers only the mail it currently holds. Once an envelope has expired and been swept, nothing remembers it — and envelopes carry no freshness floor — so a station that captured mail (anyone can pull the whole dead-drop; that is the design) can re-inject it later at any node (protocol §13.5, corrected in spec 1.12.2; audit PROTO-02). Impact is bounded: a replayed message can reappear as new mail on a freshly initialized or seed-restored device, and replays nibble at the store's headroom — but the MAC and signature still bind content, and prekey-addressed replay to a consumed key fails outright.

## 6. Filling the store is censorship, and the caps are only partial shields

A blind node cannot tell junk mail from real mail, so it cannot prefer one over the other. A single hostile station working within its rate budget can fill a node's 5000-envelope store with maximum-TTL junk, after which every further push — including legitimate mail — is rejected until the junk ages out through its own lifetime: up to 30 days per fill, repeatable, scaling with colluding devices (protocol §13.6 "resource exhaustion as censorship"; audit PROTO-03). Mail already deposited stays servable (the keep-oldest policy), and the NODE-01 directory cap added by the audit is the same class of partial shield for registrations (5000 rows, new registrations shed `429 node_full` at cap) — it bounds the damage, it does not prevent the fill. The same blindness exposes mules: a hostile node can fill a visiting mule's 100-slot carry queue with valid-shaped garbage (audit SPA-03).

## 7. A shared or unlocked device is the identity

The unlocked browser holds the seed and both private keys in its storage, shows the backup seed on demand, and keeps the inbox in decrypted form; there is no lock screen or passphrase (protocol §13.1 trusts exactly the sender's and recipient's own browsers; audit SPA-05). Anyone who gets your unlocked device — or your written-down seed — is you, including reading what has already been delivered. Protect the phone like the letter; the seed backup is the one recovery path if the device is lost (and the one secret worth guarding like cash).

## 8. An extracted SD card is readable

There is no at-rest encryption on the node: whoever holds the SD card (or any local root) reads the directory in plaintext — aliases and public keys — plus every stored envelope, which is ciphertext the design already lets anyone pull off the air (audit PI-03; protocol §13.2 treats node-holder and operator as the same trust level). No client secrets ever exist on the node to steal. The mitigation is physical: treat the hardware as the trust boundary, and use the optional read-only-root mode and volatile state that the provisioning ships for tamper resistance.

## 9. Release hashes are unsigned; `curl | bash` trusts the channel

Installations verify every downloaded asset against the release `SHA256SUMS` (checksums catch corruption, truncation and wrong-tag mistakes — audit SUPPLY-01/03), but that sums file is itself unsigned and travels over the same channel as the artifacts it pins. An attacker who controls the channel — repository takeover, a malicious release edit, a compromised origin — can regenerate the hashes in the same stroke, and the one-line `curl | sudo bash` path adds a window where the installer comes from moving `main` while the assets come from the latest tag (audit SUPPLY-02). Operator guidance: prefer a pinned `--ref vX.Y.Z`, and treat the offline USB bundle as the verification boundary — assemble it on a machine you trust and keep the `SHA256SUMS` with it.

## 10. Mules can withhold or drop mail

The protocol guarantees that nodes and mules *cannot read or forge* mail; it cannot guarantee that they *carry* it. A mule can refuse to forward what it holds, a hostile node can hand a mule garbage that evicts real cargo, and a sender cannot tell the difference between suppression and an envelope that expired on the way — selective withholding is indistinguishable from ordinary loss in a delay-tolerant network (protocol §13.2/§13.6; audit SPA-03). Delivery confirmations are best-effort signals that travel the same way, so silence means *unknown*, never *not delivered*. Retries are on you: send again, or walk the route yourself.

## 11. The signed-capsule design is not implemented yet

The designed closure for §9 — signed release capsules, with the signing key on an air-gapped machine, a staging endpoint, and anti-rollback counters — exists as a complete, implementable design record in [`offline-maintenance.md`](offline-maintenance.md) §2 and nowhere else: no capsule code ships today (audit SUPPLY-02). Until its follow-up issues land, the acceptance test for a release remains the checksum-verified offline bundle path of §9, and the trust root is the channel you copied it from.

---

Maintained as part of the issue-#14 security audit (final report: [`docs/security-audit.md`](security-audit.md), v1.0.0). If a design decision changes one of these residuals, update both that report's finding and this page together — the structure test `tests/docs_structure.mjs` pins this list's coverage.
