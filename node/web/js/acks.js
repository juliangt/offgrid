/*
 * Off-grid DTN messaging SPA — delivery acknowledgments (§4.5), both
 * sides of the convention:
 *
 *   recipient: after fully receiving ONE message (a flat envelope, or a
 *              chunked message at reassembly completion), emit at most
 *              one signed ack envelope addressed back to the sender's
 *              dest_hint — an ordinary v1 envelope, blind to nodes and
 *              mules (§4.5). Acks are never acked (termination rule).
 *   sender   : keep a local `sent` record per message (keyed by the
 *              envelope id acks reference) and flip its state
 *              queued → sent → delivered when a signature-verified ack
 *              arrives that binds to the recipient it was sent to.
 *
 * Everything here is pure and DOM-free; the persistence lives in store.js
 * (the `sent` store, §15.6 migration v3) and the wiring in ui.js. Part of
 * the pure protocol engine. ES5 on purpose: captive-portal mini-browsers
 * run the OS WebView.
 */
"use strict";

/* ---------------------------------------------------------------------
 * Convention helpers (§4.5).
 * ------------------------------------------------------------------- */

/*
 * TTL alignment (§4.5, binding formula). The ack carries a TTL >= the
 * original's remaining life, clamped to the §8.1 range — and the ack is a
 * NEW envelope: nothing about the original is mutated, so the ack never
 * extends the original's life (no refresh rule, §15-style):
 *
 *   remaining = (orig.created_at + orig.ttl) - ack_time
 *   ack_ttl   = min(TTL_MAX, max(remaining, TTL_MIN))
 *   ack.created_at = ack_time          (NOT the original's)
 *
 * So the ack is servable at least TTL_MIN (a §8.1 envelope constraint)
 * and never more than TTL_MAX; when the original still had TTL_MIN or
 * more of life left, the ack expires no later than the original.
 */
function ackTtlFor(origCreatedAt, origTtl, ackTimeSec) {
  var remaining = (origCreatedAt + origTtl) - ackTimeSec;
  var ttl = remaining > TTL_MAX ? TTL_MAX : remaining;
  return ttl < TTL_MIN ? TTL_MIN : ttl;
}

/*
 * The ack reference id (§4.5, binding choice): `r` is ALWAYS an envelope
 * id (64 hex) — for a FLAT message the id of its single envelope; for a
 * CHUNKED message the id of the LAST chunk (index n-1), the final
 * envelope of the message. Flat inners therefore need no id of their own,
 * and the sender can map `r` back to the message locally: it kept every
 * emitted envelope id in its `sent` record (never on the network).
 */
function ackReferenceIdFor(envIds) {
  if (!envIds || !envIds.length) return null;
  return envIds[envIds.length - 1];
}

/*
 * The sender-side state machine (§4.5): one `sent` record per tracked
 * message, keyed by the ack reference id (the id acks will carry, see
 * ackReferenceIdFor). `to_pubkey` is the recipient's Ed25519 public key
 * from the directory — the key a genuine ack MUST be signed with, so the
 * sender can bind the ack to the peer it actually sent to (a forged or
 * third-party ack fails this bind even under a self-consistent signature).
 */
function sentNewRecord(opts) {
  var ids = [];
  for (var i = 0; i < opts.envIds.length; i++) ids.push(opts.envIds[i]);
  return {
    id: ackReferenceIdFor(ids),      /* storage key == the ack reference id */
    env_ids: ids,                    /* every envelope of the message */
    to_alias: opts.toAlias,
    to_pubkey: opts.toPubkey,        /* recipient Ed25519 (Base64, §10.3) */
    m: opts.text,
    t: opts.t,
    created_at: opts.createdAt,
    ttl: opts.ttl,
    state: "queued",                 /* queued → sent → delivered (§4.5) */
    sent_at: null,
    acked_at: null,
    ack_type: null
  };
}

/*
 * Bind a decrypted ack (a §4.3 result with `.ack`) to a sent record:
 * the reference must name THIS message, the type must be the defined
 * "received" (1), and the signature's key must be the recipient the
 * message was sent to. Any mismatch is silently unmatched — an ack that
 * binds to nothing is ignored, never surfaced (§4.3 silent handling).
 */
function ackMatchesSent(dec, record) {
  if (!dec || !dec.ok || !dec.ack || !record) return false;
  if (dec.ack.w !== ACK_TAG) return false;
  if (dec.ack.y !== ACK_TYPE_RECEIVED) return false;
  if (dec.ack.r !== record.id) return false;
  return dec.k === record.to_pubkey;
}

/* The delivered flip: a NEW record (the input is never mutated) carrying
 * the ack time and type. The caller persists it only after
 * ackMatchesSent(dec, record) held. */
function sentDeliveredRecord(record, ackTimeSec) {
  var out = {};
  for (var f in record) {
    if (Object.prototype.hasOwnProperty.call(record, f)) out[f] = record[f];
  }
  out.state = "delivered";
  out.acked_at = ackTimeSec;
  out.ack_type = ACK_TYPE_RECEIVED;
  return out;
}

/* Honest per-state wording (§4.5): "queued" and "sent" make NO claim
 * beyond what the sender knows; only a verified ack says "delivered". */
function sentStatusLabel(state) {
  if (state === "delivered") return "delivered — the recipient's device confirmed receipt";
  if (state === "sent") return "sent — carried by a mule";
  return "queued — waiting for the next sync";
}

/*
 * Recipient-side ack decision (§4.5, pure): given a §4.3 decrypt result
 * and the lifetime of the received message, return the parameters of the
 * ONE ack to emit — or null when nothing may be emitted. The termination
 * rule lives here: an arrival that IS an ack (dec.ack set) never produces
 * an ack task, so acks cannot loop.
 *   - flat message: refId = the envelope's own id;
 *   - chunked message: called once at reassembly completion with refId =
 *     the last chunk's envelope id (ackReferenceIdFor of the chunk ids).
 * `origCreatedAt`/`origTtl` are the original envelope's (for chunks, the
 * shared fields every chunk carries).
 */
function ackTaskForArrival(dec, refId, origCreatedAt, origTtl) {
  if (!dec || !dec.ok) return null;
  if (dec.ack) return null;                       /* §4.5 termination rule */
  if (typeof refId !== "string" || !HEX64_REGEX.test(refId)) return null;
  return { r: refId, created_at: origCreatedAt, ttl: origTtl, type: ACK_TYPE_RECEIVED };
}
