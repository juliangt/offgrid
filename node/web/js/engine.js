/*
 * Off-grid DTN messaging SPA — engine export. Collects the pure
 * protocol engine (no DOM touched so far) into one `DTN` object,
 * `window.DTN` in the browser, so the exact shipped code can be
 * exercised headless from Node (see tests/crypto_roundtrip.mjs).
 */
"use strict";

/* ---------------------------------------------------------------------
 * 7. Engine export (no DOM touched so far).
 * ------------------------------------------------------------------- */
var DTN = {};
DTN.TRANSIT_CAPACITY = TRANSIT_CAPACITY;
DTN.TTL_DEFAULT = TTL_DEFAULT;
DTN.TTL_MIN = TTL_MIN;
DTN.TTL_MAX = TTL_MAX;
DTN.MESSAGE_MAX_BYTES = MESSAGE_MAX_BYTES;
DTN.CHUNK_TAG = CHUNK_TAG;
DTN.CHUNK_MAX_PARTS = CHUNK_MAX_PARTS;
DTN.CHUNK_G_BYTES = CHUNK_G_BYTES;
DTN.CHUNK_META_MAX_BYTES = CHUNK_META_MAX_BYTES;
DTN.CHUNK_TEXT_PLUS_ALIAS_LIMIT = CHUNK_TEXT_PLUS_ALIAS_LIMIT;
DTN.CHUNK_WARN_PARTS = CHUNK_WARN_PARTS;
DTN.ALIAS_REGEX = ALIAS_REGEX;
DTN.CANONICAL_HOST = CANONICAL_HOST;
DTN.CANONICAL_URL = CANONICAL_URL;
DTN.utf8Encode = utf8Encode;
DTN.utf8Decode = utf8Decode;
DTN.messageByteLength = messageByteLength;
DTN.b64encode = b64encode;
DTN.b64decode = b64decode;
DTN.hexEncode = hexEncode;
DTN.hexDecode = hexDecode;
DTN.sha256 = sha256;
DTN.randomBytes = randomBytes;
DTN.concatBytes = concatBytes;
DTN.jsonEscapeString = jsonEscapeString;
DTN.canonicalSignedString = canonicalSignedString;
DTN.canonicalInnerJson = canonicalInnerJson;
DTN.canonicalChunkedSignedString = canonicalChunkedSignedString;
DTN.canonicalChunkedInnerJson = canonicalChunkedInnerJson;
DTN.canonicalEnvelopeString = canonicalEnvelopeString;
DTN.validateAlias = validateAlias;
DTN.createIdentity = createIdentity;
DTN.identityFromSeed = identityFromSeed;
DTN.deriveDestHint = deriveDestHint;
DTN.computeEnvelopeId = computeEnvelopeId;
DTN.buildEnvelope = buildEnvelope;
DTN.decryptEnvelope = decryptEnvelope;
DTN.validEnvelopeShape = validEnvelopeShape;
DTN.classifyPullEnvelopes = classifyPullEnvelopes;
DTN.evictTransitQueue = evictTransitQueue;
DTN.convertEnvelopeV1toV2 = convertEnvelopeV1toV2;
DTN.maxAdvertisedEnvelopeVersion = maxAdvertisedEnvelopeVersion;
DTN.prepareOutgoingBatch = prepareOutgoingBatch;
DTN.chunkPackCapped = chunkPackCapped;
DTN.chunkTextBudget = chunkTextBudget;
DTN.chunkSplitText = chunkSplitText;
DTN.chunkPlannedCount = chunkPlannedCount;
DTN.chunkComposerLimit = chunkComposerLimit;
DTN.buildMessageEnvelopes = buildMessageEnvelopes;
DTN.chunkNewState = chunkNewState;
DTN.chunkStateWithPart = chunkStateWithPart;
DTN.chunkStateHave = chunkStateHave;
DTN.chunkStateComplete = chunkStateComplete;
DTN.chunkStateText = chunkStateText;
DTN.chunkStateExpired = chunkStateExpired;
DTN.chunkInboxRecord = chunkInboxRecord;
DTN.nacl = naclRef;

if (typeof window !== "undefined") {
  window.DTN = DTN;
}
