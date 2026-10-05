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
DTN.ACK_TAG = ACK_TAG;
DTN.ACK_TYPE_RECEIVED = ACK_TYPE_RECEIVED;
DTN.ACK_META_MAX_BYTES = ACK_META_MAX_BYTES;
DTN.SENT_HISTORY_MAX = SENT_HISTORY_MAX;
DTN.HINT_EPOCH_SECONDS = HINT_EPOCH_SECONDS;
DTN.HINT_INFO = HINT_INFO;
DTN.HINT_LENGTH_BYTES = HINT_LENGTH_BYTES;
DTN.HINT_TRANSITION_DEADLINE = HINT_TRANSITION_DEADLINE;
DTN.PREKEY_BUNDLE_VERSION = PREKEY_BUNDLE_VERSION;
DTN.PREKEY_SPK_TTL_SECONDS = PREKEY_SPK_TTL_SECONDS;
DTN.PREKEY_OPK_LOW_WATER = PREKEY_OPK_LOW_WATER;
DTN.PREKEY_OPK_BATCH_TARGET = PREKEY_OPK_BATCH_TARGET;
DTN.PREKEY_OPK_MIN = PREKEY_OPK_MIN;
DTN.PREKEY_OPK_MAX = PREKEY_OPK_MAX;
DTN.PREKEY_BUNDLE_MAX_BYTES = PREKEY_BUNDLE_MAX_BYTES;
DTN.PREKEY_PUBLIC_B64_LEN = PREKEY_PUBLIC_B64_LEN;
DTN.PREKEY_SIG_B64_LEN = PREKEY_SIG_B64_LEN;
DTN.QR_PAYLOAD_PREFIX = QR_PAYLOAD_PREFIX;
DTN.QR_PAYLOAD_VERSION = QR_PAYLOAD_VERSION;
DTN.QR_MAX_VERSION = QR_MAX_VERSION;
DTN.QR_ECC_LEVEL = QR_ECC_LEVEL;
DTN.QR_TS_SKEW_SECONDS = QR_TS_SKEW_SECONDS;
DTN.QR_QUIET_ZONE_MODULES = QR_QUIET_ZONE_MODULES;
DTN.qrCrc32 = qrCrc32;
DTN.qrCrc32Hex = qrCrc32Hex;
DTN.qrCanonicalPayloadString = qrCanonicalPayloadString;
DTN.qrCanonicalObjectString = qrCanonicalObjectString;
DTN.qrBuildPayload = qrBuildPayload;
DTN.qrParsePayload = qrParsePayload;
DTN.qrContactRecord = qrContactRecord;
DTN.qrMergeRecipients = qrMergeRecipients;
DTN.qrMakeMatrix = qrMakeMatrix;
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
DTN.hmacSha256 = hmacSha256;
DTN.hkdfSha256 = hkdfSha256;
DTN.randomBytes = randomBytes;
DTN.concatBytes = concatBytes;
DTN.jsonEscapeString = jsonEscapeString;
DTN.canonicalSignedString = canonicalSignedString;
DTN.canonicalInnerJson = canonicalInnerJson;
DTN.canonicalChunkedSignedString = canonicalChunkedSignedString;
DTN.canonicalChunkedInnerJson = canonicalChunkedInnerJson;
DTN.canonicalAckSignedString = canonicalAckSignedString;
DTN.canonicalAckInnerJson = canonicalAckInnerJson;
DTN.canonicalEnvelopeString = canonicalEnvelopeString;
DTN.validateAlias = validateAlias;
DTN.createIdentity = createIdentity;
DTN.identityFromSeed = identityFromSeed;
DTN.deriveDestHint = deriveDestHint;
DTN.epochOf = epochOf;
DTN.epochSalt = epochSalt;
DTN.deriveRotatingHint = deriveRotatingHint;
DTN.hintCandidates = hintCandidates;
DTN.computeEnvelopeId = computeEnvelopeId;
DTN.buildEnvelope = buildEnvelope;
DTN.decryptEnvelope = decryptEnvelope;
DTN.validEnvelopeShape = validEnvelopeShape;
DTN.canonicalPrekeyBundleString = canonicalPrekeyBundleString;
DTN.prekeySignBundle = prekeySignBundle;
DTN.prekeyBundleShapeOk = prekeyBundleShapeOk;
DTN.prekeyVerifyBundleSig = prekeyVerifyBundleSig;
DTN.prekeyRandomIndex = prekeyRandomIndex;
DTN.prekeyTargetForEntry = prekeyTargetForEntry;
DTN.prekeyGenerateStock = prekeyGenerateStock;
DTN.prekeyBundleForPublish = prekeyBundleForPublish;
DTN.prekeyTrialKeys = prekeyTrialKeys;
DTN.prekeyStateWithoutOpk = prekeyStateWithoutOpk;
DTN.prekeyNeedsReplenish = prekeyNeedsReplenish;
DTN.prekeyReplenishedStock = prekeyReplenishedStock;
DTN.classifyPullEnvelopes = classifyPullEnvelopes;
DTN.evictTransitQueue = evictTransitQueue;
DTN.convertEnvelopeV1toV2 = convertEnvelopeV1toV2;
DTN.maxAdvertisedEnvelopeVersion = maxAdvertisedEnvelopeVersion;
DTN.observedEpochFromCapabilities = observedEpochFromCapabilities;
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
DTN.ackTtlFor = ackTtlFor;
DTN.ackReferenceIdFor = ackReferenceIdFor;
DTN.ackTaskForArrival = ackTaskForArrival;
DTN.sentNewRecord = sentNewRecord;
DTN.ackMatchesSent = ackMatchesSent;
DTN.sentDeliveredRecord = sentDeliveredRecord;
DTN.sentStatusLabel = sentStatusLabel;
DTN.nacl = naclRef;

if (typeof window !== "undefined") {
  window.DTN = DTN;
}
