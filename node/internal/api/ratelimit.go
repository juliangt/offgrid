// ratelimit.go — per-client admission control for the node's write path
// (issue #16 Phase 2, Track 2: DoS/sabotage resistance at the daemon layer).
//
// This is defense in depth: the daemon assumes the phase-1 network shields
// (raspberry/firewall/*) were bypassed or misconfigured, so the API sheds
// abusive write traffic itself. Two independent in-memory token buckets are
// enforced per source IP:
//
//  1. a POST request budget (requests/second) on POST /api/v1/sync and
//     POST /api/v1/directory — the expensive entry points (body parse,
//     validation, storage work);
//  2. a pushed-envelope budget (envelopes/hour) on sync pushes, so one
//     station cannot own the whole 5000-envelope store of §8.1 even while
//     staying under the request budget.
//
// Everything here is RAM-only and ephemeral by design (docs/protocol.md §13:
// the node never persists user-identifying data): bucket keys are source IPs
// seen in the last few minutes and vanish on restart. There is no disk
// state, no log line, and no per-envelope attribution anywhere.

package api

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Admission-control defaults (issue #16 Phase 2). Both budgets are sized
// against the legitimate mule of §8.1/§11 — a phone browser that pushes its
// whole transit_queue (≤ 100 envelopes per sync) a handful of times per
// portal visit:
//
//   - POST request budget: burst 60 requests per IP, refilled at 1 request
//     per 2 s. A legitimate visit spends ~10 requests (page-load sync,
//     manual sync, directory registration); burst 60 keeps ~6-30× headroom
//     even for a heavy user, while a scripted flood trips it in well under
//     a second of sustained hammering.
//   - Envelope budget: burst 600 envelopes per IP, refilled at 600/hour.
//     Six consecutive full-capacity syncs (6 × 100, §8.1 transit FIFO cap)
//     always fit; the refill equals ten envelopes/minute, so follow-up
//     visits are unaffected while a single station filling the entire
//     5000-envelope store needs more than eight hours — the global §8.1 cap
//     plus the TTL janitor (§10.6) win that race by design.
//
// These are vars purely as a test hook (the maxEnvelopes pattern of the
// storage package); production code must never reassign them. Tests use
// overrideAdmissionLimits below.
var (
	postRequestBurst          = 60
	postRequestRefillInterval = 2 * time.Second // one request token per interval
	syncEnvelopeBurst         = 600
	syncEnvelopeRefillPerHour = 600
)

// Bucket-map bounding: the map is keyed by source IP and must not grow
// unbounded under a spoofed-source flood (the kernel may deliver packets
// with forged addresses that were never associated stations). Buckets idle
// longer than bucketIdleTTL are evicted by a lazy sweep that runs inside
// allow() only once the map has grown to bucketEvictionFloor entries — O(n)
// and rare in steady state (a quiet village square holds dozens of buckets,
// not thousands). Both are vars for the same test-hook reason as above.
var (
	bucketEvictionFloor = 4096
	bucketIdleTTL       = 10 * time.Minute
)

// tokenBucket is one client's balance: tokens refill continuously at the
// limiter's rate up to burst, and each admitted withdrawal costs cost units.
type tokenBucket struct {
	tokens float64
	last   time.Time // last refill/use — the idle-eviction clock
}

// rateLimiter is an in-memory token-bucket limiter keyed by client IP. The
// zero value is not usable; build one with newRateLimiter. now is injectable
// so tests can drive refill and eviction deterministically.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	burst   float64
	refill  float64 // tokens per second; <= 0 means "burst only, never refills"
	now     func() time.Time
}

// newRateLimiter builds a limiter with the given burst and a refill of one
// token every interval (interval <= 0 disables refill: burst-only budget).
func newRateLimiter(burst int, interval time.Duration) *rateLimiter {
	refill := 0.0
	if interval > 0 {
		refill = 1 / interval.Seconds()
	}
	return &rateLimiter{
		buckets: make(map[string]*tokenBucket),
		burst:   float64(burst),
		refill:  refill,
		now:     time.Now,
	}
}

// allow admits a withdrawal of cost tokens if the client's bucket can cover
// it atomically (fail closed: a batch that cannot be covered in full is
// rejected and consumes nothing, so a rejected push never half-spends a
// budget). It reports the time until the request could be retried — the
// Retry-After value — and 0 when admitted.
//
// As a side effect of admission it maintains the eviction invariant: once
// the map reaches bucketEvictionFloor entries, buckets idle longer than
// bucketIdleTTL are dropped before a new one is created.
func (l *rateLimiter) allow(key string, cost float64) (bool, time.Duration) {
	if cost < 0 {
		cost = 0
	}
	// A cost larger than the entire burst could never be covered once any
	// token is spent; clamp it so such a request is admitted against a FULL
	// bucket only instead of being refused forever. With the shipped limits
	// this is unreachable (costs are 1 request or ≤ 100 envelopes against a
	// burst of 60/600) — it exists so a mis-tuned hook cannot brick a route.
	if cost > l.burst {
		cost = l.burst
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.buckets) >= bucketEvictionFloor {
		l.sweepIdleLocked(now)
	}
	b, ok := l.buckets[key]
	if !ok {
		if cost == 0 {
			// Zero-cost probes (e.g. pull-only syncs) must not mint buckets:
			// the map stays empty and unbounded growth from the read path of
			// the write endpoint is impossible.
			return true, 0
		}
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.last).Seconds()
	if l.refill > 0 && elapsed > 0 {
		b.tokens += elapsed * l.refill
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
	}
	b.last = now

	if b.tokens >= cost {
		b.tokens -= cost
		return true, 0
	}
	if l.refill <= 0 {
		// Burst-only budget: nothing will ever refill. Advertise an hour —
		// "not now" — rather than an infinite Retry-After.
		return false, time.Hour
	}
	deficit := cost - b.tokens
	return false, time.Duration(deficit / l.refill * float64(time.Second))
}

// sweepIdle evicts every bucket last touched before now-bucketIdleTTL and
// returns how many were dropped. Exported within the package for tests (the
// lazy trigger inside allow is hard to hit deterministically without a
// multi-thousand-bucket fixture); production relies on the lazy path.
func (l *rateLimiter) sweepIdle(now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sweepIdleLocked(now)
}

// sweepIdleLocked is sweepIdle with the mutex already held.
func (l *rateLimiter) sweepIdleLocked(now time.Time) int {
	cutoff := now.Add(-bucketIdleTTL)
	evicted := 0
	for key, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, key)
			evicted++
		}
	}
	return evicted
}

// clientKey derives the per-client bucket key from the NETWORK-layer source
// address only (r.RemoteAddr).
//
// X-Forwarded-For and friends MUST NOT be consulted: the node sits directly
// on an open access point — there is no reverse proxy in the path — so every
// XFF-style header is 100% attacker-controlled. Trusting it would (a) let
// one device mint unlimited fresh buckets by rotating the header, defeating
// the whole limiter, and (b) attribute shed decisions to a spoofable
// identity. RemoteAddr is set by the kernel from the TCP peer address and
// cannot be forged by the client. The key is the port-stripped IP so a
// client's many connections share one bucket.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // no port (unexpected for TCP): the raw address still keys a bucket
	}
	return host
}

// newAdmissionControl builds the two write-path limiters from the package
// defaults (vars, so tests can retune them before constructing a server).
func newAdmissionControl() (post *rateLimiter, envelopes *rateLimiter) {
	return newRateLimiter(postRequestBurst, postRequestRefillInterval),
		newRateLimiter(syncEnvelopeBurst, syncEnvelopeRefillPerHourToInterval())
}

// syncEnvelopeRefillPerHourToInterval converts the envelope refill budget
// (tokens per hour) into the per-token interval newRateLimiter expects.
func syncEnvelopeRefillPerHourToInterval() time.Duration {
	if syncEnvelopeRefillPerHour <= 0 {
		return 0 // burst-only budget
	}
	return time.Hour / time.Duration(syncEnvelopeRefillPerHour)
}

// overrideAdmissionLimits replaces the package-level admission defaults and
// the bucket-bounding knobs, returning a func that restores every previous
// value (defer it). Test hook in the maxEnvelopes save/set/restore pattern;
// the values are read when a server is constructed, so override before
// calling New.
func overrideAdmissionLimits(postBurst int, postRefill time.Duration, envBurst, envRefillPerHour, evictionFloor int, idleTTL time.Duration) (restore func()) {
	oldPB, oldPR := postRequestBurst, postRequestRefillInterval
	oldEB, oldER := syncEnvelopeBurst, syncEnvelopeRefillPerHour
	oldFloor, oldIdle := bucketEvictionFloor, bucketIdleTTL
	postRequestBurst, postRequestRefillInterval = postBurst, postRefill
	syncEnvelopeBurst, syncEnvelopeRefillPerHour = envBurst, envRefillPerHour
	bucketEvictionFloor, bucketIdleTTL = evictionFloor, idleTTL
	return func() {
		postRequestBurst, postRequestRefillInterval = oldPB, oldPR
		syncEnvelopeBurst, syncEnvelopeRefillPerHour = oldEB, oldER
		bucketEvictionFloor, bucketIdleTTL = oldFloor, oldIdle
	}
}

// withRequestBudget wraps one of the two POST handlers with the per-IP
// request budget. The check runs BEFORE the body is read a single byte
// (cheap-first): an over-budget client pays one map lookup and gets a 429
// instead of making the node parse megabytes of JSON.
func (s *server) withRequestBudget(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := s.postBudget.allow(clientKey(r), 1); !ok {
			writeRateLimited(w, wait)
			return
		}
		next(w, r)
	}
}

// writeRateLimited emits the §10.1 error shape with the 429 rate_limited
// code and an RFC 7431-style Retry-After hint in whole seconds (≥ 1) so a
// legitimate client that races the budget backs off instead of hot-looping.
func writeRateLimited(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.FormatInt(retryAfterSeconds(wait), 10))
	writeError(w, http.StatusTooManyRequests, codeRateLimited)
}

// retryAfterSeconds renders a wait duration as a whole number of seconds,
// rounded up, never below 1: HTTP Retry-After is integer seconds and "0"
// would invite an immediate retry storm.
func retryAfterSeconds(wait time.Duration) int64 {
	if wait <= 0 {
		return 1
	}
	s := int64((wait + time.Second - 1) / time.Second)
	if s < 1 {
		s = 1
	}
	return s
}
