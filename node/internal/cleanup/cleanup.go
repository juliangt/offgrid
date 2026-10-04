// Package cleanup runs the expired-envelope janitor of docs/protocol.md
// §10.6: one sweep immediately at daemon startup, then a sweep every 15
// minutes. Sweeps apply the exclusive expiry boundary
// (DELETE FROM envelopes WHERE created_at + ttl < now), which pairs with the
// inclusive serving boundary of the pull select so an envelope is always
// either servable or deleted — never in limbo.
package cleanup

import (
	"context"
	"log"
	"time"
)

// Janitor is the storage surface the cleaner needs; satisfied by
// *storage.Store.
type Janitor interface {
	DeleteExpired(now int64) (int64, error)
}

// Start launches the cleanup goroutine and returns immediately. It performs
// one sweep right away (fresh nodes start empty; restarted nodes reap their
// backlog without waiting a full interval), then ticks on interval until ctx
// is cancelled. interval must come from the caller; the daemon passes the
// binding 15 minutes of §10.6.
func Start(ctx context.Context, store Janitor, interval time.Duration) {
	go run(ctx, store, interval)
}

// run is the janitor loop body.
func run(ctx context.Context, store Janitor, interval time.Duration) {
	sweep(store)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep(store)
		}
	}
}

// sweep performs one expired-envelope pass and logs the outcome. A failed
// sweep is logged but never fatal: the next tick retries in 15 minutes.
func sweep(store Janitor) {
	deleted, err := store.DeleteExpired(time.Now().Unix())
	if err != nil {
		log.Printf("[cleanup] error deleting expired envelopes: %v", err)
		return
	}
	log.Printf("[cleanup] deleted %d expired envelopes", deleted)
}
