package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"offgrid/dtn-node/internal/storage"
)

// TestEnsureDBDirCreatesNestedPath verifies the cold-start bootstrap: -db in
// a nonexistent nested directory under a temp root gets its parent chain
// created (mode 0750, no world access), reports created=true, and the full
// open path — the exact sequence of main() — succeeds and serves an empty
// pull.
func TestEnsureDBDirCreatesNestedPath(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "var", "lib", "dtn-node", "node_storage.db")

	created, err := ensureDBDir(dbPath)
	if err != nil {
		t.Fatalf("ensureDBDir: %v", err)
	}
	if !created {
		t.Fatalf("a fresh nested directory must be created")
	}

	info, err := os.Stat(filepath.Dir(dbPath))
	if err != nil {
		t.Fatalf("stat created directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("parent of db must be a directory")
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		t.Fatalf("created directory must not be world-accessible, got %o", perm)
	}

	// Full cold-start path as in main(): bootstrap, then open the store.
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("storage.Open after bootstrap: %v", err)
	}
	defer store.Close()

	pulled, err := store.PullEnvelopes(nil, 10, time.Now().Unix())
	if err != nil {
		t.Fatalf("pull on fresh store: %v", err)
	}
	if len(pulled) != 0 {
		t.Fatalf("fresh store must be empty, got %+v", pulled)
	}
}

// TestEnsureDBDirNoopWhenExists verifies idempotency: an existing directory
// is left untouched and reported as not-created.
func TestEnsureDBDirNoopWhenExists(t *testing.T) {
	dir := t.TempDir() // exists already

	created, err := ensureDBDir(filepath.Join(dir, "node_storage.db"))
	if err != nil || created {
		t.Fatalf("existing directory must be a no-op, got created=%v err=%v", created, err)
	}

	created, err = ensureDBDir(filepath.Join(dir, "sub", "node_storage.db"))
	if err != nil || !created {
		t.Fatalf("nested missing directory must be created, got created=%v err=%v", created, err)
	}
}

// TestEnsureDBDirBareFilenameIsNoop verifies that a bare filename in the
// current directory (dir == ".") is not mangled: nothing is created anywhere.
func TestEnsureDBDirBareFilenameIsNoop(t *testing.T) {
	created, err := ensureDBDir("node_storage.db")
	if err != nil || created {
		t.Fatalf("bare filename must be a no-op, got created=%v err=%v", created, err)
	}
}
