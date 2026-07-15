// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// sync_fga_writer_test.go — unit test (no DB) for the syncFGAWriter resilient
// per-tuple fallback: a per-tuple write failure must be logged (CWE-778 fix),
// not silently swallowed, while the write stays non-fatal.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// failingRelationStore fails every WriteTuples so the resilient per-tuple pass
// runs and each tuple fails.
type failingRelationStore struct{ writeCalls int }

func (f *failingRelationStore) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (f *failingRelationStore) WriteTuples(_ context.Context, _ []clients.RelationTuple) error {
	f.writeCalls++
	return errors.New("openfga write rejected")
}
func (f *failingRelationStore) DeleteTuples(context.Context, []clients.RelationTuple) error {
	return nil
}

func TestSyncFGAWriter_PerTupleFailure_IsLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	store := &failingRelationStore{}
	w := kachopg.NewSyncFGAWriter(store, logger)

	// Two tuples → the batch write fails → resilient per-tuple pass → each fails.
	err := w.WriteTuples(context.Background(), []reconcile.SyncFGATuple{
		{User: "user:usr_a", Relation: "viewer", Object: "account:acc_a"},
		{User: "user:usr_b", Relation: "admin", Object: "account:acc_b"},
	})
	// Non-fatal: the async drainer is the durable retry path.
	if err != nil {
		t.Fatalf("WriteTuples must stay non-fatal on per-tuple failure, got %v", err)
	}

	out := buf.String()
	if got := strings.Count(out, "sync FGA per-tuple write failed"); got != 2 {
		t.Fatalf("expected 2 per-tuple warnings, got %d; log=%s", got, out)
	}
	// The tuple identity + error must be observable in the log.
	for _, want := range []string{"user:usr_a", "account:acc_b", "openfga write rejected"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning must include %q; log=%s", want, out)
		}
	}
}

// TestSyncFGAWriter_NilLogger_NoPanic — nil logger stays safe (warnings skipped).
func TestSyncFGAWriter_NilLogger_NoPanic(t *testing.T) {
	w := kachopg.NewSyncFGAWriter(&failingRelationStore{}, nil)
	if err := w.WriteTuples(context.Background(), []reconcile.SyncFGATuple{
		{User: "user:usr_a", Relation: "viewer", Object: "account:acc_a"},
		{User: "user:usr_b", Relation: "admin", Object: "account:acc_b"},
	}); err != nil {
		t.Fatalf("nil-logger writer must stay non-fatal, got %v", err)
	}
}
