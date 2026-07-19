// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// sync_fga_writer_test.go — unit test (no DB) for the syncFGAWriter create-path
// closer.
//
// INVARIANT UNDER TEST (all-or-nothing materialization): the reconciler
// materializes the creator's per-object owner grant as the set {v_get,v_list,
// v_create,v_update,v_delete,tier} on ONE object. Owner-tuple materialization is
// eventually-consistent (it does NOT gate Operation.done), but if the sync write
// applies that object's tuples NON-atomically (per-tuple), a transient
// write-contention on ONE tuple (e.g. v_delete) leaves the object PARTIAL: a
// creator doing a bounded-retry immediate mutate could see v_update (PATCH) but
// not the still-undrained v_delete (DELETE → 403 "lacks v_delete").
//
// The fix makes the sync write ATOMIC PER-OBJECT: an object's whole tuple-set
// lands in ONE transactional OpenFGA Write (all-or-nothing) OR is fully deferred
// to the async fga_outbox drainer — NEVER partial. So v_update-visible ⟹
// v_delete-visible: the grant is never observed half-materialized.

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

// atomicRelationStore models OpenFGA's TRANSACTIONAL Write: one WriteTuples call
// applies its tuples ALL-or-NOTHING. A call fails (and applies nothing) iff it
// carries the `contended` tuple — simulating a transient per-tuple
// write-contention (HIGHER_CONSISTENCY) that a per-tuple fallback trips on: it
// isolates the good tuples but drops the contended one, leaving a PARTIAL object.
// Records exactly what actually landed so a test can assert the per-object
// all-or-nothing invariant.
type atomicRelationStore struct {
	contended clients.RelationTuple
	applied   map[clients.RelationTuple]struct{}
	calls     int
}

func (s *atomicRelationStore) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}

func (s *atomicRelationStore) WriteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	s.calls++
	// Atomic: a request carrying the contended tuple applies NONE of its tuples.
	for _, t := range tuples {
		if t == s.contended {
			return errors.New("openfga write: status 500: write-contention (HIGHER_CONSISTENCY)")
		}
	}
	if s.applied == nil {
		s.applied = make(map[clients.RelationTuple]struct{})
	}
	for _, t := range tuples {
		s.applied[t] = struct{}{}
	}
	return nil
}

func (s *atomicRelationStore) DeleteTuples(context.Context, []clients.RelationTuple) error {
	return nil
}

func (s *atomicRelationStore) has(t clients.RelationTuple) bool {
	_, ok := s.applied[t]
	return ok
}

// ownerGrant is the reconciler's per-object owner grant on ONE object: the closed
// per-verb v_* set + the back-compat tier tuple, all for the creator.
func ownerGrant(subject, object string) []reconcile.SyncFGATuple {
	relations := []string{"v_get", "v_list", "v_create", "v_update", "v_delete", "viewer"}
	out := make([]reconcile.SyncFGATuple, 0, len(relations))
	for _, r := range relations {
		out = append(out, reconcile.SyncFGATuple{User: subject, Relation: r, Object: object})
	}
	return out
}

func rt(t reconcile.SyncFGATuple) clients.RelationTuple {
	return clients.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object}
}

// TestSyncFGAWriter_OwnerGrant_AtomicPerObject_NoPartial is the core RED→GREEN
// proof. Under a transient contention on v_delete the sync write MUST leave the
// object either FULLY materialized or FULLY deferred — never a partial grant with
// v_update present but v_delete missing (which would let a creator's bounded-retry
// PATCH succeed while an immediate DELETE 403s). The per-tuple fallback (base) leaves 5-of-6
// tuples → partial → RED. The per-object atomic write defers the whole set → GREEN.
func TestSyncFGAWriter_OwnerGrant_AtomicPerObject_NoPartial(t *testing.T) {
	const (
		creator = "user:usr_creator0000000000"
		object  = "iam_access_binding:acb_owner00000000000"
	)
	grant := ownerGrant(creator, object)
	vUpdate := rt(reconcile.SyncFGATuple{User: creator, Relation: "v_update", Object: object})
	vDelete := rt(reconcile.SyncFGATuple{User: creator, Relation: "v_delete", Object: object})

	store := &atomicRelationStore{contended: vDelete}
	w := kachopg.NewSyncFGAWriter(store, nil)

	if err := w.WriteTuples(context.Background(), grant); err != nil {
		t.Fatalf("WriteTuples must stay non-fatal (async drainer backstops), got %v", err)
	}

	// INVARIANT: v_update-visible ⟺ v_delete-visible (same atomic Write).
	if store.has(vUpdate) != store.has(vDelete) {
		t.Fatalf("partial owner grant: v_update landed=%v but v_delete landed=%v — "+
			"op-done would NOT imply full grant (403 on immediate DELETE)",
			store.has(vUpdate), store.has(vDelete))
	}
	// Stronger: the object is all-or-nothing across the WHOLE set.
	present := 0
	for _, g := range grant {
		if store.has(rt(g)) {
			present++
		}
	}
	if present != 0 && present != len(grant) {
		t.Fatalf("non-atomic owner grant: %d of %d tuples landed (must be 0 or all)", present, len(grant))
	}
	// With the contended tuple in the set, all-or-nothing collapses to nothing
	// (deferred to the async drainer) — the whole object is retried durably.
	if present != 0 {
		t.Fatalf("contended object must defer its FULL set, got %d tuples applied", present)
	}
}

// TestSyncFGAWriter_OwnerGrant_CleanBatch_AllLand — with no contention the whole
// owner grant lands (fast path), so the materialization window closes immediately.
func TestSyncFGAWriter_OwnerGrant_CleanBatch_AllLand(t *testing.T) {
	const (
		creator = "user:usr_creator0000000000"
		object  = "iam_access_binding:acb_owner00000000000"
	)
	grant := ownerGrant(creator, object)
	store := &atomicRelationStore{} // no contended tuple
	w := kachopg.NewSyncFGAWriter(store, nil)

	if err := w.WriteTuples(context.Background(), grant); err != nil {
		t.Fatalf("clean WriteTuples must succeed, got %v", err)
	}
	for _, g := range grant {
		if !store.has(rt(g)) {
			t.Fatalf("clean batch must land every tuple; missing %s#%s", g.Object, g.Relation)
		}
	}
}

// TestSyncFGAWriter_SiblingReject_DoesNotStripOwner locks the #232 isolation AND
// per-object atomicity across objects: a fan-out pass carries the owner's valid
// object A PLUS a sibling object B whose tier is a computed-only relation OpenFGA
// rejects. The owner's object A must materialize its FULL set (not stripped by
// B's rejection), and the rejected object B must land NOTHING (atomic defer,
// never a partial B).
func TestSyncFGAWriter_SiblingReject_DoesNotStripOwner(t *testing.T) {
	const (
		creator = "user:usr_creator0000000000"
		objA    = "iam_access_binding:acb_owner00000000000" // owner — all valid
		objB    = "iam_role:rol_sibling0000000000000"       // sibling — computed-only tier reject
	)
	ownerA := ownerGrant(creator, objA)
	siblingB := []reconcile.SyncFGATuple{
		{User: creator, Relation: "v_get", Object: objB},
		{User: creator, Relation: "viewer", Object: objB}, // computed-only → OpenFGA rejects
	}
	// Interleave A and B so a naive flat write cannot rely on ordering.
	var pass []reconcile.SyncFGATuple
	pass = append(pass, ownerA[0], siblingB[0], ownerA[1], ownerA[2], siblingB[1])
	pass = append(pass, ownerA[3], ownerA[4], ownerA[5])

	viewerB := rt(reconcile.SyncFGATuple{User: creator, Relation: "viewer", Object: objB})
	store := &atomicRelationStore{contended: viewerB}
	w := kachopg.NewSyncFGAWriter(store, nil)

	if err := w.WriteTuples(context.Background(), pass); err != nil {
		t.Fatalf("WriteTuples must stay non-fatal, got %v", err)
	}

	// Owner object A: FULL set present (not stripped by B's reject).
	for _, g := range ownerA {
		if !store.has(rt(g)) {
			t.Fatalf("owner object A tuple stripped by sibling B reject: missing %s#%s (#232 regression)",
				g.Object, g.Relation)
		}
	}
	// Sibling object B: NOTHING present (atomic defer — never partial B).
	for _, g := range siblingB {
		if store.has(rt(g)) {
			t.Fatalf("rejected object B must land NOTHING (atomic defer), but %s#%s landed",
				g.Object, g.Relation)
		}
	}
}

// TestSyncFGAWriter_PerObjectFailure_IsLogged — a wholly-failing object defers its
// full tuple-set to the async drainer and logs it once PER OBJECT (CWE-778:
// observable, not silent), staying non-fatal.
func TestSyncFGAWriter_PerObjectFailure_IsLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Two distinct objects, both failing → two per-object deferrals.
	store := &failingRelationStore{}
	w := kachopg.NewSyncFGAWriter(store, logger)

	err := w.WriteTuples(context.Background(), []reconcile.SyncFGATuple{
		{User: "user:usr_a", Relation: "viewer", Object: "account:acc_a"},
		{User: "user:usr_b", Relation: "admin", Object: "account:acc_b"},
	})
	if err != nil {
		t.Fatalf("WriteTuples must stay non-fatal on per-object failure, got %v", err)
	}

	out := buf.String()
	if got := strings.Count(out, "sync FGA per-object write failed"); got != 2 {
		t.Fatalf("expected 2 per-object warnings, got %d; log=%s", got, out)
	}
	// The object identity + error must be observable in the log.
	for _, want := range []string{"account:acc_a", "account:acc_b", "openfga write rejected"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning must include %q; log=%s", want, out)
		}
	}
}

// failingRelationStore fails every WriteTuples so each object's atomic write
// fails and is deferred.
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
