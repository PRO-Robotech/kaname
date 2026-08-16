// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// set_atomicity_integration_test.go — the queue must carry ONE SUBJECT'S VERB SET
// ON ONE OBJECT as a single unit, so the receiving store never shows that set
// half-present.
//
// WHAT IS ASSERTED, AND WHY IT IS THE RECEIVING SIDE. The weak form of this test —
// "we enqueued every verb" — stays green on exactly the defect it should catch: the
// rows are all there, they simply arrive at OpenFGA one at a time, and between the
// first and the last the subject can read the object but not update it. So the
// assertion here is made on the STORE: after every apply the set of relations the
// subject holds on the object must be either EMPTY or COMPLETE, never a strict
// non-empty subset.
//
// The whole chain is exercised — emit into the real table (trigger, constraints and
// all), read the rows back, decode them with the drainer's own decoder, apply them
// with the drainer's own applier — because the unit of atomicity is a property of
// the ROW, and only the real INSERT proves what a row actually contains.
//
// Skipped under `go test -short` (needs Docker).
package fga_outbox_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/fga_outbox"
)

// observedStore is a stand-in for OpenFGA that keeps the tuple set AND records a
// snapshot of it after every applied call. It is deliberately no more forgiving than
// the real store on the one axis this test is about: a write or a delete lands as a
// whole or not at all (RelationStore.WriteTuples is transactional), so a partial
// observation can only come from the CALLER splitting the set.
type observedStore struct {
	live      map[clients.RelationTuple]struct{}
	snapshots []map[clients.RelationTuple]struct{}
	calls     int
}

func newObservedStore() *observedStore {
	return &observedStore{live: map[clients.RelationTuple]struct{}{}}
}

func (s *observedStore) snapshot() {
	cp := make(map[clients.RelationTuple]struct{}, len(s.live))
	for t := range s.live {
		cp[t] = struct{}{}
	}
	s.snapshots = append(s.snapshots, cp)
}

func (s *observedStore) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}

func (s *observedStore) WriteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	s.calls++
	for _, t := range tuples {
		s.live[t] = struct{}{}
	}
	s.snapshot()
	return nil
}

func (s *observedStore) DeleteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	s.calls++
	for _, t := range tuples {
		delete(s.live, t)
	}
	s.snapshot()
	return nil
}

// relationsOn returns the relations `user` holds on `object` in one snapshot.
func relationsOn(snap map[clients.RelationTuple]struct{}, user, object string) []string {
	var out []string
	for t := range snap {
		if t.User == user && t.Object == object {
			out = append(out, t.Relation)
		}
	}
	sort.Strings(out)
	return out
}

// requireNeverPartial fails when ANY observation of the store holds a strict,
// non-empty subset of `want` for (user, object). Empty and complete are both fine;
// anything between them is the defect — that is the state in which a caller who has
// just read its own fresh resource is refused permission to change it.
func requireNeverPartial(t *testing.T, s *observedStore, user, object string, want []string) {
	t.Helper()
	full := strings.Join(want, ",")
	for i, snap := range s.snapshots {
		got := relationsOn(snap, user, object)
		if len(got) == 0 || strings.Join(got, ",") == full {
			continue
		}
		t.Fatalf("observation %d of %d: %s holds a PARTIAL relation set on %s: [%s]; "+
			"the set must be empty or complete ([%s]). A subject that can read its own "+
			"fresh object must be able to change and delete it too",
			i+1, len(s.snapshots), user, object, strings.Join(got, ", "), full)
	}
}

// applyAllRows drains every pending row of the outbox exactly as the drainer does —
// same decoder, same applier — in id order.
func applyAllRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, store clients.RelationStore, object string) int {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT event_type, payload::text
		  FROM kacho_iam.fga_outbox
		 WHERE payload->>'object' = $1
		   AND sent_at IS NULL
		 ORDER BY id ASC`, object)
	require.NoError(t, err)
	type row struct {
		eventType string
		payload   string
	}
	var pending []row
	for rows.Next() {
		var r row
		require.NoError(t, rows.Scan(&r.eventType, &r.payload))
		pending = append(pending, r)
	}
	rows.Close()
	require.NoError(t, rows.Err())

	apply := clients.NewFGAApplier(store)
	for _, r := range pending {
		ev, err := clients.DecodeFGAOutboxEvent([]byte(r.payload))
		require.NoErrorf(t, err, "row payload %s must decode", r.payload)
		require.NoError(t, apply(ctx, r.eventType, ev))
	}
	return len(pending)
}

// TestObjectVerbSetNeverObservedPartiallyMaterialized — the grant direction.
func TestObjectVerbSetNeverObservedPartiallyMaterialized(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	const (
		subject = "user:usr_set_atomicity"
		object  = "vpc_address:vaddr_set_atomicity"
	)
	verbs := []string{"v_delete", "v_get", "v_list", "v_update"} // sorted — the full set
	grant := make([]clients.RelationTuple, 0, len(verbs))
	for _, v := range verbs {
		grant = append(grant, clients.RelationTuple{User: subject, Relation: v, Object: object})
	}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, grant))
	require.NoError(t, tx.Commit(ctx))

	store := newObservedStore()
	applied := applyAllRows(ctx, t, pool, store, object)
	require.Positive(t, applied, "the emit must have produced at least one row")

	requireNeverPartial(t, store, subject, object, verbs)
	require.Equal(t, verbs, relationsOn(store.live, subject, object),
		"the full verb set must be present once the queue is drained")
}

// TestObjectVerbSetNeverObservedPartiallyRevoked — the revoke direction, which is the
// quieter half: a grant that materializes late is a caller retrying, while a revoke
// that lands in pieces is access that outlives its removal, and "works" and "not
// revoked yet" look exactly the same from outside.
func TestObjectVerbSetNeverObservedPartiallyRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	const (
		subject = "user:usr_set_revoke"
		object  = "vpc_address:vaddr_set_revoke"
	)
	verbs := []string{"v_delete", "v_get", "v_list", "v_update"}
	set := make([]clients.RelationTuple, 0, len(verbs))
	for _, v := range verbs {
		set = append(set, clients.RelationTuple{User: subject, Relation: v, Object: object})
	}

	store := newObservedStore()
	// The grant is applied out-of-band (it is not what this case is about) so the
	// revoke starts from a complete set.
	require.NoError(t, store.WriteTuples(ctx, set))
	store.snapshots = nil

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, fga_outbox.EmitDeleteTx(ctx, tx, set))
	require.NoError(t, tx.Commit(ctx))

	applied := applyAllRows(ctx, t, pool, store, object)
	require.Positive(t, applied, "the emit must have produced at least one row")

	requireNeverPartial(t, store, subject, object, verbs)
	require.Empty(t, relationsOn(store.live, subject, object),
		"the whole set must be gone once the queue is drained")
}

// TestOutboxPartitionKeyCoversTheWholeGrantSet — the ordering half of the same
// property. Atomicity needs the set in ONE row; ordering needs every row that names
// the same (subject, object) to share ONE partition, or a revoke can be applied
// ahead of the grant it supersedes and the tuple survives its own removal.
//
// The positive control is the second half: two DIFFERENT subjects on the same object
// must NOT share a partition — otherwise the fix would buy atomicity by serialising
// unrelated work, which is the cost migration 0067 measured and removed.
func TestOutboxPartitionKeyCoversTheWholeGrantSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	const (
		alice  = "user:usr_partition_alice"
		bob    = "user:usr_partition_bob"
		object = "vpc_address:vaddr_partition"
	)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, []clients.RelationTuple{
		{User: alice, Relation: "v_get", Object: object},
		{User: alice, Relation: "v_update", Object: object},
	}))
	// The revoke of alice's set — a different row shape, same partition required.
	require.NoError(t, fga_outbox.EmitDeleteTx(ctx, tx, []clients.RelationTuple{
		{User: alice, Relation: "v_get", Object: object},
	}))
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, []clients.RelationTuple{
		{User: bob, Relation: "v_get", Object: object},
	}))
	require.NoError(t, tx.Commit(ctx))

	keys := map[string][]string{} // partition key → subjects it carries
	rows, err := pool.Query(ctx, `
		SELECT `+fga_outbox.PartitionColumn+`, payload->>'user'
		  FROM kacho_iam.fga_outbox
		 WHERE payload->>'object' = $1
		 ORDER BY id ASC`, object)
	require.NoError(t, err)
	for rows.Next() {
		var key, user string
		require.NoError(t, rows.Scan(&key, &user))
		keys[key] = append(keys[key], user)
	}
	rows.Close()
	require.NoError(t, rows.Err())

	require.Len(t, keys, 2, "one partition per (subject, object), got %v", keys)
	for key, subjects := range keys {
		for _, s := range subjects {
			require.Equal(t, subjects[0], s,
				fmt.Sprintf("partition %q must carry exactly one subject, got %v", key, subjects))
		}
	}
}

// TestSetRowCarriesTheEchoOnlyForGrants — the rollout asymmetry, pinned.
//
// A pod that predates the set form reads `relation` and ignores `relations`. Given an
// echo it applies ONE relation and marks the row delivered; given none it cannot decode
// the row at all and poisons it.
//
// For a GRANT the first is better: the subject ends up with LESS access than it is owed,
// the row is consumed, and the next reconcile pass completes it. For a REVOKE it is
// strictly worse and irrecoverable: the row retires while most of the set survives its
// own removal — an over-grant invisible to the poison ledger, the wedge warning and the
// redrive, because as far as the queue is concerned the work is done.
//
// So the echo is written for writes and withheld for deletes. Asserted on the ROW,
// because that is what the other reader sees.
func TestSetRowCarriesTheEchoOnlyForGrants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	const (
		subject = "user:usr_echo"
		object  = "vpc_address:vaddr_echo"
	)
	set := []clients.RelationTuple{
		{User: subject, Relation: "v_get", Object: object},
		{User: subject, Relation: "v_update", Object: object},
	}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, set))
	require.NoError(t, fga_outbox.EmitDeleteTx(ctx, tx, set))
	require.NoError(t, tx.Commit(ctx))

	rows, err := pool.Query(ctx, `
		SELECT event_type,
		       coalesce(payload->>'relation', ''),
		       jsonb_array_length(coalesce(payload->'relations', '[]'::jsonb))
		  FROM kacho_iam.fga_outbox
		 WHERE payload->>'object' = $1
		 ORDER BY id ASC`, object)
	require.NoError(t, err)
	type row struct {
		eventType string
		echo      string
		setSize   int
	}
	var got []row
	for rows.Next() {
		var r row
		require.NoError(t, rows.Scan(&r.eventType, &r.echo, &r.setSize))
		got = append(got, r)
	}
	rows.Close()
	require.NoError(t, rows.Err())

	require.Len(t, got, 2, "one row per direction")
	require.Equal(t, 2, got[0].setSize)
	require.Equal(t, "v_get", got[0].echo,
		"a GRANT set row carries the echo: an older reader applies part of it and the row keeps moving")
	require.Equal(t, 2, got[1].setSize)
	require.Empty(t, got[1].echo,
		"a REVOKE set row carries NO echo: an older reader must poison it loudly rather than "+
			"retire it having removed one relation of the set")
}
