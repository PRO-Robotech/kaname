// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// register_resource_mirror_integration_test.go — IAM (callee) side of
// resource-scoped AccessBinding registration: RegisterResource UPSERTs a
// kacho_iam.resource_mirror row AND emits the owner-tuple intent into
// kacho_iam.fga_outbox in ONE writer-tx (atomic co-commit, ban #10);
// UnregisterResource symmetrically DELETEs the mirror row + emits the tuple
// revoke in one tx.
//
// This path only FILLS the mirror — nothing here reads it for authz (that is the
// reconciler). The owner-tuple path is unchanged (idempotent at-least-once via
// the drainer).
//
// Skipped under `go test -short`.
package internal_iam_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	internaliam "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// newRegisterUCWithMirror builds the RegisterResource use-case backed by a real
// pool's fga_outbox emitter + resource_mirror emitter + tx beginner (no FGA dial).
func newRegisterUCWithMirror(t *testing.T) (*internaliam.RegisterResourceUseCase, *mirrorProbe) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, kachopg.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	uc := internaliam.NewRegisterResourceUseCase(
		kachopg.NewFGAOutboxEmitter(),
		kachopg.NewResourceMirrorEmitter(),
		kachopg.NewPoolTxBeginner(pool),
	)
	return uc, &mirrorProbe{pool: pool}
}

// happy path — Create compute-instance with labels → mirror row appears,
// owner-tuple co-committed in the same writer-tx.
func TestRegisterResource_B01_MirrorRowAndTupleCoCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	err := uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:prj-P",
		Relation:        "parent",
		Object:          "compute_instance:inst-abc",
		Labels:          map[string]string{"env": "dev", "team": "core"},
		ParentProjectId: "prj-P",
		ParentAccountId: "acc-A",
	})
	require.NoError(t, err)

	prj, acc, labels := p.readMirror(t, ctx, "compute.instance", "inst-abc")
	require.Equal(t, "prj-P", prj)
	require.Equal(t, "acc-A", acc)
	require.Equal(t, map[string]string{"env": "dev", "team": "core"}, labels)

	// Owner-tuple co-committed in the SAME writer-tx.
	require.Equal(t, 1, p.outboxCount(t, ctx), "owner-tuple emitted alongside mirror")
}

// payload with empty labels → mirror row with labels={}, parent filled.
func TestRegisterResource_B02_EmptyLabelsGraceful(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	err := uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:prj-P",
		Relation:        "parent",
		Object:          "compute_instance:inst-nolabels",
		Labels:          map[string]string{},
		ParentProjectId: "prj-P",
	})
	require.NoError(t, err)

	prj, _, labels := p.readMirror(t, ctx, "compute.instance", "inst-nolabels")
	require.Equal(t, "prj-P", prj)
	require.Equal(t, map[string]string{}, labels)
}

// co-commit atomicity — owner-tuple and mirror row appear together.
// A failure inside the writer-tx leaves NEITHER (verified by the rollback path
// in the resource_mirror + fga_outbox emitter tests). Here we assert the
// positive: after a successful Register, BOTH effects are present.
func TestRegisterResource_B03_AtomicCoCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-P", Relation: "parent", Object: "compute_instance:inst-atomic",
		Labels: map[string]string{"env": "dev"}, ParentProjectId: "prj-P", ParentAccountId: "acc-A",
	}))

	prj, _, _ := p.readMirror(t, ctx, "compute.instance", "inst-atomic")
	require.Equal(t, "prj-P", prj, "mirror present")
	require.Equal(t, 1, p.outboxCount(t, ctx), "tuple present — both committed together")
}

// idempotency — repeat RegisterResource (drainer retry) → no mirror dup.
func TestRegisterResource_B06_IdempotentMirrorUpsert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	req := &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-P", Relation: "parent", Object: "compute_instance:inst-idem",
		Labels: map[string]string{"env": "dev"}, ParentProjectId: "prj-P",
	}
	require.NoError(t, uc.Register(ctx, req))
	require.NoError(t, uc.Register(ctx, req), "repeat must be OK (idempotent)")

	require.Equal(t, 1, p.mirrorCount(t, ctx, "compute.instance", "inst-idem"),
		"PK ⇒ exactly one mirror row on repeat (β-06)")
}

// concurrency — parallel Register of one object with different labels →
// exactly one mirror row, deterministic last-write (no half-write, ban #10).
func TestRegisterResource_B05_ConcurrentUpsertOneRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	labelSets := []map[string]string{
		{"env": "dev"},
		{"env": "prod"},
		{"env": "staging"},
		{"env": "dev", "team": "core"},
	}
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			errs[i] = uc.Register(ctx, &iamv1.RegisterResourceRequest{
				SubjectId: "project:prj-P", Relation: "parent", Object: "compute_instance:inst-race",
				Labels: labelSets[i%len(labelSets)], ParentProjectId: "prj-P",
			})
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		require.NoError(t, e, "concurrent register #%d must succeed (no INTERNAL leak)", i)
	}
	require.Equal(t, 1, p.mirrorCount(t, ctx, "compute.instance", "inst-race"),
		"PK serializes concurrent writers ⇒ exactly one row (β-05)")
	_, _, labels := p.readMirror(t, ctx, "compute.instance", "inst-race")
	require.Contains(t, []string{"dev", "prod", "staging"}, labels["env"],
		"final labels are one deterministic last-write, not a half-merge")
}

// Unregister → mirror row deleted AND tuple-revoke emitted in one tx.
func TestRegisterResource_B07_UnregisterDeletesMirrorAndRevokesTuple(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-P", Relation: "parent", Object: "compute_instance:inst-gone",
		Labels: map[string]string{"env": "dev"}, ParentProjectId: "prj-P",
	}))
	require.Equal(t, 1, p.mirrorCount(t, ctx, "compute.instance", "inst-gone"))

	require.NoError(t, uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:prj-P", Relation: "parent", Object: "compute_instance:inst-gone",
	}))
	require.Equal(t, 0, p.mirrorCount(t, ctx, "compute.instance", "inst-gone"),
		"Unregister removes the mirror row (β-07)")
	require.Equal(t, "fga.tuple.delete", p.lastOutboxEvent(t, ctx),
		"tuple-revoke emitted in the same tx as the mirror delete")
}

// idempotent: Unregister of a never-registered object → OK, no panic.
func TestRegisterResource_B07b_UnregisterAbsentIsOK(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, _ := newRegisterUCWithMirror(t)

	require.NoError(t, uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:prj-P", Relation: "parent", Object: "compute_instance:inst-never",
	}), "unregister of absent object must be OK (β-07/D-β5)")
}

// backward-compat — legacy caller sends only fields 1-4 → mirror row with
// empty labels/parent (graceful), tuple emitted as before.
func TestRegisterResource_B09_LegacyCallerEmptyMirror(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-P", Relation: "parent", Object: "compute_instance:inst-legacy",
		// no labels / parent_* — old compute
	}))

	prj, acc, labels := p.readMirror(t, ctx, "compute.instance", "inst-legacy")
	require.Equal(t, "", prj)
	require.Equal(t, "", acc)
	require.Equal(t, map[string]string{}, labels)
	require.Equal(t, 1, p.outboxCount(t, ctx), "owner-tuple emitted as before")
}

// negative — invalid labels (uppercase key) → InvalidArgument, no mirror,
// no outbox row (validation rejects before the writer-tx).
func TestRegisterResource_B15_InvalidLabelsRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	err := uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-P", Relation: "parent", Object: "compute_instance:inst-badlabels",
		Labels: map[string]string{"ENV": "x"}, ParentProjectId: "prj-P",
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err), "invalid label key → InvalidArgument (β-15)")
	require.Equal(t, 0, p.mirrorCount(t, ctx, "compute.instance", "inst-badlabels"), "no mirror row on validation failure")
	require.Equal(t, 0, p.outboxCount(t, ctx), "no outbox row on validation failure")
}

// mirror carries ONLY tenant-facing labels + parent-scope (no infra
// fields); a stale row survives (dangling tolerated) — read does not panic.
func TestRegisterResource_B16_MirrorShapeAndDanglingSurvives(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, p := newRegisterUCWithMirror(t)

	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-P", Relation: "parent", Object: "compute_instance:inst-orphan",
		Labels: map[string]string{"env": "dev"}, ParentProjectId: "prj-P", ParentAccountId: "acc-A",
	}))

	// Column set is exactly the tenant-facing projection (no infra columns).
	cols := p.columns(t, ctx)
	require.ElementsMatch(t,
		[]string{"object_type", "object_id", "parent_project_id", "parent_account_id", "labels", "source_version", "updated_at"},
		cols, "resource_mirror exposes only tenant-facing labels + parent-scope + monotonic source_version (β-16, β-hardening)")

	// Stale row survives without an Unregister: re-reading is fine.
	prj, _, _ := p.readMirror(t, ctx, "compute.instance", "inst-orphan")
	require.Equal(t, "prj-P", prj)
}

// ── helpers ──────────────────────────────────────────────────────────────────

type mirrorProbe struct{ pool *pgxpool.Pool }

func (p *mirrorProbe) readMirror(t *testing.T, ctx context.Context, objType, objID string) (prj, acc string, labels map[string]string) {
	t.Helper()
	var raw string
	require.NoError(t, p.pool.QueryRow(ctx,
		`SELECT parent_project_id, parent_account_id, labels::text
		   FROM kacho_iam.resource_mirror WHERE object_type = $1 AND object_id = $2`, objType, objID).
		Scan(&prj, &acc, &raw))
	labels = map[string]string{}
	require.NoError(t, json.Unmarshal([]byte(raw), &labels))
	return prj, acc, labels
}

func (p *mirrorProbe) mirrorCount(t *testing.T, ctx context.Context, objType, objID string) int {
	t.Helper()
	var n int
	require.NoError(t, p.pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_mirror WHERE object_type = $1 AND object_id = $2`, objType, objID).Scan(&n))
	return n
}

func (p *mirrorProbe) outboxCount(t *testing.T, ctx context.Context) int {
	t.Helper()
	var n int
	require.NoError(t, p.pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE payload->>'object' NOT IN ('iam_fgaproxy:system', 'cluster:cluster_kacho_root')`).Scan(&n))
	return n
}

func (p *mirrorProbe) lastOutboxEvent(t *testing.T, ctx context.Context) string {
	t.Helper()
	var et string
	require.NoError(t, p.pool.QueryRow(ctx,
		`SELECT event_type FROM kacho_iam.fga_outbox
		  WHERE payload->>'object' NOT IN ('iam_fgaproxy:system', 'cluster:cluster_kacho_root')
		  ORDER BY id DESC LIMIT 1`).Scan(&et))
	return et
}

func (p *mirrorProbe) columns(t *testing.T, ctx context.Context) []string {
	t.Helper()
	rows, err := p.pool.Query(ctx,
		`SELECT column_name FROM information_schema.columns
		  WHERE table_schema = 'kacho_iam' AND table_name = 'resource_mirror'`)
	require.NoError(t, err)
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		require.NoError(t, rows.Scan(&c))
		cols = append(cols, c)
	}
	return cols
}
