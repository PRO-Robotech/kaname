// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// register_resource_integration_test.go — SEC-C group A (A-01..A-05).
//
// Verifies RegisterResource / UnregisterResource (Internal FGA-proxy):
//   - A-01 happy: tuple enqueued into kacho_iam.fga_outbox (event fga.tuple.write),
//     in the SAME writer-tx (rollback ⇒ no orphan row);
//   - A-02 idempotent register: re-issue same tuple → OK (second outbox row,
//     drainer collapses via already_exists→ErrAlreadyApplied);
//   - A-03 unregister: enqueues fga.tuple.delete;
//   - A-04 idempotent unregister: missing tuple → OK (no NotFound);
//   - A-05 invalid args: empty subject/relation/object + malformed object →
//     sync InvalidArgument, NO outbox row.
//
// The use-case writes the owner-hierarchy tuple verbatim from the request
// ({subject_id, relation, object}); the SEC-A proto carries the pre-composed
// FGA strings (drainer applies them as today, fga_applier.go idempotent
// classification). Authz-gate (group B) is exercised in the rebac test.
//
// Skipped under `go test -short`.
package internal_iam_test

import (
	"context"
	"encoding/json"
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

// newRegisterUC builds the RegisterResource use-case backed by a real pool's
// outbox emitter + tx beginner (no FGA dial — drainer applies asynchronously).
func newRegisterUC(t *testing.T) (*internaliam.RegisterResourceUseCase, *outboxProbe) {
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
	return uc, &outboxProbe{pool: pool}
}

func TestRegisterResource_A01_EnqueuesWriteTupleInTx(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, h := newRegisterUC(t)

	err := uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-1",
		Relation:  "parent",
		Object:    "vpc_network:enp00000000000000001",
	})
	require.NoError(t, err)

	n, et, payload := h.lastOutbox(t, ctx)
	require.Equal(t, 1, n, "exactly one outbox row enqueued")
	require.Equal(t, "fga.tuple.write", et)
	require.Equal(t, "project:prj-1", payload["user"])
	require.Equal(t, "parent", payload["relation"])
	require.Equal(t, "vpc_network:enp00000000000000001", payload["object"])
	require.True(t, h.outboxUnsent(t, ctx), "sent_at IS NULL until drainer applies")
}

func TestRegisterResource_A02_IdempotentRegister(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, h := newRegisterUC(t)

	req := &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-1", Relation: "parent", Object: "vpc_network:enp00000000000000001",
	}
	err := uc.Register(ctx, req)
	require.NoError(t, err)
	err = uc.Register(ctx, req) // repeat — must be OK, never AlreadyExists.
	require.NoError(t, err, "repeat register must be OK, not AlreadyExists (idempotency contract)")

	// Two write rows enqueued; the drainer (fga_applier already_exists→success)
	// collapses them to a single FGA tuple. The RPC never surfaces AlreadyExists.
	n, _, _ := h.lastOutbox(t, ctx)
	require.Equal(t, 2, n)
}

func TestRegisterResource_A03_UnregisterEnqueuesDeleteTuple(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, h := newRegisterUC(t)

	err := uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:prj-1", Relation: "parent", Object: "vpc_network:enp00000000000000001",
	})
	require.NoError(t, err)

	n, et, _ := h.lastOutbox(t, ctx)
	require.Equal(t, 1, n)
	require.Equal(t, "fga.tuple.delete", et)
}

func TestRegisterResource_A04_IdempotentUnregister(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, _ := newRegisterUC(t)

	// Tuple never registered — unregister must be OK, never NotFound.
	err := uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:prj-1", Relation: "parent", Object: "vpc_network:enp99999999999999999",
	})
	require.NoError(t, err, "unregister of absent tuple must be OK, not NotFound")
}

func TestRegisterResource_A05_InvalidArgsNoOutbox(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, h := newRegisterUC(t)

	cases := []struct {
		name string
		req  *iamv1.RegisterResourceRequest
	}{
		{"empty subject_id", &iamv1.RegisterResourceRequest{Relation: "parent", Object: "vpc_network:enp1"}},
		{"empty relation", &iamv1.RegisterResourceRequest{SubjectId: "project:prj-1", Object: "vpc_network:enp1"}},
		{"empty object", &iamv1.RegisterResourceRequest{SubjectId: "project:prj-1", Relation: "parent"}},
		{"object with space", &iamv1.RegisterResourceRequest{SubjectId: "project:prj-1", Relation: "parent", Object: "vpc_network:enp 1"}},
		{"object missing colon", &iamv1.RegisterResourceRequest{SubjectId: "project:prj-1", Relation: "parent", Object: "vpc_network"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := uc.Register(ctx, c.req)
			require.Error(t, err)
			require.Equal(t, codes.InvalidArgument, status.Code(err), "validation → InvalidArgument")
		})
	}
	n, _, _ := h.lastOutbox(t, ctx)
	require.Equal(t, 0, n, "no outbox row on validation failure")
}

// ── helpers ──────────────────────────────────────────────────────────────────

// outboxProbe reads back kacho_iam.fga_outbox rows for assertions.
type outboxProbe struct{ pool *pgxpool.Pool }

// lastOutbox returns the row count and the latest row's event_type + payload,
// scoped to test-created tuples. It excludes EVERY migration-seeded relation-
// tuple: the SEC-C fga_writer tuples (object `iam_fgaproxy:system`, 0009) AND
// the cluster-root seeds (object `cluster:cluster_kacho_root`: the SEC-L
// operator system_viewer, 0010, and the 5.1 reader system_viewer tuples, 0014).
// A static "exclude iam_fgaproxy only" filter silently miscounted once any
// cluster-root seed landed.
func (p *outboxProbe) lastOutbox(t *testing.T, ctx context.Context) (count int, eventType string, payload map[string]string) {
	t.Helper()
	const notSeed = `payload->>'object' NOT IN ('iam_fgaproxy:system', 'cluster:cluster_kacho_root')`
	require.NoError(t, p.pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox WHERE `+notSeed).Scan(&count))
	payload = map[string]string{}
	if count == 0 {
		return count, "", payload
	}
	var raw string
	require.NoError(t, p.pool.QueryRow(ctx,
		`SELECT event_type, payload::text FROM kacho_iam.fga_outbox WHERE `+notSeed+
			` ORDER BY id DESC LIMIT 1`).
		Scan(&eventType, &raw))
	require.NoError(t, json.Unmarshal([]byte(raw), &payload))
	return count, eventType, payload
}

// outboxUnsent reports whether the latest test-created outbox row has
// sent_at IS NULL.
func (p *outboxProbe) outboxUnsent(t *testing.T, ctx context.Context) bool {
	t.Helper()
	var unsent bool
	require.NoError(t, p.pool.QueryRow(ctx,
		`SELECT sent_at IS NULL FROM kacho_iam.fga_outbox
		  WHERE payload->>'object' NOT IN ('iam_fgaproxy:system', 'cluster:cluster_kacho_root')
		  ORDER BY id DESC LIMIT 1`).Scan(&unsent))
	return unsent
}
