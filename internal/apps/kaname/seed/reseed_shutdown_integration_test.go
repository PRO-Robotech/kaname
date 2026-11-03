// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// The stock database, transaction, domain writer and commit all remain real.
// The decorator only stops at an observed transaction boundary so cancellation
// is reproducible without relying on a fast machine or a scheduling sleep.
type reseedShutdownRepo struct {
	kanamerepo.Repository
	calls   atomic.Int64
	commits atomic.Int64
	stopAt  int64
	arrived chan struct{}
}

func (r *reseedShutdownRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	call := r.calls.Add(1)
	writer, err := r.Repository.Writer(ctx)
	if err != nil {
		return nil, err
	}
	if call == r.stopAt {
		close(r.arrived)
		<-ctx.Done()
	}
	return &reseedShutdownWriter{Writer: writer, owner: r}, nil
}

type reseedShutdownWriter struct {
	kanamerepo.Writer
	owner *reseedShutdownRepo
}

func (w *reseedShutdownWriter) Commit(ctx context.Context) error {
	if err := w.Writer.Commit(ctx); err != nil {
		return err
	}
	w.owner.commits.Add(1)
	return nil
}

type reseedShutdownResult struct {
	examined, reseeded, failed int
	structural                 bool
	err                        error
}
type reseedShutdownLane struct {
	name, table string
	run         func(context.Context, kanamerepo.Repository, *pgxpool.Pool) reseedShutdownResult
}

func reseedShutdownLanes() []reseedShutdownLane {
	return []reseedShutdownLane{
		{"verbs", "role_verb", func(ctx context.Context, r kanamerepo.Repository, p *pgxpool.Pool) reseedShutdownResult {
			c, e := seed.ReseedSystemRoleVerbs(ctx, r, p, catalogfixture.Facts(), nil)
			return reseedShutdownResult{c.Examined, c.Reseeded, c.Failed, c.Structural(), e}
		}},
		{"rule-refs", "role_rule_ref", func(ctx context.Context, r kanamerepo.Repository, p *pgxpool.Pool) reseedShutdownResult {
			c, e := seed.ReseedSystemRoleRuleRefs(ctx, r, p, nil)
			return reseedShutdownResult{c.Examined, c.Reseeded, c.Failed, c.Structural(), e}
		}},
	}
}
func reseedProjectionSnapshot(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string) string {
	t.Helper()
	require.Contains(t, []string{"role_verb", "role_rule_ref"}, table)
	var snapshot string
	require.NoError(t, pool.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM kaname.`+table+` r`).Scan(&snapshot))
	return snapshot
}

// This is a regression for the actual native SIGTERM failure found by kaname#1038:
// shutdown with zero completed roles became Structural/exit1, while shutdown
// after some commits became exit0. Neither interrupted traversal is complete.
func TestReseedShutdownCancellationPreservesProgress(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the leased PostgreSQL integration job")
	}
	for _, lane := range reseedShutdownLanes() {
		t.Run(lane.name, func(t *testing.T) {
			for _, stopAt := range []int64{0, 1, 2} {
				name := map[int64]string{0: "before-list", 1: "before-first-role-work", 2: "after-one-real-commit"}[stopAt]
				t.Run(name, func(t *testing.T) {
					_, pool := newReseedPool(t)
					lifetime, stop := context.WithTimeout(t.Context(), 20*time.Second)
					defer stop()
					real := kanamepg.New(pool, nil)
					// Positive same-database control: no broken catalog/fixture may turn the
					// cancellation case green by preventing any role from being materialized.
					positive := lane.run(lifetime, real, pool)
					require.NoError(t, positive.err)
					require.Greater(t, positive.examined, 1)
					require.Equal(t, positive.examined, positive.reseeded)
					require.Zero(t, positive.failed)
					require.False(t, positive.structural)
					r := &reseedShutdownRepo{Repository: real, stopAt: stopAt, arrived: make(chan struct{})}
					ctx, cancel := context.WithCancel(lifetime)
					defer cancel()
					if stopAt == 0 {
						cancel()
					}
					done := make(chan reseedShutdownResult, 1)
					go func() { done <- lane.run(ctx, r, pool) }()
					if stopAt != 0 {
						select {
						case <-r.arrived:
						case <-lifetime.Done():
							t.Fatal("real transaction boundary was not reached")
						}
					}
					// Snapshot is taken while the selected real transaction is open but has
					// not touched its role. Prior commits already exist in PostgreSQL.
					before := reseedProjectionSnapshot(t, lifetime, pool, lane.table)
					cancel()
					var result reseedShutdownResult
					select {
					case result = <-done:
					case <-lifetime.Done():
						t.Fatal("reseed did not stop after cancellation")
					}
					require.ErrorIs(t, result.err, context.Canceled, "internal orchestration must retain cancellation identity")
					require.False(t, result.structural, "an interrupted traversal is not a complete structural refusal")
					require.Equal(t, stopAt, r.calls.Load(), "do not open writers for unattempted roles after cancellation")
					committed := max(int64(0), stopAt-1)
					require.Equal(t, committed, r.commits.Load(), "only actual commits may be reported as progress")
					require.Equal(t, int(committed), result.reseeded)
					require.LessOrEqual(t, result.failed, 1, "unattempted roles cannot be fabricated as failed transactions")
					require.JSONEq(t, before, reseedProjectionSnapshot(t, lifetime, pool, lane.table), "cancellation preserves earlier commits and rolls back the current role")
				})
			}
		})
	}
}

// A live-context all-role failure is the necessary negative control: treating
// every zero-progress result as benign shutdown would silently lose this gate.
func TestReseedShutdownDoesNotHideLiveStructuralFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the leased PostgreSQL integration job")
	}
	for _, lane := range reseedShutdownLanes() {
		t.Run(lane.name, func(t *testing.T) {
			_, pool := newReseedPool(t)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			repo := kanamepg.New(pool, nil)
			positive := lane.run(ctx, repo, pool)
			require.NoError(t, positive.err)
			require.Greater(t, positive.examined, 1)
			before := reseedProjectionSnapshot(t, ctx, pool, lane.table)
			// A private DB fault, not seeded C/I/GD or rewritten authority. A statement
			// trigger rejects even empty DELETE, so every attempted role really fails.
			_, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION kaname.probe_reseed_shutdown_refusal() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'independent reseed shutdown negative control'; END $$;
    CREATE TRIGGER probe_reseed_shutdown_refusal BEFORE DELETE ON kaname.%s
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.probe_reseed_shutdown_refusal();`, lane.table))
			require.NoError(t, err)
			result := lane.run(ctx, repo, pool)
			require.NoError(t, ctx.Err(), "negative control must finish on an active context")
			require.Error(t, result.err)
			require.True(t, result.structural, "genuine complete all-role refusal remains fatal to startup")
			require.Equal(t, positive.examined, result.examined)
			require.Zero(t, result.reseeded)
			require.Equal(t, result.examined, result.failed)
			require.JSONEq(t, before, reseedProjectionSnapshot(t, ctx, pool, lane.table), "all failed transactions leave the projection intact")
		})
	}
}
