// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/stretchr/testify/require"
)

// The real observer callback is a deterministic arrival boundary AFTER the
// failed role transaction. Cancel exactly after the final actual failure, not
// while database work is in flight. This is the completed-failure twin of the
// independent interrupted-traversal tests, not synthetic authz or storage.
type cancelAfterLastReseedFailure struct {
	expected, observed int
	cancel             context.CancelFunc
}

func (o *cancelAfterLastReseedFailure) observe(outcome string) {
	if outcome != "failed" {
		return
	}
	o.observed++
	if o.observed == o.expected {
		o.cancel()
	}
}
func (o *cancelAfterLastReseedFailure) IncRoleVerbReseed(outcome string) { o.observe(outcome) }
func (o *cancelAfterLastReseedFailure) IncRuleRefReseed(outcome string)  { o.observe(outcome) }

func TestReseedCompletedStructuralFailureSurvivesLateCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("requires leased PostgreSQL integration job")
	}
	for _, lane := range reseedShutdownLanes() {
		t.Run(lane.name, func(t *testing.T) {
			_, pool := newReseedPool(t)
			lifetime, stop := context.WithTimeout(t.Context(), 20*time.Second)
			defer stop()
			repo := kanamepg.New(pool, nil)
			positive := lane.run(lifetime, repo, pool)
			require.NoError(t, positive.err)
			require.Greater(t, positive.examined, 1)
			require.Equal(t, positive.examined, positive.reseeded)
			before := reseedProjectionSnapshot(t, lifetime, pool, lane.table)
			_, err := pool.Exec(lifetime, fmt.Sprintf(`CREATE FUNCTION kaname.probe_completed_reseed_refusal() RETURNS trigger LANGUAGE plpgsql AS $$
   BEGIN RAISE EXCEPTION 'independent completed-reseed failure'; END $$;
   CREATE TRIGGER probe_completed_reseed_refusal BEFORE DELETE ON kaname.%s
   FOR EACH STATEMENT EXECUTE FUNCTION kaname.probe_completed_reseed_refusal();`, lane.table))
			require.NoError(t, err)
			active := lane.run(lifetime, repo, pool)
			require.NoError(t, lifetime.Err())
			require.Error(t, active.err)
			require.True(t, active.structural)
			require.Equal(t, positive.examined, active.failed)
			ctx, cancel := context.WithCancel(lifetime)
			defer cancel()
			observer := &cancelAfterLastReseedFailure{expected: active.examined, cancel: cancel}
			var completed, structural bool
			var examined, reseeded, failed int
			var got error
			switch lane.name {
			case "verbs":
				c, e := seed.ReseedSystemRoleVerbs(ctx, repo, pool, catalogfixture.Facts(), observer)
				completed, structural, examined, reseeded, failed, got = c.Completed, c.Structural(), c.Examined, c.Reseeded, c.Failed, e
			case "rule-refs":
				c, e := seed.ReseedSystemRoleRuleRefs(ctx, repo, pool, observer)
				completed, structural, examined, reseeded, failed, got = c.Completed, c.Structural(), c.Examined, c.Reseeded, c.Failed, e
			default:
				t.Fatal("unrecognized reseed lane")
			}
			require.Equal(t, active.examined, observer.observed, "all failures happened before the cancellation boundary")
			require.ErrorIs(t, ctx.Err(), context.Canceled)
			require.NoError(t, lifetime.Err(), "test timeout must not cause the late-cancellation premise")
			require.Equal(t, active.examined, examined)
			require.Equal(t, examined, failed)
			require.Zero(t, reseeded)
			require.Error(t, got)
			require.True(t, completed, "late cancellation cannot turn already completed real work into an incomplete traversal")
			require.True(t, structural, "completed all-role refusal must remain structural during shutdown")
			require.JSONEq(t, before, reseedProjectionSnapshot(t, lifetime, pool, lane.table))
		})
	}
}
