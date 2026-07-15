// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// group_delete_concurrent_integration_test.go — concurrent-goroutine race proof
// for the production groupWriter.Delete contested CAS path (data-integrity.md
// checklist #5: every contested CAS/guard path must carry a concurrent race test
// proving exactly-one-winner). The sibling user delete-vs-create write-skew is
// proven in access_binding_subject_exists_integration_test.go via an INLINE SQL
// mirror of the users branch; the GROUP branch (distinct reverse-guard on
// access_bindings + access_binding_subjects + the migration-0049 groups-row
// FOR KEY SHARE probe + the migration-0050 groups BEFORE DELETE trigger) had no
// concurrent test and is exercised here through the REAL groupWriter.Delete —
// never an inline SQL copy.
//
// Both subtests are deterministic (no goroutine, no pg_stat_activity polling, no
// possibility of a hang), mirroring TestABSubjectExists_ConcurrentDeleteVsCreate_
// NoDangling: a real AccessBinding write for a GROUP subject is held open in one
// tx (its 0049 subject_ref_exists trigger takes FOR KEY SHARE on the groups row),
// then the production groupWriter.Delete runs on a SEPARATE connection whose
// session lock_timeout is short so a blocked delete self-releases (SQLSTATE 55P03)
// instead of blocking to statement_timeout. That the delete blocks at all PROVES
// the two paths serialize on the groups row — the write-skew window the software
// NOT-EXISTS guard alone could not close. After the writer commits, a fresh
// guarded delete re-qualifies against the now-committed reference and rejects with
// FailedPrecondition — never a dangling group-subject binding.

import (
	"context"
	stderrors "errors"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// newLockTimeoutPool — a pgxpool whose every session sets `lock_timeout` so a
// guarded write that blocks on a conflicting row-lock self-releases (55P03)
// rather than waiting out statement_timeout. Used for the delete side so the
// serialization proof is bounded and deterministic.
func newLockTimeoutPool(t *testing.T, ctx context.Context, dsn string, lockTimeoutMS int) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["lock_timeout"] = strconv.Itoa(lockTimeoutMS)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func TestGroup_DeleteVsAddSubject_ConcurrentCAS_NoDangling(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)

	// master pool — seeding + the held-open AccessBinding write tx.
	master, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer master.Close()
	seedRepo := kachopg.New(master, nil)

	// delete-side repo on a lock_timeout=2s pool so the production
	// groupWriter.Delete self-releases instead of blocking to statement_timeout.
	delRepo := kachopg.New(newLockTimeoutPool(t, ctx, dsn, 2000), nil)

	// realGroupDelete drives the PRODUCTION groupWriter.Delete on a fresh
	// lock_timeout writer-tx (rolled back — this side never commits a delete).
	realGroupDelete := func(id domain.GroupID) error {
		w, werr := delRepo.Writer(ctx)
		require.NoError(t, werr)
		defer func() { _ = w.Rollback(ctx) }()
		return w.GroupsW().Delete(ctx, id)
	}

	// ── subjects[0] projection: the access_bindings NOT-EXISTS guard ──────────
	t.Run("subjects0_access_bindings_guard", func(t *testing.T) {
		uid := mustSeedUser(t, ctx, master, "gdc-a")
		acc := seedAccount(t, ctx, seedRepo, "acc-gdc-a", uid)
		g := seedGroup(t, ctx, seedRepo, acc.ID, "gdc-a")

		// A real AccessBinding.Create for subject group:g, held open (uncommitted).
		// Its 0049 subject_ref_exists trigger takes FOR KEY SHARE on the groups row.
		wIns, err := seedRepo.Writer(ctx)
		require.NoError(t, err)
		committed := false
		defer func() {
			if !committed {
				_ = wIns.Rollback(ctx)
			}
		}()
		_, err = wIns.AccessBindingsW().Insert(ctx, domain.AccessBinding{
			ID:           domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
			SubjectType:  domain.SubjectTypeGroup,
			SubjectID:    domain.SubjectID(g.ID),
			RoleID:       "rol000000000sysviewer",
			ResourceType: "account",
			ResourceID:   string(acc.ID),
		})
		require.NoError(t, err)

		// Production groupWriter.Delete must block on the write's key-share lock
		// and time out — proving the two paths serialize on the groups row.
		require.Error(t, realGroupDelete(g.ID),
			"guarded Group.Delete must block on the AB.Create key-share lock, not delete the group (race window would be open)")

		// Commit → releases the lock. A fresh guarded delete now observes the
		// committed binding and rejects — never a dangling group-subject binding.
		require.NoError(t, wIns.Commit(ctx))
		committed = true

		err = realGroupDelete(g.ID)
		require.Error(t, err)
		require.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
			"post-commit Group.Delete must reject (group still bound), got %v", err)

		// Invariant: the group survived and the binding references a live group.
		var groupCnt, bindCnt int
		require.NoError(t, master.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.groups WHERE id=$1`, string(g.ID)).Scan(&groupCnt))
		require.Equal(t, 1, groupCnt, "bound group must survive the guarded delete")
		require.NoError(t, master.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.access_bindings WHERE subject_type='group' AND subject_id=$1`,
			string(g.ID)).Scan(&bindCnt))
		require.Equal(t, 1, bindCnt, "the committed binding must reference the live group")
	})

	// ── subjects[1..N]: the access_binding_subjects guard + 0050 trigger ──────
	t.Run("subjectsN_access_binding_subjects_guard", func(t *testing.T) {
		uid := mustSeedUser(t, ctx, master, "gdc-b")
		acc := seedAccount(t, ctx, seedRepo, "acc-gdc-b", uid)
		g := seedGroup(t, ctx, seedRepo, acc.ID, "gdc-b")

		// A COMMITTED binding whose subjects[0] is the user — group:g is NOT the
		// access_bindings projection; it exists ONLY as an access_binding_subjects
		// child row (the subjects[1..N] path guarded by migration 0050's BEFORE
		// DELETE trigger + the Delete CTE's second NOT EXISTS).
		bindingID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
		wSeed, err := seedRepo.Writer(ctx)
		require.NoError(t, err)
		_, err = wSeed.AccessBindingsW().Insert(ctx, domain.AccessBinding{
			ID:           bindingID,
			SubjectType:  domain.SubjectTypeUser,
			SubjectID:    domain.SubjectID(uid),
			RoleID:       "rol000000000sysviewer",
			ResourceType: "account",
			ResourceID:   string(acc.ID),
		})
		require.NoError(t, err)
		require.NoError(t, wSeed.Commit(ctx))

		// Add group:g as an extra subject, held open (uncommitted) — the 0049
		// trigger fires on access_binding_subjects too, taking FOR KEY SHARE on
		// the groups row.
		wIns, err := seedRepo.Writer(ctx)
		require.NoError(t, err)
		committed := false
		defer func() {
			if !committed {
				_ = wIns.Rollback(ctx)
			}
		}()
		require.NoError(t, wIns.AccessBindingsW().InsertSubjects(ctx, bindingID, []domain.Subject{
			{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(g.ID)},
		}))

		// Production groupWriter.Delete must block/serialize on the groups row.
		require.Error(t, realGroupDelete(g.ID),
			"guarded Group.Delete must block on the add-subject key-share lock (race window would be open)")

		require.NoError(t, wIns.Commit(ctx))
		committed = true

		// Fresh guarded delete now sees the committed access_binding_subjects row
		// → rejected (0050 trigger / second NOT EXISTS), no dangling subject ref.
		err = realGroupDelete(g.ID)
		require.Error(t, err)
		require.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
			"post-commit Group.Delete must reject (group still referenced as a binding subject), got %v", err)

		var groupCnt, subjCnt int
		require.NoError(t, master.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.groups WHERE id=$1`, string(g.ID)).Scan(&groupCnt))
		require.Equal(t, 1, groupCnt, "referenced group must survive the guarded delete")
		require.NoError(t, master.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.access_binding_subjects WHERE subject_type='group' AND subject_id=$1`,
			string(g.ID)).Scan(&subjCnt))
		require.Equal(t, 1, subjCnt, "the committed subject row must reference the live group")
	})
}
