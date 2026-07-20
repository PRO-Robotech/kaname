// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// access_binding_target_integration_test.go — redesign-2026 F8 (IAM-1-21/29):
// the active-grant partial UNIQUE now includes `target_digest`, so:
//
//   - two concurrent IDENTICAL Create (same subject, role, scope AND target) →
//     exactly one winner, the rest ALREADY_EXISTS (the digest is a key column;
//     WHERE revoked_at IS NULL is UNCHANGED — never weakened to status='ACTIVE');
//   - after RevokeGuarded of the winner, an identical re-grant is a NEW ACTIVE row
//     (revoked row frees the slot);
//   - two DISTINCT targets (same subject/role/scope) COEXIST — the new F8
//     dimension — because their digests differ.
//
// Runs under -race. Запуск: TESTCONTAINERS_RYUK_DISABLED=true go test
// ./internal/repo/kacho/pg/... -race -timeout 30m -p 1.

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// insertBindingWithTarget Inserts+Commits one ACTIVE binding carrying the given
// target on the (uid, account) 5-tuple.
func insertBindingWithTarget(t *testing.T, ctx context.Context, repo *kachopg.Repository,
	id domain.AccessBindingID, uid domain.UserID, accID string, tgt domain.AccessTarget) (domain.AccessBinding, error) {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, ierr := w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: id, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: accID,
		Target: tgt,
	})
	if ierr != nil {
		_ = w.Rollback(ctx)
		return domain.AccessBinding{}, ierr
	}
	return out, w.Commit(ctx)
}

// TestAB_IAM_1_29_ReGrantWithTarget_Race — concurrent identical per-object target
// grants collide on the extended active-grant UNIQUE (subject, role, scope,
// target_digest); after revoke the identical re-grant is a NEW ACTIVE row.
func TestAB_IAM_1_29_ReGrantWithTarget_Race(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-29-tgt-race")
	acc := seedAccount(t, ctx, repo, "acc-iam1-29-tgt-race", uid)
	accID := string(acc.ID)

	tgt := domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "compute.instance", ID: "ins-race1"}}}

	// ── Phase 1: concurrent identical Create (same target) → one winner ────
	const goroutines = 8
	type res struct {
		id  domain.AccessBindingID
		err error
	}
	out := make(chan res, goroutines)
	var ready sync.WaitGroup
	ready.Add(goroutines)
	startGate := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
			ready.Done()
			<-startGate
			_, ierr := insertBindingWithTarget(t, ctx, repo, id, uid, accID, tgt)
			out <- res{id, ierr}
		}()
	}
	ready.Wait()
	close(startGate)

	var winner domain.AccessBindingID
	successes, already, other := 0, 0, 0
	for i := 0; i < goroutines; i++ {
		r := <-out
		switch {
		case r.err == nil:
			successes++
			winner = r.id
		case stderrors.Is(r.err, iamerr.ErrAlreadyExists):
			already++
		default:
			other++
			t.Logf("unexpected race error: %v", r.err)
		}
	}
	require.Equal(t, 1, successes, "exactly one identical (subject,role,scope,target) Create wins")
	assert.Equal(t, goroutines-1, already, "losers get ALREADY_EXISTS (partial UNIQUE incl. target_digest)")
	assert.Equal(t, 0, other, "no unexpected errors / panics")

	// ── Phase 2: revoke the winner ────────────────────────────────────────
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().RevokeGuarded(ctx, winner, uid)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// ── Phase 3: identical re-grant is a NEW ACTIVE row ───────────────────
	regrantID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	regranted, err := insertBindingWithTarget(t, ctx, repo, regrantID, uid, accID, tgt)
	require.NoError(t, err, "re-grant after revoke must succeed — revoked row frees the slot")
	assert.NotEqual(t, winner, regranted.ID, "re-grant is a distinct new ACTIVE binding id")
	assert.Equal(t, domain.AccessBindingStatusActive, regranted.Status)
	// target round-trips through the DB column.
	require.Len(t, regranted.Target.Resources, 1)
	assert.Equal(t, "compute.instance", regranted.Target.Resources[0].Type)
	assert.Equal(t, "ins-race1", regranted.Target.Resources[0].ID)
}

// TestAB_IAM_1_29_DistinctTargets_Coexist — the NEW F8 dimension: same
// subject/role/scope with DISTINCT targets do NOT collide (distinct digests), while
// the whole-anchor allInScope grant is yet another distinct slot ("all").
func TestAB_IAM_1_29_DistinctTargets_Coexist(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-29-tgt-coexist")
	acc := seedAccount(t, ctx, repo, "acc-iam1-29-tgt-coexist", uid)
	accID := string(acc.ID)

	// per-object ins-1, per-object ins-2, and whole-anchor allInScope — three
	// distinct target_digests → three coexisting ACTIVE rows.
	_, e1 := insertBindingWithTarget(t, ctx, repo,
		domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), uid, accID,
		domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "compute.instance", ID: "ins-1"}}})
	require.NoError(t, e1)

	_, e2 := insertBindingWithTarget(t, ctx, repo,
		domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), uid, accID,
		domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "compute.instance", ID: "ins-2"}}})
	require.NoError(t, e2, "a DISTINCT per-object target must NOT collide with ins-1")

	_, e3 := insertBindingWithTarget(t, ctx, repo,
		domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), uid, accID,
		domain.AccessTarget{AllInScope: true})
	require.NoError(t, e3, "the whole-anchor allInScope grant is a distinct slot ('all')")

	// but a DUPLICATE of ins-1 collides.
	_, e4 := insertBindingWithTarget(t, ctx, repo,
		domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), uid, accID,
		domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "compute.instance", ID: "ins-1"}}})
	require.Error(t, e4)
	assert.True(t, stderrors.Is(e4, iamerr.ErrAlreadyExists), "identical target collides (ALREADY_EXISTS)")
}
