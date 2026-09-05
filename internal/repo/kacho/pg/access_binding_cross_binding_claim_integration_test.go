// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_cross_binding_claim_integration_test.go — the SQL side of the
// cross-binding survivor probe (SelectTuplesClaimedByOtherActiveBindings).
//
// WHY IT EXISTS. The emitted-tuple ledger is keyed PER BINDING (binding_id,
// fga_user, relation, object), а сам ФАКТ отношения не счётный: его ключ —
// (объект, отношение, субъект), без выдачи. Две выдачи ОДНОМУ субъекту на ОДНУ
// область держат ДВЕ строки ведомости на ОДИН живой факт. Снос, дословно
// повторяющий свою ведомость, поэтому снимает доступ, который другая ДЕЙСТВУЮЩАЯ
// выдача продолжает давать (тихая потеря доступа, самоподдерживающаяся — ведомость
// читают как зеркало фактов, поэтому ни один проход реконсайлера её не перепишет).
// Delete/Revoke subtract this probe's result, so a shared tuple dies only with its
// LAST ACTIVE claimant.
//
// The three properties the SQL must hold, all locked below:
//   - a tuple another ACTIVE binding records → returned (retain it);
//   - the probing binding's OWN rows → NEVER returned (a binding must not keep its
//     own tuples alive, or nothing would ever be revoked);
//   - a REVOKED other binding's rows → NOT returned (a dead grant keeps nothing
//     alive) — the property that makes the LAST claimant's revoke effective.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// claimedProbe runs the survivor probe on a fresh reader-tx.
func claimedProbe(t *testing.T, ctx context.Context, repo *kachopg.Repository,
	exclude domain.AccessBindingID, candidates []repoab.RelationTuple) []repoab.RelationTuple {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd.AccessBindings().SelectTuplesClaimedByOtherActiveBindings(ctx, exclude, candidates)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	return got
}

func TestABEmittedTuples_CrossBindingClaim_OnlyOtherActiveBindingsKeepATupleAlive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "xclaim")
	acc := seedAccount(t, ctx, repo, "acc-xclaim", uid)

	// TWO bindings of the SAME subject on the SAME scope. Different roles, because
	// the partial UNIQUE access_bindings_active_grant_uniq forbids a duplicate ACTIVE
	// 5-tuple — which is exactly why the shared-tuple class exists at all: distinct
	// bindings whose emitted sets OVERLAP.
	abA := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: string(acc.ID),
	})
	abB := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysadmin", ResourceType: "account", ResourceID: string(acc.ID),
	})

	shared := repoab.RelationTuple{User: "user:" + string(uid), Relation: "editor", Object: "account:" + string(acc.ID)}
	onlyA := repoab.RelationTuple{User: "user:" + string(uid), Relation: "v_delete", Object: "account:" + string(acc.ID)}
	// A tuple nobody recorded at all — must never be reported as claimed.
	unknown := repoab.RelationTuple{User: "user:" + string(uid), Relation: "v_create", Object: "account:" + string(acc.ID)}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, abA.ID, []repoab.RelationTuple{shared, onlyA}))
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, abB.ID, []repoab.RelationTuple{shared}))
	require.NoError(t, w.Commit(ctx))

	candidates := []repoab.RelationTuple{shared, onlyA, unknown}

	// A's teardown: `shared` is still held by the ACTIVE B ⇒ retain; A's own rows
	// (onlyA, and its own copy of shared) must not keep anything alive.
	require.Equal(t, []repoab.RelationTuple{shared}, claimedProbe(t, ctx, repo, abA.ID, candidates),
		"only the tuple another ACTIVE binding records may be retained")

	// Symmetric: from B's side, A keeps `shared` alive.
	require.Equal(t, []repoab.RelationTuple{shared}, claimedProbe(t, ctx, repo, abB.ID, []repoab.RelationTuple{shared}),
		"the probe is symmetric — either binding sees the other's claim")

	// B revoked (soft): a dead grant keeps NOTHING alive, so A's teardown may now
	// remove `shared` — the LAST ACTIVE claimant's revoke must be effective.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w2.AccessBindingsW().RevokeGuarded(ctx, abB.ID, uid)
	require.NoError(t, err)
	require.NoError(t, w2.Commit(ctx))

	require.Empty(t, claimedProbe(t, ctx, repo, abA.ID, candidates),
		"a REVOKED binding's ledger row must NOT keep a tuple alive (otherwise the last revoke never lands)")

	// Degenerate input: no candidates ⇒ no query, no rows.
	require.Empty(t, claimedProbe(t, ctx, repo, abA.ID, nil), "empty candidate set ⇒ empty result")
}
