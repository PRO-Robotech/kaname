// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// batch_matches_per_object_integration_test.go — two read paths, one answer.
//
// The page read (batch.go + repo/kacho/pg/structural_facts_repo.go) exists because
// deriving facts one object at a time makes a page cost grow with the page. It is a second
// READ of the same columns, and a second read is a place a divergence can hide: if the two
// paths ever disagreed, authorization would depend on whether the question arrived alone or
// on a page — and pages are exactly where nobody looks.
//
// So the equivalence is asserted rather than argued, for EVERY derivable type, including the
// cases most likely to be got wrong by one path and not the other:
//
//   - a row with a parent (the ordinary case);
//   - a row whose parent column is NULL (a system role) — nothing must be claimed, and both
//     paths must claim nothing in the same way;
//   - an id with NO row — absence, not an error, and not an empty fact set;
//   - a chain two levels deep (a project-scoped binding), where the closure is the answer
//     rather than the row.
//
// Real Postgres. No relation store is needed: this compares two projections of the same
// rows. Skipped under -short.

package authzcascade

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// eqWorld — one account with one child row of every derivable type.
type eqWorld struct {
	pool     *pgxpool.Pool
	perObj   *Resolver
	batched  *Resolver
	account  string
	project  string
	byType   map[string][]string
	missByID map[string]string
}

func newEqWorld(t *testing.T) *eqWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real-Postgres equivalence test in -short mode")
	}
	dsn := kachopg.NewTestPostgres(t)
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	repo := kachopg.New(pool, nil)
	batchRepo := kachopg.NewStructuralFactsRepo(pool)

	w := &eqWorld{
		pool:   pool,
		perObj: New(repo),
		batched: New(repo).WithBatch(BatchSourceFunc(
			func(ctx context.Context) (StructuralSnapshot, error) { return batchRepo.StructuralSnapshot(ctx) })),
		account:  costID("acc", "eq1"),
		project:  costID("prj", "eq1"),
		byType:   map[string][]string{},
		missByID: map[string]string{},
	}

	ctx := context.Background()
	owner := costID("usr", "eqown1")
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ($1, $1, $2)`,
		w.account, owner)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kacho_iam.users (id, external_id, email, account_id)
	                       VALUES ($1, $1, $1 || '@example.test', $2)`, owner, w.account)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	exec := func(sql string, args ...any) {
		_, eerr := pool.Exec(ctx, sql, args...)
		require.NoError(t, eerr, "seed: %s", sql)
	}
	exec(`INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ($1, $2, $1)`, w.project, w.account)

	accountRole := costID("rol", "eq1")
	exec(`INSERT INTO kacho_iam.roles (id, account_id, name, permissions)
	      VALUES ($1, $2, $3, '["vpc.network.all.get"]'::jsonb)`,
		accountRole, w.account, lowerName(accountRole))
	// A SYSTEM role: account_id IS NULL, so nothing structural may be claimed about it.
	systemRole := costID("rol", "eqsys1")
	// is_system is derived from the scope columns, so it is not written here.
	exec(`INSERT INTO kacho_iam.roles (id, cluster_id, name, permissions)
	      VALUES ($1, 'cluster_kacho_root', $2, '["vpc.network.all.get"]'::jsonb)`,
		systemRole, lowerName(systemRole))

	group := costID("grp", "eq1")
	exec(`INSERT INTO kacho_iam.groups (id, account_id, name) VALUES ($1, $2, $3)`,
		group, w.account, lowerName(group))
	sa := costID("sva", "eq1")
	exec(`INSERT INTO kacho_iam.service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
		sa, w.account, lowerName(sa))
	user := costID("usr", "eqmem1")
	exec(`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
	      VALUES ($1, $1, $1 || '@example.test', $2)`, user, w.account)

	// Bindings on all three scope tiers: the project-scoped one is the two-level chain.
	//
	// The ROLE differs by tier because the platform's assignability rule does: an
	// account-tier custom role may be bound on its own account and on a project nested
	// in it, but the cluster scope admits SYSTEM roles only. The fixture used the
	// account role on all three, which is a shape the service refuses at its own gate
	// and the database now refuses outright — so it described a world that cannot
	// exist, which makes anything measured on it about that world rather than ours.
	projBinding := costID("acb", "eqprj1")
	accBinding := costID("acb", "eqacc1")
	cluBinding := costID("acb", "eqclu1")
	for i, b := range []struct{ id, scopeType, scopeID, role string }{
		{projBinding, "project", w.project, accountRole},
		{accBinding, "account", w.account, accountRole},
		{cluBinding, "cluster", "cluster_kacho_root", systemRole},
	} {
		grantee := costID("usr", fmt.Sprintf("eqgte%d", i))
		exec(`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		      VALUES ($1, $1, $1 || '@example.test', $2)`, grantee, w.account)
		exec(`INSERT INTO kacho_iam.access_bindings
		        (id, subject_type, subject_id, role_id, resource_type, resource_id)
		      VALUES ($1, 'user', $2, $3, $4, $5)`, b.id, grantee, b.role, b.scopeType, b.scopeID)
	}

	w.byType = map[string][]string{
		"account":             {w.account},
		"project":             {w.project},
		"iam_user":            {user, owner},
		"iam_group":           {group},
		"iam_role":            {accountRole, systemRole},
		"iam_service_account": {sa},
		"iam_access_binding":  {projBinding, accBinding, cluBinding},
	}
	// One id per type that has no row at all.
	w.missByID = map[string]string{
		"account":             costID("acc", "eqmiss"),
		"project":             costID("prj", "eqmiss"),
		"iam_user":            costID("usr", "eqmiss"),
		"iam_group":           costID("grp", "eqmiss"),
		"iam_role":            costID("rol", "eqmiss"),
		"iam_service_account": costID("sva", "eqmiss"),
		"iam_access_binding":  costID("acb", "eqmiss"),
	}
	return w
}

// lowerName derives a name satisfying the lowercase-identifier CHECK the named tables carry.
func lowerName(id string) string {
	return "n" + strings.ToLower(strings.ReplaceAll(id[3:], "-", "_"))
}

func sortedFacts(facts []authztypes.TupleKey) []string {
	out := make([]string, 0, len(facts))
	for _, f := range facts {
		out = append(out, f.Object+"#"+f.Relation+"@"+f.User)
	}
	sort.Strings(out)
	return out
}

// TestBatchFactsMatchPerObjectFacts — the equivalence, per type, including the shapes most
// likely to diverge.
func TestBatchFactsMatchPerObjectFacts(t *testing.T) {
	w := newEqWorld(t)
	ctx := context.Background()

	require.True(t, w.batched.BatchReachable(), "premise: the batched resolver can batch")
	require.False(t, w.perObj.BatchReachable(), "premise: the per-object one cannot")

	examined, withFacts := 0, 0
	for objectType, ids := range w.byType {
		all := append(append([]string{}, ids...), w.missByID[objectType])
		batch, err := w.batched.StructuralFactsBatch(ctx, objectType, all)
		require.NoError(t, err, "batch read of %s", objectType)

		for _, id := range ids {
			examined++
			perObject, perr := w.perObj.StructuralFacts(ctx, objectType, id)
			require.NoError(t, perr, "per-object read of %s:%s", objectType, id)
			got, present := batch[id]
			require.Truef(t, present,
				"%s:%s has a row, so the batch must have an entry for it — an absent entry is "+
					"how a MISS is reported and would send the caller back to a per-object read",
				objectType, id)
			require.Equalf(t, sortedFacts(perObject), sortedFacts(got),
				"the two read paths must derive the SAME facts for %s:%s; a divergence would "+
					"make authorization depend on whether the question arrived alone or on a page",
				objectType, id)
			if len(perObject) > 0 {
				withFacts++
			}
		}

		miss := w.missByID[objectType]
		_, present := batch[miss]
		require.Falsef(t, present,
			"%s:%s has no row, so it must be ABSENT from the batch result rather than present "+
				"and empty — the caller distinguishes the two", objectType, miss)
		perObjectMiss, perr := w.perObj.StructuralFacts(ctx, objectType, miss)
		require.NoError(t, perr, "an absent row is not an error")
		require.Empty(t, perObjectMiss, "and yields no facts")
	}

	// Premise checks, so "all equal" cannot mean "nothing compared" or "nothing had facts".
	require.Equal(t, len(DerivableTypes), len(w.byType),
		"every derivable type must be covered here; a type added to the resolver without a "+
			"fixture would otherwise be silently unexamined")
	// Floor lowered 12 → 11 when the tenant-facing condition surface was retired:
	// `iam_condition` was one of the fixture's derivable types and its row went
	// with the type. A floor guards against a SILENT shrink of what is compared;
	// a deliberate retire moves it, and only by what the retire actually removed.
	require.GreaterOrEqual(t, examined, 11, "examined %d rows", examined)
	require.GreaterOrEqual(t, withFacts, 8,
		"only %d of the compared rows produced any facts — an equivalence over empty sets "+
			"would prove nothing", withFacts)
	t.Logf("compared %d rows over %d types; %d produced facts", examined, len(w.byType), withFacts)
}

// TestBatchClosesTheChainLikeTheWalk — the two-level case, named because the first
// implementation of the per-object resolver got exactly this wrong: a project-scoped binding
// needs binding→project AND project→account, and supplying only the first leaves the second
// hop with nothing to resolve over.
func TestBatchClosesTheChainLikeTheWalk(t *testing.T) {
	w := newEqWorld(t)
	ctx := context.Background()

	binding := w.byType["iam_access_binding"][0] // the project-scoped one
	batch, err := w.batched.StructuralFactsBatch(ctx, "iam_access_binding", []string{binding})
	require.NoError(t, err)
	facts := sortedFacts(batch[binding])

	require.Contains(t, facts,
		"iam_access_binding:"+binding+"#project@project:"+w.project,
		"the binding's own pointer")
	require.Contains(t, facts, "project:"+w.project+"#account@account:"+w.account,
		"and the project's account pointer, without which the account tier has nothing to "+
			"resolve over")
	require.Contains(t, facts, "account:"+w.account+"#cluster@cluster:cluster_kacho_root",
		"and the account's cluster pointer, which is how the cloud tier reaches it")
}
