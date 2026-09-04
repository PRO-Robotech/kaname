// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

// testhelpers_assignable_test.go — PG16 setup + seed helpers for the
// assignable-roles use-case integration tests (ListAssignableRoles +
// AccessBinding.Create scope-enforcement). Lives in package access_binding_test
// (black-box) — mirrors the helpers used by internal/repo/kacho/pg and the
// cluster handler integration tests, which cannot be shared across packages.
//
// The Postgres itself is one per test BINARY (testmain_pgtest_test.go); each
// caller of setupTestDB still gets its own database.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// allowRelationStore — fake clients.RelationStore that grants every Check.
// Used by integration tests exercising the cluster grant-authority path
// (cluster scope has no DB owner; authority is FGA admin only). Tuple writes
// are no-ops (the SQL/use-case behaviour under test does not depend on them).
type allowRelationStore struct{}

func (allowRelationStore) Check(context.Context, string, string, string) (bool, error) {
	return true, nil
}

// The write side is gone with the port method it stood for: clients.RelationStore
// declared WriteTuples/DeleteTuples while it was a port onto someone else's storage,
// and stage S6 left it with the question alone. Methods standing for a port method
// that no longer exists have no caller, so nothing can exercise them and nothing they
// might assert could ever go red — they only make this stub look wider than it is.
var _ clients.RelationStore = allowRelationStore{}

// setupTestDB hands the calling test its OWN database, with kacho_iam on the
// search path.
//
// It used to start a fresh container and replay the whole migration chain on
// every call — 32 callers, 32 containers, ~254s before a single assertion. The
// database now comes from the one container this test binary owns (wired in
// testmain_pgtest_test.go), cloned from a template migrated once — see
// internal/pgtest for why a clone is the same isolation a separate container gave.
//
// The sentence that used to end this paragraph — "the OpenFGA containers this package
// also starts are unaffected" — is dropped: this package starts none. It stopped
// starting them when the external relation engine was removed (stage S6), and a note
// about a container nobody starts sends the next reader looking for a cost that is
// not there.
func setupTestDB(t testing.TB) string {
	t.Helper()
	return pgtest.NewDB(t)
}

func poolFromDSN(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := coredb.NewPool(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// mustSeedUser inserts a user + its own account, returns the UserID.
func mustSeedUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID),
		fmt.Sprintf("ext-%s-%s", suffix, uid),
		fmt.Sprintf("u-%s@example.com", suffix),
		"Test User "+suffix)
	require.NoError(t, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID),
		fmt.Sprintf("seed-acc-%s-%s", suffix, accID[len(accID)-6:]),
		string(uid))
	require.NoError(t, err)

	require.NoError(t, tx.Commit(ctx))
	return uid
}

// seedAccountByOwner inserts an account owned by the given (already-seeded)
// owner and returns its id (so the owner has grant-authority via owner_user_id).
func seedAccountByOwner(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string, owner domain.UserID) domain.AccountID {
	t.Helper()
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID), name+"-"+string(accID)[len(accID)-6:], string(owner))
	require.NoError(t, err)
	return accID
}

// seedProjectInAccount inserts a project under the account and returns its id.
func seedProjectInAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc domain.AccountID, name string) domain.ProjectID {
	t.Helper()
	prj := domain.ProjectID(ids.NewID(domain.PrefixProject))
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.projects (id, account_id, name, description, labels)
		VALUES ($1, $2, $3, $4, '{}'::jsonb)`,
		string(prj), string(acc), name+"-"+string(prj)[len(prj)-6:], "test project")
	require.NoError(t, err)
	return prj
}

// seedClusterAdmin grants active cluster-admin to the subject (owner path on
// cluster scope is FGA-only; integration tests use the cluster_admin_grants row
// — but grant-authority on cluster needs FGA admin, so use-case tests that
// require cluster grant-authority wire a fake RelationStore instead; this helper
// is retained for parity with other suites).
func seedClusterAdmin(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject domain.UserID) {
	t.Helper()
	id := domain.NewKac127ID(domain.PrefixClusterAdminGrant)
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.cluster_admin_grants
		     (id, cluster_id, subject_type, subject_id, granted_by, granted_at, granted_until)
		 VALUES ($1, $2, 'user', $3, $3, now(), NULL)`,
		id, domain.ClusterSingletonID, string(subject))
	require.NoError(t, err)
}

// awaitOp polls the operations repo until the op is done (or deadline).
func awaitOp(t *testing.T, ctx context.Context, opsRepo operations.Repo, id string) *operations.Operation {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		op, err := opsRepo.Get(ctx, id)
		require.NoError(t, err)
		if op.Done {
			return op
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("operation %s not done within deadline", id)
	return nil
}
