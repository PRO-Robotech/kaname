// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

// testhelpers_assignable_test.go — testcontainers PG16 setup + seed helpers for
// the assignable-roles use-case integration tests (ListAssignableRoles +
// AccessBinding.Create scope-enforcement). Lives in package access_binding_test
// (black-box) — mirrors the helpers used by internal/repo/kacho/pg and the
// cluster handler integration tests, which cannot be shared across packages.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// allowRelationStore — fake clients.RelationStore that grants every Check.
// Used by integration tests exercising the cluster grant-authority path
// (cluster scope has no DB owner; authority is FGA admin only). Tuple writes
// are no-ops (the SQL/use-case behaviour under test does not depend on them).
type allowRelationStore struct{}

func (allowRelationStore) Check(context.Context, string, string, string) (bool, error) {
	return true, nil
}
func (allowRelationStore) WriteTuples(context.Context, []clients.RelationTuple) error  { return nil }
func (allowRelationStore) DeleteTuples(context.Context, []clients.RelationTuple) error { return nil }

var _ clients.RelationStore = allowRelationStore{}

func setupTestDB(t testing.TB) string {
	t.Helper()
	ctx := context.Background()

	pgc, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("kacho_iam_test"),
		postgres.WithUsername("iam"),
		postgres.WithPassword("iam"),
		postgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgc.Terminate(ctx) })

	dsn, err := pgc.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))

	return appendSearchPathOptions(dsn)
}

func appendSearchPathOptions(dsn string) string {
	const optionsParam = "options=-c%20search_path%3Dkacho_iam%2Cpublic"
	if strings.Contains(dsn, "options=") || strings.Contains(dsn, "options%3D") {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + optionsParam
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
