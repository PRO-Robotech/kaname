// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migration_0017_backfill_operations_account_id_integration_test.go —
// integration tests (testcontainers PG16) for the
// `0017_backfill_operations_account_id.sql` migration.
//
// Sub-phase 1.2 (migration 0016) added the additive, nullable account_id denorm
// column to kacho_iam.operations, and the create use-cases now stamp it from
// metadata. But operations created BEFORE the 0016 deploy carry account_id=NULL
// → the account-scoped /iam/operations feed (AccountService.ListAllOperations,
// WHERE account_id=$x) shows EMPTY for all historical rows. Migration 0017
// backfills account_id for those pre-1.2 rows by joining the already-populated
// resource_id column to the resource's owning account:
//
//   - account ops   (resource_id = accounts.id)         → account_id = resource_id
//   - project ops   (resource_id = projects.id)         → account_id = projects.account_id
//   - group ops     (resource_id = groups.id)           → account_id = groups.account_id
//   - SA ops        (resource_id = service_accounts.id) → account_id = service_accounts.account_id
//   - user ops      (resource_id = users.id)            → account_id = users.account_id
//
// Category-II ops (role / access_binding / SAKey / condition, resource_id has no
// owning-account column) and rows with NULL resource_id are left NULL (D-5).
//
// The migration only fills NULLs and joins on resource_id, so it is idempotent
// and additive (re-running on already-backfilled rows is a no-op).
//
// NewTestPostgres runs ALL migrations up (incl. 0017) before the test body, so
// these tests are RED until 0017_backfill_operations_account_id.sql exists (the
// seeded NULL rows stay NULL) and GREEN once it does. Skip under testing.Short().

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
	pg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// applyBackfill0017 re-runs the exact Up body of
// 0017_backfill_operations_account_id.sql against the current DB. NewTestPostgres
// already ran 0017 once at migration time — on an EMPTY operations table — so a
// data-only backfill must be re-applied here after the test has seeded the
// pre-1.2 rows. Reading the shipped file (not a copy) keeps the test honest:
// any drift in the migration SQL is exercised verbatim. The backfill is
// idempotent (WHERE account_id IS NULL), so re-running it is safe.
func applyBackfill0017(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	raw, err := migrations.FS.ReadFile("0017_backfill_operations_account_id.sql")
	require.NoError(t, err, "read migration 0017")

	body := string(raw)
	// Take everything between `-- +goose Up` and `-- +goose Down`.
	up := body
	if i := strings.Index(body, "-- +goose Down"); i >= 0 {
		up = body[:i]
	}
	up = strings.Replace(up, "-- +goose Up", "", 1)
	require.NotEmpty(t, strings.TrimSpace(up), "0017 Up body must be non-empty")

	_, err = pool.Exec(ctx, up)
	require.NoError(t, err, "apply 0017 backfill Up body")
}

// seedAcctUser0017 inserts a (user, account) pair in one tx (owner_user_id and
// users.account_id FKs are DEFERRABLE INITIALLY DEFERRED — chicken-and-egg). It
// returns the created account id and user id.
func seedAcctUser0017(ctx context.Context, t *testing.T, pool *pgxpool.Pool, suffix string) (accID, userID string) {
	t.Helper()
	accID = ids.NewID(domain.PrefixAccount)
	userID = ids.NewID(domain.PrefixUser)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err, "begin seed tx")
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'Backfill User', 'ACTIVE')`,
		userID, accID, "ext-"+suffix+"-"+userID, "u-"+suffix+"@example.com")
	require.NoError(t, err, "seed user")

	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		accID, "bf-acc-"+suffix+"-"+accID[len(accID)-6:], userID)
	require.NoError(t, err, "seed account")

	require.NoError(t, tx.Commit(ctx), "commit seed tx")
	return accID, userID
}

// insertNullAccountOp inserts a pre-1.2 operations row with resource_id set but
// account_id NULL (the state the backfill must fix). NOT NULL columns get
// realistic defaults from the schema; we set only the columns we exercise.
func insertNullAccountOp(ctx context.Context, t *testing.T, pool *pgxpool.Pool, opID, resourceID string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.operations (id, description, done, resource_id, account_id)
		VALUES ($1, 'pre-1.2 op', true, $2, NULL)`,
		opID, resourceID)
	require.NoError(t, err, "insert null-account op")
}

// readOpAccountID returns the (value, isNull) of operations.account_id for opID.
func readOpAccountID(ctx context.Context, t *testing.T, pool *pgxpool.Pool, opID string) (val string, isNull bool) {
	t.Helper()
	var acc *string
	err := pool.QueryRow(ctx,
		`SELECT account_id FROM kacho_iam.operations WHERE id = $1`, opID).Scan(&acc)
	require.NoError(t, err, "read op account_id")
	if acc == nil {
		return "", true
	}
	return *acc, false
}

func TestMigration0017_BackfillsProjectAccountOpsByResourceID(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	dsn := pg.NewTestPostgres(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	accID, _ := seedAcctUser0017(ctx, t, pool, "p")

	// A project owned by accID.
	prjID := ids.NewID(domain.PrefixProject)
	_, err = pool.Exec(ctx, `
		INSERT INTO projects (id, account_id, name, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		prjID, accID, "bf-prj-"+prjID[len(prjID)-6:])
	require.NoError(t, err, "seed project")

	// pre-1.2 ops: one keyed by the project id, one by the account id.
	prjOpID := ids.NewID(domain.PrefixOperationIAM)
	accOpID := ids.NewID(domain.PrefixOperationIAM)
	insertNullAccountOp(ctx, t, pool, prjOpID, prjID)
	insertNullAccountOp(ctx, t, pool, accOpID, accID)

	applyBackfill0017(ctx, t, pool)

	// After backfill:
	//   - the project op derives account_id from projects.account_id,
	//   - the account op derives account_id from its own resource_id.
	got, isNull := readOpAccountID(ctx, t, pool, prjOpID)
	assert.False(t, isNull, "project op account_id must be backfilled (not NULL)")
	assert.Equal(t, accID, got, "project op account_id must equal projects.account_id")

	gotAcc, isNullAcc := readOpAccountID(ctx, t, pool, accOpID)
	assert.False(t, isNullAcc, "account op account_id must be backfilled (not NULL)")
	assert.Equal(t, accID, gotAcc, "account op account_id must equal its resource_id (the account itself)")
}

func TestMigration0017_BackfillsGroupServiceAccountUserOps(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	dsn := pg.NewTestPostgres(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	accID, userID := seedAcctUser0017(ctx, t, pool, "g")

	// group + service_account owned by accID.
	grpID := ids.NewID(domain.PrefixGroup)
	_, err = pool.Exec(ctx, `
		INSERT INTO groups (id, account_id, name, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		grpID, accID, "bf-grp-"+grpID[len(grpID)-6:])
	require.NoError(t, err, "seed group")

	svaID := ids.NewID(domain.PrefixServiceAccount)
	_, err = pool.Exec(ctx, `
		INSERT INTO service_accounts (id, account_id, name)
		VALUES ($1, $2, $3)`,
		svaID, accID, "bf-sva-"+svaID[len(svaID)-6:])
	require.NoError(t, err, "seed service_account")

	grpOpID := ids.NewID(domain.PrefixOperationIAM)
	svaOpID := ids.NewID(domain.PrefixOperationIAM)
	usrOpID := ids.NewID(domain.PrefixOperationIAM)
	insertNullAccountOp(ctx, t, pool, grpOpID, grpID)
	insertNullAccountOp(ctx, t, pool, svaOpID, svaID)
	insertNullAccountOp(ctx, t, pool, usrOpID, userID)

	applyBackfill0017(ctx, t, pool)

	for _, tc := range []struct{ name, opID string }{
		{"group op", grpOpID},
		{"service_account op", svaOpID},
		{"user op", usrOpID},
	} {
		got, isNull := readOpAccountID(ctx, t, pool, tc.opID)
		assert.False(t, isNull, "%s account_id must be backfilled (not NULL)", tc.name)
		assert.Equal(t, accID, got, "%s account_id must equal the resource's account_id", tc.name)
	}
}

func TestMigration0017_LeavesCategoryIIAndUnknownResourceOpsNull(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	dsn := pg.NewTestPostgres(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// category-II resource ids (role / access_binding) have no owning-account
	// join column → must stay NULL. Also an op with a resource_id that joins
	// nothing (dangling) and an op with NULL resource_id stay NULL.
	roleOpID := ids.NewID(domain.PrefixOperationIAM)
	acbOpID := ids.NewID(domain.PrefixOperationIAM)
	danglingOpID := ids.NewID(domain.PrefixOperationIAM)
	insertNullAccountOp(ctx, t, pool, roleOpID, ids.NewID(domain.PrefixRole))
	insertNullAccountOp(ctx, t, pool, acbOpID, ids.NewID(domain.PrefixAccessBinding))
	insertNullAccountOp(ctx, t, pool, danglingOpID, ids.NewID(domain.PrefixProject)) // no such project row

	// op with NULL resource_id (e.g. an Internal-only op) stays NULL.
	nullResOpID := ids.NewID(domain.PrefixOperationIAM)
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.operations (id, description, done, resource_id, account_id)
		VALUES ($1, 'no-resource op', true, NULL, NULL)`, nullResOpID)
	require.NoError(t, err)

	applyBackfill0017(ctx, t, pool)

	for _, opID := range []string{roleOpID, acbOpID, danglingOpID, nullResOpID} {
		_, isNull := readOpAccountID(ctx, t, pool, opID)
		assert.True(t, isNull, "category-II / dangling / no-resource op %s must stay account_id NULL", opID)
	}
}

func TestMigration0017_DoesNotOverwriteAlreadyStampedAccountID(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	dsn := pg.NewTestPostgres(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// account A owns the project, but the op was already stamped with a DIFFERENT
	// (correct-at-write-time) account_id. The backfill only fills NULLs, so it
	// MUST NOT overwrite the existing value (WHERE account_id IS NULL guard).
	accA, _ := seedAcctUser0017(ctx, t, pool, "a")

	prjID := ids.NewID(domain.PrefixProject)
	_, err = pool.Exec(ctx, `
		INSERT INTO projects (id, account_id, name, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		prjID, accA, "bf-prj-"+prjID[len(prjID)-6:])
	require.NoError(t, err)

	const stamped = "acc00000000already01"
	opID := ids.NewID(domain.PrefixOperationIAM)
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.operations (id, description, done, resource_id, account_id)
		VALUES ($1, 'already stamped', true, $2, $3)`,
		opID, prjID, stamped)
	require.NoError(t, err)

	applyBackfill0017(ctx, t, pool)

	got, isNull := readOpAccountID(ctx, t, pool, opID)
	require.False(t, isNull)
	assert.Equal(t, stamped, got, "backfill must NOT overwrite an already-stamped account_id")
}
