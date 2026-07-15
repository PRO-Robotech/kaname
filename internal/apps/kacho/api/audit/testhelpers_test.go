// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package audit_test

// testhelpers_test.go — shared
// testcontainers + seed + audit-assert helpers for the durable audit_outbox
// emit-on-CRUD integration tests (Account / Project / User / ServiceAccount /
// Group / Role Create / Update / Delete).
//
// One package (`audit_test`) drives all six resource use-cases through their
// real Execute → operations.Run worker → writer-tx, then reads back the
// kacho_iam.audit_outbox rows. Centralising the testcontainers helper here
// avoids duplicating setupTestDB across six packages.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// evtIDFormat — the audit_outbox_id_check shape (bug #126 regression-guard:
// 22-char body, NOT the 17-char NewKac127ID).
var evtIDFormat = regexp.MustCompile(`^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$`)

// testEnv bundles the per-test Postgres pool + repo + ops repo wired against a
// fresh testcontainers DB.
type testEnv struct {
	pool    *pgxpool.Pool
	repo    *kachopg.Repository
	opsRepo operations.Repo
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return &testEnv{
		pool:    pool,
		repo:    kachopg.New(pool, nil),
		opsRepo: operations.NewRepo(pool, "kacho_iam"),
	}
}

// awaitWorkers blocks until all async operation workers spawned by the
// use-cases under test have finished (deterministic LRO wait — no time.Sleep).
func awaitWorkers(t *testing.T) {
	t.Helper()
	require.NoError(t, operations.Wait(context.Background()))
}

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

// withPrincipal returns a ctx carrying the given user principal (the verified
// caller identity the use-cases stamp into the audit row's actor).
func withPrincipal(uid domain.UserID) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: string(uid), DisplayName: string(uid)})
}

// seedUserAccount inserts a user + an owning account (the user owns the account)
// and returns both ids. The user is the account owner so owner-gated CRUD
// (Update/Delete) authorises with the principal == owner path (no OpenFGA).
func seedUserAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (domain.UserID, domain.AccountID) {
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
		"Audit User "+suffix)
	require.NoError(t, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID),
		fmt.Sprintf("aud-acc-%s-%s", suffix, accID[len(accID)-6:]),
		string(uid))
	require.NoError(t, err)

	require.NoError(t, tx.Commit(ctx))
	return uid, accID
}

// seedExtraUser inserts a standalone user (used as a group member / target)
// without an owning account.
func seedExtraUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID domain.AccountID, suffix string) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID),
		fmt.Sprintf("extra-%s-%s", suffix, uid),
		fmt.Sprintf("extra-%s@example.com", suffix),
		"Extra User "+suffix)
	require.NoError(t, err)
	return uid
}

// auditRow — one decoded audit_outbox row.
type auditRow struct {
	id        string
	eventType string
	status    string
	tenant    *string
	payload   map[string]any
	rawJSON   string
}

// auditRowsByEventResource returns rows whose event_type and payload resource_id
// match — scoped to the test's own row, ignoring seed/bootstrap rows.
func auditRowsByEventResource(ctx context.Context, t *testing.T, pool *pgxpool.Pool, eventType, resourceID string) []auditRow {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT id, event_type, status, tenant_account_id, event_payload::text
		   FROM kacho_iam.audit_outbox
		  WHERE event_type = $1 AND event_payload->>'resource_id' = $2
		  ORDER BY created_at ASC`,
		eventType, resourceID)
	require.NoError(t, err)
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var (
			r      auditRow
			tenant *string
		)
		require.NoError(t, rows.Scan(&r.id, &r.eventType, &r.status, &tenant, &r.rawJSON))
		require.NoError(t, json.Unmarshal([]byte(r.rawJSON), &r.payload))
		r.tenant = tenant
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

// countAuditByResource counts ALL audit rows for a resource id regardless of
// event_type (used by no-op / rollback assertions).
func countAuditByResource(ctx context.Context, t *testing.T, pool *pgxpool.Pool, resourceID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.audit_outbox WHERE event_payload->>'resource_id' = $1`,
		resourceID).Scan(&n))
	return n
}

// requireOneAuditRow asserts exactly one row, returns it.
func requireOneAuditRow(ctx context.Context, t *testing.T, pool *pgxpool.Pool, eventType, resourceID string) auditRow {
	t.Helper()
	rows := auditRowsByEventResource(ctx, t, pool, eventType, resourceID)
	require.Len(t, rows, 1, "expected exactly one %s audit row for %s", eventType, resourceID)
	return rows[0]
}
