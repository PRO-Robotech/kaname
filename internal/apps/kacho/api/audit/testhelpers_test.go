// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package audit_test

// testhelpers_test.go — shared
// database + seed + audit-assert helpers for the durable audit_outbox
// emit-on-CRUD integration tests (Account / Project / User / ServiceAccount /
// Group / Role Create / Update / Delete).
//
// One package (`audit_test`) drives all six resource use-cases through their
// real Execute → operations.Run worker → writer-tx, then reads back the
// kacho_iam.audit_outbox rows. Centralising the setup helper here avoids
// duplicating setupTestDB across six packages.
//
// The Postgres itself is one per test BINARY (testmain_pgtest_test.go); each
// caller of setupTestDB still gets its own database.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
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

// setupTestDB hands the calling test its OWN database, with kacho_iam on the
// search path.
//
// It used to start a fresh container and replay the whole migration chain on
// every call. The database now comes from the one container this test binary
// owns (wired in testmain_pgtest_test.go), cloned from a template migrated once
// — see internal/pgtest for why a clone is the same isolation a separate
// container gave.
func setupTestDB(t testing.TB) string {
	t.Helper()
	return pgtest.NewDB(t)
}

// withPrincipal returns a ctx carrying the given user principal (the verified
// caller identity the use-cases stamp into the audit row's actor).
func withPrincipal(uid domain.UserID) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: string(uid), DisplayName: string(uid)})
}

// seedUserAccount inserts a user + an owning account (the user owns the account)
// and returns both ids. The user is the account owner so owner-gated CRUD
// (Update/Delete) authorises with the principal == owner path — the relation model
// is not asked at all, which is why these fixtures need no grants.
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
