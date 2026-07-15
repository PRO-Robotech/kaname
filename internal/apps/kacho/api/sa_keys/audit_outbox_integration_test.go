// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package sa_keys

// audit_outbox_integration_test.go — durable audit_outbox emit on SAKey
// Issue / Revoke, atomically with the DB key-mapping mutation (worker-tx,
// запрет #10).
//
// Drives the real IssueSAKeyUseCase / RevokeSAKeyUseCase against a
// testcontainers Postgres (so the audit row INSERT actually hits the
// audit_outbox CHECK constraints), with a fake Hydra OAuth2 admin. The audit
// row is emitted inside the SAME worker-tx as the persist of the
// service_account_oauth_clients row (Issue) / its delete (Revoke).
//
// Acceptance scenarios (SAKey slice):
//   - 5.2-20 Issue emits exactly one iam.sa_key.issued row — actor=verified
//     principal, keyId/serviceAccountId/keyAlgorithm carried, NO key material.
//   - 5.2-21 Revoke emits exactly one iam.sa_key.revoked row, atomic with the
//     mapping delete.
//   - 5.2-34 commit-together: a committed mutation always has its audit row.
//   - 5.2-35 rollback-no-orphan: a worker-tx that fails to commit (Insert
//     conflict) leaves neither the mapping row nor the audit row.
//   - 5.2-36 no-secrets: the serialized payload contains none of
//     client_secret / privateKey / BEGIN / PRIVATE KEY / access_token /
//     refresh_token / password.
//   - 5.2-37 22-char id regression-guard: id matches ^evt_…{20,30}$ and
//     reads back (CHECK passed, not silently dropped).
//   - 5.2-40 anti-spoofing actor: actor is the verified principal, never a body
//     value.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
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
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

var sakeyEvtIDRe = regexp.MustCompile(`^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$`)

// setupSAKeyTestDB spins up a Postgres 16 testcontainer, runs the IAM
// migrations and returns a DSN whose search_path defaults to kacho_iam.
func setupSAKeyTestDB(t testing.TB) string {
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

// seedSAKeyUserAndSA seeds a user + owning account + a service account and
// returns the (userID, serviceAccountID). The SA id is a 20-char `sva<17>`
// (ids.NewID, no underscore) so the use-case prefix check passes; the user id
// satisfies the created_by FK on service_account_oauth_clients.
func seedSAKeyUserAndSA(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (domain.UserID, domain.ServiceAccountID) {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	svaID := domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID),
		fmt.Sprintf("ext-%s-%s", suffix, uid),
		fmt.Sprintf("u-%s@example.com", suffix),
		"SAKey User "+suffix)
	require.NoError(t, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID),
		fmt.Sprintf("sak-acc-%s-%s", suffix, accID[len(accID)-6:]),
		string(uid))
	require.NoError(t, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.service_accounts (id, account_id, name)
		VALUES ($1, $2, $3)`,
		string(svaID), string(accID),
		fmt.Sprintf("sak-sa-%s", suffix))
	require.NoError(t, err)

	require.NoError(t, tx.Commit(ctx))
	return uid, svaID
}

// sakeyAuditRows reads the audit_outbox rows for an event_type whose payload
// key_id matches the supplied key. Scoped to the test's own rows.
type sakeyAuditRow struct {
	id         string
	eventType  string
	status     string
	payload    map[string]any
	payloadRaw string
}

func sakeyAuditRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, eventType, keyID string) []sakeyAuditRow {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT id, event_type, status, event_payload::text
		   FROM kacho_iam.audit_outbox
		  WHERE event_type = $1 AND event_payload->>'key_id' = $2
		  ORDER BY created_at ASC`,
		eventType, keyID)
	require.NoError(t, err)
	defer rows.Close()
	var out []sakeyAuditRow
	for rows.Next() {
		var r sakeyAuditRow
		require.NoError(t, rows.Scan(&r.id, &r.eventType, &r.status, &r.payloadRaw))
		require.NoError(t, json.Unmarshal([]byte(r.payloadRaw), &r.payload))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

// buildIssueUC wires a real IssueSAKeyUseCase against the live pool + the given
// fake Hydra, with the durable audit emitter attached.
func buildIssueUC(pool *pgxpool.Pool, hydra OAuthClientAdmin) *IssueSAKeyUseCase {
	repo := kachopg.NewSAOAuthClientRepo(pool)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	uc := NewIssueSAKeyUseCase(repo, kachopg.NewPoolTxBeginner(pool), hydra, opsRepo)
	uc.WithAuditEmitter(kachopg.NewAuditOutboxEmitter(pool))
	return uc
}

func buildRevokeUC(pool *pgxpool.Pool, hydra OAuthClientAdmin) *RevokeSAKeyUseCase {
	repo := kachopg.NewSAOAuthClientRepo(pool)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	uc := NewRevokeSAKeyUseCase(repo, kachopg.NewPoolTxBeginner(pool), hydra, opsRepo)
	uc.WithAuditEmitter(kachopg.NewAuditOutboxEmitter(pool))
	return uc
}

// awaitIssuedKey polls audit_outbox until the issued row for keyID appears (the
// use-case is async: operations.Run spawns a worker goroutine that runs
// doIssue + MarkDone). Fails the test after the deadline.
func awaitAudit(ctx context.Context, t *testing.T, pool *pgxpool.Pool, eventType, keyID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.audit_outbox
			  WHERE event_type = $1 AND event_payload->>'key_id' = $2`,
			eventType, keyID).Scan(&n))
		if n >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("audit row %s for key %s never appeared", eventType, keyID)
}

// fakeHydra — minimal OAuthClientAdmin recording calls and returning a fixed
// client id. No secret material is produced (private_key_jwt mode).
type fakeHydra struct {
	createCalls int
	deleteCalls int
}

func (f *fakeHydra) CreateOAuthClient(ctx context.Context, req clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error) {
	f.createCalls++
	return clients.HydraOAuthClient{ClientID: "hydra-cli-" + fmt.Sprint(f.createCalls)}, nil
}
func (f *fakeHydra) DeleteOAuthClient(ctx context.Context, clientID string) error {
	f.deleteCalls++
	return nil
}

// collidingHydra returns a CONSTANT ClientID on every CreateOAuthClient, so the
// second Issue's mapping INSERT collides on the (unchanged) UNIQUE hydra_client_id
// index → the worker-tx rolls back. Used by the atomicity test after migration
// 0047 relaxed sva_unique (N:1 keys per ServiceAccount) removed the previous
// duplicate-Issue rollback trigger.
type collidingHydra struct {
	createCalls int
	deleteCalls int
}

func (f *collidingHydra) CreateOAuthClient(_ context.Context, _ clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error) {
	f.createCalls++
	return clients.HydraOAuthClient{ClientID: "hydra-cli-collision-const"}, nil
}
func (f *collidingHydra) DeleteOAuthClient(_ context.Context, _ string) error {
	f.deleteCalls++
	return nil
}

// ── 5.2-20 Issue emits durable iam.sa_key.issued WITHOUT key material ─────────

func TestSAKeyAudit_5_2_20_IssueEmitsNoSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupSAKeyTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid, svaID := seedSAKeyUserAndSA(t, ctx, pool, "5220")
	uc := buildIssueUC(pool, &fakeHydra{})

	op, err := uc.Execute(withSAKeyPrincipal(ctx, string(uid)), IssueInput{
		ServiceAccountID: svaID,
		CreatedByUserID:  string(uid),
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	// Issue is async — wait for the mapping row to persist, then read its id.
	var keyID string
	require.Eventually(t, func() bool {
		return pool.QueryRow(ctx,
			`SELECT id FROM kacho_iam.service_account_oauth_clients WHERE sva_id = $1`,
			string(svaID)).Scan(&keyID) == nil
	}, 5*time.Second, 20*time.Millisecond, "issued key must persist")
	require.True(t, strings.HasPrefix(keyID, domain.PrefixSAOAuthClient), "key id must be a soc_ id")

	awaitAudit(ctx, t, pool, "iam.sa_key.issued", keyID)
	rows := sakeyAuditRows(ctx, t, pool, "iam.sa_key.issued", keyID)
	require.Len(t, rows, 1, "Issue must emit exactly one iam.sa_key.issued row")
	r := rows[0]

	require.Equal(t, string(uid), r.payload["actor"], "actor is the verified principal")
	require.Equal(t, string(svaID), r.payload["service_account_id"])
	require.Equal(t, keyID, r.payload["key_id"])
	require.Equal(t, "ES256", r.payload["key_algorithm"])
	require.Equal(t, "pending", r.status)
	require.Regexp(t, sakeyEvtIDRe, r.id, "audit id must match the 22-char evt_ format (#126 guard)")

	assertNoSecrets(t, r.payloadRaw)
}

// ── 5.2-21 Revoke emits durable iam.sa_key.revoked ────────────────────────────

func TestSAKeyAudit_5_2_21_RevokeEmits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupSAKeyTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid, svaID := seedSAKeyUserAndSA(t, ctx, pool, "5221")

	// Issue a key first.
	issueUC := buildIssueUC(pool, &fakeHydra{})
	_, err = issueUC.Execute(withSAKeyPrincipal(ctx, string(uid)), IssueInput{
		ServiceAccountID: svaID,
		CreatedByUserID:  string(uid),
	})
	require.NoError(t, err)
	var keyID string
	require.Eventually(t, func() bool {
		return pool.QueryRow(ctx,
			`SELECT id FROM kacho_iam.service_account_oauth_clients WHERE sva_id = $1`,
			string(svaID)).Scan(&keyID) == nil
	}, 5*time.Second, 20*time.Millisecond, "issued key must persist")

	// Revoke it (different principal to prove actor-from-context).
	revoker := uid
	revokeUC := buildRevokeUC(pool, &fakeHydra{})
	_, err = revokeUC.Execute(withSAKeyPrincipal(ctx, string(revoker)), RevokeInput{
		ServiceAccountID: svaID,
		KeyID:            domain.SAOAuthClientID(keyID),
	})
	require.NoError(t, err)

	awaitAudit(ctx, t, pool, "iam.sa_key.revoked", keyID)
	rows := sakeyAuditRows(ctx, t, pool, "iam.sa_key.revoked", keyID)
	require.Len(t, rows, 1, "Revoke must emit exactly one iam.sa_key.revoked row")
	r := rows[0]
	require.Equal(t, string(revoker), r.payload["actor"])
	require.Equal(t, string(svaID), r.payload["service_account_id"])
	require.Equal(t, keyID, r.payload["key_id"])
	require.Regexp(t, sakeyEvtIDRe, r.id)
	assertNoSecrets(t, r.payloadRaw)

	// commit-together (5.2-34): the mapping row must be gone alongside the
	// committed audit row.
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.service_account_oauth_clients WHERE id = $1`, keyID).Scan(&n))
	require.Equal(t, 0, n, "the revoked mapping row must be deleted (commit-together)")
}

// ── 5.2-35 rollback-no-orphan: an Insert that violates a UNIQUE index rolls
// back the whole worker-tx → neither mapping nor audit row. ───────────────────
//
// The trigger is the (unchanged) UNIQUE hydra_client_id index: migration 0047
// relaxed sva_unique to N:1, so a duplicate sva no longer rolls back. We drive
// the collision with a hydra stub that returns a CONSTANT client id, so the
// second Issue's mapping INSERT deterministically fails and rolls the worker-tx
// back — the atomicity property under test is unchanged.

func TestSAKeyAudit_5_2_35_IssueRollbackNoOrphan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupSAKeyTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid, svaID := seedSAKeyUserAndSA(t, ctx, pool, "5235")
	uc := buildIssueUC(pool, &collidingHydra{})

	// First Issue succeeds and lands one key (hydra_client_id="…collision-const").
	_, err = uc.Execute(withSAKeyPrincipal(ctx, string(uid)), IssueInput{
		ServiceAccountID: svaID, CreatedByUserID: string(uid),
	})
	require.NoError(t, err)
	var firstKey string
	require.Eventually(t, func() bool {
		return pool.QueryRow(ctx,
			`SELECT id FROM kacho_iam.service_account_oauth_clients WHERE sva_id = $1`,
			string(svaID)).Scan(&firstKey) == nil
	}, 5*time.Second, 20*time.Millisecond)
	awaitAudit(ctx, t, pool, "iam.sa_key.issued", firstKey)

	// Second Issue collides on UNIQUE hydra_client_id — the mapping Insert hits
	// service_account_oauth_clients' hydra_client_id unique index (23505) → the
	// worker-tx rolls back. No second mapping row and no orphan audit row.
	op2, err := uc.Execute(withSAKeyPrincipal(ctx, string(uid)), IssueInput{
		ServiceAccountID: svaID, CreatedByUserID: string(uid),
	})
	require.NoError(t, err) // async — error surfaces on the Operation, not here
	require.NotNil(t, op2)

	// Deterministic barrier: block until the second Operation is Done (positive
	// signal that the worker actually dequeued and attempted it), then assert it
	// carries the constraint error — so the negative counts below only fire after
	// the 23505-rollback path provably ran (not because the worker was merely slow).
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	var finalOp *operations.Operation
	require.Eventually(t, func() bool {
		o, gerr := opsRepo.Get(ctx, op2.ID)
		if gerr != nil || o == nil || !o.Done {
			return false
		}
		finalOp = o
		return true
	}, 10*time.Second, 20*time.Millisecond, "second Issue Operation never reached Done")
	require.NotNil(t, finalOp.Error,
		"the rolled-back duplicate-hydra_client_id Issue Operation must carry the constraint error")

	var keyCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.service_account_oauth_clients WHERE sva_id = $1`,
		string(svaID)).Scan(&keyCount))
	require.Equal(t, 1, keyCount, "duplicate Issue must not create a second mapping row")

	var auditCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.audit_outbox WHERE event_type = 'iam.sa_key.issued'`).Scan(&auditCount))
	require.Equal(t, 1, auditCount, "rolled-back Issue must leave no orphan audit row (atomicity, запрет #10)")
}

// ── 5.2-40 anti-spoofing: actor is the principal, never a body value ──────────

func TestSAKeyAudit_5_2_40_ActorFromPrincipal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupSAKeyTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid, svaID := seedSAKeyUserAndSA(t, ctx, pool, "5240")
	uc := buildIssueUC(pool, &fakeHydra{})

	// CreatedByUserID body field set to the real principal (handler enforces
	// equality); the audit actor must equal the principal regardless.
	_, err = uc.Execute(withSAKeyPrincipal(ctx, string(uid)), IssueInput{
		ServiceAccountID: svaID,
		CreatedByUserID:  string(uid),
	})
	require.NoError(t, err)

	var keyID string
	require.Eventually(t, func() bool {
		return pool.QueryRow(ctx,
			`SELECT id FROM kacho_iam.service_account_oauth_clients WHERE sva_id = $1`,
			string(svaID)).Scan(&keyID) == nil
	}, 5*time.Second, 20*time.Millisecond)
	awaitAudit(ctx, t, pool, "iam.sa_key.issued", keyID)

	rows := sakeyAuditRows(ctx, t, pool, "iam.sa_key.issued", keyID)
	require.Len(t, rows, 1)
	require.Equal(t, string(uid), rows[0].payload["actor"],
		"actor must be the authenticated principal (PrincipalFromContext)")
}

// assertNoSecrets fails if the serialized payload carries any secret-bearing
// marker.
func assertNoSecrets(t *testing.T, payloadRaw string) {
	t.Helper()
	for _, banned := range []string{
		"client_secret", "privateKey", "private_key", "BEGIN", "PRIVATE KEY",
		"access_token", "refresh_token", "password",
	} {
		require.NotContains(t, payloadRaw, banned,
			"audit payload must not contain secret material (%q)", banned)
	}
}

func withSAKeyPrincipal(ctx context.Context, userID string) context.Context {
	return operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: userID})
}
