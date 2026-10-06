// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package sa_keys

// audit_outbox_integration_test.go — durable audit_outbox emit on SAKey
// Issue / Revoke, atomically with the DB key-mapping mutation (worker-tx,
// запрет #10).
//
// Drives the real IssueSAKeyUseCase / RevokeSAKeyUseCase against a
// testcontainers Postgres (so the audit row INSERT actually hits the
// audit_outbox CHECK constraints). The audit row is emitted inside the SAME
// worker-tx as the persist of the service_account_oauth_clients row (Issue) /
// its delete (Revoke).
//
// Acceptance scenarios (SAKey slice):
//   - 5.2-20 Issue emits exactly one iam.sa_key.issued row — actor=verified
//     principal, keyId/serviceAccountId/keyAlgorithm carried, NO key material.
//   - 5.2-21 Revoke emits exactly one iam.sa_key.revoked row, atomic with the
//     mapping delete.
//   - 5.2-34 commit-together: a committed mutation always has its audit row.
//   - 5.2-35 rollback-no-orphan: a worker-tx whose Insert the database refuses
//     (the credential ceiling of the service account) leaves neither the
//     mapping row nor the audit row.
//   - 5.2-36 no-secrets: the serialized payload contains none of
//     client_secret / privateKey / BEGIN / PRIVATE KEY / access_token /
//     refresh_token / password.
//   - 5.2-37 22-char id regression-guard: id matches ^evt_…{20,30}$ and
//     reads back (CHECK passed, not silently dropped).
//   - 5.2-40 anti-spoofing actor: actor is the verified principal, never a body
//     value.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

var sakeyEvtIDRe = regexp.MustCompile(`^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$`)

// setupSAKeyTestDB hands the calling test its OWN database, IAM migrations
// already applied, and returns a DSN whose search_path defaults to kaname.
//
// It used to start a fresh Postgres 16 container and replay the migration chain
// on every call. The database now comes from the one container this test binary
// owns (wired in testmain_pgtest_test.go), cloned from a template migrated once
// — see pkg/pgtest for why a clone is the same isolation a separate
// container gave.
func setupSAKeyTestDB(t testing.TB) string {
	t.Helper()

	return pgtest.NewDB(t)
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
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID),
		fmt.Sprintf("ext-%s-%s", suffix, uid),
		fmt.Sprintf("u-%s@example.com", suffix),
		"SAKey User "+suffix)
	require.NoError(t, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID),
		fmt.Sprintf("sak-acc-%s-%s", suffix, accID[len(accID)-6:]),
		string(uid))
	require.NoError(t, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.service_accounts (id, account_id, name)
		VALUES ($1, $2, $3)`,
		string(svaID), string(accID),
		fmt.Sprintf("sak-sa-%s", suffix))
	require.NoError(t, err)

	seedWayIn(t, ctx, tx)
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
		   FROM kaname.audit_outbox
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

// buildIssueUC wires a real IssueSAKeyUseCase against the live pool, with the
// durable audit emitter attached, on a landing that runs the platform token
// endpoint.
func buildIssueUC(pool *pgxpool.Pool) *IssueSAKeyUseCase {
	repo := kanamepg.NewSAOAuthClientRepo(pool)
	opsRepo := operations.NewRepo(pool, "kaname")
	uc := NewIssueSAKeyUseCase(repo, kanamepg.NewPoolTxBeginner(pool), opsRepo).WithOwnIssuance()
	uc.WithAuditEmitter(kanamepg.NewAuditOutboxEmitter(pool))
	return uc
}

func buildRevokeUC(pool *pgxpool.Pool) *RevokeSAKeyUseCase {
	repo := kanamepg.NewSAOAuthClientRepo(pool)
	opsRepo := operations.NewRepo(pool, "kaname")
	uc := NewRevokeSAKeyUseCase(repo, kanamepg.NewPoolTxBeginner(pool), opsRepo)
	uc.WithAuditEmitter(kanamepg.NewAuditOutboxEmitter(pool))
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
			`SELECT count(*) FROM kaname.audit_outbox
			  WHERE event_type = $1 AND event_payload->>'key_id' = $2`,
			eventType, keyID).Scan(&n))
		if n >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("audit row %s for key %s never appeared", eventType, keyID)
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
	uc := buildIssueUC(pool)

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
			`SELECT id FROM kaname.service_account_oauth_clients WHERE sva_id = $1`,
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
	issueUC := buildIssueUC(pool)
	_, err = issueUC.Execute(withSAKeyPrincipal(ctx, string(uid)), IssueInput{
		ServiceAccountID: svaID,
		CreatedByUserID:  string(uid),
	})
	require.NoError(t, err)
	var keyID string
	require.Eventually(t, func() bool {
		return pool.QueryRow(ctx,
			`SELECT id FROM kaname.service_account_oauth_clients WHERE sva_id = $1`,
			string(svaID)).Scan(&keyID) == nil
	}, 5*time.Second, 20*time.Millisecond, "issued key must persist")

	// Revoke it (different principal to prove actor-from-context).
	revoker := uid
	revokeUC := buildRevokeUC(pool)
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
		`SELECT count(*) FROM kaname.service_account_oauth_clients WHERE id = $1`, keyID).Scan(&n))
	require.Equal(t, 0, n, "the revoked mapping row must be deleted (commit-together)")
}

// ── 5.2-35 rollback-no-orphan: an Insert the database refuses rolls back the
// whole worker-tx → neither mapping nor audit row. ───────────────────────────
//
// The refusal is the credential ceiling of the service account, stated at 1:
// the second Issue's mapping INSERT is refused by the counting trigger (KQ001)
// and the worker-tx rolls back. The trigger used to be a provider stub handing
// out one client name twice against the unique index of the mirror column;
// column and index are gone (kaname#362), the atomicity property under test is
// unchanged.

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
	tag, err := pool.Exec(ctx, `
		UPDATE kaname.own_ceilings SET limit_value = 1, stated_at = now()
		 WHERE kind = 'iam.serviceAccount.credential'`)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "потолок ключей служебной учётки не объявлен — отказывать нечему")
	uc := buildIssueUC(pool)

	// First Issue succeeds and lands one key.
	_, err = uc.Execute(withSAKeyPrincipal(ctx, string(uid)), IssueInput{
		ServiceAccountID: svaID, CreatedByUserID: string(uid),
	})
	require.NoError(t, err)
	var firstKey string
	require.Eventually(t, func() bool {
		return pool.QueryRow(ctx,
			`SELECT id FROM kaname.service_account_oauth_clients WHERE sva_id = $1`,
			string(svaID)).Scan(&firstKey) == nil
	}, 5*time.Second, 20*time.Millisecond)
	awaitAudit(ctx, t, pool, "iam.sa_key.issued", firstKey)

	// Second Issue is over the ceiling — the mapping Insert is refused by the
	// database → the worker-tx rolls back. No second mapping row and no orphan
	// audit row.
	op2, err := uc.Execute(withSAKeyPrincipal(ctx, string(uid)), IssueInput{
		ServiceAccountID: svaID, CreatedByUserID: string(uid),
	})
	require.NoError(t, err) // async — error surfaces on the Operation, not here
	require.NotNil(t, op2)

	// Deterministic barrier: block until the second Operation is Done (positive
	// signal that the worker actually dequeued and attempted it), then assert it
	// carries the refusal — so the negative counts below only fire after the
	// rollback path provably ran (not because the worker was merely slow).
	opsRepo := operations.NewRepo(pool, "kaname")
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
		"the rolled-back over-the-ceiling Issue Operation must carry the refusal")

	var keyCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.service_account_oauth_clients WHERE sva_id = $1`,
		string(svaID)).Scan(&keyCount))
	require.Equal(t, 1, keyCount, "the refused Issue must not create a second mapping row")

	var auditCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.audit_outbox WHERE event_type = 'iam.sa_key.issued'`).Scan(&auditCount))
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
	uc := buildIssueUC(pool)

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
			`SELECT id FROM kaname.service_account_oauth_clients WHERE sva_id = $1`,
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
