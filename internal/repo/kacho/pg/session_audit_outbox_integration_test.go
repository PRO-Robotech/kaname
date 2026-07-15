// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// session_audit_outbox_integration_test.go — session slice. Durable
// audit_outbox emit on session revoke / revoke-all /
// force-logout, atomically with the revocation write.
//
// The session/force-logout revoke path is a SINGLE-STATEMENT pool-scoped
// adapter today (no caller-tx). Per the acceptance doc, atomic audit requires
// wrapping revocation + audit-INSERT in ONE tx (commit-together-or-rollback-
// together, запрет #10). The SessionRevocationsAdapter is extended with
// tx-scoped variants (RevokeTx / RevokeAllUserTokensTx) that emit the audit row
// in the same tx as the revocation.
//
// Covered behaviour (session slice):
//   - RevokeTx (single jti) → one iam.session.revoked, payload carries
//     subjectId/reason/tokenJti/actor, NO token secret.
//   - RevokeAllUserTokensTx → one iam.session.all_revoked.
//   - ForceLogout path (RevokeAllUserTokensTx, force-logout event_type) →
//     one iam.session.force_logout.
//   - commit-together: a committed revocation always has its audit row.
//   - rollback-no-orphan: a rolled-back tx leaves neither revocation nor
//     audit row.
//   - no-secrets: payload carries only tokenJti (identifier), no token.
//   - 22-char id guard: id matches ^evt_…{20,30}$ and reads back.
//   - concurrent idempotent upsert of the same jti → audit count equals
//     the number of committed upsert tx (emit-per-committed-change), no orphan.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

var sessionEvtIDRe = regexp.MustCompile(`^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$`)

func countAuditByEventAndSubject(ctx context.Context, t *testing.T, pool *pgxpool.Pool, eventType, subjectID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.audit_outbox
		  WHERE event_type = $1 AND event_payload->>'subject_id' = $2`,
		eventType, subjectID).Scan(&n))
	return n
}

func readOneAudit(ctx context.Context, t *testing.T, pool *pgxpool.Pool, eventType, subjectID string) (id, status, payloadRaw string) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id, status, event_payload::text FROM kacho_iam.audit_outbox
		  WHERE event_type = $1 AND event_payload->>'subject_id' = $2`,
		eventType, subjectID).Scan(&id, &status, &payloadRaw))
	return id, status, payloadRaw
}

// ── 5.2-03 RevokeTx (single jti) emits iam.session.revoked ─────────────────────

func TestSessionAudit_5_2_03_RevokeJtiEmits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	adapter := kachopg.NewSessionRevocationsAdapter(pool)
	admin := mustSeedUser(t, ctx, pool, "ssn03adm")
	target := mustSeedUser(t, ctx, pool, "ssn03tgt")
	jti := "jti-5203-" + string(target)

	rev := domain.SessionRevocation{
		TokenJTI:     jti,
		RevokedAt:    time.Now().UTC(),
		Reason:       "compromised",
		UserID:       target,
		TTLExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	require.NoError(t, adapter.RevokeTx(ctx, rev, admin))

	require.Equal(t, 1, countAuditByEventAndSubject(ctx, t, pool, "iam.session.revoked", string(target)),
		"single-jti revoke must emit exactly one iam.session.revoked row")

	id, status, payloadRaw := readOneAudit(ctx, t, pool, "iam.session.revoked", string(target))
	require.Regexp(t, sessionEvtIDRe, id, "audit id must match the 22-char evt_ format (#126 guard)")
	require.Equal(t, "pending", status)

	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(payloadRaw), &payload))
	require.Equal(t, string(target), payload["subject_id"])
	require.Equal(t, string(admin), payload["actor"], "actor sourced from revoked_by principal")
	require.Equal(t, "compromised", payload["reason"])
	require.Equal(t, jti, payload["token_jti"], "tokenJti identifier carried (not the token itself)")

	// The revocation row must also exist (commit-together, 5.2-34).
	revoked, err := adapter.IsRevoked(ctx, jti)
	require.NoError(t, err)
	require.True(t, revoked, "the session_revocations row must be committed alongside the audit row")
}

// ── 5.2-04 RevokeAllUserTokensTx emits iam.session.all_revoked ─────────────────

func TestSessionAudit_5_2_04_RevokeAllEmits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	adapter := kachopg.NewSessionRevocationsAdapter(pool)
	admin := mustSeedUser(t, ctx, pool, "ssn04adm")
	target := mustSeedUser(t, ctx, pool, "ssn04tgt")

	require.NoError(t, adapter.RevokeAllUserTokensTx(ctx,
		target, time.Now().UTC(), "admin-revoke", admin, "iam.session.all_revoked"))

	require.Equal(t, 1, countAuditByEventAndSubject(ctx, t, pool, "iam.session.all_revoked", string(target)),
		"revoke-all must emit exactly one iam.session.all_revoked row")

	_, _, payloadRaw := readOneAudit(ctx, t, pool, "iam.session.all_revoked", string(target))
	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(payloadRaw), &payload))
	require.Equal(t, string(target), payload["subject_id"])
	require.Equal(t, string(admin), payload["actor"])
	require.Equal(t, "admin-revoke", payload["reason"])

	// Cutoff row must be committed (commit-together).
	_, found, err := adapter.UserRevokedBefore(ctx, string(target))
	require.NoError(t, err)
	require.True(t, found, "the user_token_revocations cutoff must be committed with the audit row")
}

// ── 5.2-05 ForceLogout path emits iam.session.force_logout ─────────────────────

func TestSessionAudit_5_2_05_ForceLogoutEmits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	adapter := kachopg.NewSessionRevocationsAdapter(pool)
	admin := mustSeedUser(t, ctx, pool, "ssn05adm")
	target := mustSeedUser(t, ctx, pool, "ssn05tgt")

	require.NoError(t, adapter.RevokeAllUserTokensTx(ctx,
		target, time.Now().UTC(), "admin-force-logout", admin, "iam.session.force_logout"))

	require.Equal(t, 1, countAuditByEventAndSubject(ctx, t, pool, "iam.session.force_logout", string(target)),
		"force-logout must emit exactly one iam.session.force_logout row")
	id, _, payloadRaw := readOneAudit(ctx, t, pool, "iam.session.force_logout", string(target))
	require.Regexp(t, sessionEvtIDRe, id)
	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(payloadRaw), &payload))
	require.Equal(t, string(admin), payload["actor"])
	require.Equal(t, string(target), payload["subject_id"])
}

// ── 5.2-35 rollback-no-orphan (session) ───────────────────────────────────────
//
// A RevokeTx whose tx is forced to fail (duplicate audit id via a poisoned
// generator is not available; instead we use a context-cancel after the
// revocation write but before commit by driving a closed pool). Simpler and
// deterministic: drive RevokeTx with a cancelled context — the tx never commits,
// so neither the revocation nor the audit row is visible.
func TestSessionAudit_5_2_35_RollbackNoOrphan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	adapter := kachopg.NewSessionRevocationsAdapter(pool)
	admin := mustSeedUser(t, ctx, pool, "ssn35adm")
	target := mustSeedUser(t, ctx, pool, "ssn35tgt")
	jti := "jti-5235-" + string(target)

	cancelled, cancel := context.WithCancel(ctx)
	cancel() // tx will fail to begin/commit

	rev := domain.SessionRevocation{
		TokenJTI:     jti,
		RevokedAt:    time.Now().UTC(),
		Reason:       "compromised",
		UserID:       target,
		TTLExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	err = adapter.RevokeTx(cancelled, rev, admin)
	require.Error(t, err, "a cancelled tx must surface an error, not a silent commit")

	require.Equal(t, 0, countAuditByEventAndSubject(ctx, t, pool, "iam.session.revoked", string(target)),
		"rolled-back revoke must leave no orphan audit row")
	revoked, err := adapter.IsRevoked(ctx, jti)
	require.NoError(t, err)
	require.False(t, revoked, "rolled-back revoke must leave no revocation row")
}

// ── 5.2-36 no-secrets-in-payload (session) ────────────────────────────────────

func TestSessionAudit_5_2_36_NoSecretsInPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	adapter := kachopg.NewSessionRevocationsAdapter(pool)
	admin := mustSeedUser(t, ctx, pool, "ssn36adm")
	target := mustSeedUser(t, ctx, pool, "ssn36tgt")
	jti := "jti-5236-" + string(target)

	require.NoError(t, adapter.RevokeTx(ctx, domain.SessionRevocation{
		TokenJTI:     jti,
		RevokedAt:    time.Now().UTC(),
		Reason:       "compromised",
		UserID:       target,
		TTLExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}, admin))

	_, _, payloadRaw := readOneAudit(ctx, t, pool, "iam.session.revoked", string(target))
	// Disallowed secret-bearing keys/markers must not appear.
	for _, banned := range []string{"privateKeyPem", "private_key", "BEGIN", "PRIVATE KEY",
		"client_secret", "access_token", "refresh_token", "password"} {
		require.NotContains(t, payloadRaw, banned,
			"audit payload must not contain secret material (%q)", banned)
	}
	// Allowed identifier is present.
	require.Contains(t, payloadRaw, jti, "tokenJti identifier is allowed and present")
}

// ── 5.2-42 concurrent idempotent upsert → deterministic audit count ───────────

func TestSessionAudit_5_2_42_ConcurrentRevokeAuditCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	adapter := kachopg.NewSessionRevocationsAdapter(pool)
	admin := mustSeedUser(t, ctx, pool, "ssn42adm")
	target := mustSeedUser(t, ctx, pool, "ssn42tgt")
	jti := "jti-5242-" + string(target)

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			errs[i] = adapter.RevokeTx(ctx, domain.SessionRevocation{
				TokenJTI:     jti, // SAME jti — ON CONFLICT DO UPDATE upsert path
				RevokedAt:    time.Now().UTC(),
				Reason:       fmt.Sprintf("compromised-%d", i),
				UserID:       target,
				TTLExpiresAt: time.Now().UTC().Add(24 * time.Hour),
			}, admin)
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		require.NoError(t, e, "concurrent idempotent upsert #%d must succeed (no race error)", i)
	}

	// Each committed upsert tx emits one audit row (emit-per-committed-change).
	// All n upserts commit (idempotent ON CONFLICT DO UPDATE), so n audit rows
	// — every one atomic with its upsert tx, none orphaned.
	require.Equal(t, n, countAuditByEventAndSubject(ctx, t, pool, "iam.session.revoked", string(target)),
		"audit count must equal the number of committed upsert transactions")
}
