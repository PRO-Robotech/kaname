// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// bootstrap_admin.go — startup-time bootstrap admin grant + fga_outbox enqueue.
//
// Flow:
//  1. Read env `KACHO_IAM_BOOTSTRAP_ROOT_EMAIL` (caller passes the value).
//  2. If empty — skip (no-op, log DEBUG).
//  3. Lookup user by email. Not found → log INFO + idempotent retry on next boot.
//  4. Found → atomic TX:
//     INSERT cluster_admin_grant (subject=user, granted_by='bootstrap')
//     INSERT fga_outbox (event_type='fga.tuple.write', payload={tuple})
//     INSERT audit_outbox (event_type='iam.cluster_admin.granted', payload={...})
//  5. SQLSTATE 23505 (UNIQUE on cluster_admin_grants_subject_unique) → graceful WARN
//     (concurrent HA cold-start; the winner already created the grant).
//  6. Other errors → return — fail-closed for unknown DB-state.
//
// HA-race-safety: 23505 → graceful skip. Idempotent re-run: 23505 → graceful
// skip (same code path).
package seed

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// BootstrapAdminInput — bootstrap-run parameters.
type BootstrapAdminInput struct {
	Email     string // KACHO_IAM_BOOTSTRAP_ROOT_EMAIL
	ClusterID string // domain.ClusterSingletonID by default
	NowFn     func() time.Time
}

// BootstrapAdminResult — bootstrap-run result (observability / tests).
type BootstrapAdminResult struct {
	Skipped       bool   // true if email empty or user not found
	SkipReason    string // 'email empty' | 'user not registered' | 'concurrent race (23505)'
	GrantID       string // id of the cluster_admin_grant created (when Skipped=false)
	FGAOutboxID   string // id of the enqueued fga_outbox row
	AuditOutboxID string // id of the enqueued audit_outbox row
	UserID        string // resolved user id
}

// RunBootstrapAdmin — execute the bootstrap flow.
//
// Pool — kacho-iam master pgxpool (post-migration). Logger — slog.Default-
// compatible. Returns nil error in all graceful-skip / happy / 23505-race
// cases; error only on unexpected DB-failure (fail-closed for unknown state).
func RunBootstrapAdmin(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, in BootstrapAdminInput) (BootstrapAdminResult, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if in.NowFn == nil {
		in.NowFn = func() time.Time { return time.Now().UTC() }
	}
	clusterID := in.ClusterID
	if clusterID == "" {
		clusterID = domain.ClusterSingletonID
	}

	email := strings.TrimSpace(in.Email)
	if email == "" {
		logger.DebugContext(ctx, "bootstrap admin: KACHO_IAM_BOOTSTRAP_ROOT_EMAIL not set, skipping")
		return BootstrapAdminResult{Skipped: true, SkipReason: "email empty"}, nil
	}

	// Step 1: Lookup user by email.
	var userID string
	err := pool.QueryRow(ctx,
		`SELECT id FROM users WHERE email = $1 LIMIT 1`, email).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		logger.InfoContext(ctx, "bootstrap admin user not registered yet, skipping cluster admin grant",
			slog.String("email", email))
		return BootstrapAdminResult{Skipped: true, SkipReason: "user not registered"}, nil
	}
	if err != nil {
		return BootstrapAdminResult{}, fmt.Errorf("bootstrap admin: lookup user by email: %w", err)
	}

	// Step 2: Atomic TX — cluster_admin_grant + fga_outbox + audit_outbox.
	now := in.NowFn()
	grantID := domain.NewKac127ID(domain.PrefixClusterAdminGrant)
	// fgaOutboxID is assigned on a successful INSERT in step 2b (bigserial id from RETURNING).
	var fgaOutboxID string
	auditOutboxID := newULIDLikeID(domain.PrefixAuditEvent + "_")

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return BootstrapAdminResult{}, fmt.Errorf("bootstrap admin: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // best-effort rollback on error path

	// 2a: cluster_admin_grant
	_, err = tx.Exec(ctx,
		`INSERT INTO cluster_admin_grants (id, cluster_id, subject_type, subject_id, granted_by, granted_at)
		 VALUES ($1, $2, 'user', $3, 'bootstrap', $4)`,
		grantID, clusterID, userID, now)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Idempotent / concurrent HA — winner already INSERTed.
			logger.WarnContext(ctx,
				"concurrent bootstrap detected, cluster admin grant already created by another instance",
				slog.String("email", email),
				slog.String("user_id", userID))
			return BootstrapAdminResult{Skipped: true, SkipReason: "concurrent race (23505)", UserID: userID}, nil
		}
		return BootstrapAdminResult{}, fmt.Errorf("bootstrap admin: insert cluster_admin_grant: %w", err)
	}

	// 2b: fga_outbox — tuple write for the FGA-tuple drainer.
	// fga_outbox schema (migration 0002): bigserial id, event_type, payload (jsonb).
	fgaPayload := map[string]any{
		"object":   "cluster:" + clusterID,
		"relation": "system_admin",
		"user":     "user:" + userID,
	}
	fgaBytes, err := json.Marshal(fgaPayload)
	if err != nil {
		return BootstrapAdminResult{}, fmt.Errorf("bootstrap admin: marshal fga payload: %w", err)
	}
	var fgaSerial int64
	err = tx.QueryRow(ctx,
		`INSERT INTO fga_outbox (event_type, payload, created_at)
		 VALUES ('fga.tuple.write', $1::jsonb, $2)
		 RETURNING id`,
		fgaBytes, now).Scan(&fgaSerial)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "42P01" || pgErr.Code == "42703") {
			logger.WarnContext(ctx,
				"fga_outbox schema not present; skipping FGA enqueue (next boot will retry)",
				slog.String("pg_code", pgErr.Code), slog.String("pg_msg", pgErr.Message))
			fgaOutboxID = ""
		} else {
			return BootstrapAdminResult{}, fmt.Errorf("bootstrap admin: insert fga_outbox: %w", err)
		}
	} else {
		fgaOutboxID = fmt.Sprintf("fga_%d", fgaSerial)
	}

	// 2c: audit_outbox — iam.cluster_admin.granted event.
	auditPayload := map[string]any{
		"grant_id":     grantID,
		"subject_type": "user",
		"subject_id":   userID,
		"cluster_id":   clusterID,
		"granted_by":   "bootstrap",
	}
	auditBytes, err := json.Marshal(auditPayload)
	if err != nil {
		return BootstrapAdminResult{}, fmt.Errorf("bootstrap admin: marshal audit payload: %w", err)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO audit_outbox (id, event_type, tenant_account_id,
		                            event_payload, status, attempts, created_at, next_attempt_at)
		 VALUES ($1, 'iam.cluster_admin.granted', NULL, $2::jsonb, 'pending', 0, $3, $3)`,
		auditOutboxID, auditBytes, now)
	if err != nil {
		return BootstrapAdminResult{}, fmt.Errorf("bootstrap admin: insert audit_outbox: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return BootstrapAdminResult{}, fmt.Errorf("bootstrap admin: commit tx: %w", err)
	}

	logger.InfoContext(ctx, "bootstrap admin: cluster admin grant + outbox enqueue committed",
		slog.String("email", email),
		slog.String("user_id", userID),
		slog.String("grant_id", grantID),
		slog.String("fga_outbox_id", fgaOutboxID),
		slog.String("audit_outbox_id", auditOutboxID),
	)

	return BootstrapAdminResult{
		Skipped:       false,
		GrantID:       grantID,
		FGAOutboxID:   fgaOutboxID,
		AuditOutboxID: auditOutboxID,
		UserID:        userID,
	}, nil
}

// newULIDLikeID — generates a ULID-like id (`<prefix><22-char crockford>`)
// for outbox tables. The audit_outbox / fga_outbox CHECK regex accepts a
// 20..30 char suffix.
func newULIDLikeID(prefix string) string {
	const crockford = "0123456789abcdefghjkmnpqrstvwxyz"
	const bodyLen = 22
	var raw [14]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("seed: crypto/rand failed: " + err.Error())
	}
	hi := binary.BigEndian.Uint64(raw[0:8])
	lo := binary.BigEndian.Uint64(raw[6:14])

	body := make([]byte, bodyLen)
	for i := 0; i < bodyLen; i++ {
		bitOff := uint(i*5) % 64 // #nosec G115 -- i is the bounded loop index [0,bodyLen); i*5 cannot overflow uint.
		src := hi
		if i >= 12 {
			src = lo
		}
		val := (src >> (64 - bitOff - 5)) & 0x1f
		body[i] = crockford[val]
	}
	return prefix + string(body)
}
