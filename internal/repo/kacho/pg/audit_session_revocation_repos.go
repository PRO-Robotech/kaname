// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// audit_session_revocation_repos.go — audit_outbox + session_revocations
// repositories. The audit_outbox and session_revocations
// tables back the Hydra token/refresh hooks and the
// force-logout flow.
package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// ───────────────────────────────────────────────────────────────────────────
// AuditOutbox repo
// ───────────────────────────────────────────────────────────────────────────

type AuditOutboxRepo struct {
	pool *pgxpool.Pool
}

func NewAuditOutboxRepo(pool *pgxpool.Pool) *AuditOutboxRepo {
	return &AuditOutboxRepo{pool: pool}
}

const auditCols = `id, event_type, tenant_account_id,
                   event_payload, status, attempts, created_at, next_attempt_at`

func (r *AuditOutboxRepo) Get(ctx context.Context, id domain.AuditEventID) (domain.AuditOutboxEntry, error) {
	row := r.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM audit_outbox WHERE id = $1`, auditCols), string(id))
	out, err := scanAuditOutboxEntry(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AuditOutboxEntry{}, iamerr.Wrapf(iamerr.ErrNotFound, "AuditEvent %s not found", id)
	}
	if err != nil {
		return domain.AuditOutboxEntry{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// InsertTx — enqueue audit event atomically с domain mutation (caller controls TX).
func (r *AuditOutboxRepo) InsertTx(ctx context.Context, tx pgx.Tx, e domain.AuditOutboxEntry) (domain.AuditOutboxEntry, error) {
	const q = `
		INSERT INTO audit_outbox (
		    id, event_type, tenant_account_id,
		    event_payload, status, attempts, created_at, next_attempt_at
		) VALUES ($1, $2, $3, $4::jsonb, COALESCE(NULLIF($5, ''), 'pending'),
		          COALESCE($6, 0), COALESCE($7, now()), COALESCE($8, now()))
		RETURNING ` + auditCols
	var tenantAcc any
	if e.TenantAccountID != nil && *e.TenantAccountID != "" {
		tenantAcc = string(*e.TenantAccountID)
	}
	row := tx.QueryRow(ctx, q,
		string(e.ID), string(e.EventType), tenantAcc,
		jsonBytesOrEmpty(e.EventPayload), string(e.Status), e.Attempts,
		nullableTime(e.CreatedAt), nullableTime(e.NextAttemptAt),
	)
	out, err := scanAuditOutboxEntry(row)
	if err != nil {
		return domain.AuditOutboxEntry{}, mapErr(err, "", string(e.ID))
	}
	return out, nil
}

func scanAuditOutboxEntry(row pgx.Row) (domain.AuditOutboxEntry, error) {
	var (
		e         domain.AuditOutboxEntry
		tenantAcc sql.NullString
		payload   []byte
	)
	if err := row.Scan(
		(*string)(&e.ID), (*string)(&e.EventType), &tenantAcc,
		&payload, (*string)(&e.Status), &e.Attempts, &e.CreatedAt, &e.NextAttemptAt,
	); err != nil {
		return domain.AuditOutboxEntry{}, err
	}
	if tenantAcc.Valid {
		a := domain.AccountID(tenantAcc.String)
		e.TenantAccountID = &a
	}
	e.EventPayload = append([]byte(nil), payload...)
	return e, nil
}

// ───────────────────────────────────────────────────────────────────────────
// SessionRevocation repo
// ───────────────────────────────────────────────────────────────────────────

type SessionRevocationRepo struct {
	pool *pgxpool.Pool
}

func NewSessionRevocationRepo(pool *pgxpool.Pool) *SessionRevocationRepo {
	return &SessionRevocationRepo{pool: pool}
}

func (r *SessionRevocationRepo) IsRevoked(ctx context.Context, jti string) (bool, error) {
	const q = `SELECT 1 FROM session_revocations WHERE token_jti = $1 AND ttl_expires_at > now() LIMIT 1`
	var x int
	err := r.pool.QueryRow(ctx, q, jti).Scan(&x)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, mapErr(err, "", jti)
	}
	return true, nil
}

func (r *SessionRevocationRepo) Insert(ctx context.Context, tx pgx.Tx, s domain.SessionRevocation) (domain.SessionRevocation, error) {
	const q = `
		INSERT INTO session_revocations (token_jti, revoked_at, reason, user_id, ttl_expires_at)
		VALUES ($1, COALESCE($2, now()), $3, $4, $5)
		RETURNING token_jti, revoked_at, reason, user_id, ttl_expires_at`
	row := tx.QueryRow(ctx, q,
		s.TokenJTI, nullableTime(s.RevokedAt), s.Reason, string(s.UserID), s.TTLExpiresAt,
	)
	var out domain.SessionRevocation
	var userID string
	if err := row.Scan(&out.TokenJTI, &out.RevokedAt, &out.Reason, &userID, &out.TTLExpiresAt); err != nil {
		return domain.SessionRevocation{}, mapErr(err, "", s.TokenJTI)
	}
	out.UserID = domain.UserID(userID)
	return out, nil
}

// DeleteExpired — cron-cleanup; возвращает количество удаленных row.
func (r *SessionRevocationRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM session_revocations WHERE ttl_expires_at <= $1`, now)
	if err != nil {
		return 0, mapErr(err, "", "")
	}
	return tag.RowsAffected(), nil
}
