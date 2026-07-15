// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// session_revocations_repo.go — extended SessionRevocationRepo methods used by
// hook handlers: revoked_by_user_id + bulk-recent lookup for warm-up cache.
package pg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// revokeWithAdminUpsert — the canonical session_revocations upsert SQL, shared
// by the pool-scoped RevokeWithAdmin and the tx-scoped RevokeWithAdminTx. Both
// preserve the ON CONFLICT (token_jti) DO UPDATE idempotent contract.
const revokeWithAdminUpsert = `
	INSERT INTO session_revocations (token_jti, revoked_at, reason, user_id, ttl_expires_at, revoked_by_user_id)
	VALUES ($1, COALESCE($2, now()), $3, $4, $5, NULLIF($6, ''))
	ON CONFLICT (token_jti) DO UPDATE
	    SET revoked_at = EXCLUDED.revoked_at,
	        reason = EXCLUDED.reason,
	        ttl_expires_at = EXCLUDED.ttl_expires_at,
	        revoked_by_user_id = EXCLUDED.revoked_by_user_id
	RETURNING token_jti, revoked_at, reason, user_id, ttl_expires_at`

// RevokeWithAdmin — INSERT с поддержкой revoked_by_user_id (pool-scoped).
// revokedBy может быть "" (system / CAEP push).
func (r *SessionRevocationRepo) RevokeWithAdmin(ctx context.Context, s domain.SessionRevocation, revokedBy domain.UserID) (domain.SessionRevocation, error) {
	return scanRevokeWithAdmin(r.pool.QueryRow(ctx, revokeWithAdminUpsert,
		s.TokenJTI, nullableTime(s.RevokedAt), s.Reason,
		string(s.UserID), s.TTLExpiresAt, string(revokedBy),
	), s.TokenJTI)
}

// RevokeWithAdminTx — tx-scoped variant of RevokeWithAdmin. Runs the identical
// upsert on the caller-supplied tx so the revocation can commit atomically with
// an audit_outbox row (запрет #10). Same idempotent ON CONFLICT
// contract; revocation behaviour is unchanged, only the tx ownership differs.
func (r *SessionRevocationRepo) RevokeWithAdminTx(ctx context.Context, tx pgx.Tx, s domain.SessionRevocation, revokedBy domain.UserID) (domain.SessionRevocation, error) {
	return scanRevokeWithAdmin(tx.QueryRow(ctx, revokeWithAdminUpsert,
		s.TokenJTI, nullableTime(s.RevokedAt), s.Reason,
		string(s.UserID), s.TTLExpiresAt, string(revokedBy),
	), s.TokenJTI)
}

func scanRevokeWithAdmin(row pgx.Row, jti string) (domain.SessionRevocation, error) {
	var out domain.SessionRevocation
	var userID string
	if err := row.Scan(&out.TokenJTI, &out.RevokedAt, &out.Reason, &userID, &out.TTLExpiresAt); err != nil {
		return domain.SessionRevocation{}, mapErr(err, "", jti)
	}
	out.UserID = domain.UserID(userID)
	return out, nil
}

// ListRecent — bulk-load всех jti revoked within last `window`. Используется
// api-gateway pod'ом при cold-start для warm-up in-memory кеша.
func (r *SessionRevocationRepo) ListRecent(ctx context.Context, window time.Duration) ([]domain.SessionRevocation, error) {
	if window <= 0 {
		window = 15 * time.Minute
	}
	const q = `
		SELECT token_jti, revoked_at, reason, user_id, ttl_expires_at
		  FROM session_revocations
		 WHERE revoked_at > now() - $1::interval
		   AND ttl_expires_at > now()
		 ORDER BY revoked_at DESC`
	rows, err := r.pool.Query(ctx, q, window.String())
	if err != nil {
		return nil, mapErr(err, "ListRecent", "")
	}
	defer rows.Close()
	var out []domain.SessionRevocation
	for rows.Next() {
		var sr domain.SessionRevocation
		var userID string
		if err := rows.Scan(&sr.TokenJTI, &sr.RevokedAt, &sr.Reason, &userID, &sr.TTLExpiresAt); err != nil {
			return nil, mapErr(err, "ListRecent.scan", "")
		}
		sr.UserID = domain.UserID(userID)
		out = append(out, sr)
	}
	return out, rows.Err()
}

// ListByUser — active (not-yet-expired) revocations for a user, newest first.
// Used by InternalSessionRevocationsService.ListByUser (admin/audit). A
// non-positive limit defaults to 100 (caller clamps the upper bound).
func (r *SessionRevocationRepo) ListByUser(ctx context.Context, userID string, limit int32) ([]domain.SessionRevocation, error) {
	if limit <= 0 {
		limit = 100
	}
	const q = `
		SELECT token_jti, revoked_at, reason, user_id, ttl_expires_at
		  FROM session_revocations
		 WHERE user_id = $1 AND ttl_expires_at > now()
		 ORDER BY revoked_at DESC
		 LIMIT $2`
	rows, err := r.pool.Query(ctx, q, userID, limit)
	if err != nil {
		return nil, mapErr(err, "ListByUser", "")
	}
	defer rows.Close()
	var out []domain.SessionRevocation
	for rows.Next() {
		var sr domain.SessionRevocation
		var uid string
		if err := rows.Scan(&sr.TokenJTI, &sr.RevokedAt, &sr.Reason, &uid, &sr.TTLExpiresAt); err != nil {
			return nil, mapErr(err, "ListByUser.scan", "")
		}
		sr.UserID = domain.UserID(uid)
		out = append(out, sr)
	}
	return out, rows.Err()
}

// GetByJTI — single-row lookup. Возвращает ErrNotFound если row нет или ttl
// уже истек.
func (r *SessionRevocationRepo) GetByJTI(ctx context.Context, jti string) (domain.SessionRevocation, error) {
	const q = `
		SELECT token_jti, revoked_at, reason, user_id, ttl_expires_at
		  FROM session_revocations
		 WHERE token_jti = $1 AND ttl_expires_at > now()`
	row := r.pool.QueryRow(ctx, q, jti)
	var sr domain.SessionRevocation
	var userID string
	err := row.Scan(&sr.TokenJTI, &sr.RevokedAt, &sr.Reason, &userID, &sr.TTLExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.SessionRevocation{}, iamerr.Wrapf(iamerr.ErrNotFound, "session revocation %s not found", jti)
	}
	if err != nil {
		return domain.SessionRevocation{}, mapErr(err, "", jti)
	}
	sr.UserID = domain.UserID(userID)
	return sr, nil
}
