// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// user_token_revocations_repo.go — pool-scoped repo for the per-user
// "revoke-all-before" cutoff (migration 0012). Backs admin ForceLogout +
// Revoke(revoke_all_user_tokens); the refresh-hook reads RevokedBefore to deny
// a token whose session auth_time is at-or-before the cutoff.
package pg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// UserTokenRevocationRepo — pool-scoped (autocommit-style single-statement
// writes; no CQRS Writer-TX overhead — these are stateless hook / internal-RPC
// side-effects, same pattern as SessionRevocationsAdapter).
type UserTokenRevocationRepo struct {
	pool *pgxpool.Pool
}

// NewUserTokenRevocationRepo — constructor.
func NewUserTokenRevocationRepo(pool *pgxpool.Pool) *UserTokenRevocationRepo {
	return &UserTokenRevocationRepo{pool: pool}
}

// UpsertRevokeAll — idempotent, monotonic upsert of a user-level cutoff.
//
// ban #10: the "cutoff never moves backwards" invariant is enforced on the DB
// via GREATEST inside a single-statement INSERT … ON CONFLICT … DO UPDATE. The
// PK (user_id) row-lock serializes concurrent writers; GREATEST makes the merge
// commutative so the converged cutoff is the maximum submitted revoke_before
// regardless of arrival order (no software read-modify-write / TOCTOU).
// upsertRevokeAllSQL — the canonical monotonic cutoff upsert, shared by the
// pool-scoped UpsertRevokeAll and the tx-scoped UpsertRevokeAllTx.
const upsertRevokeAllSQL = `
	INSERT INTO user_token_revocations (user_id, revoke_before, reason, revoked_by_user_id, updated_at)
	VALUES ($1, $2, $3, NULLIF($4, ''), now())
	ON CONFLICT (user_id) DO UPDATE
	    SET revoke_before      = GREATEST(user_token_revocations.revoke_before, EXCLUDED.revoke_before),
	        reason             = EXCLUDED.reason,
	        revoked_by_user_id = EXCLUDED.revoked_by_user_id,
	        updated_at         = now()`

func (r *UserTokenRevocationRepo) UpsertRevokeAll(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	_, err := r.pool.Exec(ctx, upsertRevokeAllSQL,
		string(u.UserID), u.RevokeBefore, u.Reason, string(revokedBy),
	)
	if err != nil {
		return mapErr(err, "", string(u.UserID))
	}
	return nil
}

// UpsertRevokeAllTx — tx-scoped variant of UpsertRevokeAll. Runs the identical
// monotonic-cutoff upsert on the caller-supplied tx so the cutoff can commit
// atomically with an audit_outbox row (запрет #10). Same DB-side
// GREATEST invariant; the row-lock on the PK still serializes concurrent writers.
func (r *UserTokenRevocationRepo) UpsertRevokeAllTx(ctx context.Context, tx pgx.Tx, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	_, err := tx.Exec(ctx, upsertRevokeAllSQL,
		string(u.UserID), u.RevokeBefore, u.Reason, string(revokedBy),
	)
	if err != nil {
		return mapErr(err, "", string(u.UserID))
	}
	return nil
}

// RevokedBefore — the active per-user cutoff. Returns (cutoff, true, nil) when a
// marker exists, (zero, false, nil) when none. An error is surfaced so the
// caller can fail-closed (the refresh-hook MUST deny on a lookup error).
func (r *UserTokenRevocationRepo) RevokedBefore(ctx context.Context, userID string) (time.Time, bool, error) {
	const q = `SELECT revoke_before FROM user_token_revocations WHERE user_id = $1`
	var before time.Time
	err := r.pool.QueryRow(ctx, q, userID).Scan(&before)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, mapErr(err, "", userID)
	}
	return before, true, nil
}
