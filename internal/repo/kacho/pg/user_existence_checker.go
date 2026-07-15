// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// user_existence_checker.go — D-9 guard: checks that a user exists in
// kacho_iam.users before allowing a cluster_admin_grants INSERT.
//
// Why software check rather than FK: cluster_admin_grants.subject_id is
// polymorphic (subject_type ∈ {user, service_account}), so a single FK to
// users.id would be incorrect for service_account subjects. PostgreSQL does
// not support partial/conditional FKs. The check is within the same DB
// (same schema) so it is fast, low-risk, and avoids a new migration solely
// for the current user-only use-case (acceptance D-2 restricts to USER type).
//
// The check is intentionally done on the request-path (before the TX) so it
// can return InvalidArgument immediately; the service-layer use-case calls
// ExistsUser before opening the writer-tx.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// UserExistenceChecker — thin read adapter that checks kacho_iam.users.
type UserExistenceChecker struct {
	pool *pgxpool.Pool
}

// NewUserExistenceChecker — constructor.
func NewUserExistenceChecker(pool *pgxpool.Pool) *UserExistenceChecker {
	return &UserExistenceChecker{pool: pool}
}

// ExistsUser — returns nil if the user row exists, ErrInvalidArg-wrapped
// error if not. Uses SELECT 1 … LIMIT 1 (no row-lock needed).
func (c *UserExistenceChecker) ExistsUser(ctx context.Context, userID string) error {
	var x int
	err := c.pool.QueryRow(ctx,
		`SELECT 1 FROM kacho_iam.users WHERE id = $1 LIMIT 1`, userID).Scan(&x)
	if err == nil {
		return nil
	}
	if err == pgx.ErrNoRows {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "User %s not found", userID)
	}
	return fmt.Errorf("user existence check: %w", err)
}
