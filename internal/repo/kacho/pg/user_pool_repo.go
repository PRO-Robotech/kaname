// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// user_pool_repo.go — pool-scoped read-only adapter для UserLookupPort
// (used by stateless hook handlers).
//
// Существующий user_repo.go работает в рамках TX (CQRS Reader/Writer pattern).
// Hook handlers — stateless HTTP endpoints, требуют lightweight pool-scoped
// read без TX overhead.
package pg

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// UserPoolRepo — pool-scoped read.
type UserPoolRepo struct {
	pool *pgxpool.Pool
}

// NewUserPoolRepo — constructor.
func NewUserPoolRepo(pool *pgxpool.Pool) *UserPoolRepo {
	return &UserPoolRepo{pool: pool}
}

// FindActiveByExternalID — все ACTIVE rows для identity (Kratos sub).
// Pool-scoped query (no TX). Возвращает empty slice если ни одной row не найдено.
func (r *UserPoolRepo) FindActiveByExternalID(ctx context.Context, externalID domain.ExternalSubject) ([]domain.User, error) {
	const q = `
		SELECT id, account_id, external_id, email, display_name, invite_status, invited_by, created_at
		  FROM users
		 WHERE external_id = $1 AND invite_status = 'ACTIVE'
		 ORDER BY created_at ASC`
	rows, err := r.pool.Query(ctx, q, string(externalID))
	if err != nil {
		return nil, mapErr(err, "", string(externalID))
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		u, err := scanUserFromRows(rows)
		if err != nil {
			return nil, mapErr(err, "", string(externalID))
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// GetByID — single row lookup by user_id.
func (r *UserPoolRepo) GetByID(ctx context.Context, id domain.UserID) (domain.User, error) {
	const q = `
		SELECT id, account_id, external_id, email, display_name, invite_status, invited_by, created_at
		  FROM users
		 WHERE id = $1`
	row := r.pool.QueryRow(ctx, q, string(id))
	u, err := scanUserFromRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
		}
		return domain.User{}, mapErr(err, "", string(id))
	}
	return u, nil
}

func scanUserFromRows(rows pgx.Rows) (domain.User, error) {
	var u domain.User
	var displayName, externalID string
	var invitedBy *string
	if err := rows.Scan(
		(*string)(&u.ID), (*string)(&u.AccountID), &externalID,
		(*string)(&u.Email), &displayName,
		(*string)(&u.InviteStatus), &invitedBy, &u.CreatedAt,
	); err != nil {
		return domain.User{}, err
	}
	u.ExternalID = domain.ExternalSubject(externalID)
	u.DisplayName = domain.DisplayName(displayName)
	if invitedBy != nil {
		u.InvitedBy = domain.UserID(*invitedBy)
	}
	return u, nil
}

func scanUserFromRow(row pgx.Row) (domain.User, error) {
	var u domain.User
	var displayName, externalID string
	var invitedBy *string
	if err := row.Scan(
		(*string)(&u.ID), (*string)(&u.AccountID), &externalID,
		(*string)(&u.Email), &displayName,
		(*string)(&u.InviteStatus), &invitedBy, &u.CreatedAt,
	); err != nil {
		return domain.User{}, err
	}
	u.ExternalID = domain.ExternalSubject(externalID)
	u.DisplayName = domain.DisplayName(displayName)
	if invitedBy != nil {
		u.InvitedBy = domain.UserID(*invitedBy)
	}
	return u, nil
}
