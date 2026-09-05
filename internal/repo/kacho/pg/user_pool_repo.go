// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// userPoolCols — проекция pool-scoped чтения. Она УЖЕ отличается от userCols
// (метки сюда не входят: хукам они не адресованы), поэтому это своя проекция, а
// не переиспользование чужой. Объявлена один раз: прежде тот же список стоял
// инлайном в обоих запросах, а приёмники под него — в двух побайтово
// одинаковых сканерах, то есть одну проекцию несли ЧЕТЫРЕ независимых места.
const userPoolCols = "id, account_id, external_id, email, display_name, invite_status, invited_by, created_at"

// UserPoolRepo — pool-scoped read.
type UserPoolRepo struct {
	pool *pgxpool.Pool
}

// NewUserPoolRepo — constructor.
func NewUserPoolRepo(pool *pgxpool.Pool) *UserPoolRepo {
	return &UserPoolRepo{pool: pool}
}

// FindByExternalID — ВСЕ rows для identity (Kratos sub), независимо от
// invite_status. Pool-scoped query (no TX).
//
// ACTIVE-фильтрующего близнеца здесь СОЗНАТЕЛЬНО нет (был, удалён вместе с
// последним вызывающим). Фильтр отвечает «дай пригодные строки», а хук
// спрашивает «в каком состоянии субъект»: заблокированный пользователь под
// фильтром возвращался пустым результатом, неотличимым от identity без
// зеркала, — и урезанный набор claims, существующий для второго, выдавался
// первому. Строку возвращаем как есть, вердикт выносит
// domain.InviteStatus.MayAuthenticate. Tx-scoped userReader свой ACTIVE-only
// вариант сохраняет: у upsert-пути вопрос действительно «дай пригодные».
func (r *UserPoolRepo) FindByExternalID(ctx context.Context, externalID domain.ExternalSubject) ([]domain.User, error) {
	q := fmt.Sprintf(`
		SELECT %s
		  FROM users
		 WHERE external_id = $1
		 ORDER BY created_at ASC`, userPoolCols)
	rows, err := r.pool.Query(ctx, q, string(externalID))
	if err != nil {
		return nil, mapErr(err, "", string(externalID))
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		u, err := scanUserFromRow(rows)
		if err != nil {
			return nil, mapErr(err, "", string(externalID))
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// GetByID — single row lookup by user_id.
func (r *UserPoolRepo) GetByID(ctx context.Context, id domain.UserID) (domain.User, error) {
	q := fmt.Sprintf(`
		SELECT %s
		  FROM users
		 WHERE id = $1`, userPoolCols)
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

// scanUserFromRow — ЕДИНСТВЕННОЕ объявление порядка назначений под
// userPoolCols. Принимает `scanner`, а не pgx.Row: pgx.Rows несёт тот же метод,
// поэтому одиночное чтение и обход набора строк обслуживаются одним списком, а
// не двумя его копиями.
func scanUserFromRow(row scanner) (domain.User, error) {
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
