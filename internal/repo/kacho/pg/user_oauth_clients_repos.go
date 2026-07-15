// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// user_oauth_clients_repos.go — репозиторий персональных access-токенов
// пользователя (UserTokenService — private_key_jwt через Hydra), зеркало
// SAOAuthClientRepo без federation-полей.
package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ───────────────────────────────────────────────────────────────────────────
// UserOAuthClient repo
// ───────────────────────────────────────────────────────────────────────────

type UserOAuthClientRepo struct {
	pool *pgxpool.Pool
}

func NewUserOAuthClientRepo(pool *pgxpool.Pool) *UserOAuthClientRepo {
	return &UserOAuthClientRepo{pool: pool}
}

const uocCols = `id, user_id, hydra_client_id, description, created_by_user_id,
                 created_at, expires_at, last_used_at,
                 public_key_pem, key_algorithm, name, labels`

func (r *UserOAuthClientRepo) Get(ctx context.Context, id domain.UserOAuthClientID) (domain.UserOAuthClient, error) {
	row := r.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM user_oauth_clients WHERE id = $1`, uocCols),
		string(id))
	out, err := scanUserOAuthClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.UserOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "UserToken %s not found", id)
	}
	if err != nil {
		return domain.UserOAuthClient{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// GetByOAuthClientID — обратный lookup для token-hook claim enrichment: Hydra
// отдаёт kacho-iam `client_id` (== hydra_client_id) выпустившего токен клиента,
// а нам нужен принципал — владеющий User.
func (r *UserOAuthClientRepo) GetByOAuthClientID(ctx context.Context, hydraClientID domain.OAuthClientID) (domain.UserOAuthClient, error) {
	row := r.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM user_oauth_clients WHERE hydra_client_id = $1`, uocCols),
		string(hydraClientID))
	out, err := scanUserOAuthClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.UserOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "UserOAuthClient with hydra_client_id %s not found", hydraClientID)
	}
	if err != nil {
		return domain.UserOAuthClient{}, mapErr(err, "", string(hydraClientID))
	}
	return out, nil
}

// Insert персистит новую строку токена в writer-tx вызывающего. Принимает
// непрозрачный service.Tx (порт use-case), восстанавливает конкретный pgx.Tx
// через txAsPgx, чтобы pgx оставался внутри repo/kacho/pg.
func (r *UserOAuthClientRepo) Insert(ctx context.Context, txh service.Tx, c domain.UserOAuthClient) (domain.UserOAuthClient, error) {
	tx := txAsPgx(txh)
	const q = `
		INSERT INTO user_oauth_clients (
		    id, user_id, hydra_client_id, description, created_by_user_id,
		    created_at, expires_at, last_used_at,
		    public_key_pem, key_algorithm, name, labels
		) VALUES ($1, $2, $3, $4, $5, COALESCE($6, now()), $7, $8, $9, $10, $11, $12::jsonb)
		RETURNING ` + uocCols
	labelsJSON, err := marshalLabels(c.Labels)
	if err != nil {
		return domain.UserOAuthClient{}, mapErr(err, "", string(c.ID))
	}
	row := tx.QueryRow(ctx, q,
		string(c.ID), string(c.UserID), string(c.OAuthClientID),
		string(c.Description), string(c.CreatedByUserID),
		nullableTime(c.CreatedAt), nullableTimePtr(c.ExpiresAt), nullableTimePtr(c.LastUsedAt),
		c.PublicKeyPEM, c.KeyAlgorithm, string(c.Name), labelsJSON,
	)
	out, err := scanUserOAuthClient(row)
	if err != nil {
		return domain.UserOAuthClient{}, mapErr(err, "", string(c.ID))
	}
	return out, nil
}

// AccountForUser — резолвит account владельца-User по его id. Используется для
// стемпинга `account_id` на Issue/Revoke user-token Operation-метаданных, чтобы
// account-scoped /iam/operations включал token-операции. Нет User → ErrNotFound.
func (r *UserOAuthClientRepo) AccountForUser(ctx context.Context, id domain.UserID) (domain.AccountID, error) {
	var accountID string
	err := r.pool.QueryRow(ctx,
		`SELECT account_id FROM users WHERE id = $1`, string(id)).Scan(&accountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
	}
	if err != nil {
		return "", mapErr(err, "UserOAuthClient.AccountForUser", string(id))
	}
	return domain.AccountID(accountID), nil
}

// List возвращает токены владельца-User, страница по id ASC (cursor-based).
func (r *UserOAuthClientRepo) List(ctx context.Context, userID domain.UserID, pageToken string, pageSize int32) ([]domain.UserOAuthClient, string, error) {
	if pageSize <= 0 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT ` + uocCols + `
	        FROM user_oauth_clients
	       WHERE user_id = $1 AND id > $2
	       ORDER BY id ASC
	       LIMIT $3`
	rows, err := r.pool.Query(ctx, q, string(userID), pageToken, pageSize+1)
	if err != nil {
		return nil, "", mapErr(err, "UserOAuthClient.List", "")
	}
	defer rows.Close()
	var out []domain.UserOAuthClient
	for rows.Next() {
		c, err := scanUserOAuthClient(rows)
		if err != nil {
			return nil, "", mapErr(err, "UserOAuthClient.List", "")
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "UserOAuthClient.List", "")
	}
	var nextToken string
	if safeconv.IntToInt32(len(out)) > pageSize {
		nextToken = string(out[pageSize-1].ID)
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

// DeleteByID удаляет одну строку токена. Идемпотентно — ErrNotFound если нет.
// Принимает непрозрачный service.Tx (порт use-case), восстанавливает pgx.Tx
// через txAsPgx.
func (r *UserOAuthClientRepo) DeleteByID(ctx context.Context, txh service.Tx, id domain.UserOAuthClientID) error {
	tx := txAsPgx(txh)
	tag, err := tx.Exec(ctx, `DELETE FROM user_oauth_clients WHERE id = $1`, string(id))
	if err != nil {
		return mapErr(err, "UserOAuthClient.DeleteByID", string(id))
	}
	if tag.RowsAffected() == 0 {
		return iamerr.Wrapf(iamerr.ErrNotFound, "UserToken %s not found", id)
	}
	return nil
}

// TouchLastUsed — атомарное обновление last_used_at (RETURNING для проверки exists).
func (r *UserOAuthClientRepo) TouchLastUsed(ctx context.Context, tx pgx.Tx, id domain.UserOAuthClientID, at time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE user_oauth_clients SET last_used_at = $2 WHERE id = $1`,
		string(id), at)
	if err != nil {
		return mapErr(err, "UserOAuthClient.TouchLastUsed", string(id))
	}
	if tag.RowsAffected() == 0 {
		return iamerr.Wrapf(iamerr.ErrNotFound, "UserToken %s not found", id)
	}
	return nil
}

func scanUserOAuthClient(row pgx.Row) (domain.UserOAuthClient, error) {
	var (
		c          domain.UserOAuthClient
		expiresAt  sql.NullTime
		lastUsedAt sql.NullTime
		labelsBody []byte
	)
	if err := row.Scan(
		(*string)(&c.ID), (*string)(&c.UserID), (*string)(&c.OAuthClientID),
		(*string)(&c.Description), (*string)(&c.CreatedByUserID),
		&c.CreatedAt, &expiresAt, &lastUsedAt,
		&c.PublicKeyPEM, &c.KeyAlgorithm, (*string)(&c.Name), &labelsBody,
	); err != nil {
		return domain.UserOAuthClient{}, err
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		c.ExpiresAt = &t
	}
	if lastUsedAt.Valid {
		t := lastUsedAt.Time
		c.LastUsedAt = &t
	}
	labels, err := unmarshalLabels(labelsBody)
	if err != nil {
		return domain.UserOAuthClient{}, err
	}
	c.Labels = labels
	return c, nil
}
