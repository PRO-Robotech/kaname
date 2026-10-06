// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// user_oauth_clients_repos.go — репозиторий персональных access-токенов
// пользователя (UserTokenService — private_key_jwt), зеркало SAOAuthClientRepo
// без federation-полей.
//
// Клиентом токен называется по идентификатору своей строки; второго имени у
// него нет (kaname#362): столбец имени клиента у прежнего внешнего издателя
// снят вместе с поиском по нему.
package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/safeconv"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
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

const uocCols = `id, user_id, description, created_by_user_id,
                 created_at, expires_at, last_used_at,
                 public_key_pem, key_algorithm, name, labels,
                 credential_kind, secret_hash`

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

// Insert персистит новую строку токена в writer-tx вызывающего. Принимает
// непрозрачный service.Tx (порт use-case), восстанавливает конкретный pgx.Tx
// через txAsPgx, чтобы pgx оставался внутри repo/kaname/pg.
func (r *UserOAuthClientRepo) Insert(ctx context.Context, txh service.Tx, c domain.UserOAuthClient) (domain.UserOAuthClient, error) {
	tx := txAsPgx(txh)
	const q = `
		INSERT INTO user_oauth_clients (
		    id, user_id, description, created_by_user_id,
		    created_at, expires_at, last_used_at,
		    public_key_pem, key_algorithm, name, labels,
		    credential_kind, secret_hash
		) VALUES ($1, $2, $3, $4, COALESCE($5, now()), $6, $7, $8, $9, $10, $11::jsonb,
		          $12, COALESCE($13, ''::bytea))
		RETURNING ` + uocCols
	labelsJSON, err := marshalLabels(c.Labels)
	if err != nil {
		return domain.UserOAuthClient{}, mapErr(err, "", string(c.ID))
	}
	row := tx.QueryRow(ctx, q,
		string(c.ID), string(c.UserID),
		string(c.Description), string(c.CreatedByUserID),
		nullableTime(c.CreatedAt), nullableTimePtr(c.ExpiresAt), nullableTimePtr(c.LastUsedAt),
		c.PublicKeyPEM, c.KeyAlgorithm, string(c.Name), labelsJSON,
		// Вид ЗАПИСЫВАЕТСЯ. Пустой вид сюда доехать не может — глагол выдачи
		// разрешает его синхронно, до вставки, — но ограничение таблицы всё
		// равно отвергнет пустую строку: словарь закрыт.
		string(c.CredentialKind), c.SecretHash,
	)
	out, err := scanUserOAuthClient(row)
	if err != nil {
		return domain.UserOAuthClient{}, mapErr(err, "", string(c.ID))
	}
	return out, nil
}

// AccountForUser — резолвит account владельца-User по его id и состояние,
// разрешающее ему аутентифицироваться. Используется для стемпинга `account_id`
// на Issue/Revoke user-token Operation-метаданных (иначе account-scoped
// /iam/operations исключает token-операции) и для отказа в выдаче нового токена
// тому, кому аутентификация запрещена.
//
// Строка читается КАК ЕСТЬ, без фильтра по состоянию: фильтр отвечает «нет
// такого пользователя» на пользователя, который есть, — и вызывающий, увидев
// пустой результат, не отличит его от несуществующего. Состояние возвращается,
// чтобы его судили, а не выводили из отсутствия.
//
// Нет User → ErrNotFound.
func (r *UserOAuthClientRepo) AccountForUser(ctx context.Context, id domain.UserID) (domain.AccountID, bool, error) {
	var (
		accountID    string
		inviteStatus string
	)
	err := r.pool.QueryRow(ctx,
		`SELECT account_id, invite_status FROM users WHERE id = $1`, string(id)).Scan(&accountID, &inviteStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
	}
	if err != nil {
		return "", false, mapErr(err, "UserOAuthClient.AccountForUser", string(id))
	}
	return domain.AccountID(accountID), domain.InviteStatus(inviteStatus).MayAuthenticate(), nil
}

// List возвращает токены владельца-User, страница по id ASC (cursor-based).
func (r *UserOAuthClientRepo) List(ctx context.Context, userID domain.UserID, pageToken string, pageSize int32) ([]domain.UserOAuthClient, string, error) {
	// page_size outside [0..maxListPageSize] is REJECTED, never clamped (a clamp
	// returns a short page indistinguishable from a complete one). 0 → the
	// platform default, the same one every other List of the service applies.
	limit, err := effectivePageSize(pageSize)
	if err != nil {
		return nil, "", err
	}
	pageSize = safeconv.ClampInt32(limit) // already bounded to [1..maxListPageSize]: no clamp happens
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

// DeleteOwnedByID снимает строку удостоверения ОДНИМ оператором, суженным
// владельцем, и возвращает снятую строку.
//
// Владелец стоит в самом `WHERE`, а не в проверке перед ним: «прочитать, свериться,
// удалить» — software check-then-act, запрещённый ban #10, и под конкуренцией два
// отзыва проходят проверку оба. Здесь строку выбирает и снимает один оператор под
// row-lock: второй писатель видит уже снятую строку и получает ноль строк.
//
// found=false — ЗАКОННЫЙ исход, а не ошибка. Он покрывает три случая сразу:
// строки не было никогда, строку уже сняли, строка принадлежит другому владельцу.
// Различить их отсюда нельзя BY CONSTRUCTION, и это не упущение, а требование:
// вызывающий, которому вернули бы разные исходы, узнавал бы по различию,
// существует ли ЧУЖОЕ удостоверение (§Hardening #6). Ветки, в
// которой они могли бы разойтись, здесь просто нет.
func (r *UserOAuthClientRepo) DeleteOwnedByID(
	ctx context.Context, txh service.Tx,
	ownerID domain.UserID, id domain.UserOAuthClientID,
) (domain.UserOAuthClient, bool, error) {
	tx := txAsPgx(txh)
	row := tx.QueryRow(ctx,
		fmt.Sprintf(`DELETE FROM user_oauth_clients WHERE id = $1 AND user_id = $2 RETURNING %s`, uocCols),
		string(id), string(ownerID))
	out, err := scanUserOAuthClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.UserOAuthClient{}, false, nil
	}
	if err != nil {
		return domain.UserOAuthClient{}, false, mapErr(err, "UserOAuthClient.DeleteOwnedByID", string(id))
	}
	return out, true, nil
}

// ExistsOwnedByID — есть ли у человека ownerID удостоверение id. Предикат тот
// же, что у оператора снятия выше (`id AND user_id`): строка чужого владельца
// отсюда неотличима от отсутствующей BY CONSTRUCTION, ветки, на которой они
// могли бы разойтись, нет.
//
// Ответ классифицирующий, а не решающий: снятие решает оператор снятия под
// своим замком, и проигравший гонку получает там тот же исход «нет». Ошибка
// чтения — НЕ «нет»: она уходит вызывающему как есть, чтобы неполученный ответ
// не был прочитан отсутствием строки.
func (r *UserOAuthClientRepo) ExistsOwnedByID(ctx context.Context, ownerID domain.UserID, id domain.UserOAuthClientID) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM user_oauth_clients WHERE id = $1 AND user_id = $2)`,
		string(id), string(ownerID)).Scan(&exists)
	if err != nil {
		return false, mapErr(err, "UserOAuthClient.ExistsOwnedByID", string(id))
	}
	return exists, nil
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
		(*string)(&c.ID), (*string)(&c.UserID),
		(*string)(&c.Description), (*string)(&c.CreatedByUserID),
		&c.CreatedAt, &expiresAt, &lastUsedAt,
		&c.PublicKeyPEM, &c.KeyAlgorithm, (*string)(&c.Name), &labelsBody,
		(*string)(&c.CredentialKind), &c.SecretHash,
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
