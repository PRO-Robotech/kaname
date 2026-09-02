// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// user_oauth_clients_repos.go — репозиторий персональных access-токенов
// пользователя (UserTokenService — private_key_jwt), зеркало SAOAuthClientRepo
// без federation-полей.
//
// # Колонка зеркала читается и пишется как ОТСУТСТВУЮЩАЯ величина
//
// `hydra_client_id` хранит идентификатор клиента у внешнего поставщика. У строк
// нового выпуска его НЕТ (`NULL`): выдача больше не заводит там клиента. Пустая
// доменная строка означает «нет», и обратно она читается тем же «нет».
//
// Пустая СТРОКА в колонку не пишется намеренно. Колонка несёт уникальный индекс,
// и пустая строка — обычное значение: второй токен того же пользователя упёрся
// бы в 23505. Отсутствие значения уникальный индекс различает, поэтому таких
// строк может быть сколько угодно (миграция
// 20260823180500_user_token_credential_needs_no_provider_mirror).
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

// GetByOAuthClientID — обратный lookup обратного вызова внешнего поставщика: он
// отдаёт `client_id` выпустившего токен клиента, а нам нужен принципал —
// владеющий User.
//
// Путь обслуживает ТОЛЬКО строки прежнего выпуска — те, у которых зеркало есть.
// Строку нового выпуска он не разрешает и не должен: клиента с таким именем у
// поставщика не существует, поэтому и обратного вызова о нём не бывает.
//
// Пустой идентификатор отсекается ДО запроса. Иначе сравнение колонки с пустой
// строкой на дереве с частично заполненной колонкой стало бы способом спросить
// «дай любую строку без зеркала» — а спрашивающий здесь всегда называет
// конкретного клиента.
func (r *UserOAuthClientRepo) GetByOAuthClientID(ctx context.Context, hydraClientID domain.OAuthClientID) (domain.UserOAuthClient, error) {
	if hydraClientID == "" {
		return domain.UserOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "User credential %s not found", hydraClientID)
	}
	row := r.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM user_oauth_clients WHERE hydra_client_id = $1`, uocCols),
		string(hydraClientID))
	out, err := scanUserOAuthClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.UserOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "User credential %s not found", hydraClientID)
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
		    public_key_pem, key_algorithm, name, labels,
		    credential_kind, secret_hash
		) VALUES ($1, $2, $3, $4, $5, COALESCE($6, now()), $7, $8, $9, $10, $11, $12::jsonb,
		          $13, COALESCE($14, ''::bytea))
		RETURNING ` + uocCols
	labelsJSON, err := marshalLabels(c.Labels)
	if err != nil {
		return domain.UserOAuthClient{}, mapErr(err, "", string(c.ID))
	}
	row := tx.QueryRow(ctx, q,
		string(c.ID), string(c.UserID), nullableProviderMirror(c.OAuthClientID),
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
	// returns a short page indistinguishable from a complete one). 0 → default.
	if int64(pageSize) < 0 || int64(pageSize) > maxListPageSize {
		return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg,
			"page_size must be in [0..%d] (0 means default)", maxListPageSize)
	}
	if pageSize == 0 {
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
// существует ли ЧУЖОЕ удостоверение (security.md §Hardening #6). Ветки, в
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
		mirror     sql.NullString
		expiresAt  sql.NullTime
		lastUsedAt sql.NullTime
		labelsBody []byte
	)
	if err := row.Scan(
		(*string)(&c.ID), (*string)(&c.UserID), &mirror,
		(*string)(&c.Description), (*string)(&c.CreatedByUserID),
		&c.CreatedAt, &expiresAt, &lastUsedAt,
		&c.PublicKeyPEM, &c.KeyAlgorithm, (*string)(&c.Name), &labelsBody,
		(*string)(&c.CredentialKind), &c.SecretHash,
	); err != nil {
		return domain.UserOAuthClient{}, err
	}
	if mirror.Valid {
		c.OAuthClientID = domain.OAuthClientID(mirror.String)
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

// nullableProviderMirror — доменное «зеркала нет» в отсутствие значения колонки.
//
// Пустая доменная строка и `NULL` здесь одно и то же состояние, названное на
// двух языках. Писать вместо `NULL` пустую строку нельзя: уникальный индекс
// зеркала считает её обычным значением, и вторая такая строка не легла бы вовсе.
func nullableProviderMirror(id domain.OAuthClientID) *string {
	if id == "" {
		return nil
	}
	s := string(id)
	return &s
}
