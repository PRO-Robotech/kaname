// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// access_key_login_repo.go — адаптер хранилища ПОЛОСЫ ВХОДА ключом (iam Ф13,
// PRO-Robotech/kacho#1282; приёмка
// `docs/engineering/acceptance/passwordless-login-with-access-key.md`, Р2, Р3).
// Исполняет порт `humansession.AccessKeyLoginStore`.
//
// # Что держит база, а не адаптер
//
//   - одно ЖИВОЕ испытание на контекст формы — частичный ключ уникальности по
//     непотреблённым строкам (Ф13-03): замещение — снятие и вставка одной
//     транзакцией, а не «посмотреть и решить» (ban #10);
//   - однократность — ОДИН условный оператор с отметкой потребления (Ф13-08);
//   - сдвиг счётчика ключа — тот же условный оператор, что у полосы сессии
//     (Ф7 Р6): второй реализации сдвига в дереве не заводится.
//
// Чтения строки ключа и человека адаптер НЕ переписывает: он зовёт те же
// операторы, что полоса сессии, — иначе две полосы читали бы одну строку двумя
// разными запросами и разошлись бы молча.

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// AccessKeyLoginRepo — хранилище полосы входа: свои испытания плюс чтения и
// сдвиг счётчика, взятые у хранилища ключей.
type AccessKeyLoginRepo struct {
	pool *pgxpool.Pool
	keys *AccessKeyRepo
}

// NewAccessKeyLoginRepo — построение над пулом. Хранилище ключей берётся
// готовым: полоса входа читает ТЕ ЖЕ строки теми же операторами.
func NewAccessKeyLoginRepo(pool *pgxpool.Pool, keys *AccessKeyRepo) *AccessKeyLoginRepo {
	return &AccessKeyLoginRepo{pool: pool, keys: keys}
}

// IssueChallenge — выдача, ЗАМЕЩАЮЩАЯ живое испытание того же контекста
// (Ф13-03), одной транзакцией. Частичный ключ уникальности делает два живых
// испытания одного контекста невыразимыми: одновременные выдачи
// сериализуются им, а не порядком чтений.
func (r *AccessKeyLoginRepo) IssueChallenge(ctx context.Context, c domain.AccessKeyLoginChallenge) error {
	if err := c.Validate(); err != nil {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%v", err)
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return mapErr(err, "AccessKeyLogin.IssueChallenge", "")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		DELETE FROM access_key_login_challenges
		 WHERE form_context = $1 AND consumed_at IS NULL`, c.FormContext); err != nil {
		return mapErr(err, "AccessKeyLogin.IssueChallenge", "")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO access_key_login_challenges (challenge, form_context, issued_at, expires_at)
		VALUES ($1, $2, $3, $4)`, c.Challenge, c.FormContext, c.IssuedAt, c.ExpiresAt); err != nil {
		return mapErr(err, "AccessKeyLogin.IssueChallenge", "")
	}
	if err := tx.Commit(ctx); err != nil {
		return mapErr(err, "AccessKeyLogin.IssueChallenge", "")
	}
	return nil
}

// ConsumeChallenge — ОДИН оператор однократности: строка этого контекста, не
// потреблённая и не истёкшая на now, получает отметку. Ноль затронутых строк —
// её нет, она потреблена либо истекла; различать это вызывающему незачем.
func (r *AccessKeyLoginRepo) ConsumeChallenge(ctx context.Context, challenge []byte, formContext string, now time.Time) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE access_key_login_challenges
		   SET consumed_at = $3
		 WHERE challenge = $1 AND form_context = $2
		   AND consumed_at IS NULL AND expires_at > $3`, challenge, formContext, now)
	if err != nil {
		return false, mapErr(err, "AccessKeyLogin.ConsumeChallenge", "")
	}
	return tag.RowsAffected() == 1, nil
}

// KeyByCredentialID — строка ключа тем же чтением, что у полосы сессии.
func (r *AccessKeyLoginRepo) KeyByCredentialID(ctx context.Context, credentialID []byte) (domain.AccessKey, bool, error) {
	return r.keys.KeyByCredentialID(ctx, credentialID)
}

// UserOf — человек тем же чтением, что у полосы сессии.
func (r *AccessKeyLoginRepo) UserOf(ctx context.Context, id domain.UserID) (domain.User, error) {
	return r.keys.UserOf(ctx, id)
}

// AdvanceSignCount — сдвиг счётчика ключа ТЕМ ЖЕ оператором, что у полосы
// сессии: своей транзакцией, потому что полоса входа своей транзакции ключей
// не ведёт — она ведёт транзакцию выдачи сессии.
func (r *AccessKeyLoginRepo) AdvanceSignCount(ctx context.Context, id domain.AccessKeyID, expected, reported uint32, usedAt time.Time) (bool, error) {
	w, err := r.keys.Writer(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = w.Rollback(ctx) }()
	advanced, err := w.AdvanceSignCount(ctx, id, expected, reported, usedAt)
	if err != nil {
		return false, err
	}
	if !advanced {
		return false, nil
	}
	if err := w.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// SweepUnservableLoginChallenges — уборка (форма Ф-ж): испытания, которые
// оператор однократности уже не обслужит — истёкшие и предъявленные — старше
// порога.
func (r *AccessKeyLoginRepo) SweepUnservableLoginChallenges(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument batch: must be positive")
	}
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM access_key_login_challenges
		 WHERE ctid IN (
		       SELECT ctid FROM access_key_login_challenges
		        WHERE (expires_at <= now() - $1::interval)
		           OR (consumed_at IS NOT NULL AND consumed_at <= now() - $1::interval)
		        LIMIT $2)`, grace, batch)
	if err != nil {
		return 0, false, mapErr(err, "AccessKeyLogin.SweepChallenges", "")
	}
	return tag.RowsAffected(), tag.RowsAffected() >= int64(batch), nil
}
