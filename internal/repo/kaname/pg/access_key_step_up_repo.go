// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// access_key_step_up_repo.go — адаптер хранилища ВЕТВИ КЛЮЧА церемонии
// повышения (задача PRO-Robotech/kaname#827; приёмка
// `docs/engineering/acceptance/step-up-with-any-enrolled-method.md`, Р2, Р3;
// замысел §2.1). Исполняет порт `humansession.StepUpChallengeStore`.
//
// # Что держит база, а не адаптер
//
//   - одно ЖИВОЕ испытание на запись сессии — частичный ключ уникальности по
//     непредъявленным строкам: смена — один оператор вставки с этим ключом
//     арбитром, а не «снять, затем вставить» (ban #10, тот же приём, что у
//     полосы входа ключом — kaname#769);
//   - однократность — ОДИН условный оператор по паре (сессия, испытание);
//   - принадлежность — внешний ключ на запись сессии: снятие записи уборкой
//     снимает её испытания каскадом.
//
// Моменты приходят параметром — часами службы, как у испытаний Ф7: срок —
// величина контракта Ф7, и ось времени приёмка строит управляемыми часами.
//
// Чтения строки ключа адаптер НЕ переписывает: он зовёт те же операторы, что
// хранилище ключей, — иначе две полосы читали бы одну строку двумя разными
// запросами и разошлись бы молча.

import (
	"context"
	stderrors "errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// AccessKeyStepUpRepo — хранилище ветви ключа повышения: свои испытания плюс
// чтения, взятые у хранилища ключей.
type AccessKeyStepUpRepo struct {
	pool *pgxpool.Pool
	keys *AccessKeyRepo
}

// NewAccessKeyStepUpRepo — построение над пулом. Хранилище ключей берётся
// готовым: ветвь повышения читает ТЕ ЖЕ строки теми же операторами.
func NewAccessKeyStepUpRepo(pool *pgxpool.Pool, keys *AccessKeyRepo) *AccessKeyStepUpRepo {
	return &AccessKeyStepUpRepo{pool: pool, keys: keys}
}

// IssueStepUpChallenge — выдача, ЗАМЕЩАЮЩАЯ живое испытание той же записи
// сессии, ОДНИМ оператором. Арбитр ждёт фиксации соперника и переписывает его
// строку — живым остаётся позднее испытание, отказа нет; строка, предъявленная
// соперником за время ожидания, из-под ключа уходит, и оператор вставляет
// новую. Прежнее значение после смены в таблице не лежит ни в каком виде — его
// предъявление читается «не выдавалось».
func (r *AccessKeyStepUpRepo) IssueStepUpChallenge(ctx context.Context, c domain.StepUpChallenge) error {
	if err := c.Validate(); err != nil {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%v", err)
	}
	if _, err := r.pool.Exec(ctx, `
		INSERT INTO access_key_step_up_challenges (challenge, session_id, issued_at, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (session_id) WHERE consumed_at IS NULL
		DO UPDATE SET challenge  = EXCLUDED.challenge,
		              issued_at  = EXCLUDED.issued_at,
		              expires_at = EXCLUDED.expires_at`,
		c.Challenge, string(c.SessionID), c.IssuedAt, c.ExpiresAt); err != nil {
		return mapErr(err, "AccessKeyStepUp.IssueChallenge", "")
	}
	return nil
}

// ConsumeStepUpChallenge — ОДИН условный оператор однократности: строка этой
// пары, не предъявленная и не истёкшая на now, получает отметку. Проигравший
// гонку сгорания получает ноль строк и читает «уже предъявлено».
func (r *AccessKeyStepUpRepo) ConsumeStepUpChallenge(ctx context.Context, session domain.HumanSessionID, challenge []byte, now time.Time) (bool, error) {
	if session == "" || now.IsZero() {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument step-up challenge: session and moment required")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE access_key_step_up_challenges
		   SET consumed_at = $3
		 WHERE session_id = $1 AND challenge = $2
		   AND consumed_at IS NULL AND expires_at > $3`, string(session), challenge, now)
	if err != nil {
		return false, mapErr(err, "AccessKeyStepUp.ConsumeChallenge", "")
	}
	return tag.RowsAffected() == 1, nil
}

// StepUpChallengeState — классифицирующее чтение той же пары после
// несгоревшего испытания. Строки нет — «не выдавалось» (в том числе испытание
// другой сессии и сменённое); отметка есть — «уже предъявлено»; предел вышел —
// «истекло». Живая непредъявленная строка здесь означает, что пару сменили
// между оператором и чтением, — то же «не выдавалось»: предъявленное значение
// годным уже не было.
func (r *AccessKeyStepUpRepo) StepUpChallengeState(ctx context.Context, session domain.HumanSessionID, challenge []byte, now time.Time) (domain.StepUpChallengeState, error) {
	var (
		consumed *time.Time
		expires  time.Time
	)
	err := r.pool.QueryRow(ctx, `
		SELECT consumed_at, expires_at FROM access_key_step_up_challenges
		 WHERE session_id = $1 AND challenge = $2`, string(session), challenge).Scan(&consumed, &expires)
	switch {
	case stderrors.Is(err, pgx.ErrNoRows):
		return domain.StepUpChallengeNotIssued, nil
	case err != nil:
		return 0, mapErr(err, "AccessKeyStepUp.ChallengeState", "")
	case consumed != nil:
		return domain.StepUpChallengePresented, nil
	case !expires.After(now):
		return domain.StepUpChallengeExpired, nil
	}
	return domain.StepUpChallengeNotIssued, nil
}

// KeyByCredentialID — строка ключа тем же чтением, что у хранилища ключей.
func (r *AccessKeyStepUpRepo) KeyByCredentialID(ctx context.Context, credentialID []byte) (domain.AccessKey, bool, error) {
	return r.keys.KeyByCredentialID(ctx, credentialID)
}

// CredentialIDsOf — удостоверения человека тем же чтением, что у хранилища
// ключей (`ORDER BY created_at, id`).
func (r *AccessKeyStepUpRepo) CredentialIDsOf(ctx context.Context, userID domain.UserID) ([][]byte, error) {
	return r.keys.CredentialIDsOf(ctx, userID)
}

// SweepUnservableStepUpChallenges — уборка (форма Ф-ж): испытания, которые
// оператор однократности уже не обслужит, — истёкшие и предъявленные — старше
// порога. Порог приносит реестр (срок испытания, не ноль: три состояния
// испытания наружу различимы, и различимость держит хранение строки).
func (r *AccessKeyStepUpRepo) SweepUnservableStepUpChallenges(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument batch: must be positive")
	}
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM access_key_step_up_challenges
		 WHERE ctid IN (
		       SELECT ctid FROM access_key_step_up_challenges
		        WHERE (expires_at <= now() - $1::interval)
		           OR (consumed_at IS NOT NULL AND consumed_at <= now() - $1::interval)
		        LIMIT $2)`, grace, batch)
	if err != nil {
		return 0, false, mapErr(err, "AccessKeyStepUp.SweepChallenges", "")
	}
	return tag.RowsAffected(), tag.RowsAffected() >= int64(batch), nil
}
