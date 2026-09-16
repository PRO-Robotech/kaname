// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// recovery_code_repo.go — адаптер хранилища кода восстановления и того, что
// завершение восстановления пишет сверх сессии (фаза Ф5, задача
// PRO-Robotech/kacho#1271; порт — `internal/apps/kaname/api/humansession`,
// операции на транзакции `humanSessionWriter`).
//
// # Однократность — ОДИН оператор (Р1, Ф5-05)
//
// Применение кода — `UPDATE … SET consumed_at WHERE user_id AND code_digest AND
// consumed_at IS NULL AND expires_at > $now RETURNING …`: под конкуренцией
// строку блокирует первый, второй видит её уже применённой и получает ноль
// строк. Истёкший, чужой, неверный и применённый код различаются ТОЛЬКО тем,
// что ни один из них оператор не находит, — и вызывающему различать их незачем.
//
// Часы — вызывающего (форма Ф-д): момент приходит параметром, `now()` базы
// здесь не судит ничего, кроме уборки.
//
// # Что этот файл НЕ называет
//
// Таблицу способа входа — её называет только её адаптер; замещение материала
// делегируется `replaceLoginVerifierTx` (см. `human_session_repo.go`). Журнал
// завершений пишется той же функцией, что у приёмника обратного вызова
// поставщика (`insertRecoveryCompletionTx`): источника события два, запись одна
// (Р4).

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/invite_mail_outbox"
)

// recoveryTargetSQL — человек по адресу ВМЕСТЕ с подтверждённостью адреса: одно
// чтение на обеих полосах запроса (Р2, Р7). Порядок тот же, что у чтения
// человека по адресу.
var recoveryTargetSQL = fmt.Sprintf(`
	SELECT %s, (email_verified_at IS NOT NULL) AS verified
	  FROM users
	 WHERE lower(email) = lower($1)
	 ORDER BY created_at ASC, id ASC
	 LIMIT 1`, userCols)

// RecoveryTarget — см. порт. Порядок назначений под userCols объявлен один раз
// (`scanUserInto`); подтверждённость — приёмник, дописанный после проекции.
func (r *HumanSessionRepo) RecoveryTarget(ctx context.Context, email domain.Email) (humansession.RecoveryTarget, bool, error) {
	var (
		u        domain.User
		verified bool
	)
	err := scanUserInto(r.pool.QueryRow(ctx, recoveryTargetSQL, string(email)), &u, &verified)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return humansession.RecoveryTarget{}, false, nil
		}
		return humansession.RecoveryTarget{}, false, mapErr(err, "RecoveryTarget", "")
	}
	return humansession.RecoveryTarget{User: u, EmailVerified: verified}, true, nil
}

// SweepUnservableRecoveryCodes — уборка (форма Ф-ж): строки, которые оператор
// применения уже не обслужит — применённые и истёкшие — старше порога.
func (r *HumanSessionRepo) SweepUnservableRecoveryCodes(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument batch: must be positive")
	}
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM recovery_codes
		 WHERE ctid IN (
		       SELECT ctid FROM recovery_codes
		        WHERE (expires_at <= now() - $1::interval)
		           OR (consumed_at IS NOT NULL AND consumed_at <= now() - $1::interval)
		        LIMIT $2)`, grace, batch)
	if err != nil {
		return 0, false, mapErr(err, "RecoveryCodes.Sweep", "")
	}
	return tag.RowsAffected(), tag.RowsAffected() >= int64(batch), nil
}

var _ humansession.RecoveryCodeSweeper = (*HumanSessionRepo)(nil)

// InsertRecoveryCode — см. порт.
func (w *humanSessionWriter) InsertRecoveryCode(ctx context.Context, c domain.RecoveryCode) error {
	if err := c.Validate(); err != nil {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	_, err := w.tx.Exec(ctx, `
		INSERT INTO recovery_codes (id, user_id, code_digest, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		string(c.ID), string(c.UserID), string(c.Digest), c.IssuedAt, c.ExpiresAt)
	if err != nil {
		return mapErr(err, "RecoveryCode.Insert", string(c.ID))
	}
	return nil
}

// SupersedeRecoveryCodes — см. порт: неприменённые коды личности снимаются;
// новый запрос вытесняет прежний.
func (w *humanSessionWriter) SupersedeRecoveryCodes(ctx context.Context, userID domain.UserID) (int, error) {
	tag, err := w.tx.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1 AND consumed_at IS NULL`, string(userID))
	if err != nil {
		return 0, mapErr(err, "RecoveryCode.Supersede", string(userID))
	}
	return int(tag.RowsAffected()), nil
}

// ConsumeRecoveryCode — ОДИН оператор применения (см. шапку).
func (w *humanSessionWriter) ConsumeRecoveryCode(ctx context.Context, userID domain.UserID, digest domain.CodeDigest, now time.Time) (domain.RecoveryCode, bool, error) {
	if digest == "" {
		return domain.RecoveryCode{}, false, nil
	}
	var (
		out        domain.RecoveryCode
		consumedAt time.Time
	)
	err := w.tx.QueryRow(ctx, `
		UPDATE recovery_codes SET consumed_at = $3
		 WHERE user_id = $1 AND code_digest = $2 AND consumed_at IS NULL AND expires_at > $3
		RETURNING id, user_id, code_digest, issued_at, expires_at, consumed_at`,
		string(userID), string(digest), now).Scan(&out.ID, &out.UserID, &out.Digest, &out.IssuedAt, &out.ExpiresAt, &consumedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.RecoveryCode{}, false, nil
		}
		return domain.RecoveryCode{}, false, mapErr(err, "RecoveryCode.Consume", string(userID))
	}
	out.ConsumedAt = &consumedAt
	return out, true, nil
}

// EmitRecoveryMail — намерение письма той же транзакцией (Ф5-09).
func (w *humanSessionWriter) EmitRecoveryMail(ctx context.Context, in humansession.RecoveryMailIntent) error {
	if in.Code.IsZero() {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument recovery_mail.code: required")
	}
	if err := invite_mail_outbox.EmitRecoveryTx(ctx, w.tx, string(in.UserID), string(in.AccountID), in.To, in.Code.Letter(), in.ValidFor); err != nil {
		return mapErr(err, "RecoveryMail.Emit", string(in.UserID))
	}
	return nil
}

// InsertRecoveryCompletion — журнал завершений по ключу потока: та же вставка,
// что у приёмника обратного вызова (Р4). Внешний субъект у нашего потока не
// задан — столбец NULL.
func (w *humanSessionWriter) InsertRecoveryCompletion(ctx context.Context, rc domain.RecoveryCompletion) (bool, error) {
	if err := rc.Validate(); err != nil {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	_, inserted, err := insertRecoveryCompletionTx(ctx, w.tx, rc)
	if err != nil {
		return false, mapErr(err, "RecoveryCompletion.Insert", rc.RecoveryJTI)
	}
	return inserted, nil
}
