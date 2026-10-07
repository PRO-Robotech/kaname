// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// verification_code_repo.go — адаптер кода подтверждения адреса и письма
// подтверждения (задача PRO-Robotech/kaname#456; порт —
// `internal/apps/kaname/api/humansession`, операции на транзакции
// `humanSessionWriter`).
//
// # Предел писем — ОДИН условный оператор (Р9, ban #10)
//
// Строка кода вставляется оператором, условие которого и есть предел: нет
// письма моложе промежутка и писем в окне меньше предела. Решение — число
// вставленных строк, а не чтение перед записью. Транзакция запроса письма
// открыта замком писателя нескольких сессий на строке человека
// (`holdPersonForSessionSet`): одновременные запросы одного человека
// сериализованы им, и второй видит строку первого своим новым снимком.
//
// # Предъявление — ОДИН оператор (Р7)
//
// Счёт попытки и сверка свёртки не разнесены чтением и записью: оператор берёт
// живую строку кода человека сессии и одним `UPDATE` либо ставит отметку
// применения (свёртка совпала), либо прибавляет попытку. Код, выданный другому
// значению адреса, оператор не находит: адрес строки кода сверяется с текущим
// адресом строки человека в том же операторе (Ф6 Р10).
//
// Часы — вызывающего (форма Ф-д): момент приходит параметром, `now()` базы
// здесь не судит ничего, кроме уборки.

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/invite_mail_outbox"
)

// supersedeVerificationCodesSQL — живые коды человека вытеснены; строка
// остаётся: по строкам кодов считается предел писем.
const supersedeVerificationCodesSQL = `
	UPDATE email_verification_codes
	   SET superseded_at = GREATEST($2::timestamptz, issued_at)
	 WHERE user_id = $1 AND consumed_at IS NULL AND superseded_at IS NULL`

// SupersedeVerificationCodes — см. порт.
func (w *humanSessionWriter) SupersedeVerificationCodes(ctx context.Context, userID domain.UserID, at time.Time) (int, error) {
	tag, err := w.tx.Exec(ctx, supersedeVerificationCodesSQL, string(userID), at)
	if err != nil {
		return 0, mapErr(err, "VerificationCode.Supersede", string(userID))
	}
	return int(tag.RowsAffected()), nil
}

// insertVerificationCodePacedSQL — строка кода ПОД пределом писем: $7 —
// промежуток, $8 — окно, $9 — число писем за окно.
const insertVerificationCodePacedSQL = `
	INSERT INTO email_verification_codes (id, user_id, email, code_digest, issued_at, expires_at)
	SELECT $1, $2, $3, $4, $5, $6
	 WHERE NOT EXISTS (
	         SELECT 1 FROM email_verification_codes
	          WHERE user_id = $2 AND issued_at > $5::timestamptz - $7::interval)
	   AND (SELECT count(*) FROM email_verification_codes
	         WHERE user_id = $2 AND issued_at > $5::timestamptz - $8::interval) < $9`

// letterPaceSQL — чем отказ предела объясняется: момент последнего письма и
// самое старое письмо окна с их числом. Читается ПОСЛЕ отказа оператора и
// выбирает только срок ответа, а не исход.
const letterPaceSQL = `
	SELECT max(issued_at),
	       min(issued_at) FILTER (WHERE issued_at > $2::timestamptz - $3::interval),
	       count(*) FILTER (WHERE issued_at > $2::timestamptz - $3::interval)
	  FROM email_verification_codes
	 WHERE user_id = $1`

// InsertVerificationCodePaced — см. порт.
func (w *humanSessionWriter) InsertVerificationCodePaced(ctx context.Context, c domain.VerificationCode, pace humansession.VerificationPace) (humansession.LetterRefusal, error) {
	if err := c.Validate(); err != nil {
		return humansession.LetterRefusal{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if err := pace.Validate(); err != nil {
		return humansession.LetterRefusal{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	tag, err := w.tx.Exec(ctx, insertVerificationCodePacedSQL,
		string(c.ID), string(c.UserID), string(c.Email), string(c.Digest), c.IssuedAt, c.ExpiresAt,
		pace.Interval, pace.Window, pace.Limit)
	if err != nil {
		return humansession.LetterRefusal{}, mapErr(err, "VerificationCode.Insert", string(c.UserID))
	}
	if tag.RowsAffected() == 1 {
		return humansession.LetterRefusal{}, nil
	}
	var (
		last, oldest *time.Time
		inWindow     int
	)
	if err := w.tx.QueryRow(ctx, letterPaceSQL, string(c.UserID), c.IssuedAt, pace.Window).Scan(&last, &oldest, &inWindow); err != nil {
		return humansession.LetterRefusal{}, mapErr(err, "VerificationCode.Pace", string(c.UserID))
	}
	return humansession.LetterRefusal{Refused: true, RetryAfter: letterRetryAfter(c.IssuedAt, pace, last, oldest, inWindow)}, nil
}

// letterRetryAfter — до ближайшего разрешённого момента: позднейший из двух
// сроков — промежуток от последнего письма и выход самого старого письма из
// окна. Ни один не в будущем (гонка часов) — секунда: отказ без срока клиенту
// ничего не говорит.
func letterRetryAfter(at time.Time, pace humansession.VerificationPace, last, oldest *time.Time, inWindow int) time.Duration {
	var wait time.Duration
	if last != nil {
		if d := last.Add(pace.Interval).Sub(at); d > wait {
			wait = d
		}
	}
	if oldest != nil && inWindow >= pace.Limit {
		if d := oldest.Add(pace.Window).Sub(at); d > wait {
			wait = d
		}
	}
	if wait <= 0 {
		wait = time.Second
	}
	return wait
}

// EmitVerificationMail — намерение письма той же транзакцией (Р8).
func (w *humanSessionWriter) EmitVerificationMail(ctx context.Context, in humansession.VerificationMailIntent) error {
	if in.Code.IsZero() {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument verification_mail.code: required")
	}
	if err := invite_mail_outbox.EmitVerificationTx(ctx, w.tx, string(in.UserID), string(in.AccountID), in.To, in.Code.Letter(), in.ValidFor); err != nil {
		return mapErr(err, "VerificationMail.Emit", string(in.UserID))
	}
	return nil
}

// presentVerificationCodeSQL — ОДИН оператор предъявления (см. шапку): $2 —
// свёртка предъявленного, $3 — момент, $4 — предел попыток на код.
const presentVerificationCodeSQL = `
	UPDATE email_verification_codes c
	   SET attempts    = c.attempts + CASE WHEN c.code_digest = $2 THEN 0 ELSE 1 END,
	       consumed_at = CASE WHEN c.code_digest = $2 THEN $3::timestamptz ELSE NULL END
	  FROM users u
	 WHERE c.user_id = $1
	   AND u.id = c.user_id
	   AND lower(u.email) = lower(c.email)
	   AND c.consumed_at IS NULL
	   AND c.superseded_at IS NULL
	   AND c.expires_at > $3::timestamptz
	   AND c.attempts < $4
	RETURNING (c.code_digest = $2) AS matched, c.email, c.attempts`

// PresentVerificationCode — см. порт.
func (w *humanSessionWriter) PresentVerificationCode(ctx context.Context, userID domain.UserID, digest domain.CodeDigest, now time.Time, attempts int) (humansession.PresentedCode, domain.Email, error) {
	if userID == "" || digest == "" || attempts <= 0 {
		return humansession.CodeNotFound, "", nil
	}
	var (
		matched bool
		email   string
		spent   int
	)
	err := w.tx.QueryRow(ctx, presentVerificationCodeSQL, string(userID), string(digest), now, attempts).Scan(&matched, &email, &spent)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return humansession.CodeNotFound, "", nil
		}
		return humansession.CodeNotFound, "", mapErr(err, "VerificationCode.Present", string(userID))
	}
	if !matched {
		if spent >= attempts {
			return humansession.CodeExhausted, "", nil
		}
		return humansession.CodeMismatched, "", nil
	}
	return humansession.CodeMatched, domain.Email(email), nil
}

// MarkEmailVerified — см. порт: отметка тем же оператором, что писатель
// отметки адаптера способа входа (`markEmailVerifiedSQL`), транзакцией исхода
// подтверждения.
func (w *humanSessionWriter) MarkEmailVerified(ctx context.Context, userID domain.UserID, email domain.Email, at time.Time) (bool, error) {
	if userID == "" || at.IsZero() {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument email_verified_at: user and moment required")
	}
	var exists, marked bool
	if err := w.tx.QueryRow(ctx, markEmailVerifiedSQL, string(userID), string(email), at).Scan(&exists, &marked); err != nil {
		return false, mapErr(err, "User.MarkEmailVerified", string(userID))
	}
	return marked, nil
}

// SweepUnservableVerificationCodes — уборка: строки старше окна писем, которые
// ни предъявление, ни предел писем уже не прочтут. Строка очереди письма,
// несущая открытое значение кода, снимается уборкой очереди сданных писем;
// строка кода несёт только свёртку.
func (r *HumanSessionRepo) SweepUnservableVerificationCodes(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument batch: must be positive")
	}
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM email_verification_codes
		 WHERE ctid IN (
		       SELECT ctid FROM email_verification_codes
		        WHERE issued_at <= now() - $1::interval
		          AND (expires_at <= now() OR consumed_at IS NOT NULL OR superseded_at IS NOT NULL)
		        LIMIT $2)`, grace, batch)
	if err != nil {
		return 0, false, mapErr(err, "VerificationCodes.Sweep", "")
	}
	return tag.RowsAffected(), tag.RowsAffected() >= int64(batch), nil
}

// chargeSourceSQL — окно обращений источника ($1 — полоса, $2 — источник):
// вставка — первое обращение; правка берёт замок строки окна, переход окна и
// списание — одно выражение, условие `WHERE` отвергает правку, когда окно
// полно ($4 — предел, $5 — окно, $3 — момент). Решение — число строк.
const chargeSourceSQL = `
	INSERT INTO source_request_windows AS w (lane, source, window_started_at, requests, updated_at)
	VALUES ($1, $2, $3, 1, $3)
	ON CONFLICT (lane, source) DO UPDATE
	   SET window_started_at = CASE WHEN w.window_started_at <= $3::timestamptz - $5::interval
	                                THEN $3::timestamptz ELSE w.window_started_at END,
	       requests = CASE WHEN w.window_started_at <= $3::timestamptz - $5::interval
	                       THEN 1 ELSE w.requests + 1 END,
	       updated_at = $3
	 WHERE w.window_started_at <= $3::timestamptz - $5::interval OR w.requests < $4`

// sourceKeyLimit — длина ключа источника по ограничению схемы; длиннее —
// усекается: слияние двух источников сужает, а не расширяет окно.
const sourceKeyLimit = 256

// ChargeSource — см. порт `humansession.SourcePacer`.
func (r *HumanSessionRepo) ChargeSource(ctx context.Context, lane humansession.SourceLane, source string, at time.Time, pace humansession.SourcePace) (bool, error) {
	if err := pace.Validate(); err != nil {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if len(source) > sourceKeyLimit {
		source = source[:sourceKeyLimit]
	}
	if source == "" {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument source: required — a window belongs to a source")
	}
	tag, err := r.pool.Exec(ctx, chargeSourceSQL, string(lane), source, at, pace.Limit, pace.Window)
	if err != nil {
		return false, mapErr(err, "SourceWindow.Charge", string(lane))
	}
	return tag.RowsAffected() == 1, nil
}

var _ humansession.SourcePacer = (*HumanSessionRepo)(nil)

// sweepExpiredCodeLettersSQL — строки очереди писем, чей КОД истёк: письмо
// восстановления, письмо подтверждения и письмо с кодом смены адреса
// (kaname#635) несут открытое значение кода до сдачи
// узлу, и строка, код которой уже ничего не подтверждает и ничего не
// восстанавливает, держит предъявителя без предмета. Снимается и
// недоставленная: отравленная строка отметки доставки не получит никогда, а
// общий уборщик доставленных её не снимает (kaname#456, условие аудита).
const sweepExpiredCodeLettersSQL = `
	DELETE FROM invite_mail_outbox
	 WHERE ctid IN (
	       SELECT ctid FROM invite_mail_outbox
	        WHERE event_type IN ('mail.recovery.send', 'mail.verification.send', 'mail.email-change.send')
	          AND created_at + make_interval(mins => COALESCE((payload->>'code_valid_minutes')::int, 0))
	              <= now() - $1::interval
	        LIMIT $2)`

// SweepExpiredBearerLetters — уборка писем с истёкшим кодом (см. оператор).
func (r *HumanSessionRepo) SweepExpiredBearerLetters(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument batch: must be positive")
	}
	tag, err := r.pool.Exec(ctx, sweepExpiredCodeLettersSQL, grace, batch)
	if err != nil {
		return 0, false, mapErr(err, "BearerLetters.Sweep", "")
	}
	return tag.RowsAffected(), tag.RowsAffected() >= int64(batch), nil
}

// SweepAgedSourceWindows — окна обращений источника, чей срок вышел раньше
// порога: такое окно при следующем обращении начинается заново, и строка
// ничего не считает.
func (r *HumanSessionRepo) SweepAgedSourceWindows(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument batch: must be positive")
	}
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM source_request_windows
		 WHERE ctid IN (
		       SELECT ctid FROM source_request_windows WHERE window_started_at <= now() - $1::interval LIMIT $2)`,
		grace, batch)
	if err != nil {
		return 0, false, mapErr(err, "SourceWindows.Sweep", "")
	}
	return tag.RowsAffected(), tag.RowsAffected() >= int64(batch), nil
}
