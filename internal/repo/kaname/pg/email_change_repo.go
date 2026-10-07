// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// email_change_repo.go — адаптер отложенной смены адреса почты, её кода, двух
// писем и оператора исхода смены (задача PRO-Robotech/kaname#635; приёмка
// `docs/engineering/acceptance/email-change-is-confirmed-from-the-new-address.md`;
// порт — `internal/apps/kaname/api/humansession`, операции на транзакции
// `humanSessionWriter`).
//
// # Темп человека — ОДИН условный оператор (Р6, ban #10)
//
// Строка принятого запроса вставляется оператором, условие которого и есть
// предел: нет запроса моложе интервала и запросов в окне меньше предела.
// Решение — число вставленных строк, а не чтение перед записью. Транзакция
// открыта замком писателя нескольких сессий на строке человека: одновременные
// запросы одного человека сериализованы им.
//
// # Предъявление — ОДИН оператор (Р5)
//
// Счёт попытки и сверка свёртки не разнесены чтением и записью. Строка запроса
// на занятый адрес свёртки не несёт: сравнение с ней ложно, и такая строка
// только считает попытки — как неверный код.
//
// # Адрес пишет РОВНО ОДИН оператор (Р8 п. 1, Р9)
//
// `humanSessionWriter.ChangeEmail` — единственный законный писатель адреса в
// существующую строку человека; его называет перечень гейта
// `TestPeopleAddressHasNoWriterInServiceCode`
// (`internal/check/people_address_lawful_writers.go`). Уникальность решает ключ
// `users_identity_email_uniq` в этом операторе, а не проверка перед ним; отказ
// ключа — `humansession.ErrEmailInUse`.
//
// Часы — вызывающего (форма Ф-д): момент приходит параметром. Окно писем
// адресата судит часы базы — так же, как у приглашения и восстановления.

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/invite_mail_outbox"
)

// addressTakenSQL — адрес занят любой строкой человека: тем же выражением, что
// ключ `users_identity_email_uniq (lower(email))`.
const addressTakenSQL = `SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = lower($1))`

// AddressTaken — см. порт.
func (w *humanSessionWriter) AddressTaken(ctx context.Context, email domain.Email) (bool, error) {
	var taken bool
	if err := w.tx.QueryRow(ctx, addressTakenSQL, string(email)).Scan(&taken); err != nil {
		return false, mapErr(err, "EmailChange.AddressTaken", "")
	}
	return taken, nil
}

// supersedeEmailChangeCodesSQL — живая отложенная смена человека вытеснена;
// строка остаётся: по строкам считается темп.
const supersedeEmailChangeCodesSQL = `
	UPDATE email_change_codes
	   SET superseded_at = GREATEST($2::timestamptz, issued_at)
	 WHERE user_id = $1 AND consumed_at IS NULL AND superseded_at IS NULL`

// SupersedeEmailChangeCodes — см. порт.
func (w *humanSessionWriter) SupersedeEmailChangeCodes(ctx context.Context, userID domain.UserID, at time.Time) (int, error) {
	tag, err := w.tx.Exec(ctx, supersedeEmailChangeCodesSQL, string(userID), at)
	if err != nil {
		return 0, mapErr(err, "EmailChange.Supersede", string(userID))
	}
	return int(tag.RowsAffected()), nil
}

// insertEmailChangeCodePacedSQL — строка принятого запроса ПОД темпом человека:
// $7 — интервал, $8 — окно, $9 — число запросов за окно. Свёртка ($4) пуста у
// запроса на занятый адрес.
const insertEmailChangeCodePacedSQL = `
	INSERT INTO email_change_codes (id, user_id, new_email, code_digest, issued_at, expires_at)
	SELECT $1, $2, $3, NULLIF($4, ''), $5, $6
	 WHERE NOT EXISTS (
	         SELECT 1 FROM email_change_codes
	          WHERE user_id = $2 AND issued_at > $5::timestamptz - $7::interval)
	   AND (SELECT count(*) FROM email_change_codes
	         WHERE user_id = $2 AND issued_at > $5::timestamptz - $8::interval) < $9`

// emailChangePaceSQL — чем отказ темпа объясняется: момент последнего запроса и
// самый старый запрос окна с их числом. Читается ПОСЛЕ отказа оператора и
// выбирает только срок ответа, а не исход.
const emailChangePaceSQL = `
	SELECT max(issued_at),
	       min(issued_at) FILTER (WHERE issued_at > $2::timestamptz - $3::interval),
	       count(*) FILTER (WHERE issued_at > $2::timestamptz - $3::interval)
	  FROM email_change_codes
	 WHERE user_id = $1`

// InsertEmailChangeCodePaced — см. порт.
func (w *humanSessionWriter) InsertEmailChangeCodePaced(ctx context.Context, c domain.EmailChangeCode, pace humansession.VerificationPace) (humansession.LetterRefusal, error) {
	if err := c.Validate(); err != nil {
		return humansession.LetterRefusal{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if err := pace.Validate(); err != nil {
		return humansession.LetterRefusal{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	tag, err := w.tx.Exec(ctx, insertEmailChangeCodePacedSQL,
		string(c.ID), string(c.UserID), string(c.NewEmail), string(c.Digest), c.IssuedAt, c.ExpiresAt,
		pace.Interval, pace.Window, pace.Limit)
	if err != nil {
		return humansession.LetterRefusal{}, mapErr(err, "EmailChange.Insert", string(c.UserID))
	}
	if tag.RowsAffected() == 1 {
		return humansession.LetterRefusal{}, nil
	}
	var (
		last, oldest *time.Time
		inWindow     int
	)
	if err := w.tx.QueryRow(ctx, emailChangePaceSQL, string(c.UserID), c.IssuedAt, pace.Window).Scan(&last, &oldest, &inWindow); err != nil {
		return humansession.LetterRefusal{}, mapErr(err, "EmailChange.Pace", string(c.UserID))
	}
	return humansession.LetterRefusal{Refused: true, RetryAfter: letterRetryAfter(c.IssuedAt, pace, last, oldest, inWindow)}, nil
}

// emailChangeWindowRetrySQL — срок до перехода окна адресата: читается ПОСЛЕ
// отказа оператора списания и выбирает только срок ответа, а не исход.
const emailChangeWindowRetrySQL = `
	SELECT GREATEST(EXTRACT(EPOCH FROM (window_started_at + make_interval(secs => $3) - now())), 0)::bigint
	  FROM invite_mail_windows
	 WHERE kind = $1 AND recipient = $2`

// ChargeEmailChangeWindow — см. порт: списание тем же оператором, что у
// приглашения и восстановления (`chargeInviteMailWindowTx`, вид
// `email-change`).
func (w *humanSessionWriter) ChargeEmailChangeWindow(ctx context.Context, to domain.Email, limit outboxtypes.InviteMailRateLimit) (humansession.LetterRefusal, error) {
	admitted, err := chargeInviteMailWindowTx(ctx, w.tx, mailWindowEmailChange, string(to), limit)
	if err != nil {
		return humansession.LetterRefusal{}, mapErr(err, "EmailChange.RecipientWindow", "")
	}
	if admitted {
		return humansession.LetterRefusal{}, nil
	}
	windowSeconds := int64(limit.Window / time.Second)
	if windowSeconds < 1 {
		windowSeconds = 1
	}
	var seconds int64
	recipient := strings.ToLower(strings.TrimSpace(string(to)))
	if err := w.tx.QueryRow(ctx, emailChangeWindowRetrySQL, string(mailWindowEmailChange), recipient, windowSeconds).Scan(&seconds); err != nil {
		return humansession.LetterRefusal{}, mapErr(err, "EmailChange.RecipientWindow", "")
	}
	wait := time.Duration(seconds) * time.Second
	if wait <= 0 {
		wait = time.Second
	}
	return humansession.LetterRefusal{Refused: true, RetryAfter: wait}, nil
}

// EmitEmailChangeMail — письмо с кодом на новый адрес той же транзакцией (Р7).
func (w *humanSessionWriter) EmitEmailChangeMail(ctx context.Context, in humansession.EmailChangeMailIntent) error {
	if in.Code.IsZero() {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument email_change_mail.code: required")
	}
	if err := invite_mail_outbox.EmitEmailChangeTx(ctx, w.tx, string(in.UserID), string(in.AccountID), string(in.To), in.Code.Letter(), in.ValidFor); err != nil {
		return mapErr(err, "EmailChangeMail.Emit", string(in.UserID))
	}
	return nil
}

// presentEmailChangeCodeSQL — ОДИН оператор предъявления (см. шапку): $2 —
// свёртка предъявленного, $3 — момент, $4 — предел попыток на код. У строки
// без свёртки сравнение ложно.
const presentEmailChangeCodeSQL = `
	UPDATE email_change_codes c
	   SET attempts    = c.attempts + CASE WHEN c.code_digest IS NOT DISTINCT FROM $2 THEN 0 ELSE 1 END,
	       consumed_at = CASE WHEN c.code_digest IS NOT DISTINCT FROM $2 THEN $3::timestamptz ELSE NULL END
	 WHERE c.user_id = $1
	   AND c.consumed_at IS NULL
	   AND c.superseded_at IS NULL
	   AND c.expires_at > $3::timestamptz
	   AND c.attempts < $4
	RETURNING (c.code_digest IS NOT DISTINCT FROM $2) AS matched, c.new_email, c.attempts`

// PresentEmailChangeCode — см. порт.
func (w *humanSessionWriter) PresentEmailChangeCode(ctx context.Context, userID domain.UserID, digest domain.CodeDigest, now time.Time, attempts int) (humansession.PresentedCode, domain.Email, error) {
	if userID == "" || digest == "" || attempts <= 0 {
		return humansession.CodeNotFound, "", nil
	}
	var (
		matched  bool
		newEmail string
		spent    int
	)
	err := w.tx.QueryRow(ctx, presentEmailChangeCodeSQL, string(userID), string(digest), now, attempts).Scan(&matched, &newEmail, &spent)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return humansession.CodeNotFound, "", nil
		}
		return humansession.CodeNotFound, "", mapErr(err, "EmailChange.Present", string(userID))
	}
	if !matched {
		if spent >= attempts {
			return humansession.CodeExhausted, "", nil
		}
		return humansession.CodeMismatched, "", nil
	}
	return humansession.CodeMatched, domain.Email(newEmail), nil
}

// ChangeEmail — ЕДИНСТВЕННЫЙ законный писатель адреса в существующую строку
// человека (шапка файла). Прежний адрес читается тем же оператором: строка
// взята замком транзакции, и чтение до правки видит её значение до смены.
// Отметку снимает триггер `users_email_change_drops_verification`; ставит её
// вызывающий существующим оператором отметки той же транзакцией.
func (w *humanSessionWriter) ChangeEmail(ctx context.Context, userID domain.UserID, newEmail domain.Email) (domain.Email, error) {
	if userID == "" || strings.TrimSpace(string(newEmail)) == "" {
		return "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument email: user and new address required")
	}
	var previous string
	err := w.tx.QueryRow(ctx, `
		WITH prev AS (SELECT email FROM users WHERE id = $1)
		UPDATE users SET email = $2 WHERE id = $1
		RETURNING (SELECT email FROM prev)`, string(userID), string(newEmail)).Scan(&previous)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", userID)
		}
		mapped := mapErr(err, "User.ChangeEmail", string(userID))
		if errors.Is(mapped, iamerr.ErrAlreadyExists) {
			return "", humansession.ErrEmailInUse
		}
		return "", mapped
	}
	return domain.Email(previous), nil
}

// EmitEmailChangedMail — уведомление на прежний адрес той же транзакцией (Р7).
func (w *humanSessionWriter) EmitEmailChangedMail(ctx context.Context, in humansession.EmailChangedMailIntent) error {
	if err := invite_mail_outbox.EmitEmailChangedTx(ctx, w.tx, string(in.UserID), string(in.AccountID), string(in.To), in.ChangedAt); err != nil {
		return mapErr(err, "EmailChangedMail.Emit", string(in.UserID))
	}
	return nil
}

// SweepUnservableEmailChangeCodes — уборка: строки старше окна темпа, которые
// ни предъявление, ни темп уже не прочтут. Строка очереди письма с кодом
// снимается уборкой писем с истёкшим кодом; строка отложенной смены несёт
// только свёртку.
func (r *HumanSessionRepo) SweepUnservableEmailChangeCodes(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument batch: must be positive")
	}
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM email_change_codes
		 WHERE ctid IN (
		       SELECT ctid FROM email_change_codes
		        WHERE issued_at <= now() - $1::interval
		          AND (expires_at <= now() OR consumed_at IS NOT NULL OR superseded_at IS NOT NULL)
		        LIMIT $2)`, grace, batch)
	if err != nil {
		return 0, false, mapErr(err, "EmailChangeCodes.Sweep", "")
	}
	return tag.RowsAffected(), tag.RowsAffected() >= int64(batch), nil
}

// EmitSubjectChangeEvent — строка очереди смены субъекта о человеке (Р8 п. 8)
// ТЕМ ЖЕ методом писателя выдач, которым пишут выдачи и членства, над той же
// транзакцией исхода: `op` и `event_type` — один вид события, адресов в
// нагрузке нет.
func (w *RegistrationWriter) EmitSubjectChangeEvent(ctx context.Context, c humansession.SubjectChange) error {
	return w.mirror.AccessBindingsW().EmitSubjectChangeEvent(ctx, access_binding.SubjectChangeEvent{
		SubjectID: c.SubjectID, SubjectType: c.SubjectType, Op: c.Op, EventType: c.Op,
	})
}

var _ humansession.EmailChangeWriter = (*RegistrationWriter)(nil)
