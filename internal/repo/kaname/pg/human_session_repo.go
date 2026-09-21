// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// human_session_repo.go — адаптер хранилища сессии человека, памяти первой
// аутентификации и следов неверных предъявлений (фаза Ф3, задача
// PRO-Robotech/kacho#1269). Порт — `internal/apps/kaname/api/humansession`.
//
// # Что этот файл НЕ называет — и почему
//
// Таблицу способа входа (`user_login_methods`) называет только её адаптер
// (`login_method_repo.go`, гейт `TestLoginVerifierStaysInside`). Замещение
// материала внутри транзакции этого адаптера поэтому ДЕЛЕГИРУЕТСЯ функции
// того файла (`replaceLoginVerifierTx`) — здесь ни имени таблицы, ни выхода
// материала нет.
//
// Операцию записи отсечки этот файл тоже не переписывает: она одна на дерево
// (`subjectCutoffRowSQL`, §4.1 п.17), и зовут её все писатели ОДНОЙ дверью
// `upsertSubjectCutoff` — она кладёт ОБЕ записи отсечки (kaname#313).

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// HumanSessionRepo — хранилище сессии на пуле.
type HumanSessionRepo struct {
	pool *pgxpool.Pool
}

// NewHumanSessionRepo — адаптер поверх пула.
func NewHumanSessionRepo(pool *pgxpool.Pool) *HumanSessionRepo {
	return &HumanSessionRepo{pool: pool}
}

// resolveSQL — запись по свёртке носителя вместе с тем, что о субъекте читает
// край. Срок и снятие судятся ЗДЕСЬ по переданному моменту, а не `now()` базы:
// часы — у вызывающего (форма Ф-д).
const resolveSQL = `
	SELECT s.id, s.user_id, s.authenticated_at, s.last_presented_at, s.expires_at,
	       s.assurance_level, s.presented_methods,
	       s.ended_at, s.created_at,
	       u.account_id, u.external_id, u.email, u.display_name, u.invite_status,
	       u.invited_by, u.created_at, u.labels, u.email_verified_at
	  FROM human_sessions s
	  JOIN users u ON u.id = s.user_id
	 WHERE s.bearer_digest = $1`

// Resolve — см. порт. Порядок причин несущий: снятая строка отвечает
// «снята» и тогда, когда срок вышел; истёкшая — «истекла» и у заблокированной
// личности; блокировка судится последней. Порядок закреплён пробой Ф3-10.
func (r *HumanSessionRepo) Resolve(ctx context.Context, digest domain.BearerDigest, now time.Time) (humansession.Resolved, humansession.NoSessionReason, error) {
	if digest == "" {
		return humansession.Resolved{}, humansession.NoSessionUnknown, nil
	}
	var (
		out         humansession.Resolved
		endedAt     *time.Time
		invitedBy   *string
		labels      []byte
		emailVerAt  *time.Time
		methods     []string
		inviteState string
	)
	err := r.pool.QueryRow(ctx, resolveSQL, string(digest)).Scan(
		&out.Session.ID, &out.Session.UserID, &out.Session.AuthenticatedAt, &out.Session.LastPresentedAt,
		&out.Session.ExpiresAt, &out.Session.AssuranceLevel, &methods,
		&endedAt, &out.Session.CreatedAt,
		&out.User.AccountID, &out.User.ExternalID, &out.User.Email, &out.User.DisplayName, &inviteState,
		&invitedBy, &out.User.CreatedAt, &labels, &emailVerAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return humansession.Resolved{}, humansession.NoSessionUnknown, nil
	}
	if err != nil {
		return humansession.Resolved{}, "", mapErr(err, "HumanSession.Resolve", "")
	}
	switch {
	case endedAt != nil:
		return humansession.Resolved{}, humansession.NoSessionEnded, nil
	case out.Session.Expired(now):
		return humansession.Resolved{}, humansession.NoSessionExpired, nil
	case domain.InviteStatus(inviteState) != domain.InviteStatusActive:
		// Заблокированная — и всякая иная, кроме активной: живая сессия бывает
		// только у активной личности (F4d-30, Ф3-10 N4).
		return humansession.Resolved{}, humansession.NoSessionBlocked, nil
	}
	out.Session.PresentedMethods = methods
	out.User.ID = out.Session.UserID
	out.User.InviteStatus = domain.InviteStatus(inviteState)
	if invitedBy != nil {
		out.User.InvitedBy = domain.UserID(*invitedBy)
	}
	if len(labels) > 0 {
		lbl, lerr := unmarshalLabels(labels)
		if lerr == nil {
			out.User.Labels = lbl
		}
	}
	out.EmailVerified = emailVerAt != nil
	return out, humansession.SessionFound, nil
}

// CountFailures — см. порт.
func (r *HumanSessionRepo) CountFailures(ctx context.Context, scope humansession.FailureScope, key string, since time.Time) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM login_failures WHERE scope = $1 AND key = $2 AND failed_at > $3`,
		string(scope), key, since).Scan(&n)
	if err != nil {
		return 0, mapErr(err, "LoginFailures.Count", "")
	}
	return n, nil
}

// OldestFailureSince — см. порт. `min` над пустым набором — NULL: «нет ни
// одного», а не ошибка.
func (r *HumanSessionRepo) OldestFailureSince(ctx context.Context, scope humansession.FailureScope, key string, since time.Time) (time.Time, bool, error) {
	var at *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT min(failed_at) FROM login_failures WHERE scope = $1 AND key = $2 AND failed_at > $3`,
		string(scope), key, since).Scan(&at)
	if err != nil {
		return time.Time{}, false, mapErr(err, "LoginFailures.Oldest", "")
	}
	if at == nil {
		return time.Time{}, false, nil
	}
	return *at, true, nil
}

// FirstAuthentication — см. порт.
func (r *HumanSessionRepo) FirstAuthentication(ctx context.Context, userID domain.UserID) (time.Time, bool, error) {
	return firstAuthenticationQ(ctx, r.pool, userID)
}

type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func firstAuthenticationQ(ctx context.Context, q rowQuerier, userID domain.UserID) (time.Time, bool, error) {
	var at time.Time
	err := q.QueryRow(ctx, `SELECT first_authenticated_at FROM human_first_authentications WHERE user_id = $1`,
		string(userID)).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, mapErr(err, "HumanFirstAuthentication.Get", string(userID))
	}
	return at, true, nil
}

// Writer — см. порт.
func (r *HumanSessionRepo) Writer(ctx context.Context) (humansession.Writer, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, mapErr(err, "HumanSession.Writer", "")
	}
	return &humanSessionWriter{tx: tx}, nil
}

// SweepUnservableSessions — уборка (форма Ф-ж): строки, которые `Resolve` уже
// не обслужит ни при каком носителе — истёкшие и снятые, — старше порога.
// Партия ограничена `ctid`-подзапросом; full=true — партия заполнена, звать ещё.
func (r *HumanSessionRepo) SweepUnservableSessions(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument batch: must be positive")
	}
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM human_sessions
		 WHERE ctid IN (
		       SELECT ctid FROM human_sessions
		        WHERE (expires_at <= now() - $1::interval)
		           OR (ended_at IS NOT NULL AND ended_at <= now() - $1::interval)
		        LIMIT $2)`, grace, batch)
	if err != nil {
		return 0, false, mapErr(err, "HumanSession.Sweep", "")
	}
	return tag.RowsAffected(), tag.RowsAffected() >= int64(batch), nil
}

// SweepAgedFailures — следы неверных предъявлений старше порога (самого
// длинного окна).
func (r *HumanSessionRepo) SweepAgedFailures(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument batch: must be positive")
	}
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM login_failures
		 WHERE ctid IN (
		       SELECT ctid FROM login_failures WHERE failed_at <= now() - $1::interval LIMIT $2)`,
		grace, batch)
	if err != nil {
		return 0, false, mapErr(err, "LoginFailures.Sweep", "")
	}
	return tag.RowsAffected(), tag.RowsAffected() >= int64(batch), nil
}

// humanSessionWriter — одна транзакция записи.
type humanSessionWriter struct {
	tx pgx.Tx
}

func (w *humanSessionWriter) InsertSession(ctx context.Context, s domain.HumanSession, digest domain.BearerDigest) error {
	if err := s.Validate(); err != nil {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if digest == "" {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument human_session.bearer_digest: required")
	}
	_, err := w.tx.Exec(ctx, `
		INSERT INTO human_sessions
		    (id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at,
		     assurance_level, presented_methods)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		string(s.ID), string(s.UserID), string(digest), s.AuthenticatedAt, s.LastPresentedAt, s.ExpiresAt,
		s.AssuranceLevel, s.PresentedMethods)
	if err != nil {
		return mapErr(err, "HumanSession.Insert", string(s.ID))
	}
	return nil
}

// RememberFirstAuthentication — LEAST под конфликтом: коммутативно, не
// поднимает никогда (Р5).
func (w *humanSessionWriter) RememberFirstAuthentication(ctx context.Context, userID domain.UserID, at time.Time) error {
	if userID == "" || at.IsZero() {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument first_authentication: user_id and moment required")
	}
	_, err := w.tx.Exec(ctx, `
		INSERT INTO human_first_authentications (user_id, first_authenticated_at)
		VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE
		    SET first_authenticated_at = LEAST(human_first_authentications.first_authenticated_at, EXCLUDED.first_authenticated_at)`,
		string(userID), at)
	if err != nil {
		return mapErr(err, "HumanFirstAuthentication.Remember", string(userID))
	}
	return nil
}

func (w *humanSessionWriter) FirstAuthentication(ctx context.Context, userID domain.UserID) (time.Time, bool, error) {
	return firstAuthenticationQ(ctx, w.tx, userID)
}

// EndSession — отметка снятия на живой (не снятой) записи; повтор ничего не
// пишет (Ф1-18).
func (w *humanSessionWriter) EndSession(ctx context.Context, id domain.HumanSessionID, at time.Time, reason string) (bool, error) {
	tag, err := w.tx.Exec(ctx, `
		UPDATE human_sessions SET ended_at = $2, ended_reason = $3
		 WHERE id = $1 AND ended_at IS NULL`, string(id), at, reason)
	if err != nil {
		return false, mapErr(err, "HumanSession.End", string(id))
	}
	return tag.RowsAffected() == 1, nil
}

// endSessionsOfSQL — ОДНА операция снятия живых записей личности на всё дерево.
//
// Выписана константой, потому что исполнителей у неё ДВА: транзакция полосы
// входа (смена пароля, снятие второго фактора, завершение восстановления) и
// пул административного принудительного выхода. Две копии одного оператора
// разошлись бы молча — и разошлись бы та, которую правили последней, — а
// расхождение здесь означает «по одной полосе человек выведен, по другой нет».
//
// `keep` пустой снимает ВСЕ живые записи: пустая строка не равна ни одному
// идентификатору, поэтому исключать ей нечего. Это не подставное значение, а
// то же поведение, каким им уже пользуется завершение восстановления.
const endSessionsOfSQL = `
		UPDATE human_sessions SET ended_at = $3, ended_reason = $4
		 WHERE user_id = $1 AND id <> $2 AND ended_at IS NULL
		 RETURNING id`

// EndOtherSessions — все прочие живые записи личности, кроме keep. Истёкшие
// строки тоже помечаются: «сессии нет» у них уже есть, а уборка снимет обе
// формы одинаково.
func (w *humanSessionWriter) EndOtherSessions(ctx context.Context, userID domain.UserID, keep domain.HumanSessionID, at time.Time, reason string) (int, error) {
	ended, err := endSessionsOf(ctx, w.tx, userID, keep, at, reason)
	if err != nil {
		return 0, mapErr(err, "HumanSession.EndOthers", string(userID))
	}
	return len(ended), nil
}

// endSessionsOf исполняет ОДИН оператор снятия и возвращает ИДЕНТИФИКАТОРЫ
// снятых записей.
//
// Идентификаторы, а не число: по ним отзывается выданное в этих сессиях, и
// второй запрос «а какие это были» вернул бы уже снятые строки вперемешку с
// теми, что сняли до нас.
func endSessionsOf(ctx context.Context, tx pgx.Tx, userID domain.UserID,
	keep domain.HumanSessionID, at time.Time, reason string,
) ([]string, error) {
	rows, err := tx.Query(ctx, endSessionsOfSQL, string(userID), string(keep), at, reason)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if serr := rows.Scan(&id); serr != nil {
			return nil, serr
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// EndAllSessions — ВСЕ живые записи сессии входа личности, снятые на пуле.
//
// Читатель у него один — административный принудительный выход, — и приходит он
// не с полосы входа, а с внутреннего слушателя: своей транзакции у него здесь
// нет, а отсечка субъекта ложится СВОЕЙ транзакцией до этого вызова.
//
// ПОЧЕМУ ЭТО ОТДЕЛЬНАЯ ОТ ОТСЕЧКИ ЗАПИСЬ, А НЕ ЕЁ СЛЕДСТВИЕ, И ЧТО ИМЕННО
// ИЗМЕРЕНО.
//
// Отсечка судит ВЫДАЧУ, и судит её НЕ ЗДЕСЬ: резолв нашей сессии отсечку не
// применяет и говорит это о себе прямо (`humansession/resolve.go`) — строка
// судится по трём признакам: снята · истекла · личность неактивна. Приёмка Ф3-25
// ставит отказ предъявленной сессии НА КРАЮ, сравнением момента аутентификации
// с отсечкой, и эта запись того пути НЕ ЗАМЕЩАЕТ.
//
// Измерено ровно одно: без снятия строка остаётся живой, и `Resolve` отвечает
// «сессия есть» на носитель, выданный до выхода. Следствия этого — три, и все
// три внутри службы:
//
//  1. СИММЕТРИЯ ДВУХ ВЫХОДОВ. Наш собственный выход снимает строку И пишет
//     отсечку (`humansession/logout.go`). Тот же акт, совершённый
//     распорядителем, писал только отсечку — то есть один и тот же выход
//     оставлял разный след;
//  2. СТРОКА НЕ УБИРАЕТСЯ. Уборка сносит истёкшие и СНЯТЫЕ строки
//     (`SweepUnservableSessions`); не снятая живёт до своего абсолютного срока;
//  3. ОТКАЗ ЗАВИСИТ ОТ ВТОРОГО ВОПРОСА. Пока строка жива, «сессии нет» получает
//     только тот, кто СВЕРХ резолва спросил и отсечку. Снятая строка отвечает
//     «снята» одним вопросом, и отвечает так всякому читателю.
//
// Возвращает ЧИСЛО снятых записей: «снимать было нечего» и «сняли» — разные
// исходы, и слитые в один они читаются вызывающим одинаково.
func (r *HumanSessionRepo) EndAllSessions(ctx context.Context, userID domain.UserID, at time.Time, reason string) (int, error) {
	if userID == "" {
		return 0, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument human_session.user_id: required")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, mapErr(err, "HumanSession.EndAll", string(userID))
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ended, err := endSessionsOf(ctx, tx, userID, "", at, reason)
	if err != nil {
		return 0, mapErr(err, "HumanSession.EndAll", string(userID))
	}

	// ВЫДАННОЕ В ЭТИХ СЕССИЯХ ОТЗЫВАЕТСЯ ТОЙ ЖЕ ТРАНЗАКЦИЕЙ (задача kaname#313).
	//
	// Привязка семейства к сессии — внешний ключ с каскадом НА УДАЛЕНИИ строки,
	// а снятие строку не удаляет: оно ставит отметку, а удаляет строку уборка
	// спустя порог удержания. Без этого оператора обновляющий токен снятой
	// сессии жил бы и ротировался в свежие, а окно равнялось бы величине
	// УДЕРЖАНИЯ — то есть настройке хранения, а не решению о безопасности.
	//
	// Той же транзакцией, а не следом: снятая сессия с живым семейством — это
	// состояние, в котором глагол уже ответил, а доступ ещё есть.
	if _, rerr := revokeFamiliesOfSessionsTx(ctx, tx, ended,
		domain.FamilyRevokedBySessionEnd); rerr != nil {
		return 0, rerr
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, mapErr(err, "HumanSession.EndAll", string(userID))
	}
	return len(ended), nil
}

// RotateBearer — новый дайджест, сдвиг момента последнего предъявления; момент
// аутентификации и срок не трогаются by construction (их нет в SET).
func (w *humanSessionWriter) RotateBearer(ctx context.Context, id domain.HumanSessionID, digest domain.BearerDigest, presentedAt time.Time) error {
	if digest == "" {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument human_session.bearer_digest: required")
	}
	tag, err := w.tx.Exec(ctx, `
		UPDATE human_sessions SET bearer_digest = $2, last_presented_at = $3
		 WHERE id = $1 AND ended_at IS NULL`, string(id), string(digest), presentedAt)
	if err != nil {
		return mapErr(err, "HumanSession.Rotate", string(id))
	}
	if tag.RowsAffected() != 1 {
		return iamerr.Wrapf(iamerr.ErrNotFound, "HumanSession %s not found", id)
	}
	return nil
}

// PresentInSession — предъявление способа внутри сессии (Ф11 Р5, Ф12): одной
// записью множество предъявленного, уровень, новый дайджест и момент; момент
// аутентификации и срок не трогаются by construction (их нет в SET). Словарь
// способов и ось уровня судит CHECK строки, а не эта функция.
func (w *humanSessionWriter) PresentInSession(ctx context.Context, id domain.HumanSessionID, methods []string, level string, digest domain.BearerDigest, presentedAt time.Time) error {
	if digest == "" {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument human_session.bearer_digest: required")
	}
	if len(methods) == 0 {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument human_session.presented_methods: required")
	}
	tag, err := w.tx.Exec(ctx, `
		UPDATE human_sessions
		   SET presented_methods = $2, assurance_level = $3, bearer_digest = $4, last_presented_at = $5
		 WHERE id = $1 AND ended_at IS NULL`, string(id), methods, level, string(digest), presentedAt)
	if err != nil {
		return mapErr(err, "HumanSession.Present", string(id))
	}
	if tag.RowsAffected() != 1 {
		return iamerr.Wrapf(iamerr.ErrNotFound, "HumanSession %s not found", id)
	}
	return nil
}

// UpsertCutoff — ТА ЖЕ дверь, что у прочих писателей отсечки: кладёт ОБЕ
// записи одной транзакцией (`upsertSubjectCutoff`, kaname#313).
//
// Здесь стоял прямой вызов оператора ПЕРВОЙ записи, и вторую этот путь не писал
// вовсе. Читателей у второй — авторитет отзыва на пути запроса, поэтому выход,
// смена пароля, восстановление и сброс второго фактора снимали доступ на
// выдаче и НЕ снимали на предъявлении: прежний носитель продолжал
// аутентифицировать вызовы.
func (w *humanSessionWriter) UpsertCutoff(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	if err := u.Validate(); err != nil {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	return upsertSubjectCutoff(ctx, w.tx, u, revokedBy)
}

// ReplaceLoginVerifier — делегируется адаптеру таблицы секрета (см. шапку).
func (w *humanSessionWriter) ReplaceLoginVerifier(ctx context.Context, m domain.LoginMethod) (bool, error) {
	return replaceLoginVerifierTx(ctx, w.tx, m)
}

// Операторы второго фактора (Ф12) — те же делегации: таблицу секрета называет
// только её адаптер.
func (w *humanSessionWriter) UpsertPendingTOTP(ctx context.Context, m domain.LoginMethod) (bool, error) {
	return upsertPendingTOTPTx(ctx, w.tx, m)
}

func (w *humanSessionWriter) ActivateTOTP(ctx context.Context, userID domain.UserID, pendingSince time.Time, step int64, at time.Time) (bool, error) {
	return activateTOTPTx(ctx, w.tx, userID, pendingSince, step, at)
}

func (w *humanSessionWriter) ReplaceLookupSet(ctx context.Context, m domain.LoginMethod) error {
	return replaceLookupSetTx(ctx, w.tx, m)
}

func (w *humanSessionWriter) LockLookupSet(ctx context.Context, userID domain.UserID) (domain.LoginMethod, bool, error) {
	return lockLookupSetTx(ctx, w.tx, userID)
}

func (w *humanSessionWriter) ConsumeLookupElement(ctx context.Context, userID domain.UserID, element string) (bool, error) {
	return consumeLookupElementTx(ctx, w.tx, userID, element)
}

func (w *humanSessionWriter) RecordAcceptedStep(ctx context.Context, userID domain.UserID, step int64) (bool, error) {
	return recordAcceptedStepTx(ctx, w.tx, userID, step)
}

func (w *humanSessionWriter) RemoveSecondFactor(ctx context.Context, userID domain.UserID) (bool, error) {
	return removeSecondFactorTx(ctx, w.tx, userID)
}

func (w *humanSessionWriter) RecordFailure(ctx context.Context, scope humansession.FailureScope, key string, at time.Time) error {
	if key == "" {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument login_failure.key: required")
	}
	if _, err := w.tx.Exec(ctx, `INSERT INTO login_failures (scope, key, failed_at) VALUES ($1, $2, $3)`,
		string(scope), key, at); err != nil {
		return mapErr(err, "LoginFailures.Record", "")
	}
	return nil
}

func (w *humanSessionWriter) ResetFailures(ctx context.Context, scope humansession.FailureScope, key string) error {
	if _, err := w.tx.Exec(ctx, `DELETE FROM login_failures WHERE scope = $1 AND key = $2`, string(scope), key); err != nil {
		return mapErr(err, "LoginFailures.Reset", "")
	}
	return nil
}

func (w *humanSessionWriter) EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error {
	return insertAuditEventTx(ctx, w.tx, ev)
}

func (w *humanSessionWriter) Commit(ctx context.Context) error {
	if err := w.tx.Commit(ctx); err != nil {
		return mapErr(err, "", "")
	}
	return nil
}

func (w *humanSessionWriter) Rollback(ctx context.Context) error {
	err := w.tx.Rollback(ctx)
	if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
}

var (
	_ humansession.Store          = (*HumanSessionRepo)(nil)
	_ humansession.Writer         = (*humanSessionWriter)(nil)
	_ humansession.SessionSweeper = (*HumanSessionRepo)(nil)
	_ humansession.FailureSweeper = (*HumanSessionRepo)(nil)
)
