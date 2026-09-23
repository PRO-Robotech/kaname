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
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
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

// SessionSetWriter — см. порт: транзакция, ПЕРВЫМ оператором которой взята
// строка личности замком писателя нескольких сессий (`lockPersonForSessionSetSQL`).
func (r *HumanSessionRepo) SessionSetWriter(ctx context.Context, userID domain.UserID) (humansession.Writer, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, mapErr(err, "HumanSession.SessionSetWriter", "")
	}
	w := &humanSessionWriter{tx: tx}
	if err := w.holdPersonForSessionSet(ctx, userID); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return w, nil
}

// sweepUnservableSessionsSQL — оператор уборки записей сессии, которые
// `Resolve` уже не обслужит: истёкшие и снятые старше порога ($1), партией не
// больше $2.
const sweepUnservableSessionsSQL = `
		DELETE FROM human_sessions
		 WHERE ctid IN (
		       SELECT ctid FROM human_sessions
		        WHERE (expires_at <= now() - $1::interval)
		           OR (ended_at IS NOT NULL AND ended_at <= now() - $1::interval)
		        LIMIT $2)`

// SweepUnservableSessions — уборка (форма Ф-ж): строки, которые `Resolve` уже
// не обслужит ни при каком носителе — истёкшие и снятые, — старше порога.
// Партия ограничена `ctid`-подзапросом; full=true — партия заполнена, звать ещё.
func (r *HumanSessionRepo) SweepUnservableSessions(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument batch: must be positive")
	}
	tag, err := r.pool.Exec(ctx, sweepUnservableSessionsSQL, grace, batch)
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
	// person — личность, строку которой транзакция держит; пусто — никакую.
	// Одна транзакция держит строку не более чем одной личности: порядка между
	// личностями не задаёт никто.
	person domain.UserID
	// sessionSet — строка личности взята замком писателя нескольких сессий
	// (`FOR NO KEY UPDATE`), а не только ключевым (`FOR KEY SHARE`).
	sessionSet bool
}

// lockPersonForSessionSetSQL — строка личности замком ПИСАТЕЛЯ НЕСКОЛЬКИХ
// СЕССИЙ этого человека (kaname#340).
//
// # ЗАЧЕМ ЗАМОК НА ЛИЧНОСТИ, А НЕ ПОРЯДОК СТРОК СЕССИИ
//
// Писателей нескольких записей сессии одного человека четыре: принудительный
// выход, смена пароля, снятие второго фактора, завершение восстановления. Смена
// пароля и снятие фактора снимают прочие записи и затем пишут в свою — то есть
// берут строки сессии «прочие → своя», а принудительный выход берёт все одним
// оператором в порядке просмотра. Порядки встречные: выход брал свою запись
// смены и ждал прочие, смена ждала свою — взаимная блокировка в 3 прогонах из
// 3, жертвой каждый раз выход (`force_logout_concurrent_teardown_integration_test.go`,
// `session_set_writers_person_first_integration_test.go`). Замок на строке
// личности, взятый ДО первой строки сессии, сериализует всех четверых на
// одной строке, и порядок строк сессии между ними перестаёт что-либо значить;
// с ним — 0 взаимных блокировок из 3 в каждой из двух сцен.
//
// # ПОЧЕМУ ЭТА СИЛА
//
// `FOR NO KEY UPDATE` конфликтует сам с собой — это и есть сериализация — и с
// удалением личности (`FOR UPDATE`); с проверкой внешнего ключа (`FOR KEY
// SHARE`) он СОВМЕСТИМ, поэтому вход человека (вставка сессии), выдача кода и
// запись отсечки им не останавливаются. Обычные правки строки личности
// (`UPDATE users` неключевых колонок) с ним сериализуются: ни одна из них в
// дереве не берёт до этого строк сессии, способа входа или кода
// восстановления, так что цикла с ними нет.
//
// Строки может не быть: тогда держать нечего, и об отсутствии личности судит
// внешний ключ следующей записи.
const lockPersonForSessionSetSQL = `
SELECT 1 FROM kaname.users WHERE id = $1 FOR NO KEY UPDATE`

// holdPersonForSessionSet — строка личности замком писателя нескольких сессий,
// если транзакция ещё не держит её так. Транзакция, уже держащая строку ДРУГОЙ
// личности, отказывает: две такие транзакции во встречном порядке личностей
// блокировали бы друг друга.
//
// Пустая личность — строки нет: оператор исполняется (цена полосы «адреса нет
// ни у кого» та же, что у полосы «адрес есть»), но держать нечего, и отметка не
// ставится.
func (w *humanSessionWriter) holdPersonForSessionSet(ctx context.Context, userID domain.UserID) error {
	if w.person != "" && w.person != userID {
		return iamerr.Wrapf(iamerr.ErrInternal,
			"human session writer: the transaction already holds another person and cannot serialize on a second one")
	}
	if w.sessionSet && w.person == userID {
		return nil
	}
	if _, err := w.tx.Exec(ctx, lockPersonForSessionSetSQL, string(userID)); err != nil {
		return mapErr(err, "User", string(userID))
	}
	if userID != "" {
		w.person, w.sessionSet = userID, true
	}
	return nil
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
// пишет (Ф1-18). Вместе с записью снимается и ВЫДАННОЕ В НЕЙ, той же
// транзакцией (kaname#313).
//
// # ПОЧЕМУ ОТЗЫВ ЗДЕСЬ ОБЯЗАТЕЛЕН
//
// Живой вызывающий у этого метода — СОБСТВЕННЫЙ ВЫХОД ЧЕЛОВЕКА. Ротацию
// обновляющего токена останавливает ровно отзыв семейства: оператор ротации не
// читает ни отметку окончания сессии, ни одну из отсечек. Значит без отзыва
// человек выходил сам, запись помечалась окончённой, а выданное в ней
// продолжало ротироваться в свежие токены — то же, что чинилось для
// распорядителя.
//
// # ПОЧЕМУ ОТЗЫВ СТОИТ ПОД УСЛОВИЕМ СНЯТИЯ
//
// Отзывается семейство ровно тогда, когда запись СНЯТА ЭТИМ вызовом. Повторный
// выход и гонка с параллельным ничего не снимают — и отзывать им нечего:
// семейство уже отозвал тот, кто снял запись. Безусловный отзыв здесь означал
// бы, что проигравший гонку переписывает причину отзыва победителя.
func (w *humanSessionWriter) EndSession(ctx context.Context, id domain.HumanSessionID, at time.Time, reason string) (bool, error) {
	tag, err := w.tx.Exec(ctx, `
		UPDATE human_sessions SET ended_at = $2, ended_reason = $3
		 WHERE id = $1 AND ended_at IS NULL`, string(id), at, reason)
	if err != nil {
		return false, mapErr(err, "HumanSession.End", string(id))
	}
	ended := tag.RowsAffected() == 1
	if !ended {
		return false, nil
	}
	if _, rerr := revokeFamiliesOfSessionsTx(ctx, w.tx, []string{string(id)},
		domain.FamilyRevokedBySessionEnd); rerr != nil {
		return false, rerr
	}
	return true, nil
}

// endSessionsOfSQL — ОДНА операция снятия живых записей личности на всё дерево.
//
// Выписана константой, потому что вызывающих у неё ДВА: полоса входа (смена
// пароля, снятие второго фактора, завершение восстановления) и
// административный принудительный выход (`ForceLogoutWriter`, kaname#340). Оба
// исполняют её ТРАНЗАКЦИЕЙ писателя сессии, через `EndOtherSessions`. Две копии
// одного оператора разошлись бы молча — и разошлись бы та, которую правили
// последней, — а расхождение здесь означает «по одной полосе человек выведен,
// по другой нет».
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
//
// Строку личности дверь берёт САМА, раньше первой строки сессии
// (`holdPersonForSessionSet`): порядок захвата строк сессии между писателями
// нескольких сессий иначе зависел бы от того, помнит ли о нём каждый
// вызывающий. Транзакция, открытая `SessionSetWriter` или уже снимавшая записи
// той же личности, её уже держит, и повторного оператора нет.
func (w *humanSessionWriter) EndOtherSessions(ctx context.Context, userID domain.UserID, keep domain.HumanSessionID, at time.Time, reason string) (int, error) {
	if err := w.holdPersonForSessionSet(ctx, userID); err != nil {
		return 0, err
	}
	return endSessionsAndRevokeWhatTheyHold(ctx, w.tx, userID, keep, at, reason)
}

// endSessionsAndRevokeWhatTheyHold — ЕДИНСТВЕННЫЙ способ снять сессии: снимает
// записи И отзывает выданное в них (задача kaname#313).
//
// # ПОЧЕМУ ЭТО ОДИН ОПЕРАТОР, А НЕ ДВА РЯДОМ
//
// Ротацию обновляющего токена останавливает РОВНО отзыв семейства: запрос
// ротации не читает ни отметку окончания сессии, ни одну из отсечек — он судит
// по `active`, сроку токена и отметке отзыва семейства, и больше ни по чему.
// Значит сессия, снятая БЕЗ отзыва семейства, снята только в записи: её
// обновляющий токен продолжает ротироваться в свежие.
//
// Пока снятие и отзыв были двумя действиями, «снять и не отозвать» было
// ПРЕДСТАВИМО — и представилось дважды. Сперва из двух методов, снимающих
// НЕСКОЛЬКО записей, отзывал один. Затем обнаружился третий — снятие ОДНОЙ
// записи по идентификатору (`EndSession`), чей живой вызывающий есть
// собственный выход человека; он не отзывал ничего, а шапка здесь утверждала,
// что снимающий метод ровно один.
//
// УТВЕРЖДЕНИЕ ЭТО БЫЛО ЛОЖНЫМ, и ложным оно было о ЗАЩИТЕ — тот самый класс,
// который эта полоса чинит везде. Радиус брался по диффу, а надо было по
// механизму: по операторам, ставящим отметку окончания записи.
//
// Теперь отзыв делает КАЖДЫЙ снимающий метод. Их было три: снятие одной
// записи, снятие прочих записей личности и снятие всех её записей на пуле.
// Третий снят (kaname#340): административный выход снимает записи транзакцией
// писателя, вместе с отсечкой и записью события, то есть вторым методом с
// пустым `keep`. Держит это гейт
// дерева `TestSessionEndingWritersRevokeWhatTheSessionHolds` — до него у пары
// «снятие сессии / отзыв семейства» не было ни одного прибора, в отличие от
// пары записей отсечки.
//
// Остатки этой полосы объявлены каждый у своего места и собраны строкой
// «предмет · причина · предикат» в
// `tmp/kn-313-own-executor-runs/remnants-as-issue-lines.txt`. Номеров у задач
// пока нет — заводит их не эта полоса.
//
// # ПОЧЕМУ ИДЕНТИФИКАТОРЫ, А НЕ ЧИСЛО
//
// Отзыв адресуется снятым записям поимённо. Второй запрос «а какие это были»
// вернул бы уже снятые строки вперемешку с теми, что сняли до нас, — и отозвал
// бы выданное в чужих сессиях.
func endSessionsAndRevokeWhatTheyHold(ctx context.Context, tx pgx.Tx, userID domain.UserID,
	keep domain.HumanSessionID, at time.Time, reason string,
) (int, error) {
	// Оператор снятия исполняется ЗДЕСЬ, а не в отдельном помощнике, и это
	// решение: помощник, снимающий записи и не отзывающий выданного, был бы
	// функцией, делающей ПОЛОВИНУ действия, — то есть ровно тем состоянием,
	// которое эта дверь и делает непредставимым. Гейт дерева считает такую
	// функцию находкой, и он прав: сегодня её звала бы только дверь, а завтра
	// кто угодно.
	// КУРСОР ЗАКРЫВАЕТСЯ РУКАМИ, А НЕ `defer`, И ЭТО НЕ НЕБРЕЖНОСТЬ: следом на
	// ТОЙ ЖЕ транзакции исполняются ещё операторы, а pgx не допускает работы с
	// соединением, пока курсор открыт. Отложенное закрытие сработало бы ПОСЛЕ
	// них — то есть слишком поздно.
	rows, err := tx.Query(ctx, endSessionsOfSQL, string(userID), string(keep), at, reason)
	if err != nil {
		return 0, mapErr(err, "HumanSession.End", string(userID))
	}
	var ended []string
	for rows.Next() {
		var id string
		if serr := rows.Scan(&id); serr != nil {
			rows.Close()
			return 0, mapErr(serr, "HumanSession.End", string(userID))
		}
		ended = append(ended, id)
	}
	rows.Close()
	if rerr := rows.Err(); rerr != nil {
		return 0, mapErr(rerr, "HumanSession.End", string(userID))
	}
	if _, rerr := revokeFamiliesOfSessionsTx(ctx, tx, ended,
		domain.FamilyRevokedBySessionEnd); rerr != nil {
		return 0, rerr
	}
	return len(ended), nil
}

// ForceLogoutWriter — транзакция записи для административного принудительного
// выхода на посадке `own` (kaname#340): снятие ВСЕХ живых записей личности
// (`EndOtherSessions` с пустым `keep`), отсечка и запись события — одним
// коммитом.
//
// Это ТОТ ЖЕ писатель, что у полосы входа, а не отдельный путь: прежде снятие
// шло своей транзакцией на пуле ПОСЛЕ транзакции отсечки, и запись события,
// положенная транзакцией отсечки, ложилась до снятия — числа снятых она нести
// не могла. Порядок операторов внутри транзакции задаёт вызывающий: снятие,
// отсечка, событие.
//
// # СТРОКА ЛИЧНОСТИ БЕРЁТСЯ ПЕРВОЙ, ДО ЛЮБОЙ СТРОКИ СЕССИИ
//
// Удаление личности идёт по каскаду сверху вниз: строка `users` (`FOR UPDATE`
// самим удалением), затем её записи сессии. Без этого замка выход брал строку
// личности ПОСЛЕ строк сессии — проверкой внешнего ключа отсечки, — то есть
// навстречу удалению. Измерено сценой «выход × удаление личности»
// (`force_logout_identity_deletion_race_integration_test.go`): на форме без
// замка 6 взаимных блокировок из 6 прогонов, жертвой каждый раз удаление
// (`pg_stat_database.deadlocks` = 6); с замком — 0 из 6, обе транзакции
// зафиксированы. Правило то же, что у выдачи кода авторизации: родители
// внешних ключей берутся НЕ ПОЗЖЕ строки сессии (`lockUserForKeySQL`, раздел
// «Порядок замков заведения»).
//
// Сила замка при открытии — `FOR KEY SHARE`, та, что взяла бы сама проверка
// внешнего ключа: он конфликтует ровно с удалением строки и совместим с
// остальными писателями личности. Строки может не быть вовсе — тогда держать
// нечего, и об отсутствии личности судит внешний ключ отсечки, как и прежде.
//
// Снятие (`EndOtherSessions`) поднимает замок той же строки до замка писателя
// нескольких сессий (`lockPersonForSessionSetSQL`) — до первой строки сессии.
// Подъём внутри транзакции, уже держащей строку, у ждущих не встаёт в очередь
// (Postgres не берёт повторно замок кортежа, строку которого транзакция уже
// держит): сцены «выход × удаление личности» (6 прогонов) и «четыре выхода
// сразу» (3 прогона) с ним — 0 взаимных блокировок. Открытие не берёт
// сильного замка сразу намеренно:
// транзакция частичного исхода — отсечка и запись события, без снятия, —
// открывается тем же писателем и не обязана ждать смену пароля, держащую
// личность: строк сессии она не трогает.
//
// # ОЖИДАНИЕ КАЖДОГО ЗАМКА ОГРАНИЧЕНО `lockWait`
//
// Предел ставится самой транзакции (`lock_timeout`, локально), а не берётся из
// срока вызова. `lock_timeout` ограничивает КАЖДОЕ ожидание замка отдельно, а
// не их сумму: оператор, ждущий по очереди нескольких держателей, ждёт каждого
// до `lockWait`, и вся транзакция может ждать кратно дольше. Срока у вызова
// может не быть вовсе, и тогда ожидание замка ограничивал бы только потолок
// одного оператора пула (`statement_timeout`, 30 с); а когда он есть, ожидание
// кончалось бы вместе с ним. Свой предел даёт отказ `55P03` на живом
// соединении, и хранилище переводит его в недоступность.
//
// Пул сам `lock_timeout` не ставит намеренно (`corelib/db.NewPool`): на всех
// путях всех служб он завёл бы класс `55P03`, который их переводы отказов не
// знают. Здесь предел локален одной транзакции, и перевод его знает.
//
// Ноль у `lock_timeout` означает «без предела», а предел короче миллисекунды
// записался бы нулём. Такой предел отвергается до открытия транзакции, а не
// подставляется: величину даёт служба, а не вызывающий, и её негодность —
// дефект службы, который обязан звучать, а не молча снимать ограничение.
func (r *HumanSessionRepo) ForceLogoutWriter(ctx context.Context, subject domain.UserID,
	lockWait time.Duration,
) (internaliam.OwnSessionsWriter, error) {
	if lockWait < time.Millisecond {
		return nil, iamerr.Wrapf(iamerr.ErrInternal,
			"force-logout writer: lock wait %s is not representable in lock_timeout", lockWait)
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, mapErr(err, "HumanSession.ForceLogoutWriter", "")
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`,
		fmt.Sprintf("%dms", lockWait.Milliseconds())); err != nil {
		_ = tx.Rollback(ctx)
		return nil, mapErr(err, "HumanSession.ForceLogoutWriter", "")
	}
	if _, err := tx.Exec(ctx, lockUserForKeySQL, string(subject)); err != nil {
		_ = tx.Rollback(ctx)
		return nil, mapErr(err, "User", string(subject))
	}
	return &humanSessionWriter{tx: tx, person: subject}, nil
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
	_ internaliam.OwnSessions       = (*HumanSessionRepo)(nil)
	_ internaliam.OwnSessionsWriter = (*humanSessionWriter)(nil)
	_ humansession.Store            = (*HumanSessionRepo)(nil)
	_ humansession.Writer           = (*humanSessionWriter)(nil)
	_ humansession.SessionSweeper   = (*HumanSessionRepo)(nil)
	_ humansession.FailureSweeper   = (*HumanSessionRepo)(nil)
)
