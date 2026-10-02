// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// force_logout_session_end_reason_integration_test.go — ЗАПИСЬ СЕССИИ НАЗЫВАЕТ
// ТОГО, КТО ЕЁ СНЯЛ (задача kaname#334; приёмка
// `docs/engineering/acceptance/forced-exit-has-its-own-session-end-reason.md`,
// KN-SER-01…04).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// На посадке `own` принудительный выход снимает наши записи сессии входа. Он
// пишет в них причину закрытого словаря `human_sessions_ended_reason_check`, и
// эта причина обязана отличать выход распорядителем от собственного выхода
// человека: `admin-force-logout` против `logout`. Ответ глагола и ответ
// предъявителю от этого не меняются.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЧИТАЕТСЯ И ОТКУДА
//
// Причина снятия читается из СТРОКИ базы, а не из аргумента порта: утверждается
// то, что легло, а не то, что передали. Слово причины выписано дословно из
// приёмки (Р1), а не взято из объявления домена: проба утверждает значение,
// которое база обязана принять.
//
// Запись сессии кладёт ТОТ ЖЕ писатель, которым её кладёт полоса входа
// (`humansession.IssueSession` на транзакции `HumanSessionRepo.Writer`):
// фикстура не снисходительнее продукта. Живость записи до акта — положительный
// близнец каждого сценария: без него «строка снята» зеленело бы на фикстуре,
// которая живой записи не положила.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПАРЫ
//
// KN-SER-02 против KN-SER-01 — один факт: свободная причина в запросе.
// KN-SER-03 против KN-SER-01 — один факт: кто выполнил выход.
// KN-SER-04 — положительный контроль Ф1-17: ответ предъявителю одинаков.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

const (
	// serForcedExitReason — причина снятия, которую пишет принудительный выход
	// (приёмка, Р1). Выписана дословно, а не взята из домена.
	serForcedExitReason = "admin-force-logout"
	// serOwnLogoutReason — причина собственного выхода человека.
	serOwnLogoutReason = "logout"
	// serSessionTTL — срок записи фикстуры: заведомо дольше пробы.
	serSessionTTL = 12 * time.Hour
)

// serScene — база с мигрированной схемой, обработчик посадки `own` и
// хранилище сессий поверх одного пула.
type serScene struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	sessions *kanamepg.HumanSessionRepo
	handler  *internaliam.Handler
}

func newSERScene(t *testing.T) *serScene {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	h, pool := newForceLogoutHandler(t)
	return &serScene{
		ctx:      context.Background(),
		pool:     pool,
		sessions: kanamepg.NewHumanSessionRepo(pool),
		handler:  h,
	}
}

// serPerson — личность в состоянии ACTIVE вместе со своим аккаунтом: обе
// строки одной транзакцией (внешние ключи users↔accounts отложены).
func (sc *serScene) serPerson(t *testing.T) domain.User {
	t.Helper()
	u := domain.User{
		ID:           domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID:    domain.AccountID(ids.NewID(domain.PrefixAccount)),
		InviteStatus: domain.InviteStatusActive,
	}
	tx, err := sc.pool.Begin(sc.ctx)
	require.NoError(t, err, "Дано: транзакция посева личности")
	defer func() { _ = tx.Rollback(sc.ctx) }()
	_, err = tx.Exec(sc.ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'Session End Reason Subject', 'ACTIVE')`,
		string(u.ID), string(u.AccountID), "own:"+string(u.ID), fmt.Sprintf("ser-%s@example.invalid", u.ID))
	require.NoError(t, err, "Дано: строка личности")
	_, err = tx.Exec(sc.ctx, `
		INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(u.AccountID), "ser-acc-"+string(u.AccountID)[len(u.AccountID)-6:], string(u.ID))
	require.NoError(t, err, "Дано: строка аккаунта")
	require.NoError(t, tx.Commit(sc.ctx), "Дано: посев личности зафиксирован")
	return u
}

// serSession — живая запись сессии и её носитель.
type serSession struct {
	id     domain.HumanSessionID
	bearer domain.SessionBearer
}

// serLiveSession кладёт запись писателем полосы входа и проверяет, что она
// ЖИВА: тот же резолв, которым её судит продукт, отвечает «сессия есть».
func (sc *serScene) serLiveSession(t *testing.T, u domain.User) serSession {
	t.Helper()
	w, err := sc.sessions.Writer(sc.ctx)
	require.NoError(t, err, "Дано: транзакция записи сессии")
	defer func() { _ = w.Rollback(sc.ctx) }()
	s, bearer, err := humansession.IssueSession(sc.ctx, w, humansession.IssueInput{
		User:      u,
		Presented: []assurance.Presentation{assurance.PasswordPresented()},
		At:        time.Now().UTC().Add(-time.Minute),
		TTL:       serSessionTTL,
		EmitAudit: true,
	})
	require.NoError(t, err, "Дано: запись сессии полосой входа")
	require.NoError(t, w.Commit(sc.ctx), "Дано: запись сессии зафиксирована")

	_, reason, err := sc.sessions.Resolve(sc.ctx, bearer.Digest(), time.Now().UTC())
	require.NoError(t, err, "Дано: резолв записи до акта")
	require.Equal(t, humansession.SessionFound, reason,
		"Дано: фикстура не положила ЖИВОЙ записи — всякое «снята» ниже было бы сказано о пустоте")
	row := sc.serRow(t, s.ID)
	require.Nil(t, row.endedAt, "Дано: запись до акта не снята")
	require.Nil(t, row.endedReason, "Дано: у живой записи причины нет")
	return serSession{id: s.ID, bearer: bearer}
}

// serSessionRow — пара «момент, причина» снятия из строки базы.
type serSessionRow struct {
	endedAt     *time.Time
	endedReason *string
}

func (r serSessionRow) reason() string {
	if r.endedReason == nil {
		return "<NULL>"
	}
	return *r.endedReason
}

func (sc *serScene) serRow(t *testing.T, id domain.HumanSessionID) serSessionRow {
	t.Helper()
	var r serSessionRow
	require.NoError(t, sc.pool.QueryRow(sc.ctx,
		`SELECT ended_at, ended_reason FROM kaname.human_sessions WHERE id = $1`, string(id)).
		Scan(&r.endedAt, &r.endedReason), "чтение строки сессии %s", id)
	return r
}

// serCutoff — запись журнала отсечек субъекта.
type serCutoff struct {
	revokeBefore time.Time
	reason       string
	revokedBy    *string
}

func (sc *serScene) serCutoffOf(t *testing.T, uid domain.UserID) serCutoff {
	t.Helper()
	var c serCutoff
	require.NoError(t, sc.pool.QueryRow(sc.ctx, `
		SELECT revoke_before, reason, revoked_by_user_id
		  FROM kaname.user_token_revocations WHERE user_id = $1`, string(uid)).
		Scan(&c.revokeBefore, &c.reason, &c.revokedBy), "чтение журнала отсечек субъекта %s", uid)
	return c
}

// serRequireCompletedForceLogout — первое «Тогда» KN-SER-01: форма ответа
// операции не изменилась, и опрос по id отдаёт то же самое.
func (sc *serScene) serRequireCompletedForceLogout(t *testing.T, op *operationpb.Operation, uid domain.UserID) {
	t.Helper()
	require.NotNil(t, op, "операция не вернулась")
	require.True(t, op.GetDone(), "операция обязана быть завершена: done = true")
	require.Nil(t, op.GetError(), "операция обязана завершиться успехом: error пуст, получено %v", op.GetError())
	meta := &iamv1.ForceLogoutMetadata{}
	require.NoError(t, op.GetMetadata().UnmarshalTo(meta), "metadata — ForceLogoutMetadata")
	require.Equal(t, string(uid), meta.GetUserId(), "metadata.userId — субъект выхода")
	resp := &iamv1.ForceLogoutResult{}
	require.NoError(t, op.GetResponse().UnmarshalTo(resp), "response — ForceLogoutResult")
	require.Equal(t, int32(1), resp.GetRevokedCount(), "response.revokedCount = 1")

	polled, err := operations.NewRepo(sc.pool, "kaname").Get(sc.ctx, op.GetId())
	require.NoError(t, err, "OperationService.Get(id) обязан находить операцию")
	require.True(t, polled.Done, "опрос: done = true")
	require.Nil(t, polled.Error, "опрос: error пуст")
	polledMeta := &iamv1.ForceLogoutMetadata{}
	require.NoError(t, polled.Metadata.UnmarshalTo(polledMeta), "опрос: metadata — ForceLogoutMetadata")
	require.Equal(t, string(uid), polledMeta.GetUserId(), "опрос: metadata.userId")
	polledResp := &iamv1.ForceLogoutResult{}
	require.NoError(t, polled.Response.UnmarshalTo(polledResp), "опрос: response — ForceLogoutResult")
	require.Equal(t, int32(1), polledResp.GetRevokedCount(), "опрос: response.revokedCount = 1")
}

// TestForceLogout_KN_SER_01_WithoutReasonTheSessionRowNamesTheForcedExit —
// принудительный выход без причины в запросе: запись сессии несёт
// `admin-force-logout`, причина отсечки прежняя.
func TestForceLogout_KN_SER_01_WithoutReasonTheSessionRowNamesTheForcedExit(t *testing.T) {
	sc := newSERScene(t)
	p := sc.serPerson(t)
	s := sc.serLiveSession(t, p)

	op, err := sc.handler.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{UserId: string(p.ID)})
	require.NoError(t, err, "принудительный выход без причины обязан завершиться успехом")

	// Тогда-1 — положительный контроль: форма ответа прежняя.
	sc.serRequireCompletedForceLogout(t, op, p.ID)

	// Тогда-2 — предмет.
	row := sc.serRow(t, s.id)
	assert.NotNil(t, row.endedAt, "у S обязан стоять ended_at: запись снята")
	assert.Equal(t, serForcedExitReason, row.reason(),
		"у S ended_reason обязан называть принудительный выход, а не собственный выход человека")

	// Тогда-3 — причина отсечки прежняя, актор — вызывающий.
	cut := sc.serCutoffOf(t, p.ID)
	assert.Equal(t, serForcedExitReason, cut.reason, "причина в журнале отсечек — умолчание принудительного выхода")
	if assert.NotNil(t, cut.revokedBy, "актор отсечки обязан быть назван") {
		assert.Equal(t, forceLogoutAdminID, *cut.revokedBy, "актор отсечки — вызывающий")
	}
}

// TestForceLogout_KN_SER_02_FreeReasonDoesNotReachTheClosedColumn — свободная
// причина из запроса идёт в отсечку и НЕ идёт в запись сессии.
func TestForceLogout_KN_SER_02_FreeReasonDoesNotReachTheClosedColumn(t *testing.T) {
	sc := newSERScene(t)
	p := sc.serPerson(t)
	s := sc.serLiveSession(t, p)

	op, err := sc.handler.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{
		UserId: string(p.ID),
		Reason: "incident-4711",
	})
	// Тогда-1: причина вне словаря не стоит самого выхода (Р2). Реализация,
	// передавшая её в снятие, получает здесь отказ ограничения базы.
	require.NoError(t, err, "принудительный выход со свободной причиной обязан завершиться успехом")
	require.True(t, op.GetDone(), "операция завершена: done = true")
	require.Nil(t, op.GetError(), "операция завершена успехом: error пуст, получено %v", op.GetError())

	// Тогда-2.
	row := sc.serRow(t, s.id)
	assert.NotNil(t, row.endedAt, "у S обязан стоять ended_at: запись снята")
	assert.Equal(t, serForcedExitReason, row.reason(),
		"у S ended_reason — слово закрытого словаря, а не свободная причина из запроса и не `logout`")

	// Тогда-3.
	assert.Equal(t, "incident-4711", sc.serCutoffOf(t, p.ID).reason,
		"свободная причина из запроса обязана лечь в журнал отсечек дословно")
}

// TestLogout_KN_SER_03_OwnLogoutStillWritesLogout — близнец KN-SER-01:
// собственный выход человека по-прежнему пишет `logout`.
func TestLogout_KN_SER_03_OwnLogoutStillWritesLogout(t *testing.T) {
	sc := newSERScene(t)
	q := sc.serPerson(t)
	tSess := sc.serLiveSession(t, q)

	uc, err := humansession.NewLogoutUseCase(sc.sessions, nil, nil, nil)
	require.NoError(t, err, "глагол выхода полосы входа")
	ended, err := uc.Execute(sc.ctx, tSess.bearer)
	require.NoError(t, err, "собственный выход без ошибки")
	require.True(t, ended, "собственный выход снял запись ЭТИМ вызовом")

	row := sc.serRow(t, tSess.id)
	assert.NotNil(t, row.endedAt, "у T обязан стоять ended_at")
	assert.Equal(t, serOwnLogoutReason, row.reason(), "у T ended_reason — собственный выход человека")
}

// TestForceLogout_KN_SER_04_BearerSeesNoDifference — предъявитель разницы не
// видит (Ф1-17): обе снятые записи отвечают одинаково.
func TestForceLogout_KN_SER_04_BearerSeesNoDifference(t *testing.T) {
	sc := newSERScene(t)
	p := sc.serPerson(t)
	s := sc.serLiveSession(t, p)
	q := sc.serPerson(t)
	tSess := sc.serLiveSession(t, q)

	op, err := sc.handler.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{UserId: string(p.ID)})
	require.NoError(t, err, "Дано: S снята принудительным выходом")
	require.True(t, op.GetDone(), "Дано: операция завершена")
	require.Nil(t, op.GetError(), "Дано: операция завершена успехом")
	uc, err := humansession.NewLogoutUseCase(sc.sessions, nil, nil, nil)
	require.NoError(t, err)
	ended, err := uc.Execute(sc.ctx, tSess.bearer)
	require.NoError(t, err, "Дано: T снята собственным выходом")
	require.True(t, ended, "Дано: собственный выход снял T")

	now := time.Now().UTC()
	resS, reasonS, errS := sc.sessions.Resolve(sc.ctx, s.bearer.Digest(), now)
	resT, reasonT, errT := sc.sessions.Resolve(sc.ctx, tSess.bearer.Digest(), now)
	require.NoError(t, errS, "резолв носителя S")
	require.NoError(t, errT, "резолв носителя T")

	assert.Equal(t, humansession.NoSessionEnded, reasonS, "носитель S: «сессия снята»")
	assert.Equal(t, humansession.NoSessionEnded, reasonT, "носитель T: «сессия снята»")
	assert.Equal(t, reasonT, reasonS, "ответы двум носителям обязаны совпадать")
	assert.Equal(t, resT, resS, "ответ предъявителю не несёт ничего, что различало бы два выхода")
}
