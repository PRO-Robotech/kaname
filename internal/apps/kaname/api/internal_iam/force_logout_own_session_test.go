// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// force_logout_own_session_test.go — ПРИНУДИТЕЛЬНЫЙ ВЫХОД СНИМАЕТ НАШУ ЗАПИСЬ
// СЕССИИ ВХОДА (задача kaname#313), и долговременная запись этого действия
// несёт его ИСХОД (задача kaname#340).
//
// Наблюдаемое в базе (запись перестала резолвиться, отсечка стоит, запись
// события называет исход) судят интеграционные пробы рядом. Здесь судится то,
// чего они не различают: ПОРЯДОК операторов в транзакции, число транзакций и
// что именно каждая фиксирует — в том числе на отказах, которые базой вызвать
// дорого.
package internal_iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// recordingOwnWriter — одна транзакция снятия: что в ней исполнено, в каком
// порядке, и чем она кончилась.
type recordingOwnWriter struct {
	// Сценарий.
	ended     int
	endErr    error
	cutoffErr error
	commitErr error

	// Наблюдение.
	calls     []string
	users     []domain.UserID
	keeps     []domain.HumanSessionID
	reasons   []string
	cutoffs   []domain.UserTokenRevocation
	cutoffBy  []domain.UserID
	events    []outboxtypes.AuditEvent
	committed bool
}

func (w *recordingOwnWriter) EndOtherSessions(_ context.Context, userID domain.UserID,
	keep domain.HumanSessionID, _ time.Time, reason string,
) (int, error) {
	w.calls = append(w.calls, "end")
	w.users = append(w.users, userID)
	w.keeps = append(w.keeps, keep)
	w.reasons = append(w.reasons, reason)
	if w.endErr != nil {
		return 0, w.endErr
	}
	return w.ended, nil
}

func (w *recordingOwnWriter) UpsertCutoff(_ context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	w.calls = append(w.calls, "cutoff")
	if w.cutoffErr != nil {
		return w.cutoffErr
	}
	w.cutoffs = append(w.cutoffs, u)
	w.cutoffBy = append(w.cutoffBy, revokedBy)
	return nil
}

func (w *recordingOwnWriter) EmitAudit(_ context.Context, ev outboxtypes.AuditEvent) error {
	w.calls = append(w.calls, "event")
	w.events = append(w.events, ev)
	return nil
}

func (w *recordingOwnWriter) Commit(context.Context) error {
	w.calls = append(w.calls, "commit")
	if w.commitErr != nil {
		return w.commitErr
	}
	w.committed = true
	return nil
}

func (w *recordingOwnWriter) Rollback(context.Context) error {
	w.calls = append(w.calls, "rollback")
	return nil
}

// recordingOwnSessions — хранилище, выдающее транзакции по сценарию: i-я
// открытая транзакция — i-я из `script`, сверх сценария — пустая. Все
// открытые остаются в `opened`: число транзакций — часть утверждения.
type recordingOwnSessions struct {
	script []*recordingOwnWriter
	opened []*recordingOwnWriter
}

func (r *recordingOwnSessions) ForceLogoutWriter(context.Context) (OwnSessionsWriter, error) {
	w := &recordingOwnWriter{}
	if i := len(r.opened); i < len(r.script) {
		w = r.script[i]
	}
	r.opened = append(r.opened, w)
	return w, nil
}

// ownSessionsScripted — хранилище с одной или несколькими транзакциями по сценарию.
func ownSessionsScripted(writers ...*recordingOwnWriter) *recordingOwnSessions {
	return &recordingOwnSessions{script: writers}
}

func ownSessionHandler(rec sessionRevoker, own *recordingOwnSessions) (*Handler, *recordingForceLogoutOps) {
	ops := &recordingForceLogoutOps{}
	h := NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(rec).
		WithAdminChecker(&fakeForceLogoutChecker{allow: true}).
		WithOperations(ops).
		WithOwnSessions(own)
	return h, ops
}

// TestForceLogout_EndsOurOwnLoginSession — снятие идёт по НАШЕМУ имени субъекта,
// снимает ВСЕ записи и берёт причину из закрытого словаря строки.
func TestForceLogout_EndsOurOwnLoginSession(t *testing.T) {
	tx := &recordingOwnWriter{ended: 2}
	h, _ := ownSessionHandler(&fakeForceLogoutRecorder{}, ownSessionsScripted(tx))

	op, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.NoError(t, err)
	require.True(t, op.GetDone())

	require.Equal(t, []domain.UserID{"usr_victim"}, tx.users,
		"наша запись адресуется users.id — тем именем, которое назвал распорядитель, "+
			"а не внешним субъектом, которого на этой посадке не существует")
	require.Equal(t, []domain.HumanSessionID{""}, tx.keeps,
		"принудительный выход снимает ВСЕ записи: сохранять здесь нечего")
	require.Equal(t, []string{domain.RevokeReasonLogout}, tx.reasons,
		"причина обязана быть словом ЗАКРЫТОГО словаря human_sessions_ended_reason_check: "+
			"значение вне его база отвергнет, и выход откажет на всяком входе")
}

// TestForceLogout_OwnPosture_EventIsLaidAfterTheTeardownInOneTransaction — на
// посадке `own` снятие, отсечка и запись события — ОДНА транзакция, в порядке
// «снятие → отсечка → событие», и запись несёт исход и число снятых.
func TestForceLogout_OwnPosture_EventIsLaidAfterTheTeardownInOneTransaction(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	own := ownSessionsScripted(&recordingOwnWriter{ended: 2})
	h, _ := ownSessionHandler(rec, own)

	before := time.Now().UTC()
	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{
		UserId: "usr_victim",
		Reason: "admin-force-logout",
	})
	require.NoError(t, err)

	require.Len(t, own.opened, 1, "выход обязан лечь ОДНОЙ транзакцией")
	tx := own.opened[0]
	require.Equal(t, []string{"end", "cutoff", "event", "commit"}, tx.calls,
		"запись события обязана лечь ПОСЛЕ снятия — иначе исхода ей не знать; "+
			"снятие идёт ДО отсечки — тем же порядком захвата строк, что у "+
			"собственного выхода человека")
	assert.Zero(t, rec.allCnt,
		"под `own` отсечку кладёт транзакция снятия: второй писатель положил бы "+
			"вторую запись события — намерение отдельно от исхода")

	require.Len(t, tx.cutoffs, 1)
	assert.Equal(t, domain.UserID("usr_victim"), tx.cutoffs[0].UserID)
	assert.Equal(t, "admin-force-logout", tx.cutoffs[0].Reason)
	assert.False(t, tx.cutoffs[0].RevokeBefore.Before(before), "revoke_before must be at-or-after request time")
	assert.Equal(t, []domain.UserID{testAdminID}, tx.cutoffBy,
		"решивший — проверенный принципал, а не поле тела запроса")

	require.Len(t, tx.events, 1)
	ev := tx.events[0]
	assert.Equal(t, eventSessionForceLogout, ev.EventType)
	assert.Equal(t, map[string]any{
		"actor":            testAdminID,
		"subject_type":     "user",
		"subject_id":       "usr_victim",
		"reason":           "admin-force-logout",
		"session_teardown": forceLogoutTeardownEnded,
		"sessions_ended":   2,
	}, ev.Payload,
		"состав записи — субъект, решивший, причина и ИСХОД снятия; ничего сверх, "+
			"и прежде всего ни носителя, ни его свёртки")
}

// TestForceLogout_NoLiveOwnSession_IsStillALogout — ноль снятых записей есть
// законный исход, а не отказ, и запись события называет его числом.
//
// Иначе выход отказывал бы тому, кто уже вышел, — то есть направление, делающее
// систему безопаснее, падало бы на повторе.
func TestForceLogout_NoLiveOwnSession_IsStillALogout(t *testing.T) {
	own := ownSessionsScripted(&recordingOwnWriter{ended: 0})
	h, _ := ownSessionHandler(&fakeForceLogoutRecorder{}, own)

	op, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.NoError(t, err)
	require.True(t, op.GetDone())

	require.Len(t, own.opened, 1)
	require.Len(t, own.opened[0].events, 1)
	payload := own.opened[0].events[0].Payload
	assert.Equal(t, forceLogoutTeardownEnded, payload["session_teardown"],
		"ноль снятых — исход «снято», а не отказ")
	assert.Equal(t, 0, payload["sessions_ended"],
		"ноль обязан быть НАЗВАН: отсутствие числа означает «не дошло»")
}

// TestForceLogout_OwnSessionTeardownFails_KeepsTheCutoffAndRecordsTheFailure —
// ЧАСТИЧНЫЙ ИСХОД. Первая транзакция откатывается целиком; вторая кладёт
// отсечку и запись «снятие не состоялось» без числа. Распорядителю — отказ.
//
// Отсечка остаётся НАМЕРЕННО: она защитна сама по себе и идемпотентна, а
// повтор глагола заново накладывает ту же отсечку и заново пробует то же
// снятие. Исход для распорядителя тот же, что у неснятой сессии чужого
// поставщика: два исполнителя одного предмета отвечают одинаково.
func TestForceLogout_OwnSessionTeardownFails_KeepsTheCutoffAndRecordsTheFailure(t *testing.T) {
	first := &recordingOwnWriter{endErr: errors.New("human_sessions: backend down")}
	partial := &recordingOwnWriter{}
	own := ownSessionsScripted(first, partial)
	h, ops := ownSessionHandler(&fakeForceLogoutRecorder{}, own)

	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.Error(t, err, "неснятая сессия не имеет права читаться как состоявшийся выход")
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Contains(t, ops.calls, "markerror", "опрос операции обязан увидеть отказ, а не успех")
	assert.NotContains(t, ops.calls, "markdone-with-metadata")

	require.Len(t, own.opened, 2, "частичный исход кладётся ВТОРОЙ транзакцией")
	assert.Equal(t, []string{"end", "rollback"}, first.calls,
		"первая транзакция после отказа снятия не пишет ни отсечки, ни записи — "+
			"запись «снято» в ней стала бы ложью")
	assert.False(t, first.committed)

	assert.Equal(t, []string{"cutoff", "event", "commit"}, partial.calls,
		"вторая транзакция — отсечка и запись исхода, и снятия в ней нет")
	require.Len(t, partial.cutoffs, 1, "отсечка обязана остаться: она защитна сама по себе")
	require.Len(t, partial.events, 1)
	payload := partial.events[0].Payload
	assert.Equal(t, forceLogoutTeardownFailed, payload["session_teardown"],
		"запись частичного исхода обязана сказать, что снятие не состоялось")
	_, carriesCount := payload["sessions_ended"]
	assert.False(t, carriesCount, "запись несостоявшегося снятия не несёт числа снятых")
}

// TestForceLogout_OwnPartialOutcomeNotRecorded_NothingLands — снятие отказало,
// и запись частичного исхода не легла тоже: не легло НИЧЕГО, и ответ — отказ.
func TestForceLogout_OwnPartialOutcomeNotRecorded_NothingLands(t *testing.T) {
	first := &recordingOwnWriter{endErr: errors.New("human_sessions: backend down")}
	partial := &recordingOwnWriter{commitErr: errors.New("commit: connection lost")}
	own := ownSessionsScripted(first, partial)
	h, ops := ownSessionHandler(&fakeForceLogoutRecorder{}, own)

	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.Error(t, err)
	assert.NotEqual(t, codes.OK, status.Code(err))
	assert.Contains(t, ops.calls, "markerror")
	assert.NotContains(t, ops.calls, "markdone-with-metadata")

	require.Len(t, own.opened, 2)
	assert.False(t, first.committed)
	assert.False(t, partial.committed, "ни одна транзакция не зафиксирована")
}

// TestForceLogout_OwnCutoffFails_NothingLandsAndNoPartialRecord — отказ ОТСЕЧКИ
// частичным исходом не является: откатывается всё, второй транзакции нет, ответ
// — перевод отказа хранилища.
//
// Положительный близнец соседней пробы частичного исхода: там отказывает
// снятие, и вторая транзакция есть; здесь отказывает отсечка, и её нет.
func TestForceLogout_OwnCutoffFails_NothingLandsAndNoPartialRecord(t *testing.T) {
	first := &recordingOwnWriter{ended: 1, cutoffErr: errors.New("user_token_revocations: backend down")}
	own := ownSessionsScripted(first)
	h, ops := ownSessionHandler(&fakeForceLogoutRecorder{}, own)

	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.Error(t, err, "отказ отсечки не имеет права отвечать успехом")
	assert.Contains(t, ops.calls, "markerror")

	require.Len(t, own.opened, 1,
		"отказ отсечки не оставляет записи «снятие не состоялось»: снятие состоялось, "+
			"а не легло потому, что не легла отсечка")
	assert.Equal(t, []string{"end", "cutoff", "rollback"}, first.calls)
	assert.False(t, first.committed)
}

// TestForceLogout_NoTeardownWired_RefusesAndKeepsTheCutoff — ни одного
// исполнителя снятия не провязано: глагол ОТКАЗЫВАЕТ, отсечка остаётся.
//
// Здесь стояла проба, утверждавшая обратное: непровязанное снятие отвечало
// успехом, и это объявлялось сохранением прежнего поведения. Оно и было
// дефектом формы — регрессия провязки давала тот же код ответа, то же тело
// операции и ту же запись журнала, что исправная работа, и увидеть разницу
// можно было только запросом в базу.
//
// Отсечка при этом НЕ теряется: она защитна сама по себе и идемпотентна, а
// повтор глагола после починки провязки доснимет сессию. Теряется только
// ложное «выведен».
func TestForceLogout_NoTeardownWired_RefusesAndKeepsTheCutoff(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	ops := &recordingForceLogoutOps{}
	h := NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(rec).
		WithAdminChecker(&fakeForceLogoutChecker{allow: true}).
		WithOperations(ops)

	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.Error(t, err, "непровязанное снятие не имеет права отвечать успехом")
	assert.Equal(t, codes.Unavailable, status.Code(err))

	assert.Equal(t, 1, rec.allCnt, "отсечка остаётся — она защитна и идемпотентна")
	assert.Contains(t, ops.calls, "markerror",
		"опрос операции обязан увидеть отказ, а не успех")
}
