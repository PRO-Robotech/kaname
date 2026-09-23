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
	"fmt"
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

// ctxSnapshot — состояние контекста В МОМЕНТ вызова. Сам контекст хранить
// нельзя: отвязанный срок снимается `defer cancel()` вызывающего, и после
// возврата любой записанный контекст выглядел бы отменённым.
type ctxSnapshot struct {
	err         error
	deadline    time.Time
	hasDeadline bool
}

func snapshotOf(ctx context.Context) ctxSnapshot {
	d, ok := ctx.Deadline()
	return ctxSnapshot{err: ctx.Err(), deadline: d, hasDeadline: ok}
}

// recordingOwnWriter — одна транзакция снятия: что в ней исполнено, в каком
// порядке, и чем она кончилась.
//
// Контракт настоящей транзакции соблюдается и здесь: оператор на законченном
// контексте отказывает его ошибкой, как отказывает драйвер. Дублёр, принимающий
// оператор на истёкшем сроке, зеленил бы ровно тот дефект, который пробы ниже
// ловят.
type recordingOwnWriter struct {
	// Сценарий.
	ended     int
	endErr    error
	onEnd     func(ctx context.Context) error
	onCutoff  func(ctx context.Context) error
	onEvent   func(ctx context.Context)
	onCommit  func(ctx context.Context)
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
	commitCtx ctxSnapshot
	committed bool
}

func (w *recordingOwnWriter) EndOtherSessions(ctx context.Context, userID domain.UserID,
	keep domain.HumanSessionID, _ time.Time, reason string,
) (int, error) {
	w.calls = append(w.calls, "end")
	w.users = append(w.users, userID)
	w.keeps = append(w.keeps, keep)
	w.reasons = append(w.reasons, reason)
	if w.onEnd != nil {
		if err := w.onEnd(ctx); err != nil {
			return 0, err
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if w.endErr != nil {
		return 0, w.endErr
	}
	return w.ended, nil
}

func (w *recordingOwnWriter) UpsertCutoff(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	w.calls = append(w.calls, "cutoff")
	if w.onCutoff != nil {
		if err := w.onCutoff(ctx); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.cutoffErr != nil {
		return w.cutoffErr
	}
	w.cutoffs = append(w.cutoffs, u)
	w.cutoffBy = append(w.cutoffBy, revokedBy)
	return nil
}

func (w *recordingOwnWriter) EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error {
	w.calls = append(w.calls, "event")
	if w.onEvent != nil {
		w.onEvent(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	w.events = append(w.events, ev)
	return nil
}

func (w *recordingOwnWriter) Commit(ctx context.Context) error {
	w.calls = append(w.calls, "commit")
	if w.onCommit != nil {
		w.onCommit(ctx)
	}
	w.commitCtx = snapshotOf(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
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
// открытые остаются в `opened`: число транзакций — часть утверждения. Каждая
// ПОПЫТКА открыть оставляет в `opens` состояние своего контекста; на
// законченном контексте открытие отказывает, как отказывает пул.
type recordingOwnSessions struct {
	script    []*recordingOwnWriter
	opened    []*recordingOwnWriter
	opens     []ctxSnapshot
	subjects  []domain.UserID
	lockWaits []time.Duration
}

func (r *recordingOwnSessions) ForceLogoutWriter(ctx context.Context, subject domain.UserID,
	lockWait time.Duration,
) (OwnSessionsWriter, error) {
	r.opens = append(r.opens, snapshotOf(ctx))
	r.subjects = append(r.subjects, subject)
	r.lockWaits = append(r.lockWaits, lockWait)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	assert.Equal(t, []domain.UserID{"usr_victim"}, own.subjects,
		"транзакция открывается держащей строку ТОЙ личности, чьи сессии снимает: "+
			"иначе строку личности возьмёт внешний ключ отсечки — после строк сессии, "+
			"навстречу удалению личности")
	if assert.Len(t, own.lockWaits, 1) {
		assert.Positive(t, own.lockWaits[0], "ожидание замков обязано быть ограничено")
		assert.Less(t, own.lockWaits[0], forceLogoutRecordBudget,
			"предел ожидания замка короче срока записи частичного исхода")
	}
	tx := own.opened[0]
	require.Equal(t, []string{"end", "cutoff", "event", "commit"}, tx.calls,
		"запись события обязана лечь ПОСЛЕ снятия — иначе исхода ей не знать; "+
			"строку сессии снятие берёт до строки отсечки")
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

// TestForceLogout_OwnTeardownEndedByTheRequest_PartialOutcomeRunsOnItsOwnBoundedContext
// — снятие отказало потому, что кончился сам запрос (вызывающий ушёл, пока
// снятие шло). Запись частичного исхода и отметка ошибки операции обязаны идти
// на контексте, ОТВЯЗАННОМ от отмены запроса, и при этом ОГРАНИЧЕННОМ своим
// сроком: отвязка снимает отмену, но не время — повисшая база иначе держала бы
// обработчик без предела.
func TestForceLogout_OwnTeardownEndedByTheRequest_PartialOutcomeRunsOnItsOwnBoundedContext(t *testing.T) {
	reqCtx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	first := &recordingOwnWriter{onEnd: func(context.Context) error {
		cancel()
		return nil
	}}
	partial := &recordingOwnWriter{}
	own := ownSessionsScripted(first, partial)
	h, ops := ownSessionHandler(&fakeForceLogoutRecorder{}, own)

	before := time.Now()
	_, err := h.ForceLogout(reqCtx, &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.Error(t, err)
	require.ErrorIs(t, reqCtx.Err(), context.Canceled, "фикстура: запрос обязан быть отменён")
	assert.Equal(t, codes.Unavailable, status.Code(err))

	require.Len(t, own.opens, 2, "частичный исход обязан быть ПОПЫТАН второй транзакцией")
	second := own.opens[1]
	assert.NoError(t, second.err,
		"запись частичного исхода открывалась на отменённом контексте запроса — "+
			"она не откроется никогда, и не ляжет ни отсечка, ни запись события")
	if assert.True(t, second.hasDeadline, "отвязанный контекст обязан нести свой срок") {
		assert.WithinDuration(t, before, second.deadline, 30*time.Second,
			"срок записи частичного исхода обязан быть конечным и коротким")
	}
	assert.Equal(t, []string{"cutoff", "event", "commit"}, partial.calls)
	assert.True(t, partial.committed, "частичный исход обязан зафиксироваться")

	assert.NoError(t, ops.markErrorCtx.err,
		"отметка ошибки операции шла на отменённом контексте запроса — опрос "+
			"будет вечно отвечать «не завершена»")
	assert.True(t, ops.markErrorCtx.hasDeadline, "отметка ошибки обязана нести свой срок")
}

// TestForceLogout_OwnStoreRefusalBecauseTheContextEnded_IsUnavailable — отказ
// хранилища, вызванный концом контекста (срок или отмена), — состояние, которое
// проходит, а не поломка службы. Ответ — `Unavailable`, а не `Internal`: в
// любой из двух транзакций и на любом шаге.
func TestForceLogout_OwnStoreRefusalBecauseTheContextEnded_IsUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		writers []*recordingOwnWriter
	}{
		{"отсечка первой транзакции — срок", []*recordingOwnWriter{
			{ended: 1, cutoffErr: fmt.Errorf("upsert cutoff: %w", context.DeadlineExceeded)},
		}},
		{"отсечка первой транзакции — отмена", []*recordingOwnWriter{
			{ended: 1, cutoffErr: fmt.Errorf("upsert cutoff: %w", context.Canceled)},
		}},
		{"фиксация частичного исхода — срок", []*recordingOwnWriter{
			{endErr: errors.New("human_sessions: backend down")},
			{commitErr: fmt.Errorf("commit: %w", context.DeadlineExceeded)},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, ops := ownSessionHandler(&fakeForceLogoutRecorder{}, ownSessionsScripted(tc.writers...))
			_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
			require.Error(t, err)
			assert.Equal(t, codes.Unavailable, status.Code(err),
				"конец контекста переведён в %s: %v", status.Code(err), err)
			assert.Contains(t, ops.calls, "markerror")
		})
	}
}

// TestForceLogout_OwnStatementCancelledBecauseTheRequestEnded_IsUnavailable —
// конец срока запроса приходит от хранилища НЕ ошибкой контекста: пул службы
// доводит отмену до сервера (`CancelRequest`), и оператор снимается там со
// строкой состояния `57014`, которую общий перевод отдаёт `Internal`. Отказ,
// пришедший, когда срок попытки уже кончился, обязан читаться отказом по сроку.
func TestForceLogout_OwnStatementCancelledBecauseTheRequestEnded_IsUnavailable(t *testing.T) {
	reqCtx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	first := &recordingOwnWriter{ended: 1, onCutoff: func(context.Context) error {
		cancel()
		return errors.New("internal: database error: sqlstate 57014")
	}}
	own := ownSessionsScripted(first)
	h, ops := ownSessionHandler(&fakeForceLogoutRecorder{}, own)

	_, err := h.ForceLogout(reqCtx, &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.Error(t, err)
	require.ErrorIs(t, reqCtx.Err(), context.Canceled, "фикстура: запрос обязан быть отменён")
	assert.Equal(t, codes.Unavailable, status.Code(err),
		"оператор, снятый по концу срока запроса, переведён в %s: %v", status.Code(err), err)
	assert.Len(t, own.opened, 2,
		"отказ отсечки по концу срока запроса откатил и снятие: частичный исход обязан "+
			"лечь второй транзакцией, как при отказе самого снятия")
	assert.Contains(t, ops.calls, "markerror")
}

// TestForceLogout_OwnRequestEndsAfterTheTeardown_PartialOutcomeStillLands —
// снятие прошло, а срок запроса кончился на отсечке либо на записи события
// первой транзакции. Откатывается и снятие, поэтому исход тот же, что при
// отказе снятия: вторая транзакция на своём сроке кладёт отсечку и запись
// «снятие не состоялось» без числа, ответ — `Unavailable`, операция отмечена
// ошибкой.
//
// Законный близнец — `TestForceLogout_OwnCutoffFails_NothingLandsAndNoPartialRecord`:
// тот же отказ отсечки при ЖИВОМ сроке запроса второй транзакции не открывает —
// она упёрлась бы в тот же отказ.
func TestForceLogout_OwnRequestEndsAfterTheTeardown_PartialOutcomeStillLands(t *testing.T) {
	for _, tc := range []struct {
		name       string
		arm        func(first *recordingOwnWriter, cancel context.CancelFunc)
		firstCalls []string
	}{
		{"срок кончился на отсечке", func(first *recordingOwnWriter, cancel context.CancelFunc) {
			first.onCutoff = func(context.Context) error { cancel(); return nil }
		}, []string{"end", "cutoff", "rollback"}},
		{"срок кончился на записи события", func(first *recordingOwnWriter, cancel context.CancelFunc) {
			first.onEvent = func(context.Context) { cancel() }
		}, []string{"end", "cutoff", "event", "rollback"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reqCtx, cancel := context.WithCancel(adminCtx())
			defer cancel()
			first := &recordingOwnWriter{ended: 3}
			tc.arm(first, cancel)
			partial := &recordingOwnWriter{}
			own := ownSessionsScripted(first, partial)
			h, ops := ownSessionHandler(&fakeForceLogoutRecorder{}, own)

			_, err := h.ForceLogout(reqCtx, &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
			require.Error(t, err, "откаченное снятие не имеет права читаться как состоявшийся выход")
			require.ErrorIs(t, reqCtx.Err(), context.Canceled, "фикстура: запрос обязан быть отменён")
			assert.Equal(t, codes.Unavailable, status.Code(err))
			assert.Contains(t, ops.calls, "markerror", "опрос операции обязан увидеть отказ")
			assert.NotContains(t, ops.calls, "markdone-with-metadata")

			assert.Equal(t, tc.firstCalls, first.calls, "первая транзакция откатывается целиком")
			assert.False(t, first.committed)
			require.Len(t, own.opened, 2,
				"снятие прошло, но откатилось вместе с отсечкой: без второй транзакции не легло "+
					"НИЧЕГО — ни отсечки, ни записи события")
			require.Len(t, own.opens, 2)
			assert.NoError(t, own.opens[1].err,
				"вторая транзакция открывалась на отменённом контексте запроса")
			assert.Equal(t, []string{"cutoff", "event", "commit"}, partial.calls)
			assert.True(t, partial.committed, "частичный исход обязан зафиксироваться")
			require.Len(t, partial.events, 1)
			assert.Equal(t, forceLogoutTeardownFailed, partial.events[0].Payload["session_teardown"],
				"снятие откатилось — запись обязана сказать, что оно не состоялось")
			_, carriesCount := partial.events[0].Payload["sessions_ended"]
			assert.False(t, carriesCount,
				"число, снятое откаченной транзакцией, не снято: в записи его быть не должно")
		})
	}
}

// TestForceLogout_OwnRequestEndsBeforeTheCommit_TheCommitIsNotTheRequests —
// все операторы первой транзакции прошли, а срок запроса кончился на фиксации.
// Фиксация сроку запроса не принадлежит: отмена во время `COMMIT` оставила бы
// её исход неизвестным — транзакция могла зафиксироваться на сервере, — и
// запись «снятие не состоялось» поверх неё легла бы второй записью события,
// ложной. Поэтому фиксация идёт на своём ограниченном сроке, и исход — полный.
func TestForceLogout_OwnRequestEndsBeforeTheCommit_TheCommitIsNotTheRequests(t *testing.T) {
	reqCtx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	first := &recordingOwnWriter{ended: 2, onCommit: func(context.Context) { cancel() }}
	own := ownSessionsScripted(first)
	h, ops := ownSessionHandler(&fakeForceLogoutRecorder{}, own)

	_, err := h.ForceLogout(reqCtx, &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.ErrorIs(t, reqCtx.Err(), context.Canceled, "фикстура: запрос обязан быть отменён")
	require.NoError(t, err, "выход зафиксирован — ответ обязан это сказать")

	require.Len(t, own.opened, 1, "полный исход лёг первой транзакцией — второй нет")
	assert.True(t, first.committed,
		"фиксация шла на отменённом контексте запроса: её исход неизвестен, "+
			"а поверх неё легла бы запись «снятие не состоялось»")
	assert.NoError(t, first.commitCtx.err)
	assert.True(t, first.commitCtx.hasDeadline, "срок фиксации обязан быть конечным")
	require.Len(t, first.events, 1)
	assert.Equal(t, forceLogoutTeardownEnded, first.events[0].Payload["session_teardown"])
	assert.Equal(t, 2, first.events[0].Payload["sessions_ended"])
	assert.Contains(t, ops.calls, "markdone-with-metadata")
}
