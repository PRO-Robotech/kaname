// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// force_logout_own_commit_refusal_test.go — ОТКАЗ ФИКСАЦИИ ПЕРВОЙ ТРАНЗАКЦИИ
// ПРИНУДИТЕЛЬНОГО ВЫХОДА К ЧАСТИЧНОМУ ИСХОДУ НЕ ВЕДЁТ, И СУДИТСЯ ОН ПО
// КОНТЕКСТУ САМОЙ ФИКСАЦИИ, А НЕ ПО КОНТЕКСТУ ЗАПРОСА (задача kaname#340).
//
// Фиксация идёт на своём отвязанном сроке: когда операторы прошли, исход
// отказавшей фиксации может быть неизвестен — транзакция могла
// зафиксироваться на сервере, — и запись «снятие не состоялось» поверх неё
// легла бы второй записью события, ложной. Поэтому отказ фиксации —
// какой угодно причиной — второй транзакции не открывает, и ни срок запроса,
// ни срок самой фиксации этого не меняют.
//
// Сцен три, и каждая пара отличается ОДНИМ фактом:
//
//   - фиксация исчерпала СВОЙ срок при живом запросе (срок фиксации — на
//     управляемых часах: `testing/synctest`, дублёр ждёт конца её контекста,
//     как ждёт драйвер);
//   - фиксация отказала кодом хранилища, а срок запроса кончился, пока она шла;
//   - законный близнец обеих: фиксация отказала кодом хранилища при живом
//     запросе и живом сроке фиксации.
//
// Сверх них — журнал: отказ, к частичному исходу не ведущий, называет в нём
// свой шаг и причину, потому что вызывающему уходит фиксированный текст.
package internal_iam

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// storeCodeRefusal — отказ шага кодом хранилища (не концом контекста):
// так приходит незнакомая переводу строка состояния.
func storeCodeRefusal() error {
	return iamerr.Wrapf(iamerr.ErrInternal, "database error: sqlstate XX000")
}

// assertNoPartialOutcomeAfterCommitRefusal — отказ фиксации оставил ОДНУ
// транзакцию, отмечен на операции ошибкой и не назван выходом.
func assertNoPartialOutcomeAfterCommitRefusal(t *testing.T, own *recordingOwnSessions,
	first *recordingOwnWriter, ops *recordingForceLogoutOps,
) {
	t.Helper()
	assert.Equal(t, []string{"end", "cutoff", "event", "commit", "rollback"}, first.calls,
		"все операторы первой транзакции прошли, отказала фиксация")
	assert.False(t, first.committed)
	assert.Len(t, own.opened, 1,
		"отказ фиксации открыл вторую транзакцию: её исход может быть неизвестен, "+
			"и запись «снятие не состоялось» легла бы поверх, возможно, состоявшегося выхода")
	assert.Contains(t, ops.calls, "markerror", "опрос операции обязан увидеть отказ")
	assert.NotContains(t, ops.calls, "markdone-with-metadata")
}

// TestForceLogout_OwnCommitOutlivesItsOwnBudget_IsNotAPartialOutcome — запрос
// жив, фиксация исчерпала свой отвязанный срок. В цепочке отказа —
// `DeadlineExceeded`, но это срок ФИКСАЦИИ, а не запроса: частичного исхода нет,
// ответ — недоступность (повтор осмыслен и идемпотентен).
func TestForceLogout_OwnCommitOutlivesItsOwnBudget_IsNotAPartialOutcome(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := &recordingOwnWriter{ended: 2, onCommit: func(ctx context.Context) { <-ctx.Done() }}
		own := ownSessionsScripted(first)
		h, ops := ownSessionHandler(&fakeForceLogoutRecorder{}, own)
		reqCtx := adminCtx()

		_, err := h.ForceLogout(reqCtx, &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
		require.Error(t, err, "неизвестный исход фиксации не имеет права отвечать успехом")
		require.NoError(t, reqCtx.Err(), "фикстура: запрос обязан остаться живым")
		require.ErrorIs(t, first.commitCtx.err, context.DeadlineExceeded,
			"фикстура: фиксация обязана исчерпать СВОЙ срок")

		assertNoPartialOutcomeAfterCommitRefusal(t, own, first, ops)
		assert.Equal(t, codes.Unavailable, status.Code(err),
			"конец срока фиксации — состояние, которое проходит: %v", err)
	})
}

// TestForceLogout_OwnCommitRefusedAfterTheRequestEnded_IsNotAPartialOutcome —
// срок запроса кончился, пока шла фиксация, а сама фиксация отказала кодом
// хранилища на живом своём сроке. Фиксация сроку запроса не принадлежит, и
// конец запроса её отказа не переклассифицирует: частичного исхода нет, ответ
// — перевод отказа хранилища.
func TestForceLogout_OwnCommitRefusedAfterTheRequestEnded_IsNotAPartialOutcome(t *testing.T) {
	reqCtx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	first := &recordingOwnWriter{ended: 2, onCommit: func(context.Context) { cancel() },
		commitErr: storeCodeRefusal()}
	own := ownSessionsScripted(first)
	h, ops := ownSessionHandler(&fakeForceLogoutRecorder{}, own)

	_, err := h.ForceLogout(reqCtx, &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.Error(t, err)
	require.ErrorIs(t, reqCtx.Err(), context.Canceled, "фикстура: запрос обязан быть отменён")
	require.NoError(t, first.commitCtx.err, "фикстура: срок фиксации обязан быть живым")

	assertNoPartialOutcomeAfterCommitRefusal(t, own, first, ops)
	assert.Equal(t, codes.Internal, status.Code(err),
		"отказ фиксации кодом хранилища переведён по сроку запроса: %v", err)
	assert.Equal(t, "internal error", status.Convert(err).Message())
}

// TestForceLogout_OwnCommitRefusedWhileTheRequestLives_IsNotAPartialOutcome —
// законный близнец обеих сцен выше: запрос жив, срок фиксации жив, фиксация
// отказала кодом хранилища. От первой сцены отличается причиной отказа
// фиксации, от второй — только состоянием запроса.
func TestForceLogout_OwnCommitRefusedWhileTheRequestLives_IsNotAPartialOutcome(t *testing.T) {
	reqCtx := adminCtx()
	first := &recordingOwnWriter{ended: 2, commitErr: storeCodeRefusal()}
	own := ownSessionsScripted(first)
	h, ops := ownSessionHandler(&fakeForceLogoutRecorder{}, own)

	_, err := h.ForceLogout(reqCtx, &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.Error(t, err)
	require.NoError(t, reqCtx.Err(), "фикстура: запрос обязан остаться живым")
	require.NoError(t, first.commitCtx.err, "фикстура: срок фиксации обязан быть живым")

	assertNoPartialOutcomeAfterCommitRefusal(t, own, first, ops)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Equal(t, "internal error", status.Convert(err).Message())
}

// captureForceLogoutErrorLog — журнал ошибок обработчика в буфер. Обработчик
// пишет пакетным `slog.ErrorContext`, поэтому подменяется логгер по умолчанию;
// параллельные пробы пакета (`t.Parallel`) стоят на паузе, пока идут
// последовательные, так что подмена чужих записей не ловит.
func captureForceLogoutErrorLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestForceLogout_OwnRefusalWithoutPartialOutcome_LogsItsCause — отказ первой
// транзакции, НЕ ведущий к частичному исходу, уходит вызывающему переводом, в
// котором причины нет (текст отказа фиксирован). Значит причину обязан назвать
// журнал — шаг, на котором отказ пришёл, и сам отказ хранилища, — иначе её не
// назовёт никто.
func TestForceLogout_OwnRefusalWithoutPartialOutcome_LogsItsCause(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first *recordingOwnWriter
		step  string
	}{
		{"отсечка", &recordingOwnWriter{ended: 1, cutoffErr: storeCodeRefusal()}, "cutoff"},
		{"фиксация", &recordingOwnWriter{ended: 1, commitErr: storeCodeRefusal()}, "commit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logBuf := captureForceLogoutErrorLog(t)
			own := ownSessionsScripted(tc.first)
			h, _ := ownSessionHandler(&fakeForceLogoutRecorder{}, own)

			_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
			require.Error(t, err)
			require.Len(t, own.opened, 1, "фикстура: отказ этого шага к частичному исходу не ведёт")
			assert.Equal(t, "internal error", status.Convert(err).Message(),
				"фикстура: причина до вызывающего не доходит — её несёт только журнал")

			logged := logBuf.String()
			assert.Contains(t, logged, "sqlstate XX000", "причина отказа в журнал не записана")
			assert.Contains(t, logged, `"step":"`+tc.step+`"`, "шаг отказа в журнал не записан")
		})
	}
}
