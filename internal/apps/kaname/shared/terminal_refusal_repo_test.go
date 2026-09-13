// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// terminal_refusal_repo_test.go — надстройка над `operations.Repo` переписывает
// текст отказа на ТЕРМИНАЛЬНОЙ полосе и только на ней.
//
// Приёмка: `docs/engineering/acceptance/refusal-text-names-the-lane-that-can-retry.md`,
// сценарии KN-RTX-01, KN-RTX-03, KN-RTX-04, KN-RTX-05.
//
// # Почему у надстройки ДВЕ возможности промахнуться, и обе закрыты
//
// Она судит ПАРУ (код + текст), поэтому ошибиться может в каждой половине:
// переписать всякий `ABORTED` (KN-RTX-04) либо всякий статус с этим текстом
// (KN-RTX-03). Один отрицательный сценарий закрыл бы одну из двух, и вторая
// осталась бы неотличимой от верной работы.
//
// Дельта каждого отрицательного против KN-RTX-01 — РОВНО ОДИН факт, и он назван
// в имени пробы; остальное в мире кейса совпадает дословно.
package shared_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// recordingRepo — подставной репозиторий операций: запоминает, что ему велели
// записать терминальным исходом.
//
// Он НЕ снисходительнее настоящего в том, что для этих проб существенно: сам
// текста не трогает и отдаёт его дословно. Подделка, «исправляющая» вход,
// сделала бы невидимым ровно тот дефект, ради которого пробы написаны.
type recordingRepo struct {
	operations.FullRepo
	gotError    *rpcstatus.Status
	gotResponse *anypb.Any
	doneCalls   int
	errorCalls  int
	claimCalls  int
}

func (r *recordingRepo) MarkError(_ context.Context, _ string, st *rpcstatus.Status) error {
	r.errorCalls++
	r.gotError = st
	return nil
}

// ClaimForExecution — подтверждение живости, которое исполнитель берёт ТИПОВЫМ
// утверждением. Подставной его несёт намеренно: без него проба сохранения
// апгрейда проверяла бы мир, в котором терять нечего.
func (r *recordingRepo) ClaimForExecution(_ context.Context, _ string) (bool, error) {
	r.claimCalls++
	return true, nil
}

func (r *recordingRepo) MarkDone(_ context.Context, _ string, resp *anypb.Any) error {
	r.doneCalls++
	r.gotResponse = resp
	return nil
}

// markError прогоняет один статус через надстройку и отдаёт то, что доехало.
func markError(t *testing.T, code codes.Code, msg string) *rpcstatus.Status {
	t.Helper()
	rec := &recordingRepo{}
	wrapped := shared.NewTerminalRefusalRepo(rec)
	require.NoError(t, wrapped.MarkError(context.Background(), "opr-1",
		grpcstatus.New(code, msg).Proto()))
	require.Equal(t, 1, rec.errorCalls, "надстройка обязана ДОВЕСТИ запись до репозитория")
	require.NotNil(t, rec.gotError)
	return rec.gotError
}

// KN-RTX-01 — терминальный исход называет следующий шаг.
//
// Утверждается ПАРА: один код не отличил бы новый текст от прежнего, один текст
// не заметил бы смены кода.
func TestTerminalRefusalRepo_KNRTX01_RewritesTheAsyncLaneText(t *testing.T) {
	got := markError(t, codes.Aborted, iamerr.SerializationConflictSyncText)

	assert.Equal(t, codes.Aborted, codes.Code(got.GetCode()), "код отказа НЕ меняется: класс тот же")
	assert.Equal(t, iamerr.SerializationConflictTerminalText, got.GetMessage(),
		"на терминальной полосе текст называет следующий шаг, а не повтор, которого не будет")

	// Текст обязан СМЕНИТЬСЯ: совпадение означало бы, что надстройка не сработала,
	// а проба зеленела бы на объявлении двух одинаковых констант.
	assert.NotEqual(t, iamerr.SerializationConflictSyncText, got.GetMessage(),
		"тексты полос обязаны РАЗЛИЧАТЬСЯ — иначе разведения не произошло")
}

// KN-RTX-03 — надстройка не трогает ЧУЖОЙ КОД.
//
// Дельта против KN-RTX-01 — один факт: код статуса. Текст прибит к синхронному
// ДОСЛОВНО, чтобы дельта вычислялась, а не достраивалась читателем.
func TestTerminalRefusalRepo_KNRTX03_LeavesAnotherCodeUntouched(t *testing.T) {
	got := markError(t, codes.FailedPrecondition, iamerr.SerializationConflictSyncText)

	assert.Equal(t, codes.FailedPrecondition, codes.Code(got.GetCode()))
	assert.Equal(t, iamerr.SerializationConflictSyncText, got.GetMessage(),
		"текст чужого кода доезжает ДОСЛОВНО: надстройка судит пару, а не текст")
}

// KN-RTX-04 — надстройка не трогает ABORTED С ЧУЖИМ ТЕКСТОМ.
//
// Дельта против KN-RTX-01 — один факт: текст. Код тот же. Без этой оси
// «надстройка судит пару» было бы неотличимо от «переписывает всякий ABORTED».
func TestTerminalRefusalRepo_KNRTX04_LeavesAnotherAbortedTextUntouched(t *testing.T) {
	const foreign = "binding was modified concurrently"
	got := markError(t, codes.Aborted, foreign)

	assert.Equal(t, codes.Aborted, codes.Code(got.GetCode()))
	assert.Equal(t, foreign, got.GetMessage(),
		"чужой текст под тем же кодом доезжает ДОСЛОВНО")
}

// KN-RTX-05 — успех проходит нетронутым.
func TestTerminalRefusalRepo_KNRTX05_PassesSuccessThrough(t *testing.T) {
	rec := &recordingRepo{}
	wrapped := shared.NewTerminalRefusalRepo(rec)

	payload, err := anypb.New(grpcstatus.New(codes.OK, "").Proto())
	require.NoError(t, err)
	require.NoError(t, wrapped.MarkDone(context.Background(), "opr-2", payload))

	assert.Equal(t, 1, rec.doneCalls, "запись успеха делегируется")
	assert.Equal(t, 0, rec.errorCalls, "и НЕ превращается в отказ")
	assert.Equal(t, payload, rec.gotResponse, "ответ тела доезжает дословно")
}

// Пустой статус надстройку не роняет: `MarkError(nil)` — не тот вход, который она
// судит, и падать на нём значило бы завести отказ там, где его не было.
func TestTerminalRefusalRepo_NilStatusIsPassedThrough(t *testing.T) {
	rec := &recordingRepo{}
	wrapped := shared.NewTerminalRefusalRepo(rec)
	require.NoError(t, wrapped.MarkError(context.Background(), "opr-3", nil))
	assert.Equal(t, 1, rec.errorCalls)
	assert.Nil(t, rec.gotError)
}

// TestTerminalRefusalRepoKeepsTheExecutionClaim — подтверждение живости
// ПЕРЕЖИВАЕТ оборачивание.
//
// # Почему проба заведена отдельной, а не пунктом в соседней
//
// Исполнитель операций берёт этот апгрейд ТИПОВЫМ УТВЕРЖДЕНИЕМ, а не через
// контракт. Значит его потеря — ТИХАЯ: надстройка, встроившая узкий контракт,
// собирается, все прочие пробы зелены, и исчезает лишь одно — подтверждение
// живости перед исполнением тела. Цену называет сам исполнитель: без него тело
// уже терминальной операции исполняется, и создаётся ФАНТОМНЫЙ РЕСУРС.
//
// Первая редакция надстройки этот апгрейд ТЕРЯЛА. Нашла не вычитка, а перепись
// типовых утверждений по чужому дереву.
func TestTerminalRefusalRepoKeepsTheExecutionClaim(t *testing.T) {
	rec := &recordingRepo{}
	wrapped := shared.NewTerminalRefusalRepo(rec)

	// Утверждение ТОЙ ЖЕ формы, какой его берёт исполнитель. Неудача здесь
	// означает, что апгрейд потерян при оборачивании.
	claimer, ok := wrapped.(interface {
		ClaimForExecution(ctx context.Context, id string) (bool, error)
	})
	require.True(t, ok,
		"подтверждение живости потеряно оборачиванием: исполнитель возьмёт его типовым "+
			"утверждением, не найдёт и станет исполнять тело уже терминальной операции")

	live, err := claimer.ClaimForExecution(context.Background(), "opr-4")
	require.NoError(t, err)
	assert.True(t, live, "ответ обёрнутого доезжает дословно")
	assert.Equal(t, 1, rec.claimCalls, "вызов ДОШЁЛ до обёрнутого, а не съеден надстройкой")
}

// TestTerminalRefusalRepoDoesNotInventAnExecutionClaim — законный близнец:
// репозиторий БЕЗ апгрейда не получает его от надстройки.
//
// Объявить метод безусловно значило бы сказать исполнителю «подтверждение есть»
// поверх репозитория, у которого его нет: тот стал бы звать несуществующее и
// отказывать в исполнении там, где раньше работа шла. Без этой пробы
// «пробрасывает» было бы неотличимо от «выдумывает».
func TestTerminalRefusalRepoDoesNotInventAnExecutionClaim(t *testing.T) {
	// Подставной БЕЗ ClaimForExecution — один факт против пробы выше.
	type plainRepo struct{ operations.FullRepo }
	wrapped := shared.NewTerminalRefusalRepo(&plainRepo{})

	_, ok := wrapped.(interface {
		ClaimForExecution(ctx context.Context, id string) (bool, error)
	})
	assert.False(t, ok,
		"надстройка не вправе объявлять апгрейд, которого у обёрнутого нет")
}
