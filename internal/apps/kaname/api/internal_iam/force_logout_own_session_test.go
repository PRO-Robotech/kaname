// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// force_logout_own_session_test.go — ПРИНУДИТЕЛЬНЫЙ ВЫХОД СНИМАЕТ НАШУ ЗАПИСЬ
// СЕССИИ ВХОДА, и её несостоявшееся снятие НЕ выдаётся за состоявшийся выход
// (задача kaname#313).
//
// Наблюдаемое (запись перестала резолвиться) судит интеграционная проба рядом.
// Здесь судится то, чего она не различает: КАК глагол отвечает, когда снятие
// не удалось, — тем же исходом, каким он отвечает на неснятую сессию чужого
// поставщика. Два исполнителя одного предмета не имеют права отвечать по-разному.
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
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// recordingOwnSessions — снятие наших записей сессии входа.
type recordingOwnSessions struct {
	users   []domain.UserID
	reasons []string
	ended   int
	err     error
}

func (r *recordingOwnSessions) EndAllSessions(_ context.Context, userID domain.UserID,
	_ time.Time, reason string,
) (int, error) {
	r.users = append(r.users, userID)
	r.reasons = append(r.reasons, reason)
	return r.ended, r.err
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

// TestForceLogout_EndsOurOwnLoginSession — снятие идёт по НАШЕМУ имени субъекта
// и с причиной из закрытого словаря строки.
func TestForceLogout_EndsOurOwnLoginSession(t *testing.T) {
	own := &recordingOwnSessions{ended: 2}
	h, _ := ownSessionHandler(&fakeForceLogoutRecorder{}, own)

	op, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.NoError(t, err)
	require.True(t, op.GetDone())

	require.Equal(t, []domain.UserID{"usr_victim"}, own.users,
		"наша запись адресуется users.id — тем именем, которое назвал распорядитель, "+
			"а не внешним субъектом, которого на этой посадке не существует")
	require.Equal(t, []string{domain.RevokeReasonLogout}, own.reasons,
		"причина обязана быть словом ЗАКРЫТОГО словаря human_sessions_ended_reason_check: "+
			"значение вне его база отвергнет, и выход откажет на всяком входе")
}

// TestForceLogout_OwnSessionsNotWired_StillRecordsTheCutoff — посадка без наших
// записей сессии входа сохраняет поведение, которое у неё было.
//
// Это и есть контроль прежней посадки: под `external` полоса входа не
// поднимается, наших записей нет, и снимать нечего — отсечка по-прежнему
// единственная запись этого глагола здесь.
func TestForceLogout_OwnSessionsNotWired_StillRecordsTheCutoff(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	h := forceLogoutHandler(rec)

	op, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.NoError(t, err)
	require.True(t, op.GetDone())
	assert.Equal(t, 1, rec.allCnt)
}

// TestForceLogout_OwnSessionTeardownFails_FailsTheMutation — распорядителю не
// сообщают о состоявшемся выходе, пока сессия стоит.
//
// Отсечка при этом остаётся закоммиченной НАМЕРЕННО: она защитна сама по себе и
// идемпотентна, а повтор глагола заново накладывает ту же отсечку и заново
// пробует то же снятие. Исход тот же, что и у неснятой сессии чужого
// поставщика: два исполнителя одного предмета отвечают одинаково.
func TestForceLogout_OwnSessionTeardownFails_FailsTheMutation(t *testing.T) {
	own := &recordingOwnSessions{err: errors.New("human_sessions: backend down")}
	rec := &fakeForceLogoutRecorder{}
	h, ops := ownSessionHandler(rec, own)

	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.Error(t, err, "неснятая сессия не имеет права читаться как состоявшийся выход")
	assert.Equal(t, codes.Unavailable, status.Code(err))

	assert.Equal(t, 1, rec.allCnt, "отсечка остаётся закоммиченной — она защитна и идемпотентна")
	assert.Contains(t, ops.calls, "markerror",
		"опрос операции обязан увидеть отказ, а не успех")
}

// TestForceLogout_NoLiveOwnSession_IsStillALogout — ноль снятых записей есть
// законный исход, а не отказ.
//
// Иначе выход отказывал бы тому, кто уже вышел, — то есть направление, делающее
// систему безопаснее, падало бы на повторе.
func TestForceLogout_NoLiveOwnSession_IsStillALogout(t *testing.T) {
	own := &recordingOwnSessions{ended: 0}
	h, _ := ownSessionHandler(&fakeForceLogoutRecorder{}, own)

	op, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.NoError(t, err)
	require.True(t, op.GetDone())
}
