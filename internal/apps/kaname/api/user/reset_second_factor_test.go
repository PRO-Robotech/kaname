// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// reset_second_factor_test.go — сброс второго фактора распорядителем (фаза Ф12,
// задача PRO-Robotech/kacho#1281; приёмка Р10, Ф12-30): синхронная полоса —
// анонимный, негодный id, промах, «фактора нет» (строки нет либо только
// `pending`) — отвечает ДО порождения Operation с токеном
// `SECOND_FACTOR_NOT_ENROLLED`; исполнение — одной транзакцией писателя сессии:
// обе строки сняты, отсечка `now` с причиной `second-factor-reset` и актором
// распорядителя, событие с обоими акторами без личных данных.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// rsfMethods — дублёр хранилища способов: одна строка `totp` в заданном состоянии.
type rsfMethods struct {
	row   *domain.LoginMethod
	err   error
	calls int
}

func (m *rsfMethods) Get(_ context.Context, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error) {
	m.calls++
	if m.err != nil {
		return domain.LoginMethod{}, m.err
	}
	if m.row == nil || kind != domain.LoginMethodTOTP {
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrNotFound, "LoginMethod %s/%s not found", userID, kind)
	}
	return *m.row, nil
}

// rsfSessions — дублёр писателя сессии: одна транзакция, семантика оператора
// снятия — как у адаптера (снимает только `active`).
type rsfSessions struct {
	mu       sync.Mutex
	methods  *rsfMethods
	cutoffs  []domain.UserTokenRevocation
	revokers []domain.UserID
	audits   []outboxtypes.AuditEvent
	writers  int
	commits  int
	failOn   string
}

type rsfWriter struct {
	s        *rsfSessions
	removed  bool
	cutoff   *domain.UserTokenRevocation
	revoker  domain.UserID
	audit    *outboxtypes.AuditEvent
	rolledBk bool
}

func (s *rsfSessions) ResetWriter(context.Context) (SecondFactorResetWriter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writers++
	if s.failOn == "writer" {
		return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	}
	return &rsfWriter{s: s}, nil
}

func (w *rsfWriter) RemoveSecondFactor(_ context.Context, _ domain.UserID) (bool, error) {
	if w.s.failOn == "remove" {
		return false, iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	}
	if w.s.failOn == "vanish" {
		return false, nil // строка снята между проверкой и записью
	}
	row := w.s.methods.row
	if row == nil || row.State != domain.LoginMethodStateActive {
		return false, nil
	}
	w.removed = true
	return true, nil
}

func (w *rsfWriter) UpsertCutoff(_ context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	if err := u.Validate(); err != nil {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	w.cutoff, w.revoker = &u, revokedBy
	return nil
}

func (w *rsfWriter) EmitAudit(_ context.Context, ev outboxtypes.AuditEvent) error {
	if w.s.failOn == "audit" {
		return iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	}
	w.audit = &ev
	return nil
}

func (w *rsfWriter) Commit(context.Context) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.removed {
		w.s.methods.row = nil
	}
	if w.cutoff != nil {
		w.s.cutoffs = append(w.s.cutoffs, *w.cutoff)
		w.s.revokers = append(w.s.revokers, w.revoker)
	}
	if w.audit != nil {
		w.s.audits = append(w.s.audits, *w.audit)
	}
	w.s.commits++
	return nil
}

func (w *rsfWriter) Rollback(context.Context) error { w.rolledBk = true; return nil }

func rsfActive() *rsfMethods {
	return &rsfMethods{row: &domain.LoginMethod{
		UserID: domain.UserID(updUserID), Kind: domain.LoginMethodTOTP, State: domain.LoginMethodStateActive,
		AcceptedStep: 100, StepAccepted: true, CreatedAt: time.Now(),
	}}
}

func rsfPending() *rsfMethods {
	return &rsfMethods{row: &domain.LoginMethod{
		UserID: domain.UserID(updUserID), Kind: domain.LoginMethodTOTP, State: domain.LoginMethodStatePending, CreatedAt: time.Now(),
	}}
}

func rsfReason(t *testing.T, err error) string {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok, "ожидался gRPC status; получено %v", err)
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			return ei.GetReason()
		}
	}
	return ""
}

// TestResetSecondFactor_F12_30_SyncRefusals — анонимный, негодный id, промах —
// до касания хранилища способов; сброс не пишет ничего.
func TestResetSecondFactor_F12_30_SyncRefusals(t *testing.T) {
	methods := rsfActive()
	sessions := &rsfSessions{methods: methods}
	uc := NewResetSecondFactorUseCase(newUpdUserRepo(), newUpdOpsRepo(), methods, sessions)

	op, err := uc.Execute(context.Background(), domain.UserID(updUserID))
	require.Error(t, err)
	assert.Nil(t, op)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "анонимный — до всего")

	op, err = uc.Execute(ownerCtx(), "not-a-valid-id")
	require.Error(t, err)
	assert.Nil(t, op)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "invalid user id")

	absentRepo := newUpdUserRepo()
	absentRepo.getErr = iamerr.Wrapf(iamerr.ErrNotFound, "User usr000000000000absnt not found")
	op, err = NewResetSecondFactorUseCase(absentRepo, newUpdOpsRepo(), methods, sessions).Execute(ownerCtx(), "usr000000000000absnt")
	require.Error(t, err)
	assert.Nil(t, op)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, "User usr000000000000absnt not found", status.Convert(err).Message(), "промах — контракт-тоном, байт-идентичным сокрытию существования")

	assert.Zero(t, methods.calls, "до строки способов ни один отказ выше не доходит")
	assert.Zero(t, sessions.writers)
}

// TestResetSecondFactor_F12_30_NotEnrolledIsOneRefusal — строки нет и строка
// только `pending` — один отказ FAILED_PRECONDITION с токеном; `pending` не
// тронута, отсечки нет, события нет, Operation не порождена.
func TestResetSecondFactor_F12_30_NotEnrolledIsOneRefusal(t *testing.T) {
	var bodies []string
	for name, methods := range map[string]*rsfMethods{"absent": {}, "pending": rsfPending()} {
		t.Run(name, func(t *testing.T) {
			sessions := &rsfSessions{methods: methods}
			ops := newUpdOpsRepo()
			op, err := NewResetSecondFactorUseCase(newUpdUserRepo(), ops, methods, sessions).Execute(ownerCtx(), domain.UserID(updUserID))
			require.Error(t, err)
			assert.Nil(t, op, "отказ до порождения Operation")
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.Equal(t, "second factor is not enrolled", status.Convert(err).Message())
			assert.Equal(t, "SECOND_FACTOR_NOT_ENROLLED", rsfReason(t, err))
			bodies = append(bodies, err.Error())
			assert.Zero(t, sessions.writers, "писатель не вызван: сбрасывать нечего")
			assert.Empty(t, ops.ops, "Operation не порождена")
			if methods.row != nil {
				assert.Equal(t, domain.LoginMethodStatePending, methods.row.State, "pending не тронута")
			}
		})
	}
	require.Len(t, bodies, 2)
	assert.Equal(t, bodies[0], bodies[1], "оба отказа побайтово равны: снаружи «нет» и «pending» неразличимы")
}

// TestResetSecondFactor_F12_30_ResetIsOneTransaction — обе строки сняты,
// отсечка `now` с причиной и актором, событие с обоими акторами и без личных
// данных — одним коммитом; отказ записи события — ничего не снято.
func TestResetSecondFactor_F12_30_ResetIsOneTransaction(t *testing.T) {
	methods := rsfActive()
	sessions := &rsfSessions{methods: methods}
	repo := newUpdUserRepo()
	before := time.Now().UTC()
	op, err := NewResetSecondFactorUseCase(repo, newUpdOpsRepo(), methods, sessions).Execute(ownerCtx(), domain.UserID(updUserID))
	require.NoError(t, err)
	require.NotNil(t, op)
	assert.Contains(t, op.Description, "Reset second factor")
	require.NoError(t, operations.Wait(context.Background()))

	assert.Nil(t, methods.row, "строка totp снята (с ней — набор: оператор адаптера снимает обе)")
	assert.Equal(t, 1, sessions.commits)
	require.Len(t, sessions.cutoffs, 1)
	cut := sessions.cutoffs[0]
	assert.Equal(t, domain.UserID(updUserID), cut.UserID)
	assert.Equal(t, domain.RevokeReasonSecondFactorReset, cut.Reason)
	assert.Equal(t, domain.UserID(updOwnerID), cut.RevokedBy, "актор отсечки — распорядитель")
	assert.Equal(t, domain.UserID(updOwnerID), sessions.revokers[0])
	assert.False(t, cut.RevokeBefore.Before(before), "отсечка — моментом now")
	assert.False(t, cut.RevokeBefore.After(time.Now().UTC().Add(time.Second)))

	require.Len(t, sessions.audits, 1)
	ev := sessions.audits[0]
	assert.Equal(t, "iam.user.second_factor_reset", ev.EventType)
	assert.Equal(t, updAccountID, ev.TenantAccountID)
	assert.Equal(t, updOwnerID, ev.Payload["actor"])
	assert.Equal(t, updUserID, ev.Payload["user_id"], "субъект — человек, чей фактор снят")
	assert.Equal(t, domain.RevokeReasonSecondFactorReset, ev.Payload["reason"])
	for _, k := range []string{"email", "display_name", "displayName", "external_id", "secret", "code"} {
		assert.NotContains(t, ev.Payload, k, "персональных данных и секретов в следе нет: %s", k)
	}
	assert.Empty(t, repo.auditSnapshot(), "событие идёт писателем сессии, не зеркалом: одна транзакция со снятием")

	// Отказ записи события — ничего не снято, Operation с ошибкой.
	methods2 := rsfActive()
	sessions2 := &rsfSessions{methods: methods2, failOn: "audit"}
	ops2 := newUpdOpsRepo()
	op, err = NewResetSecondFactorUseCase(newUpdUserRepo(), ops2, methods2, sessions2).Execute(ownerCtx(), domain.UserID(updUserID))
	require.NoError(t, err)
	require.NoError(t, operations.Wait(context.Background()))
	assert.NotNil(t, methods2.row, "при отказе записи события строка не снята")
	assert.Zero(t, sessions2.commits)
	assert.Empty(t, sessions2.cutoffs)
	got, gerr := ops2.Get(context.Background(), op.ID)
	require.NoError(t, gerr)
	require.True(t, got.Done)
	assert.NotNil(t, got.Error, "Operation несёт отказ")
}

// TestResetSecondFactor_F12_30_RaceWithSelfRemoval — строка `active` была на
// синхронной проверке и исчезла к записи (человек снял сам): оператор снятия
// отвечает «нет», исход Operation — FAILED_PRECONDITION, отсечки и события нет,
// транзакция не зафиксирована.
func TestResetSecondFactor_F12_30_RaceWithSelfRemoval(t *testing.T) {
	methods := rsfActive()
	sessions := &rsfSessions{methods: methods, failOn: "vanish"}
	ops := newUpdOpsRepo()
	op, err := NewResetSecondFactorUseCase(newUpdUserRepo(), ops, methods, sessions).Execute(ownerCtx(), domain.UserID(updUserID))
	require.NoError(t, err, "синхронная проверка видела active")
	require.NoError(t, operations.Wait(context.Background()))
	assert.Zero(t, sessions.commits)
	assert.Empty(t, sessions.cutoffs)
	assert.Empty(t, sessions.audits)
	got, gerr := ops.Get(context.Background(), op.ID)
	require.NoError(t, gerr)
	require.True(t, got.Done)
	require.NotNil(t, got.Error)
	assert.EqualValues(t, codes.FailedPrecondition, got.Error.Code)
}
