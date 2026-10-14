// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// reset_second_factor_cutoff_clock_test.go — отсечку сброса второго фактора
// ставит момент ПИСАТЕЛЯ сброса — часы первичной базы (общий источник,
// kaname#589), прочитанные соединением его транзакции после захвата строки
// личности (kaname#680), — а не часы процесса реплики и не момент, прочитанный
// до открытия транзакции. Писатель не ответил моментом либо ответил нулевым —
// закрытый отказ фиксированным текстом: ничего не снято, транзакция откатана.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
)

func TestResetSecondFactor_CutoffIsTheWriterMomentUnderThePersonLock(t *testing.T) {
	at := time.Date(2026, 10, 7, 9, 37, 0, 123456000, time.UTC)
	methods := rsfActive()
	sessions := &rsfSessions{methods: methods, clock: momentclock.At(at)}
	_, err := NewResetSecondFactorUseCase(newUpdUserRepo(), newUpdOpsRepo(), methods, sessions).
		Execute(ownerCtx(), domain.UserID(updUserID))
	require.NoError(t, err)
	require.NoError(t, operations.Wait(context.Background()))
	require.Equal(t, domain.UserID(updUserID), sessions.heldFor,
		"писатель открыт под строкой личности того, чей фактор сбрасывается")
	require.Len(t, sessions.cutoffs, 1)
	require.Truef(t, sessions.cutoffs[0].RevokeBefore.Equal(at), "отсечка %s, а писатель показывал %s",
		sessions.cutoffs[0].RevokeBefore, at)
}

func TestResetSecondFactor_UnansweredOrZeroWriterMomentIsAClosedRefusal(t *testing.T) {
	for name, clock := range map[string]revocationpolicy.Clock{
		"момент не прочитан": momentclock.Failing{Err: errors.New("dial tcp 10.0.0.9:5432")},
		"момент нулевой":     momentclock.At(time.Time{}),
	} {
		t.Run(name, func(t *testing.T) {
			methods := rsfActive()
			sessions := &rsfSessions{methods: methods, clock: clock}
			ops := newUpdOpsRepo()
			op, err := NewResetSecondFactorUseCase(newUpdUserRepo(), ops, methods, sessions).
				Execute(ownerCtx(), domain.UserID(updUserID))
			require.NoError(t, err)
			require.NoError(t, operations.Wait(context.Background()))
			got, gerr := ops.Get(context.Background(), op.ID)
			require.NoError(t, gerr)
			require.True(t, got.Done)
			require.NotNil(t, got.Error, "Operation несёт отказ")
			require.Equal(t, int32(codes.Unavailable), got.Error.GetCode())
			require.Equal(t, shared.MomentUnavailableMessage, got.Error.GetMessage(), "текст фиксирован и не несёт причины")
			require.NotNil(t, methods.row, "фактор не снят")
			require.Equal(t, 1, sessions.writers, "момент читает писатель: транзакция открыта")
			require.Equal(t, 1, sessions.rollbacks, "транзакция писателя откатана")
			require.Zero(t, sessions.commits, "транзакция писателя не зафиксирована")
			require.Empty(t, sessions.cutoffs, "отсечка не записана")
		})
	}
}
