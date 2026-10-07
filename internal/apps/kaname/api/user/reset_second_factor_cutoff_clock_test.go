// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// reset_second_factor_cutoff_clock_test.go — отсечку сброса второго фактора
// ставит ОБЩИЙ источник моментов, а не часы процесса реплики (задача
// kaname#589); источник не ответил либо не подан — закрытый отказ
// фиксированным текстом, транзакция писателя не открыта, ничего не снято.

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

func TestResetSecondFactor_CutoffIsTheSharedSourceMoment(t *testing.T) {
	at := time.Date(2026, 10, 7, 9, 37, 0, 123456000, time.UTC)
	methods := rsfActive()
	sessions := &rsfSessions{methods: methods}
	_, err := NewResetSecondFactorUseCase(newUpdUserRepo(), newUpdOpsRepo(), methods, sessions).
		WithCutoffClock(momentclock.At(at)).Execute(ownerCtx(), domain.UserID(updUserID))
	require.NoError(t, err)
	require.NoError(t, operations.Wait(context.Background()))
	require.Len(t, sessions.cutoffs, 1)
	require.Truef(t, sessions.cutoffs[0].RevokeBefore.Equal(at), "отсечка %s, а источник показывал %s",
		sessions.cutoffs[0].RevokeBefore, at)
}

func TestResetSecondFactor_UnansweredOrUnwiredSourceIsAClosedRefusal(t *testing.T) {
	for name, clock := range map[string]revocationpolicy.Clock{
		"источник не ответил": momentclock.Failing{Err: errors.New("dial tcp 10.0.0.9:5432")},
		"источник не подан":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			methods := rsfActive()
			sessions := &rsfSessions{methods: methods}
			ops := newUpdOpsRepo()
			op, err := NewResetSecondFactorUseCase(newUpdUserRepo(), ops, methods, sessions).
				WithCutoffClock(clock).Execute(ownerCtx(), domain.UserID(updUserID))
			require.NoError(t, err)
			require.NoError(t, operations.Wait(context.Background()))
			got, gerr := ops.Get(context.Background(), op.ID)
			require.NoError(t, gerr)
			require.True(t, got.Done)
			require.NotNil(t, got.Error, "Operation несёт отказ")
			require.Equal(t, int32(codes.Unavailable), got.Error.GetCode())
			require.Equal(t, shared.MomentUnavailableMessage, got.Error.GetMessage(), "текст фиксирован и не несёт причины")
			require.NotNil(t, methods.row, "фактор не снят")
			require.Zero(t, sessions.writers, "транзакция писателя не открыта: момент берётся до неё")
			require.Zero(t, sessions.commits, "транзакция писателя не зафиксирована")
			require.Empty(t, sessions.cutoffs, "отсечка не записана")
		})
	}
}
