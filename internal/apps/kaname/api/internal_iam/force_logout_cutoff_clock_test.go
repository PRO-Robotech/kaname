// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// force_logout_cutoff_clock_test.go — отсечку ForceLogout ставит ОБЩИЙ
// источник моментов, а не часы процесса реплики (задача kaname#589); источник
// не ответил либо не подан — закрытый отказ фиксированным текстом ДО записи
// операции.

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func forceLogoutWithClock(rec *fakeForceLogoutRecorder, clock revocationpolicy.Clock) (*Handler, *recordingForceLogoutOps) {
	ops := &recordingForceLogoutOps{}
	return NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithAdminChecker(&fakeForceLogoutChecker{allow: true}).
		WithOperations(ops).
		WithOwnSessions(rec).
		WithCutoffClock(clock), ops
}

func TestForceLogout_CutoffIsTheSharedSourceMoment(t *testing.T) {
	at := time.Date(2026, 10, 7, 9, 37, 0, 123456000, time.UTC)
	rec := &fakeForceLogoutRecorder{}
	h, _ := forceLogoutWithClock(rec, momentclock.At(at))
	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.NoError(t, err)
	require.Equal(t, 1, rec.allCnt)
	require.Truef(t, rec.allBefore.Equal(at), "отсечка %s, а источник показывал %s", rec.allBefore, at)
}

func TestForceLogout_UnansweredOrUnwiredSourceIsAClosedRefusalBeforeTheOperation(t *testing.T) {
	for name, clock := range map[string]revocationpolicy.Clock{
		"источник не ответил": momentclock.Failing{Err: errors.New("dial tcp 10.0.0.9:5432")},
		"источник не подан":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			rec := &fakeForceLogoutRecorder{}
			h, ops := forceLogoutWithClock(rec, clock)
			_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
			st, ok := status.FromError(err)
			require.True(t, ok)
			require.Equal(t, codes.Unavailable, st.Code())
			require.Equal(t, shared.MomentUnavailableMessage, st.Message(), "текст фиксирован и не несёт причины")
			require.Empty(t, ops.calls, "операция не записана: глагол без момента не оставляет следа")
			require.Zero(t, rec.allCnt, "отсечка не записана")
		})
	}
}
