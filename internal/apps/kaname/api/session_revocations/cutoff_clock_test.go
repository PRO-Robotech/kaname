// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations

// cutoff_clock_test.go — отсечку отзыва-всех ставит ОБЩИЙ источник моментов, а
// не часы процесса реплики (задача kaname#589); источник не ответил либо не
// подан — закрытый отказ фиксированным текстом ДО записи операции.

import (
	"context"
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

func TestRevokeAll_CutoffIsTheSharedSourceMoment(t *testing.T) {
	at := time.Date(2026, 10, 7, 9, 37, 0, 123456000, time.UTC)
	w := &fakeRevoker{}
	ops := &recordingOpsRepo{}
	h := NewHandler(NewRevokeUseCase(w, ops, momentclock.At(at)), &fakeReader{})
	_, err := h.Revoke(context.Background(), &iamv1.RevokeRequest{UserId: "usr00000000000000001", RevokeAllUserTokens: true})
	require.NoError(t, err)
	require.Equal(t, 1, w.allCnt)
	require.Truef(t, w.allBefore.Equal(at), "отсечка %s, а источник показывал %s", w.allBefore, at)
}

func TestRevokeAll_UnansweredOrUnwiredSourceIsAClosedRefusalBeforeTheOperation(t *testing.T) {
	for name, clock := range map[string]revocationpolicy.Clock{
		"источник не ответил": momentclock.Failing{Err: errors.New("dial tcp 10.0.0.9:5432")},
		"источник не подан":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			w := &fakeRevoker{}
			ops := &recordingOpsRepo{}
			h := NewHandler(NewRevokeUseCase(w, ops, clock), &fakeReader{})
			_, err := h.Revoke(context.Background(), &iamv1.RevokeRequest{UserId: "usr00000000000000001", RevokeAllUserTokens: true})
			st, ok := status.FromError(err)
			require.True(t, ok)
			require.Equal(t, codes.Unavailable, st.Code())
			require.Equal(t, shared.MomentUnavailableMessage, st.Message(), "текст фиксирован и не несёт причины")
			require.Empty(t, ops.calls, "операция не записана: глагол без момента не оставляет следа")
			require.Zero(t, w.allCnt, "отсечка не записана")
		})
	}
}
