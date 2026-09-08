// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// poll_subject_changes_tone_test.go — kacho#1374: тон отказа «позиции ещё нет».
//
// # Что здесь держится
//
// Владелец журнала отвечает `UNAVAILABLE`, когда границы устоявшегося ещё нет.
// Это ОБЪЯВЛЕНО контрактом (`PollSubjectChanges`, `internal_iam_service.proto`) и
// потому обязано быть закреплено пробой: вызывающий по этому тону решает
// переспросить на следующем такте, а не разбирать поломку.
//
// Слить его с общим отказом хранилища нельзя, и цена слияния несимметрична:
// `INTERNAL` посылает читателя искать неисправность там, где верный следующий шаг
// — повторить, и делает это на КАЖДОМ холодном старте.
//
// Рядом стоит положительный контроль: общий отказ по-прежнему `INTERNAL`.
// Утверждение об одном тоне без второго зеленело бы на реализации, отвечающей
// `UNAVAILABLE` на всё подряд.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// stubSubjectChanger отвечает названным отказом.
type stubSubjectChanger struct{ err error }

func (s stubSubjectChanger) PollSubjectChanges(
	context.Context, int64, int32,
) ([]service.SubjectChange, int64, error) {
	return nil, 0, s.err
}

func TestPollSubjectChangesSeparatesNotSettledFromAFailure(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{
			name: "границы ещё нет — переспросить",
			err:  service.ErrSubjectChangeNotSettled,
			want: codes.Unavailable,
		},
		{
			// Обёрнутый отказ — та же полоса: вызывающий читает ПРИЧИНУ, а не
			// совпадение значений, иначе первое же оборачивание в адаптере
			// вернуло бы тон общего отказа.
			name: "границы ещё нет, отказ обёрнут",
			err:  fmt.Errorf("poll: %w", service.ErrSubjectChangeNotSettled),
			want: codes.Unavailable,
		},
		{
			name: "отказ хранилища — разбирать поломку",
			err:  errors.New("connection refused"),
			want: codes.Internal,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := (&Handler{}).WithSubjectChange(stubSubjectChanger{err: tc.err})
			_, err := h.PollSubjectChanges(context.Background(), &iamv1.PollSubjectChangesRequest{})
			require.Error(t, err)
			require.Equal(t, tc.want, status.Code(err),
				"тон отказа: %v", err)
		})
	}
}
