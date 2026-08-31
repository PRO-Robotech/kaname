// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// poll_subject_changes_position_lost_test.go — тон отказа «позиция утрачена»
// (задача #1712).
//
// # Что здесь держится
//
// Курсор ниже пола журнала означает, что строки между ними СНЯТЫ и вызывающий их
// уже не получит. Полос ответа три, и они несравнимы:
//
//	«позиции ещё нет»   → UNAVAILABLE, повторить с той же позиции;
//	«позиция утрачена»  → OUT_OF_RANGE + машинный признак, погасить и пересесть;
//	отказ хранилища     → INTERNAL, разбирать поломку.
//
// Слить вторую с первой нельзя: повтор с утраченной позиции не пройдёт НИКОГДА,
// и петля отзыва встала бы навсегда — молча для клиента, у которого кэш вердиктов
// продолжает отвечать по снятым правам. Слить с третьей тоже нельзя: `INTERNAL`
// текста не несёт by construction, а возобновимая позиция обязана доехать.
//
// Полосы «ещё нет» и «хранилище» держит соседняя проба
// (`poll_subject_changes_tone_test.go`); здесь они стоят положительным контролем,
// иначе утверждение зеленело бы на обработчике, отвечающем OUT_OF_RANGE на всё.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/subjectchange"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// TestPollSubjectChangesNamesTheLostPositionMachineReadably — разбираемая полоса.
func TestPollSubjectChangesNamesTheLostPositionMachineReadably(t *testing.T) {
	sentinel := &service.SubjectChangePositionLostError{EarliestResumable: 599}

	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "отказ как есть", err: sentinel},
		{
			// Обёрнутый — та же полоса: вызывающий читает ПРИЧИНУ, а не совпадение
			// значений, иначе первое же оборачивание в адаптере вернуло бы тон
			// общего отказа и потеряло возобновимую позицию.
			name: "отказ обёрнут адаптером",
			err:  fmt.Errorf("poll subject changes: %w", sentinel),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := (&Handler{}).WithSubjectChange(stubSubjectChanger{err: tc.err})
			_, err := h.PollSubjectChanges(context.Background(), &iamv1.PollSubjectChangesRequest{SinceId: 42})
			require.Error(t, err)
			require.Equal(t, codes.OutOfRange, status.Code(err), "тон отказа: %v", err)

			// Признак и позиция читаются ТЕМ ЖЕ распознавателем, каким их читает
			// край: собственная разборка деталей здесь была бы вторым местом об
			// одном предмете и разошлась бы с настоящим читателем молча.
			lost, ok := subjectchange.AsPositionLost(err)
			require.True(t, ok, "отказ не опознан читателем края: %v", err)
			require.Equal(t, int64(599), lost.EarliestResumable)
		})
	}
}

// TestPollSubjectChangesKeepsTheOtherTwoLanesDistinct — положительный контроль.
func TestPollSubjectChangesKeepsTheOtherTwoLanesDistinct(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want codes.Code
	}{
		{name: "границы ещё нет", err: service.ErrSubjectChangeNotSettled, want: codes.Unavailable},
		{name: "отказ хранилища", err: errors.New("connection refused"), want: codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := (&Handler{}).WithSubjectChange(stubSubjectChanger{err: tc.err})
			_, err := h.PollSubjectChanges(context.Background(), &iamv1.PollSubjectChangesRequest{})
			require.Error(t, err)
			require.Equal(t, tc.want, status.Code(err), "тон отказа: %v", err)
			_, ok := subjectchange.AsPositionLost(err)
			require.False(t, ok, "чужая полоса опознана как утраченная позиция: %v", err)
		})
	}
}
