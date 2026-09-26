// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package errors_test

import (
	"context"
	stderrors "errors"
	"testing"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

func TestOnEndedCall(t *testing.T) {
	storeFailure := iamerr.Wrapf(iamerr.ErrInternal, "database error: sqlstate 57014")
	unreachable := iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	named := iamerr.Wrapf(iamerr.ErrNotFound, "interactive client x: not found")

	ended, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancel2 := context.WithTimeout(context.Background(), 0)
	defer cancel2()
	live := context.Background()

	for _, tc := range []struct {
		name string
		ctx  context.Context
		err  error
		end  error
	}{
		{"отказ хранилища на отменённом вызове", ended, storeFailure, context.Canceled},
		{"отказ хранилища на истёкшем сроке", expired, storeFailure, context.DeadlineExceeded},
		{"недоступность на истёкшем сроке", expired, unreachable, context.DeadlineExceeded},
		{"близнец: отказ хранилища на живом вызове", live, storeFailure, nil},
		{"близнец: ответ с причиной на истёкшем сроке", expired, named, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := iamerr.OnEndedCall(tc.ctx, tc.err)
			if !stderrors.Is(got, tc.err) {
				t.Fatalf("исходный отказ потерян: %v", got)
			}
			switch {
			case tc.end != nil && !stderrors.Is(got, tc.end):
				t.Errorf("конец вызова не в цепочке: %v", got)
			case tc.end == nil && (stderrors.Is(got, context.Canceled) || stderrors.Is(got, context.DeadlineExceeded)):
				t.Errorf("конец вызова приписан: %v", got)
			}
		})
	}
	if iamerr.OnEndedCall(ended, nil) != nil {
		t.Errorf("отсутствие отказа стало отказом")
	}
}
