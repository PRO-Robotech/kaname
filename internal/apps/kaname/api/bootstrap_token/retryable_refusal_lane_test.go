// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retryable_refusal_lane_test.go — ПОВЕДЕНЧЕСКИЙ замок на полосы, которых
// переводчик чеканки не различал (задача kaname#114).
//
// Предмет и доводы — те же, что у одноимённых проб `sa_keys` и `user_tokens`:
// замок стоит на наблюдаемом коде gRPC, а не на наличии ветви в коде.
//
// ЛОГГЕР НЕ ПРОВЯЗАН НАМЕРЕННО: `logErr` нулевой логгер пропускает, а предмет
// пробы — КОД полосы, а не запись в журнал. Подделка логгера здесь расширила бы
// утверждение на то, о чём проба не высказывается.
package bootstrap_token

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

func TestMintMapErrKeepsTheRetryableAndAuthzLanes(t *testing.T) {
	u := &MintUseCase{}
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		in   error
		want codes.Code
	}{
		// Полосы, которых переводчик не различал.
		{"повторяемый отказ", iamerr.Wrapf(iamerr.ErrAborted, "serialization conflict"), codes.Aborted},
		{"отказ в правах", iamerr.Wrapf(iamerr.ErrPermissionDenied, "not allowed"), codes.PermissionDenied},
		{"нет удостоверения", iamerr.Wrapf(iamerr.ErrUnauthenticated, "no credential"), codes.Unauthenticated},
		// Положительные контроли: различавшееся различается по-прежнему.
		{"нет строки", iamerr.Wrapf(iamerr.ErrNotFound, "missing"), codes.NotFound},
		{"занято", iamerr.Wrapf(iamerr.ErrAlreadyExists, "taken"), codes.AlreadyExists},
		{"состояние не позволяет", iamerr.Wrapf(iamerr.ErrFailedPrecondition, "bad state"), codes.FailedPrecondition},
		{"негодный ввод", iamerr.Wrapf(iamerr.ErrInvalidArg, "bad input"), codes.InvalidArgument},
		{"недоступно", iamerr.Wrapf(iamerr.ErrUnavailable, "peer down"), codes.Unavailable},
		{"внутренняя", iamerr.Wrapf(iamerr.ErrInternal, "boom"), codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := status.Code(u.mapErr(ctx, "probe", tc.in))
			if got != tc.want {
				t.Fatalf("полоса %q переведена в %v, ожидался %v — отказ уехал не в тот код, "+
					"и вызывающий прочтёт его как другой класс события", tc.name, got, tc.want)
			}
		})
	}
}
