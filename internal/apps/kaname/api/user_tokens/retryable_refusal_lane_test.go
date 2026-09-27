// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retryable_refusal_lane_test.go — ПОВЕДЕНЧЕСКИЙ замок на полосы, которых
// переводчик этого домена не различал (задача kaname#114).
//
// ПРЕДМЕТ. Замок стоит на НАБЛЮДАЕМОМ — коде gRPC, — а не на наличии ветви в
// коде: рефактор, вернувший дефект, оставил бы пробу на `switch` зелёной
// (`testing.md` §«Regression-lock ... на уровне ОБСЕРВАБЛА»).
//
// ПОЧЕМУ ИМЕННО ЭТИ ТРИ. `ErrAborted` достижим: `pgmaperr` ставит его на
// 40001/40P01, и повтор того же запроса проходит — до правки он уезжал в
// терминальный INTERNAL, то есть повторяемый отказ приходил как поломка
// платформы и клиент его не повторял. `ErrPermissionDenied` и
// `ErrUnauthenticated` — те самые две полосы, которые годок канонического
// переводчика уже называл однажды потерянными копиями.
//
// ОБЕ СТОРОНЫ. Положительный контроль здесь же: полоса, различавшаяся и до
// правки, обязана остаться прежней — иначе проба зеленела бы на переводчике,
// отвечающем одним кодом на всё.
package user_tokens

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

func TestMapPGErrKeepsTheRetryableAndAuthzLanes(t *testing.T) {
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
		// Конец контекста — повторяемый отказ (kaname#383): до правки уезжал в
		// терминальный INTERNAL. Близнец — «внутренняя» ниже: та же обёртка, причина
		// не конец контекста.
		{"конец контекста: отмена", context.Canceled, codes.Unavailable},
		{"конец контекста: срок под обёрткой", iamerr.Wrapf(iamerr.ErrInternal, "store: %w", context.DeadlineExceeded), codes.Unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := status.Code(mapPGErr(tc.in))
			if got != tc.want {
				t.Fatalf("полоса %q переведена в %v, ожидался %v — отказ уехал не в тот код, "+
					"и вызывающий прочтёт его как другой класс события", tc.name, got, tc.want)
			}
		})
	}
}

// TestMapPGErrKeepsTheOpaqueInternalText — текст терминального INTERNAL остаётся
// СВОИМ и подробности цепочки на провод не несёт (hardening-инвариант #1).
// Утверждается СООБЩЕНИЕ, а не только код: рефактор, вернувший разбор цепочки,
// оставил бы пробу на коде зелёной.
func TestMapPGErrKeepsTheOpaqueInternalText(t *testing.T) {
	const secret = "pgx: host=db-1 user=kaname password=hunter2"
	msg := status.Convert(mapPGErr(iamerr.Wrapf(iamerr.ErrInternal, "%s", secret))).Message()
	if msg == "" || msg == secret {
		t.Fatalf("терминальный INTERNAL отдал подробность цепочки: %q", msg)
	}
	for _, leak := range []string{"pgx", "password", "host="} {
		if containsSub(msg, leak) {
			t.Fatalf("текст INTERNAL несёт %q: %q", leak, msg)
		}
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
