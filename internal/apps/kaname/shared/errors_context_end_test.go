// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// errors_context_end_test.go — КОНЕЦ КОНТЕКСТА НА ПУТИ ХРАНИЛИЩА ПОДАЁТСЯ
// НЕДОСТУПНОСТЬЮ, А НЕ ПОЛОМКОЙ (задача kaname#383).
//
// Конец контекста — состояние, которое проходит: повтор на свежем сроке
// осмыслен. `Internal` говорит обратное — «служба сломана, повторять
// нечего», — и клиент, решающий по коду, не повторит.
//
// У конца контекста ДВЕ формы, и каждая судится своим признаком:
//
//   - ошибка контекста В ЦЕПОЧКЕ — драйвер увидел конец срока до отправки
//     оператора либо по сроку сокета. Её видит сама цепочка, поэтому судит её
//     общий переводчик, `MapRepoErr`, контекста не зная;
//   - код хранилища БЕЗ ошибки контекста — пул службы доводит отмену до
//     сервера (`CancelRequest`, `corelib/db.NewPool`), и оператор снимается
//     там строкой состояния `57014`. По ошибке его не отличить от снятия по
//     собственному потолку оператора (`statement_timeout`), которое повтором
//     не лечится, поэтому судит его СОСТОЯНИЕ контекста, на котором шёл вызов,
//     — `MapRepoErrAt`.
//
// Законный близнец каждой пробы отличается ОДНИМ фактом: причина в цепочке —
// не конец контекста, либо контекст вызова жив.
package shared_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// driverTimeout — обёртка ошибки контекста той формы, какую кладёт драйвер
// (`pgconn`: «timeout: context already done: …»), — тип со своим `Unwrap`.
type driverTimeout struct{ err error }

func (e *driverTimeout) Error() string { return "timeout: " + e.err.Error() }
func (e *driverTimeout) Unwrap() error { return e.err }

// storeCode57014 — отказ хранилища кодом состояния, как его отдаёт мост
// SQLSTATE: ошибки контекста в цепочке нет.
func storeCode57014() error {
	return iamerr.Wrapf(iamerr.ErrInternal, "database error: sqlstate 57014")
}

func assertAnswer(t *testing.T, got error, code codes.Code, msg string) {
	t.Helper()
	st, ok := status.FromError(got)
	if !ok {
		t.Fatalf("ответ не статус gRPC: %v", got)
	}
	if st.Code() != code || st.Message() != msg {
		t.Fatalf("ответ %s %q, ожидался %s %q", st.Code(), st.Message(), code, msg)
	}
}

// TestMapRepoErr_ContextEndInTheChainIsUnavailable — первая форма: ошибка
// контекста в цепочке. Каждое написание, в каком она доезжает до переводчика.
func TestMapRepoErr_ContextEndInTheChainIsUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   error
	}{
		{"отмена, голая", context.Canceled},
		{"срок, голый", context.DeadlineExceeded},
		{"обёрнут вызывающим", fmt.Errorf("list accounts: %w", context.DeadlineExceeded)},
		{"обёрнут драйвером", &driverTimeout{err: context.Canceled}},
		{"под внутренним признаком", iamerr.Wrapf(iamerr.ErrInternal, "list accounts: %w", context.Canceled)},
		{"рядом с отказом отката", errors.Join(errors.New("rollback failed"), context.DeadlineExceeded)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertAnswer(t, shared.MapRepoErr(tc.in), codes.Unavailable, shared.UnavailableMessage)
		})
	}
}

// TestMapRepoErr_InternalStoreRefusalStaysInternal — законный близнец: та же
// обёртка, причина — не конец контекста. Поломка остаётся поломкой, и текст её
// остаётся фиксированным.
func TestMapRepoErr_InternalStoreRefusalStaysInternal(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   error
	}{
		{"обёрнут вызывающим", fmt.Errorf("list accounts: %w", errors.New("boom"))},
		{"обёрнут драйвером", &driverTimeout{err: errors.New("i/o timeout")}},
		{"под внутренним признаком", iamerr.Wrapf(iamerr.ErrInternal, "list accounts: %w", errors.New("boom"))},
		{"код хранилища без контекста", storeCode57014()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertAnswer(t, shared.MapRepoErr(tc.in), codes.Internal, "internal error")
		})
	}
}

// TestMapRepoErrAt_StoreCodeAfterTheCallContextEnded_IsUnavailable — вторая
// форма: код хранилища без ошибки контекста, пришедший, когда контекст вызова
// уже кончился. Близнец — тот же отказ на живом контексте: поломка.
func TestMapRepoErrAt_StoreCodeAfterTheCallContextEnded_IsUnavailable(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithTimeout(context.Background(), 0)
	defer cancelExpired()
	<-expired.Done()

	assertAnswer(t, shared.MapRepoErrAt(ended, storeCode57014()), codes.Unavailable, shared.UnavailableMessage)
	assertAnswer(t, shared.MapRepoErrAt(expired, storeCode57014()), codes.Unavailable, shared.UnavailableMessage)
	assertAnswer(t, shared.MapRepoErrAt(context.Background(), storeCode57014()), codes.Internal, "internal error")
}

// TestMapRepoErrAt_OnlyAnInternalAnswerIsReadAsTheContextEnd — конец контекста
// переклассифицирует ТОЛЬКО поломку. Ответ, который называет свою причину
// (строки нет, ввод негоден, конфликт), остаётся этим ответом: он не про срок.
func TestMapRepoErrAt_OnlyAnInternalAnswerIsReadAsTheContextEnd(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		in   error
		want codes.Code
	}{
		{iamerr.Wrapf(iamerr.ErrNotFound, "Account acc-1 not found"), codes.NotFound},
		{iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument name"), codes.InvalidArgument},
		{iamerr.Wrapf(iamerr.ErrAborted, "retry"), codes.Aborted},
		{status.Error(codes.PermissionDenied, "denied"), codes.PermissionDenied},
	} {
		if got := status.Code(shared.MapRepoErrAt(ended, tc.in)); got != tc.want {
			t.Errorf("%v: ответ %s, ожидался %s — конец контекста переписал ответ, который назвал свою причину",
				tc.in, got, tc.want)
		}
	}
	if shared.MapRepoErrAt(ended, nil) != nil {
		t.Fatal("отсутствие отказа обязано остаться отсутствием")
	}
}

// ── Общий каркас пишущей транзакции ─────────────────────────────────────────

// ctxEndRepo — хранилище, отдающее один писатель. Не названные методы не
// реализованы: каркас их не зовёт, и вызов уронил бы пробу, а не прошёл.
type ctxEndRepo struct {
	kanamerepo.Repository
	w       *ctxEndWriter
	openErr error
	onOpen  func()
}

func (r *ctxEndRepo) Writer(context.Context) (kanamerepo.Writer, error) {
	if r.onOpen != nil {
		r.onOpen()
	}
	if r.openErr != nil {
		return nil, r.openErr
	}
	return r.w, nil
}

type ctxEndWriter struct {
	kanamerepo.Writer
	commitErr error
	onCommit  func()
}

func (w *ctxEndWriter) Commit(context.Context) error {
	if w.onCommit != nil {
		w.onCommit()
	}
	return w.commitErr
}

func (w *ctxEndWriter) Rollback(context.Context) error { return nil }

// TestDoWithWriteTx_StoreRefusalAfterItsContextEnded_IsUnavailable — общий
// каркас пишущей транзакции судит отказ по контексту, на котором шёл вызов:
// открытие, мутация, фиксация. Каждая сцена — пара «контекст кончился / жив»,
// и отличается в ней ровно этот факт.
func TestDoWithWriteTx_StoreRefusalAfterItsContextEnded_IsUnavailable(t *testing.T) {
	for _, step := range []string{"открытие", "мутация", "фиксация"} {
		for _, ends := range []bool{true, false} {
			name := step + "/контекст жив"
			want, wantMsg := codes.Internal, "internal error"
			if ends {
				name = step + "/контекст кончился"
				want, wantMsg = codes.Unavailable, shared.UnavailableMessage
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				end := func() {
					if ends {
						cancel()
					}
				}
				repo := &ctxEndRepo{w: &ctxEndWriter{}}
				action := func(context.Context, kanamerepo.Writer) (int, error) { return 1, nil }
				switch step {
				case "открытие":
					repo.onOpen, repo.openErr = end, storeCode57014()
				case "мутация":
					action = func(context.Context, kanamerepo.Writer) (int, error) {
						end()
						return 0, storeCode57014()
					}
				case "фиксация":
					repo.w.onCommit, repo.w.commitErr = end, storeCode57014()
				}
				_, err := shared.DoWithWriteTx(ctx, repo, action)
				if ends != (ctx.Err() != nil) {
					t.Fatalf("фикстура: состояние контекста %v, ожидалось «кончился» = %t", ctx.Err(), ends)
				}
				assertAnswer(t, err, want, wantMsg)
			})
		}
	}
}
