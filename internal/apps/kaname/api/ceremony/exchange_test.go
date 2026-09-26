// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremony

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/oauthceremony"
)

// units — единица запроса пробы: считает открытия и урегулирования и помнит
// контекст урегулирования.
type units struct {
	opened, settled int
	settleErr       error
	settleCtxErr    error
	settleDeadline  time.Duration
}

func (u *units) OpenRequest(ctx context.Context) (context.Context, func(context.Context) error) {
	u.opened++
	return ctx, func(sctx context.Context) error {
		u.settled++
		u.settleCtxErr = sctx.Err()
		if dl, ok := sctx.Deadline(); ok {
			u.settleDeadline = time.Until(dl)
		}
		return u.settleErr
	}
}

type exchanger struct {
	err   error
	panic bool
}

func (e exchanger) Exchange(context.Context, oauthceremony.TokenRequest) (oauthceremony.TokenResult, error) {
	if e.panic {
		panic("ceremony exchange broke mid-operation")
	}
	if e.err != nil {
		return oauthceremony.TokenResult{}, e.err
	}
	return oauthceremony.TokenResult{AccessToken: "at"}, nil
}

func newExchange(t *testing.T, e ExchangeEngine, u RequestUnits) *ExchangeUseCase {
	t.Helper()
	uc, err := NewExchangeUseCase(ExchangeDeps{Engine: e, Units: u, SettleTimeout: time.Second})
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	return uc
}

// Единица запроса урегулируется ровно один раз на каждом выходе: успех, отказ,
// отказ урегулирования (на успехе он — отказ операции, токена нет).
func TestExchange_EveryExitIsSettledOnce(t *testing.T) {
	commitLost := errors.New("commit lost")
	for _, tc := range []struct {
		name      string
		engineErr error
		settleErr error
		wantToken bool
		wantErr   []error
	}{
		{"успех", nil, nil, true, nil},
		{"отказ гранта", oauthceremony.ErrInvalidGrant, nil, false, []error{oauthceremony.ErrInvalidGrant}},
		{"успех, урегулирование не состоялось", nil, commitLost, false, []error{ErrNotSettled, commitLost}},
		{"отказ и урегулирование не состоялось", oauthceremony.ErrInvalidGrant, commitLost, false,
			[]error{oauthceremony.ErrInvalidGrant, ErrNotSettled}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &units{settleErr: tc.settleErr}
			res, err := newExchange(t, exchanger{err: tc.engineErr}, u).Execute(context.Background(), oauthceremony.TokenRequest{})
			if u.opened != 1 || u.settled != 1 {
				t.Fatalf("открыта %d, урегулирована %d — ожидалось по одному", u.opened, u.settled)
			}
			if (res.AccessToken != "") != tc.wantToken {
				t.Errorf("токен %q при ожидании выдачи %v", res.AccessToken, tc.wantToken)
			}
			for _, want := range tc.wantErr {
				if !errors.Is(err, want) {
					t.Errorf("отказ %v не несёт %v", err, want)
				}
			}
			if tc.wantErr == nil && err != nil {
				t.Errorf("отказ на успехе: %v", err)
			}
		})
	}
}

// Паника посреди операции: урегулирование исполнено, паника идёт дальше.
func TestExchange_APanicMidOperationIsSettled(t *testing.T) {
	u := &units{}
	uc := newExchange(t, exchanger{panic: true}, u)
	func() {
		defer func() {
			if recover() == nil {
				t.Errorf("паника проглочена")
			}
		}()
		_, _ = uc.Execute(context.Background(), oauthceremony.TokenRequest{})
	}()
	if u.opened != 1 || u.settled != 1 {
		t.Fatalf("паника: открыта %d, урегулирована %d — ожидалось по одному", u.opened, u.settled)
	}
}

// Урегулирование отвязано от отмены вызывающего и идёт под своим сроком.
func TestExchange_SettlementOutlivesTheCallerButNotItsDeadline(t *testing.T) {
	u := &units{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = newExchange(t, exchanger{}, u).Execute(ctx, oauthceremony.TokenRequest{})
	if u.settleCtxErr != nil {
		t.Errorf("урегулирование получило отменённый контекст: %v", u.settleCtxErr)
	}
	if u.settleDeadline <= 0 || u.settleDeadline > time.Second {
		t.Errorf("урегулирование без своего срока: остаток %s", u.settleDeadline)
	}
}

func TestNewExchangeUseCase_RefusesAnIncompleteWiring(t *testing.T) {
	full := ExchangeDeps{Engine: exchanger{}, Units: &units{}, SettleTimeout: time.Second}
	for name, broken := range map[string]func(ExchangeDeps) ExchangeDeps{
		"церемонии нет":       func(d ExchangeDeps) ExchangeDeps { d.Engine = nil; return d },
		"единицы запроса нет": func(d ExchangeDeps) ExchangeDeps { d.Units = nil; return d },
		"срок не назван":      func(d ExchangeDeps) ExchangeDeps { d.SettleTimeout = 0; return d },
	} {
		if _, err := NewExchangeUseCase(broken(full)); err == nil {
			t.Errorf("%s: собрано", name)
		}
	}
	if _, err := NewExchangeUseCase(full); err != nil {
		t.Errorf("близнец: полная провязка отвергнута: %v", err)
	}
}
