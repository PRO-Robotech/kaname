// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks_test

// issuance_deadline_test.go — обёртка портов полос выдачи ставит СВОЙ предел
// на каждый метод каждого порта, пропускает исход обращения как есть, оставляет
// неподанный порт неподанным и отказывает построением на неположительном
// пределе (задача kaname#389).
//
// Перечень методов не выписан здесь: он берётся из типа входа обёртки обходом
// его полей. Порт или метод, заведённый позже, попадает под пробу сам — и, если
// обёртка его не оборачивает, проба краснеет на нём по имени. Пустой обход —
// «не измерено», не «сроки есть».

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
)

// errFromStore — исход, который порт отдаёт: обёртка обязана вернуть его как есть.
var errFromStore = errors.New("store answered")

// portCall — одно обращение глазами порта.
type portCall struct {
	port, method string
	had          bool
	remaining    time.Duration
}

type portLog struct{ calls []portCall }

func (l *portLog) record(ctx context.Context, port, method string) {
	dl, had := ctx.Deadline()
	l.calls = append(l.calls, portCall{port: port, method: method, had: had, remaining: time.Until(dl)})
}

// Имена портов — имена полей входа обёртки.
type logUsers struct{ *portLog }

func (l logUsers) FindByExternalID(ctx context.Context, _ domain.ExternalSubject) ([]domain.User, error) {
	l.record(ctx, "Users", "FindByExternalID")
	return nil, errFromStore
}

func (l logUsers) GetByID(ctx context.Context, _ domain.UserID) (domain.User, error) {
	l.record(ctx, "Users", "GetByID")
	return domain.User{}, errFromStore
}

type logServiceAccounts struct{ *portLog }

func (l logServiceAccounts) LookupByOAuthClientID(ctx context.Context, _ domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	l.record(ctx, "ServiceAccounts", "LookupByOAuthClientID")
	return domain.ServiceAccountOAuthClient{}, errFromStore
}

func (l logServiceAccounts) GetServiceAccount(ctx context.Context, _ domain.ServiceAccountID) (domain.ServiceAccount, error) {
	l.record(ctx, "ServiceAccounts", "GetServiceAccount")
	return domain.ServiceAccount{}, errFromStore
}

func (l logServiceAccounts) FindByExternalSubject(ctx context.Context, _, _ string) (domain.ServiceAccountOAuthClient, error) {
	l.record(ctx, "ServiceAccounts", "FindByExternalSubject")
	return domain.ServiceAccountOAuthClient{}, errFromStore
}

type logUserTokens struct{ *portLog }

func (l logUserTokens) LookupByOAuthClientID(ctx context.Context, _ domain.OAuthClientID) (domain.UserOAuthClient, error) {
	l.record(ctx, "UserTokens", "LookupByOAuthClientID")
	return domain.UserOAuthClient{}, errFromStore
}

func (l logUserTokens) GetUser(ctx context.Context, _ domain.UserID) (domain.User, error) {
	l.record(ctx, "UserTokens", "GetUser")
	return domain.User{}, errFromStore
}

type logCutoffs struct{ *portLog }

func (l logCutoffs) UserRevokedBefore(ctx context.Context, _ string) (time.Time, bool, error) {
	l.record(ctx, "Cutoffs", "UserRevokedBefore")
	return time.Time{}, false, errFromStore
}

type logAudit struct{ *portLog }

func (l logAudit) Emit(ctx context.Context, _ iamhooks.AuditEvent) error {
	l.record(ctx, "Audit", "Emit")
	return errFromStore
}

func loggedPorts(l *portLog) iamhooks.IssuancePorts {
	return iamhooks.IssuancePorts{
		Users:           logUsers{l},
		ServiceAccounts: logServiceAccounts{l},
		UserTokens:      logUserTokens{l},
		Cutoffs:         logCutoffs{l},
		Audit:           logAudit{l},
	}
}

// TestWithCallDeadline_EveryPortMethodCarriesItsOwnLimit — каждый метод каждого
// порта, прошедший обёртку, зовётся со сроком не больше поданного, даже когда у
// вызывающего срока нет, и отдаёт исход порта без подмены.
func TestWithCallDeadline_EveryPortMethodCarriesItsOwnLimit(t *testing.T) {
	const limit = 2 * time.Second
	log := &portLog{}
	bounded, err := iamhooks.WithCallDeadline(loggedPorts(log), limit)
	require.NoError(t, err)

	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	errType := reflect.TypeOf((*error)(nil)).Elem()
	rv := reflect.ValueOf(bounded)
	rt := rv.Type()
	var ports, methods, carried int
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		port := rv.Field(i)
		if field.Type.Kind() != reflect.Interface {
			t.Errorf("поле %s входа обёртки — не порт (%s): обёртке нечего с ним делать", field.Name, field.Type)
			continue
		}
		ports++
		if port.IsNil() {
			t.Errorf("порт %s подан, а после обёртки его нет", field.Name)
			continue
		}
		for m := 0; m < field.Type.NumMethod(); m++ {
			name := field.Type.Method(m).Name
			fn := port.MethodByName(name)
			methods++
			in := make([]reflect.Value, fn.Type().NumIn())
			for a := range in {
				in[a] = reflect.Zero(fn.Type().In(a))
			}
			if len(in) == 0 || fn.Type().In(0) != ctxType {
				t.Errorf("%s.%s не принимает контекст первым: предел на него не поставить", field.Name, name)
				continue
			}
			in[0] = reflect.ValueOf(context.Background())

			before := len(log.calls)
			out := fn.Call(in)
			if len(log.calls) != before+1 {
				t.Errorf("%s.%s: до порта дошло %d обращений вместо одного", field.Name, name, len(log.calls)-before)
				continue
			}
			got := log.calls[before]
			if got.port != field.Name || got.method != name {
				t.Errorf("%s.%s: обращение пришло в %s.%s — обёртка перепутала метод", field.Name, name, got.port, got.method)
				continue
			}
			last := out[len(out)-1]
			if last.Type() != errType || !errors.Is(last.Interface().(error), errFromStore) {
				t.Errorf("%s.%s: исход порта не дошёл до вызывающего как есть: %v", field.Name, name, last)
				continue
			}
			if !got.had {
				t.Errorf("%s.%s идёт без своего предела времени", field.Name, name)
				continue
			}
			if got.remaining <= 0 || got.remaining > limit {
				t.Errorf("%s.%s несёт срок %s при поданном пределе %s", field.Name, name, got.remaining, limit)
				continue
			}
			carried++
		}
	}
	if methods == 0 {
		t.Fatal("обход входа обёртки не нашёл ни одного метода порта — предел НЕ ИЗМЕРЕН, это не зелёное")
	}
	t.Logf("перепись: портов %d · методов %d · под пределом %s — %d", ports, methods, limit, carried)
}

// TestWithCallDeadline_AbsentPortStaysAbsent — неподанный порт обёртка не
// превращает в поданный: у полос «порт не провязан» — своя ветвь, и обёртка
// над пустотой прошла бы её мимо и упала бы на первом вызове.
func TestWithCallDeadline_AbsentPortStaysAbsent(t *testing.T) {
	bounded, err := iamhooks.WithCallDeadline(iamhooks.IssuancePorts{}, time.Second)
	require.NoError(t, err)
	rv := reflect.ValueOf(bounded)
	for i := 0; i < rv.NumField(); i++ {
		require.True(t, rv.Field(i).IsNil(), "неподанный порт %s после обёртки обязан остаться неподанным",
			rv.Type().Field(i).Name)
	}
}

// TestWithCallDeadline_RefusesANonPositiveLimitAtBuild — неположительный предел —
// отказ построения входа полос; законный близнец — наименьшая положительная
// величина.
func TestWithCallDeadline_RefusesANonPositiveLimitAtBuild(t *testing.T) {
	for _, limit := range []time.Duration{0, -time.Nanosecond, -3 * time.Second} {
		_, err := iamhooks.WithCallDeadline(loggedPorts(&portLog{}), limit)
		require.ErrorIs(t, err, revocationpolicy.ErrLimitNotPositive, "предел %s обязан отказывать построением", limit)
		require.Contains(t, err.Error(), limit.String(), "отказ обязан называть поданную величину")
	}
	_, err := iamhooks.WithCallDeadline(iamhooks.IssuancePorts{}, 0)
	require.ErrorIs(t, err, revocationpolicy.ErrLimitNotPositive,
		"неподанные порты предела не отменяют: величина неверна независимо от того, что оборачивается")

	bounded, err := iamhooks.WithCallDeadline(loggedPorts(&portLog{}), time.Nanosecond)
	require.NoError(t, err, "законный близнец: наименьшая положительная величина собирается")
	require.NotNil(t, bounded.Users)
}
