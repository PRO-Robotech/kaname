// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks_test

// lifecycle_deadline_test.go — обёртка портов хуков заведения и восстановления
// ставит СВОЙ предел на каждый порт, пропускает исход обращения как есть и
// отказывает построением на неподанном порте и неположительном пределе
// (задача kaname#441).
//
// Перечень портов не выписан здесь: он берётся из типа входа обёртки обходом
// его полей. Порт, заведённый позже, попадает под пробу сам — и, если проба его
// не зовёт или обёртка его не оборачивает, проба краснеет на нём по имени.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
)

// errFromUseCase — исход, который порт отдаёт: обёртка обязана вернуть его как есть.
var errFromUseCase = errors.New("use-case answered")

// Имена портов — имена полей входа обёртки.
type logProvisioner struct{ *portLog }

func (l logProvisioner) Provision(ctx context.Context, _ iamhooks.ProvisionInput) error {
	l.record(ctx, "Provisioner", "Provision")
	return errFromUseCase
}

type logRecovery struct{ *portLog }

func (l logRecovery) CompleteRecovery(ctx context.Context, _ iamhooks.RecoveryInput) error {
	l.record(ctx, "Recovery", "CompleteRecovery")
	return errFromUseCase
}

func loggedLifecyclePorts(l *portLog) iamhooks.LifecyclePorts {
	return iamhooks.LifecyclePorts{
		Provisioner: logProvisioner{l},
		Recovery:    logRecovery{l},
	}
}

// TestWithLifecycleDeadline_EveryPortCarriesItsOwnLimit — каждый порт, прошедший
// обёртку, зовётся со сроком не больше поданного, даже когда у вызывающего срока
// нет, и отдаёт исход порта без подмены.
func TestWithLifecycleDeadline_EveryPortCarriesItsOwnLimit(t *testing.T) {
	const limit = 2 * time.Second
	log := &portLog{}
	bounded, err := iamhooks.WithLifecycleDeadline(loggedLifecyclePorts(log), limit)
	require.NoError(t, err)

	ctx := context.Background()
	if _, had := ctx.Deadline(); had {
		t.Fatal("предпосылка: контекст вызывающего не несёт срока")
	}
	outcomes := map[string]error{
		"Provisioner": bounded.Provisioner.Provision(ctx, iamhooks.ProvisionInput{ExternalID: "ext"}),
		"Recovery":    bounded.Recovery.CompleteRecovery(ctx, iamhooks.RecoveryInput{ExternalID: "ext", RecoveryJTI: "jti"}),
	}

	portType := reflect.TypeOf(iamhooks.LifecyclePorts{})
	if portType.NumField() == 0 {
		t.Fatal("предпосылка: у входа обёртки нет ни одного порта — судить нечего")
	}
	reached := map[string]portCall{}
	for _, c := range log.calls {
		reached[c.port] = c
	}
	for i := 0; i < portType.NumField(); i++ {
		name := portType.Field(i).Name
		c, ok := reached[name]
		if !ok {
			t.Errorf("порт %s не позван пробой — его предел НЕ ИЗМЕРЕН; заведите ему вызов здесь", name)
			continue
		}
		if !c.had {
			t.Errorf("порт %s.%s зовётся без своего предела времени — зависший use-case держит хук "+
				"столько, сколько ждёт поставщик", c.port, c.method)
		} else if c.remaining <= 0 || c.remaining > limit {
			t.Errorf("порт %s.%s несёт срок %s, а поданный предел — %s", c.port, c.method, c.remaining, limit)
		}
		if got, ok := outcomes[name]; !ok || !errors.Is(got, errFromUseCase) {
			t.Errorf("порт %s: исход обращения подменён обёрткой: %v", name, got)
		}
	}
	t.Logf("перепись: портов входа %d · позвано %d · предел %s", portType.NumField(), len(reached), limit)
}

// TestWithLifecycleDeadline_RefusesAMissingPortAtBuild — неподанный порт — отказ
// построения, называющий порт: у хуков заведения и восстановления ветви «порт не
// провязан» нет, и хук без порта отказал бы на первом запросе, а не на старте.
// Законный близнец — вход со всеми портами: построение проходит.
func TestWithLifecycleDeadline_RefusesAMissingPortAtBuild(t *testing.T) {
	portType := reflect.TypeOf(iamhooks.LifecyclePorts{})
	for i := 0; i < portType.NumField(); i++ {
		name := portType.Field(i).Name
		t.Run(name, func(t *testing.T) {
			given := loggedLifecyclePorts(&portLog{})
			reflect.ValueOf(&given).Elem().FieldByName(name).Set(reflect.Zero(portType.Field(i).Type))
			got, err := iamhooks.WithLifecycleDeadline(given, time.Second)
			require.ErrorIs(t, err, iamhooks.ErrLifecyclePortNotWired, "неподанный порт %s обязан отказывать построением", name)
			require.True(t, strings.Contains(err.Error(), name), "отказ обязан называть порт %s: %v", name, err)
			require.Equal(t, iamhooks.LifecyclePorts{}, got, "отказ построения не отдаёт обёрток")
		})
	}

	t.Run("законный близнец: все порты поданы", func(t *testing.T) {
		got, err := iamhooks.WithLifecycleDeadline(loggedLifecyclePorts(&portLog{}), time.Second)
		require.NoError(t, err)
		require.NotNil(t, got.Provisioner)
		require.NotNil(t, got.Recovery)
	})
}

// TestWithLifecycleDeadline_RefusesANonPositiveLimitAtBuild — неположительный
// предел — отказ построения тем же отказом, что у полос выдачи; наименьший
// положительный проходит.
func TestWithLifecycleDeadline_RefusesANonPositiveLimitAtBuild(t *testing.T) {
	for _, limit := range []time.Duration{0, -time.Second} {
		got, err := iamhooks.WithLifecycleDeadline(loggedLifecyclePorts(&portLog{}), limit)
		require.ErrorIs(t, err, revocationpolicy.ErrLimitNotPositive, "предел %s обязан отказывать построением", limit)
		require.Contains(t, err.Error(), limit.String(), "отказ обязан называть поданную величину")
		require.Equal(t, iamhooks.LifecyclePorts{}, got, "отказ построения не отдаёт обёрток")
	}
	got, err := iamhooks.WithLifecycleDeadline(loggedLifecyclePorts(&portLog{}), time.Nanosecond)
	require.NoError(t, err, "наименьший положительный предел законен")
	require.NotNil(t, got.Provisioner)
}
