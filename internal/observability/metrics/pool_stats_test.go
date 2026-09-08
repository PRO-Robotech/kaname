// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// TestRegisterPoolStats_RepeatDoesNotKillTheProcess — повторная регистрация того
// же пула отвергается молча, а не паникой.
//
// Предмет — не аккуратность: реестр у сервиса ОДИН, а провязка идёт из
// композиционного корня, куда пул приходит из нескольких мест. MustRegister на
// повторе уронил бы старт, то есть наблюдение убило бы сервис, который оно
// наблюдает. Проверяется исход, а не наличие ветки в коде.
func TestRegisterPoolStats_RepeatDoesNotKillTheProcess(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()

	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("повторная регистрация пула уронила процесс: %v", p)
		}
	}()
	reg.RegisterPoolStats("primary", nil)
	reg.RegisterPoolStats("primary", nil)
}

// TestRegisterPoolStats_SecondPoolIsAccepted — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к пробе
// выше: второй пул того же сервиса регистрируется.
//
// Без него «повтор не роняет» осталось бы зелёным и в случае, когда метод не
// регистрирует НИЧЕГО: у kaname пулов два (ведущий и реплика для чтений), и
// без различающей метки `pool` они схлопнулись бы в одну серию — то есть занятость
// реплики читалась бы как занятость ведущего.
func TestRegisterPoolStats_SecondPoolIsAccepted(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()

	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("второй пул сервиса не принят реестром: %v", p)
		}
	}()
	reg.RegisterPoolStats("primary", nil)
	reg.RegisterPoolStats("replica", nil)
}
