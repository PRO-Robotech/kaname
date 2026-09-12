// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks_test

// lane_values_test.go — полоса хуков поставщика личности ПРОИЗВОДИТ величину по
// каждому маршруту и каждому исходу (задача продукта #2495).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Это ЖИВОЙ путь входа человека. Наблюдение было — двенадцать предупреждающих
// строк и одна строка доступа на запрос, и ни одной величины. Два состояния
// одного отказа давали несравнимые, но одинаково ненаблюдаемые картины:
//
//	полоса отказывает            → растёт число строк журнала с отказом;
//	поставщик не зовёт хук вовсе → строк журнала НЕТ; провязку на своей стороне
//	                               делает оператор, и её отсутствие невидимо
//	                               by construction: тишина тревогой не бывает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ
//
//	Р1  исход наблюдён на КАЖДОМ из четырёх маршрутов, и маршрут назван;
//	Р2  исход ТРЁХЗНАЧЕН: сделано · отвергнуто (условие на стороне поставщика
//	    не создано) · не смогли ответить (сломан продукт);
//	Р3  величина НЕ двигается без события: запрос по пути, которого полоса не
//	    несёт, наблюдением не становится;
//	Р4  набор исходов ЗАКРЫТ — разбор состояния ответа не даёт значения вне
//	    объявленного набора ни при каком входе.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
)

// laneSpy — приёмник исходов полосы, записывающий пары.
type laneSpy struct{ seen []string }

func (s *laneSpy) HookServed(route, outcome string) {
	s.seen = append(s.seen, route+"/"+outcome)
}

// statusStub — обработчик, отвечающий объявленным состоянием.
type statusStub int

func (s statusStub) ServeHTTP(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(int(s)) }

// muxWithLane собирает полосу целиком: все четыре маршрута отвечают одним
// состоянием, наблюдатель один.
func muxWithLane(status int, spy *laneSpy) http.Handler {
	return iamhooks.NewMux(iamhooks.Handlers{
		TokenHook:     statusStub(status),
		RefreshHook:   statusStub(status),
		ProvisionHook: statusStub(status),
		RecoveryHook:  statusStub(status),
		LaneObserver:  spy,
	})
}

// TestHookLane_EveryRouteNamesItselfInAValue — Р1.
func TestHookLane_EveryRouteNamesItselfInAValue(t *testing.T) {
	paths := map[string]string{
		iamhooks.RouteToken:     "/iam/v1/hooks/token",
		iamhooks.RouteRefresh:   "/iam/v1/hooks/refresh",
		iamhooks.RouteProvision: "/iam/v1/hooks/provision",
		iamhooks.RouteRecovery:  "/iam/v1/hooks/recovery",
	}
	require.Len(t, paths, len(iamhooks.Routes()),
		"перечень маршрутов полосы и перечень путей разошлись — один из двух не полон")

	for _, route := range iamhooks.Routes() {
		path, ok := paths[route]
		require.Truef(t, ok, "маршрут %q объявлен и не имеет пути в пробе", route)

		spy := &laneSpy{}
		mux := muxWithLane(http.StatusOK, spy)
		mux.ServeHTTP(httptest.NewRecorder(),
			httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))

		require.Equalf(t, []string{route + "/" + iamhooks.LaneOutcomeOK}, spy.seen,
			"обращение по %s не дало величины, называющей маршрут", path)
	}
}

// TestHookLane_ThreeOutcomesAreTold — Р2: три состояния, три разных исхода.
func TestHookLane_ThreeOutcomesAreTold(t *testing.T) {
	for _, c := range []struct {
		status int
		want   string
		why    string
	}{
		{http.StatusOK, iamhooks.LaneOutcomeOK, "хук сделал работу"},
		{http.StatusUnauthorized, iamhooks.LaneOutcomeRefused,
			"обращение отвергнуто: провязка на стороне поставщика не создана либо неверна"},
		{http.StatusInternalServerError, iamhooks.LaneOutcomeFailed,
			"ответить не смогли: сломан продукт"},
	} {
		spy := &laneSpy{}
		mux := muxWithLane(c.status, spy)
		mux.ServeHTTP(httptest.NewRecorder(),
			httptest.NewRequest(http.MethodPost, "/iam/v1/hooks/token", strings.NewReader("{}")))
		require.Equalf(t, []string{iamhooks.RouteToken + "/" + c.want}, spy.seen,
			"состояние %d не дало исхода %q (%s)", c.status, c.want, c.why)
	}
}

// TestHookLane_DoesNotMoveWithoutTheEvent — Р3.
func TestHookLane_DoesNotMoveWithoutTheEvent(t *testing.T) {
	spy := &laneSpy{}
	mux := muxWithLane(http.StatusOK, spy)
	mux.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/iam/v1/hooks/nonexistent", strings.NewReader("{}")))
	require.Empty(t, spy.seen,
		"величина двинулась на пути, которого полоса не несёт: ряды маршрутов перестали "+
			"утверждать что-либо о самих маршрутах")
}

// TestHookLane_OutcomeSetIsClosed — Р4: разбор состояния ответа не изобретает
// четвёртого значения.
//
// Обход по всему диапазону состояний, а не по трём образцам: корзина «прочее»
// заводится незаметно, и заметна она только на полном обходе.
func TestHookLane_OutcomeSetIsClosed(t *testing.T) {
	declared := map[string]bool{}
	for _, o := range iamhooks.LaneOutcomes() {
		declared[o] = true
	}
	require.Len(t, declared, 3, "исходов полосы объявлено не три")

	produced := map[string]bool{}
	for status := 100; status < 600; status++ {
		o := iamhooks.LaneOutcomeForStatus(status)
		require.Truef(t, declared[o], "состояние %d дало исход %q вне объявленного набора", status, o)
		produced[o] = true
	}
	require.Len(t, produced, len(declared),
		"объявлен исход, которого разбор состояния не даёт НИ ПРИ КАКОМ входе: "+
			"клетка присутствовала бы нулём и выглядела бы исправным наблюдением")
}
