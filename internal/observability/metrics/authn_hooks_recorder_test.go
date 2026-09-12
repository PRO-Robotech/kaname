// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// authn_hooks_recorder_test.go — клетки полосы хуков заводятся НУЛЁМ при
// провязке, иначе «за час ноль обращений» невыразимо (задача продукта #2495).
//
// # Почему закрытый набор заводится нулём
//
// Клетка, появляющаяся только при первом попадании, неотличима от «ещё не
// случалось»: правило тревоги, считающее долю, врёт ровно до первого события, а
// правило, звонящее на ОТСУТСТВИЕ обращений, не звонит никогда — сравнивать ему
// не с чем.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func hookCell(t *testing.T, r *Registry, route, outcome string) (value float64, present bool) {
	t.Helper()
	return labelledCounter(t, r, AuthnHookRequestsMetric,
		map[string]string{"route": route, "outcome": outcome})
}

var hookRoutesForTest = []string{"token", "refresh", "provision", "recovery"}
var hookOutcomesForTest = []string{"ok", "refused", "failed"}

// TestAuthnHooksRecorder_EveryCellExistsBeforeTheFirstRequest — все двенадцать
// клеток есть до первого обращения.
func TestAuthnHooksRecorder_EveryCellExistsBeforeTheFirstRequest(t *testing.T) {
	reg := NewRegistry()
	reg.AuthnHooksRecorder(hookRoutesForTest, hookOutcomesForTest)

	cells := 0
	for _, route := range hookRoutesForTest {
		for _, outcome := range hookOutcomesForTest {
			value, present := hookCell(t, reg, route, outcome)
			require.Truef(t, present, "клетки %s{route=%q,outcome=%q} нет ДО первого обращения — "+
				"«за час ноль обращений» тогда невыразимо: сравнивать не с чем",
				AuthnHookRequestsMetric, route, outcome)
			require.Zerof(t, value, "клетка %s{route=%q,outcome=%q} заведена не нулём",
				AuthnHookRequestsMetric, route, outcome)
			cells++
		}
	}
	require.Equal(t, 12, cells, "клеток осмотрено не двенадцать — обход не полон")
}

// TestAuthnHooksRecorder_MovesOnTheEventAndNotWithoutIt — величина двинулась
// там, где событие, и не двинулась там, где его не было.
func TestAuthnHooksRecorder_MovesOnTheEventAndNotWithoutIt(t *testing.T) {
	reg := NewRegistry()
	rec := reg.AuthnHooksRecorder(hookRoutesForTest, hookOutcomesForTest)

	rec.HookServed("token", "refused")

	value, present := hookCell(t, reg, "token", "refused")
	require.True(t, present)
	require.Equal(t, 1.0, value, "обращение отвергнуто, а клетка не двинулась")

	for _, route := range hookRoutesForTest {
		for _, outcome := range hookOutcomesForTest {
			if route == "token" && outcome == "refused" {
				continue
			}
			value, present := hookCell(t, reg, route, outcome)
			require.True(t, present)
			require.Zerof(t, value, "клетка %s/%s двинулась без своего события", route, outcome)
		}
	}
}

// TestAuthnHooksRecorder_EmptySetsAreRefused — пустой набор не заводит ни одной
// клетки, и витрина тогда молчит так же, как при неработающей полосе.
func TestAuthnHooksRecorder_EmptySetsAreRefused(t *testing.T) {
	require.Panics(t, func() { NewRegistry().AuthnHooksRecorder(nil, hookOutcomesForTest) },
		"пустой перечень маршрутов принят молча")
	require.Panics(t, func() { NewRegistry().AuthnHooksRecorder(hookRoutesForTest, nil) },
		"пустой перечень исходов принят молча")
}

// TestAuthnHooksRecorder_SecondWiringDoesNotKillTheProcess — реестр один.
func TestAuthnHooksRecorder_SecondWiringDoesNotKillTheProcess(t *testing.T) {
	reg := NewRegistry()
	first := reg.AuthnHooksRecorder(hookRoutesForTest, hookOutcomesForTest)
	second := reg.AuthnHooksRecorder(hookRoutesForTest, hookOutcomesForTest)
	require.Same(t, first, second, "второй вызов завёл ВТОРОГО приёмника")
}
