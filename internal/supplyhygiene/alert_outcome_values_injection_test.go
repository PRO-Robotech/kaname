// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// alert_outcome_values_injection_test.go — проба СПОСОБНОСТИ соседней проверки
// упасть.
//
// Утверждение «находок ноль» без этого файла не отличимо от «проверка не смотрит»:
// разбор мог бы не находить ни одного отбора и молчать на любом входе. Здесь ему
// подаётся вход, на котором молчать нельзя, — и рядом законный близнец, на котором
// краснеть нельзя.
package supplyhygiene

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOutcomeSelectorScanFindsAValueOutsideTheDictionary(t *testing.T) {
	dictionaries := map[string][]string{
		"kaname_authn_hook_requests_total": {"ok", "refused", "failed"},
	}

	// Отрицательная подача: значение вне словаря.
	broken := "expr: increase(kaname_authn_hook_requests_total{outcome=\"rejected\"}[15m]) > 0"
	census, findings := scanOutcomeSelectors(broken, dictionaries)
	require.NotZero(t, census.matchers, "разбор не нашёл отбора на входе, который его несёт")
	require.Len(t, findings, 1, "значение вне словаря не найдено — проверка вакуумна")
	require.Equal(t, "kaname_authn_hook_requests_total{outcome=\"rejected\"}", findings[0].String())

	// ЗАКОННЫЙ БЛИЗНЕЦ отличается ОДНИМ фактом: значение из словаря.
	legal := "expr: increase(kaname_authn_hook_requests_total{outcome=\"refused\"}[15m]) > 0"
	_, none := scanOutcomeSelectors(legal, dictionaries)
	require.Empty(t, none, "проверка краснеет на законной записи")

	// Регулярный отбор судится по альтернативам врозь: одна верна, вторая нет.
	mixed := "sum(increase(kaname_authn_hook_requests_total{outcome=~\"failed|exploded\"}[10m])) > 0"
	_, mixedFindings := scanOutcomeSelectors(mixed, dictionaries)
	require.Len(t, mixedFindings, 1, "альтернатива регулярного отбора не судится врозь")
	require.Equal(t, "exploded", mixedFindings[0].value)

	// Ряд, словаря которого в таблице нет, не судится — и не краснеет.
	foreign := "rate(kaname_authz_check_decisions_total{decision=\"error\"}[5m]) > 1"
	_, noneForeign := scanOutcomeSelectors(foreign, dictionaries)
	require.Empty(t, noneForeign, "судится ряд, словаря которого таблица не несёт")
}
