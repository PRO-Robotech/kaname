// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// identity_provider_validate_test.go — проверка старта судит ЗАКОННОСТЬ
// посадки, а не только то, что поле объявлено (задача #424, PRO-Robotech/corelib#29).
//
// Тип посадки — целое. Число мимо разбора — преобразование типа, декодер,
// кладущий число прямо в поле, — даёт значение, которое IsSet называет
// объявленным, а словарь законным не называет. Проверка старта, судившая только
// IsSet, пропускала такое число дальше: снятую посадку `external` — к
// требованиям её полосы, любое другое число — в старт без единого требования
// полосы, потому что ни одна строка таблицы к нему не относится.
//
// Проба утверждает ИСХОД старта (Config.Validate), а не вызов: отказ несёт текст
// Provider.Validate фундамента дословно, и полосных требований при нём нет.
// Законный близнец — тот же вход с `own` — старт проходит.
package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

func TestStartCheckRefusesAPostureOutsideTheDictionary(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    config.IdentityProvider
	}{
		// Снятая посадка: имя осталось устаревшей константой, число — прежним.
		{name: "снятая_посадка_external", p: config.IdentityProviderExternal},
		// Число, которого словарь не знал никогда: ни одна строка таблицы полос
		// к нему не относится, и без суждения о законности старт проходил молча.
		{name: "число_вне_словаря", p: config.IdentityProvider(7)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.False(t, tc.p.IsLegal(), "предпосылка: значение случая вне словаря")
			require.True(t, tc.p.IsSet(), "предпосылка: значение случая объявлено — отказ «не объявлено» здесь не предмет")

			err := laneCfg(tc.p).Validate()
			require.Error(t, err, "значение посадки вне словаря обязано отвергаться при старте")

			want := tc.p.Validate(config.IdentityProviderSetting)
			require.Error(t, want, "предпосылка: фундамент отвергает это значение")
			require.Contains(t, err.Error(), want.Error(),
				"отказ старта обязан нести текст проверки фундамента дословно — один текст на оба процесса")

			// Полосных требований при незаконной посадке нет: полоса неизвестна,
			// и требовать по ней нечего.
			for _, lanescoped := range []string{"required because", "hydra-admin-url"} {
				require.NotContains(t, err.Error(), lanescoped,
					"при посадке вне словаря полосное требование предъявляться не должно")
			}
		})
	}
}

// Законный близнец: тот же вход, посадка из словаря — старт проходит. Без него отрицание выше зеленело бы на
// проверке, отвергающей всё.
func TestStartCheckLetsEveryLegalPosturePass(t *testing.T) {
	values := config.IdentityProviderValues()
	require.NotEmpty(t, values, "предпосылка: словарь посадки не пуст")
	for _, v := range values {
		t.Run(v.String(), func(t *testing.T) {
			require.NoError(t, v.Validate(config.IdentityProviderSetting), "предпосылка: значение законно")
			require.NoError(t, laneCfg(v).Validate(), "законная посадка %q обязана проходить старт", v)
		})
	}
}
