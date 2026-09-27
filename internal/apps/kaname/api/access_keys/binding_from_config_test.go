// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// binding_from_config_test.go — «никого» проходит ВСЮ цепочку старта (Ф7-13,
// kaname#454): настройка → `AccessKeysConfig.Binding` → `Deps` → `NewHandler`.
//
// Каждая половина по отдельности была исправна: страж настройки принимал пустой
// перечень, а `Deps` отвергал nil как «не объявлен». Сошлись они в корне
// композиции, где привязка при «никого» приезжала nil, и служба под посадкой
// `own` не стартовала. Поэтому проба держит обе половины одним вызовом.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

func TestAccessKeys_F7_13_NobodyFromConfigBuildsTheHandler(t *testing.T) {
	for name, tc := range map[string]struct {
		origins []string
		nobody  bool
	}{
		"пустой список файла": {origins: []string{}, nobody: true},
		"слово none":          {origins: []string{config.AccessKeyOriginsNone}, nobody: true},
		"законный близнец":    {origins: []string{origin}},
	} {
		t.Run(name, func(t *testing.T) {
			c := config.AccessKeysConfig{RPID: rpID, Origins: tc.origins, Algorithms: []int64{-7, -257, -8}}
			require.NoError(t, c.Validate())
			require.Equal(t, tc.nobody, c.Nobody())

			b := c.Binding()
			require.NotNil(t, b.Origins, "объявленный перечень обязан приехать объявленным: nil у Deps означает «не задан»")
			if tc.nobody {
				require.Empty(t, b.Origins)
			} else {
				require.Equal(t, []string{origin}, b.Origins)
			}

			h := newHarness(t)
			h.deps.Binding = b
			_, err := access_keys.NewHandler(h.deps, h.ops)
			require.NoError(t, err)
		})
	}
}

// TestAccessKeys_F7_13_UndeclaredOriginsStillRefuseTheHandler — различие
// «пусто» и «не задано» сохранено: nil по-прежнему отказ, названный по предмету.
func TestAccessKeys_F7_13_UndeclaredOriginsStillRefuseTheHandler(t *testing.T) {
	h := newHarness(t)
	h.deps.Binding.Origins = nil
	_, err := access_keys.NewHandler(h.deps, h.ops)
	require.ErrorContains(t, err, "origin list required")
}
