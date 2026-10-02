// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_lifespans_chart_test.go — поставка с накладкой `own` несёт сроки
// церемонии, и страж старта её принимает; без блока сроков — отказывает с обеими
// ручками (kaname#318; приёмка
// `ceremony-lifespans-are-declared-within-their-ceilings.md`, KN-CTTL-13).
//
// Чарт ключи объявляет и значения несёт, но не судит: судит один страж старта
// над отрендеренной картой настроек. Поэтому отрицательная половина — не отказ
// рендера, а отказ стража.
package deploy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKNCTTL13_OwnDeliveryCarriesTheCeremonyLifespans(t *testing.T) {
	t.Run("13/1 профиль несёт блок", func(t *testing.T) {
		rendered := renderStandaloneChart(t, chartProfiles, operatorOverlay...)
		tree := renderedConfigTree(t, rendered)
		require.Equal(t, "60s", at(tree, "authn", "ceremony", "code-ttl"),
			"KN-CTTL-13/1: в карте настроек нет authn.ceremony.code-ttl = 60s")
		require.Equal(t, "168h", at(tree, "authn", "ceremony", "refresh-ttl"),
			"KN-CTTL-13/1: в карте настроек нет authn.ceremony.refresh-ttl = 168h")
		require.NoError(t, renderedVerdict(t, readRenderedInput(t, rendered)),
			"KN-CTTL-13/1: поставка с накладкой оператора не принята стражем старта")
	})
	t.Run("13/2 блок снят", func(t *testing.T) {
		rendered := renderStandaloneChart(t, chartProfiles, withOperatorOverlay("authn.ceremony=null")...)
		require.Nil(t, at(renderedConfigTree(t, rendered), "authn", "ceremony"),
			"KN-CTTL-13/2: блок ceremony в карте настроек есть, хотя профиль его снял")
		verdict := renderedVerdict(t, readRenderedInput(t, rendered))
		require.Error(t, verdict,
			"KN-CTTL-13/2: без блока сроков страж принял поставку — «принимает» в 13/1 неотличимо от стража, ручек не требующего")
		for _, key := range []string{"authn.ceremony.code-ttl", "authn.ceremony.refresh-ttl"} {
			require.Truef(t, strings.Contains(verdict.Error(), key),
				"KN-CTTL-13/2: отказ стража не называет %s:\n%v", key, verdict)
		}
	})
}
