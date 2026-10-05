// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// shipped_chains_declare_every_own_ceiling_injection_test.go — СПОСОБНОСТЬ
// ПРОБЫ УПАСТЬ доказывается настоящим входом из дерева: стендовая накладка, у
// которой снята одна строка потолка, обязана дать находку, называющую ключ, а
// её законные близнецы — остаться зелёными.
package deploy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const devProfile = "values.dev.yaml"

// devChainWith — цепочка «база + стендовая накладка» с правкой блока потолков.
func devChainWith(t *testing.T, name string, edit func(ceilings map[string]any)) shippedChain {
	t.Helper()
	files := []string{chartDefaultsFile, devProfile}
	merged := mergeChartProfiles(t, files)
	ceilings, ok := at(merged, "ownCeilings").(map[string]any)
	require.True(t, ok, "стендовая накладка не несёт блока `ownCeilings` — инъекции не на чем стоять")
	edit(ceilings)
	return shippedChain{Name: name, Files: files, Merged: merged}
}

func TestOwnCeilingChainInjection_RemovedCeilingIsFoundByItsKey(t *testing.T) {
	injected := devChainWith(t, "dev-без-ключей-доступа", func(c map[string]any) {
		delete(c, "accessKeysPerUser")
	})
	findings, census := judgeChainOwnCeilings(t, []shippedChain{injected})
	require.Len(t, findings, 1, "снятая строка потолка обязана дать ровно одну находку; %s\n%s",
		census, strings.Join(findings, "\n"))
	require.Contains(t, findings[0], "own-ceilings.access-keys-per-user",
		"находка обязана назвать ключ снятого потолка")
	require.Contains(t, findings[0], "KANAME_OWN_CEILINGS__ACCESS_KEYS_PER_USER",
		"находка обязана назвать переменную, которой оператор подаёт величину")
}

func TestOwnCeilingChainInjection_LegitimateTwinsStayGreen(t *testing.T) {
	asShipped := devChainWith(t, "dev-как-поставлен", func(map[string]any) {})
	zero := devChainWith(t, "dev-ключей-не-заводить", func(c map[string]any) {
		// Ноль — законная величина («ресурсов этого вида не заводить»), и
		// проба, читающая его как «не задано», отвергала бы решение оператора.
		c["accessKeysPerUser"] = 0
	})
	findings, census := judgeChainOwnCeilings(t, []shippedChain{asShipped, zero})
	require.Emptyf(t, findings, "законные близнецы дали находку; %s\n%s",
		census, strings.Join(findings, "\n"))
	require.Equal(t, 2, census.Chains)
}

func TestOwnCeilingChainInjection_PopulationCoversEveryShippedOverlay(t *testing.T) {
	chains := shippedChainsOf(t, chartChains, deliveryRoster)
	var names []string
	for _, ch := range chains {
		names = append(names, strings.Join(ch.Files, "+"))
	}
	require.Contains(t, names, chartDefaultsFile+"+"+devProfile,
		"стендовая накладка выпала из популяции — проба снова судила бы одну боевую цепочку")
	require.Contains(t, names, chartDefaultsFile+"+values.prod.yaml")
	require.Len(t, chains, len(names))
}
