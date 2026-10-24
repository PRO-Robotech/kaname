// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_lane_cpu_supply_injection_test.go — способность меры процессоров службы
// упасть и смолчать доказывается инъекцией (kaname#891).
//
// Каждая инъекция меняет против контроля РОВНО ОДИН факт `--set` поверх
// поставляемой цепочки и называет условие, которое обязана нарушить:
//
//	контроль         — профиль как поставлен: мера молчит;
//	снятый предел    — состояние до kaname#891 (запрос без предела): П1;
//	запрос ниже      — предел есть, запрос прежний 100m: П2;
//	дробный предел   — 1500m: GOMAXPROCS 2 больше предела, П3;
//	предел 1         — среда поднимает GOMAXPROCS до 2, П3;
//	законный близнец — 4 и 4: целый, равный запросу, мера молчит, иначе она
//	                   требовала бы ровно поставляемое число, а не свойство.
package deploy_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func judgeCPUSupplyOfRender(t *testing.T, sets ...string) (cpuSupplyCensus, error) {
	t.Helper()
	rendered := renderStandaloneChart(t, chartProfiles, withOperatorOverlay(append(sets, minimalOperatorCoordinates...)...)...)
	login := loginLaneOfRender(t, rendered)
	require.Positive(t, login.VerifierCapacity, "ёмкость проверяющего в рендере не прочитана — вердикт беспредметен")
	return judgeOwnLaneCPUSupply(serviceContainerResources(t, rendered), login.VerifierCapacity)
}

func TestInjection_CPUSupplyAsDeliveredIsSilent(t *testing.T) {
	census, err := judgeCPUSupplyOfRender(t)
	require.NoErrorf(t, err, "контроль инъекции красен — вердикты инъекций ниже недействительны: %s", census)
	require.Equal(t, census.GOMAXPROCS, census.ProcessorSlots,
		"контроль: мест вычисления не столько, сколько процессоров дано процессу: %s", census)
	t.Logf("контроль: %s", census)
}

func TestInjection_CPUSupplyFindsEachBrokenCondition(t *testing.T) {
	cases := []struct {
		name string
		sets []string
		want string
	}{
		{"снятый предел", []string{"resources.limits.cpu=null", "resources.requests.cpu=100m"}, "П1:"},
		{"запрос ниже предела", []string{"resources.requests.cpu=100m"}, "П2:"},
		{"дробный предел", []string{"resources.requests.cpu=1500m", "resources.limits.cpu=1500m"}, "П3:"},
		{"предел один процессор", []string{"resources.requests.cpu=1", "resources.limits.cpu=1"}, "П3:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			census, err := judgeCPUSupplyOfRender(t, c.sets...)
			require.Errorf(t, err, "мера смолчала на инъекции %v: %s", c.sets, census)
			require.Containsf(t, err.Error(), c.want, "отказ называет не то условие: %v", err)
			t.Logf("%s: %v · %s", c.name, err, census)
		})
	}
}

func TestInjection_CPUSupplyLegalTwinIsSilent(t *testing.T) {
	census, err := judgeCPUSupplyOfRender(t, "resources.requests.cpu=4", "resources.limits.cpu=4")
	require.NoErrorf(t, err, "законный близнец (4 и 4) отвергнут — мера требует число, а не свойство: %s", census)
	require.Equal(t, 4, census.ProcessorSlots, "близнец: %s", census)
	t.Logf("близнец: %s", census)
}
