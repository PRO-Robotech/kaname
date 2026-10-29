// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// binding_materialization_recorder_test.go — размер материализации привязки
// читается ПО ПОЛОСЕ (задача kaname#157).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Материализуют привязки две полосы: путь запроса (создание привязки, правка
// роли, привязка владельца, первый вход) и фоновый обход (воркер очереди
// реконсайла, периодическая подмётка, истечение срока, разовый догон на
// старте). Гистограмма размера была одна и без меток, и в неё писала только
// первая полоса — поэтому «размер материализации привязки» означал «размер на
// пути запроса», а различить это по числам было нельзя: полоса вне наблюдения
// выглядит ровно как полоса без трафика.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ
//
//	П1  ряды обеих полос заведены НУЛЁМ при регистрации: полоса, ряд которой
//	    появлялся бы при первом наблюдении, до него неотличима от неизвестной;
//	П2  наблюдение через приёмник полосы двигает ряд ЭТОЙ полосы и не двигает
//	    соседний — по обеим величинам и в обе стороны;
//	П3  приёмник один на реестр: путь запроса и обход берут его в разных местах
//	    композиционного корня, и второй конструктор уронил бы старт повторной
//	    регистрацией.

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

// laneHistogram — ряд одной величины одной полосы: число наблюдений, их сумма и
// есть ли ряд на проводе вовсе.
func laneHistogram(t *testing.T, r *Registry, family, lane string) (count uint64, sum float64, present bool) {
	t.Helper()
	families, err := r.reg.Gather()
	require.NoError(t, err)
	for _, mf := range families {
		if mf.GetName() != family {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelValue(m, "lane") == lane {
				h := m.GetHistogram()
				return h.GetSampleCount(), h.GetSampleSum(), true
			}
		}
	}
	return 0, 0, false
}

func labelValue(m *dto.Metric, name string) string {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}

// TestBindingMaterializationLanesExistBeforeTheFirstPass — П1.
func TestBindingMaterializationLanesExistBeforeTheFirstPass(t *testing.T) {
	reg := NewRegistry()
	reg.BindingMaterializationRecorder()

	require.Len(t, BindingMaterializationLanes, 2,
		"словарь полос материализации — request и sweep; третья полоса без решения о ней — находка")
	for _, family := range []string{BindingMaterializationObjectsMetric, BindingMaterializationTuplesMetric} {
		for _, lane := range BindingMaterializationLanes {
			count, _, present := laneHistogram(t, reg, family, lane)
			require.Truef(t, present, "ряда %s{lane=%q} нет ДО первого прохода — полоса без "+
				"наблюдения тогда неотличима от полосы без трафика", family, lane)
			require.Zerof(t, count, "ряд %s{lane=%q} заведён не нулём", family, lane)
		}
	}
}

// TestBindingMaterializationLanesAreReadSeparately — П2.
func TestBindingMaterializationLanesAreReadSeparately(t *testing.T) {
	cases := []struct {
		name    string
		observe func(*BindingMaterializationRecorder) *BindingMaterializationLane
		moved   string
		still   string
	}{
		{"обход", (*BindingMaterializationRecorder).SweepLane,
			BindingMaterializationLaneSweep, BindingMaterializationLaneRequest},
		{"путь запроса", (*BindingMaterializationRecorder).RequestLane,
			BindingMaterializationLaneRequest, BindingMaterializationLaneSweep},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := NewRegistry()
			tc.observe(reg.BindingMaterializationRecorder()).ObserveBindingMaterialization(7, 21)

			for family, want := range map[string]float64{
				BindingMaterializationObjectsMetric: 7,
				BindingMaterializationTuplesMetric:  21,
			} {
				count, sum, ok := laneHistogram(t, reg, family, tc.moved)
				require.True(t, ok)
				require.EqualValuesf(t, 1, count, "проход полосы %q не дошёл до её ряда %s", tc.moved, family)
				require.Equalf(t, want, sum, "ряд %s{lane=%q} записал не ту величину", family, tc.moved)

				count, _, ok = laneHistogram(t, reg, family, tc.still)
				require.True(t, ok)
				require.Zerof(t, count, "проход полосы %q сдвинул ряд СОСЕДНЕЙ полосы %q (%s) — "+
					"полосы снова читаются слитно", tc.moved, tc.still, family)
			}
		})
	}
}

// TestBindingMaterializationRecorderIsOnePerRegistry — П3.
func TestBindingMaterializationRecorderIsOnePerRegistry(t *testing.T) {
	reg := NewRegistry()
	first := reg.BindingMaterializationRecorder()
	require.NotPanics(t, func() {
		require.Same(t, first, reg.BindingMaterializationRecorder(),
			"второе обращение построило второй приёмник")
	}, "второе обращение зарегистрировало семейства повторно — старт упал бы")
}
