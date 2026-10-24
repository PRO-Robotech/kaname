// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Форма измерительных проб времени отказа Ф3-31 и Ф13-06 «л» (kaname#861):
// потолок годности — ПРОВЕРЯЕМАЯ величина, а «не выполнилось» отличимо от
// красного. Обе пробы берут потолок, его судью и третий исход из одной общей
// части (`timing_probe_test.go`); здесь их способность упасть доказана на
// синтетике, без часов и без машины, на каждой отправке.
//
// Определение потолка — приёмка Ф1-50: «годен тот потолок, при котором Ф1-49
// краснеет». Полоса с размахом у потолка поглощает различие не меньше
// потолка (критерий Ф1-48 судит |Δмедиан| против наибольшего размаха пары),
// поэтому годный потолок СТРОГО ниже внесённого различия. Потолок ∞ — мутант,
// при котором проверка размаха выродилась: любой шум годен, и проба зелена
// при любом различии.

// timingInfiniteCeiling — мутант «потолок годности бесконечен».
const timingInfiniteCeiling = time.Duration(math.MaxInt64)

// timingSyntheticInjected — различие, которое вносит инъекция Ф1-49 на
// синтетике: порядок стоимости одной проверки.
const timingSyntheticInjected = 80 * time.Millisecond

// spreadLane — полоса из timingLaneN обращений с межквартильным размахом
// РОВНО iqr у center+shift: шум худшего вида, который потолок ещё допускает.
// Половина обращений — на нижнем краю, половина — на верхнем: квартили легли
// на края, и размах равен iqr при любом timingLaneN; сверено stats() ниже.
func spreadLane(name string, center, shift, iqr time.Duration) *timingLane {
	l := &timingLane{name: name}
	for i := 0; i < timingLaneN; i++ {
		v := center + shift - iqr/2
		if i >= timingLaneN/2 {
			v += iqr
		}
		l.samples = append(l.samples, v)
	}
	if _, got := l.stats(); got != iqr {
		panic("spreadLane: размах полосы " + got.String() + ", заказан " + iqr.String())
	}
	return l
}

// TestTimingCeiling_InfiniteCeilingIsRefused — судья потолка краснеет на
// мутанте «потолок = ∞» и на потолке, равном различию; законный близнец —
// потолок, который берут обе пробы, — молчит при любом различии.
func TestTimingCeiling_InfiniteCeilingIsRefused(t *testing.T) {
	err := timingCeilingFault(timingInfiniteCeiling, timingSyntheticInjected)
	require.Error(t, err, "мутант «потолок = ∞» выжил: судья потолка его принял")
	require.Contains(t, err.Error(), "потолок годности", "отказ обязан назвать свой предмет")

	require.Error(t, timingCeilingFault(timingSyntheticInjected, timingSyntheticInjected),
		"потолок, равный различию, принят: полоса с размахом у потолка поглотит различие")
	require.Error(t, timingCeilingFault(0, timingSyntheticInjected), "нулевой потолок принят")

	for _, injected := range []time.Duration{time.Millisecond, timingSyntheticInjected, 1300 * time.Millisecond} {
		ceiling := timingFitnessCeiling(injected)
		require.NoError(t, timingCeilingFault(ceiling, injected),
			"потолок обеих проб %v при различии %v отвергнут судьёй", ceiling, injected)
	}
}

// TestTimingCeiling_InjectionRedsAtTheDeclaredCeiling — потолок обеих проб
// годен ПО ОПРЕДЕЛЕНИЮ Ф1-50: при шуме у самого потолка инъекция краснеет
// С ИМЕНЕМ полосы. Близнец с одним изменённым фактом — тот же шум при потолке
// ∞ — проходит судью годности и прячет инъекцию: так выглядит выживший мутант.
func TestTimingCeiling_InjectionRedsAtTheDeclaredCeiling(t *testing.T) {
	const injected = "B-ручка"
	ceiling := timingFitnessCeiling(timingSyntheticInjected)
	rows := synthRows(
		spreadLane("A", time.Second, 0, ceiling),
		spreadLane(injected, time.Second, timingSyntheticInjected, ceiling),
		spreadLane("C", time.Second, 0, ceiling),
	)
	_, unfit := timingUnfitLane(rows, ceiling)
	require.False(t, unfit, "шум у самого потолка признан негодным — потолок не тот, что судит")
	failures, _ := timingPairFailures(rows)
	require.Len(t, failures, 2, "инъекция %v при шуме у потолка %v не покраснела на обеих парах", timingSyntheticInjected, ceiling)
	for _, f := range failures {
		require.Contains(t, f, injected, "красное пришло не от внесённого различия: %s", f)
	}

	// Мутант: шум вдвое выше различия годен при потолке ∞, и инъекция молчит.
	noisy := 2 * timingSyntheticInjected
	rows = synthRows(
		spreadLane("A", time.Second, 0, noisy),
		spreadLane(injected, time.Second, timingSyntheticInjected, noisy),
	)
	_, unfit = timingUnfitLane(rows, timingInfiniteCeiling)
	require.False(t, unfit)
	failures, _ = timingPairFailures(rows)
	require.Empty(t, failures, "предпосылка мутанта: шум выше различия обязан прятать инъекцию")
	// А при потолке обеих проб тот же шум — «не выполнилось», а не зелёное.
	_, unfit = timingUnfitLane(rows, ceiling)
	require.True(t, unfit, "шум выше различия при потолке обеих проб не признан негодным")
}

// TestTimingFitness_NoisyLaneIsNotPerformedWithTheMarker — третий исход
// называет полосу и несёт метку, которую читает прогонщик вердикта
// (`.github/scripts/go-test-verdict.py`): «не выполнилось» ≠ красное.
func TestTimingFitness_NoisyLaneIsNotPerformedWithTheMarker(t *testing.T) {
	ceiling := timingFitnessCeiling(timingSyntheticInjected)
	rows := synthRows(spreadLane("A", time.Second, 0, ceiling/2), spreadLane("шумная", time.Second, 0, 2*ceiling))
	text, unfit := timingUnfitLane(rows, ceiling)
	require.True(t, unfit, "полоса с размахом выше потолка признана годной")
	require.True(t, strings.HasPrefix(text, timingNotPerformed), "третий исход без метки: %q", text)
	require.Contains(t, text, `"шумная"`, "третий исход не назвал полосу: %q", text)

	// Близнец: тот же ряд без шумной полосы — годен.
	_, unfit = timingUnfitLane(rows[:1], ceiling)
	require.False(t, unfit, "годная полоса признана негодной")
}
