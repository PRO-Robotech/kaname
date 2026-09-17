// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
)

// TestRegistration_F4_CellsExistWithZeroBeforeTheFirstEvent — клетки исходов
// регистрации по полосе и причине существуют с нулём на свежем реестре
// (словарь — от производителя, а не выписанный); после одного события ровно
// одна клетка выросла. Вызывающий видит ОДИН отказ (Р3) — причина живёт здесь.
func TestRegistration_F4_CellsExistWithZeroBeforeTheFirstEvent(t *testing.T) {
	reg := NewRegistry()
	rec := reg.LoginLaneRecorder()

	total := 0
	for _, lane := range registration.Lanes {
		for _, o := range registration.Outcomes() {
			value, present := labelledCounter(t, reg, RegistrationOutcomesMetric,
				map[string]string{"lane": lane.Name, "outcome": string(o)})
			require.Truef(t, present, "клетки %s{lane=%q,outcome=%q} нет до первого события",
				RegistrationOutcomesMetric, lane.Name, o)
			require.Zero(t, value)
			total++
		}
	}
	require.Equal(t, len(registration.Lanes)*len(registration.Outcomes()), total)
	t.Logf("перепись: клеток регистрации с нулём %d (полос %d × исходов %d)",
		total, len(registration.Lanes), len(registration.Outcomes()))

	rec.RegistrationObserved(registration.LanePassword, registration.OutcomeRefusedRate)
	value, _ := labelledCounter(t, reg, RegistrationOutcomesMetric,
		map[string]string{"lane": registration.LanePassword, "outcome": "refused-rate"})
	require.Equal(t, 1.0, value, "ровно одна клетка выросла на единицу")
	value, _ = labelledCounter(t, reg, RegistrationOutcomesMetric,
		map[string]string{"lane": registration.LanePassword, "outcome": "refused-occupied"})
	require.Zero(t, value, "занятость и потолок темпа — РАЗНЫЕ клетки: единый отказ снаружи различим здесь")

	var _ registration.Observer = rec
}
