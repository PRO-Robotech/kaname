// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// login_timing_envelope_test.go — наблюдаемость огибающей по потолку полосы
// входа (решение kaname#188 по Ф3-31): потолок, стоимость каждого
// калиброванного класса, число калибровок по поводу.
//
// Что утверждают пробы: потолок и счётчик калибровок существуют с нулём до
// первой калибровки (клетка каждого повода — с нулём); калибровка класса даёт
// ряд его стоимости с метками формата и параметров и поднимает клетку своего
// повода на единицу; смена потолка — новое значение потолка.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

func labelledGauge(t *testing.T, r *Registry, name string, labels map[string]string) (value float64, present bool) {
	t.Helper()
	mfs, err := r.reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			match := true
			for _, lp := range m.GetLabel() {
				if want, ok := labels[lp.GetName()]; ok && want != lp.GetValue() {
					match = false
					break
				}
			}
			if match && len(m.GetLabel()) == len(labels) {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

// TestLoginTimingEnvelope_188_FloorAndCalibrationsAreVisibleFromZero —
// потолок и клетки поводов существуют с нулём; калибровка и смена потолка
// видны рядами.
func TestLoginTimingEnvelope_188_FloorAndCalibrationsAreVisibleFromZero(t *testing.T) {
	reg := NewRegistry()
	rec := reg.LoginLaneRecorder()

	value, present := plainValue(t, reg, LoginTimingEnvelopeFloorMetric)
	require.True(t, present, "ряд потолка существует до первой калибровки: «огибающей нет» видно нулём")
	require.Zero(t, value)
	for _, trigger := range passwordverify.EnvelopeTriggers() {
		value, present = labelledCounter(t, reg, LoginTimingCalibrationsMetric, map[string]string{"trigger": string(trigger)})
		require.Truef(t, present, "клетки повода %q нет до первого события", trigger)
		require.Zero(t, value)
	}
	_, present = labelledGauge(t, reg, LoginTimingClassCostMetric, map[string]string{"format": "2a", "params": "cost=12"})
	require.False(t, present, "стоимость класса — открытый набор: ряд появляется с калибровкой класса, не раньше")

	class := domain.PasswordCostClass{Format: domain.PasswordHashFormatBcrypt,
		Params: map[domain.PasswordHashCostParam]uint32{domain.CostParamBcryptCost: 12}}
	rec.ClassCalibrated(class, 210*time.Millisecond, passwordverify.EnvelopeTriggerStartup)
	value, present = labelledGauge(t, reg, LoginTimingClassCostMetric, map[string]string{"format": "2a", "params": "cost=12"})
	require.True(t, present)
	require.InDelta(t, 0.21, value, 1e-9, "стоимость класса — в секундах")
	value, _ = labelledCounter(t, reg, LoginTimingCalibrationsMetric, map[string]string{"trigger": "startup"})
	require.Equal(t, 1.0, value)
	value, _ = labelledCounter(t, reg, LoginTimingCalibrationsMetric, map[string]string{"trigger": "read"})
	require.Zero(t, value, "ровно одна клетка выросла")

	rec.EnvelopeFloorObserved(262500*time.Microsecond, class)
	value, _ = plainValue(t, reg, LoginTimingEnvelopeFloorMetric)
	require.InDelta(t, 0.2625, value, 1e-9, "потолок — в секундах")

	var _ passwordverify.EnvelopeObserver = rec
}
