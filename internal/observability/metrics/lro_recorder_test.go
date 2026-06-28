// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// TestLRORecorder_MetricsAreLive — adapter обязан эмитить реальные серии (а не
// быть мертвым NopRecorder): terminal-write failure и inflight gauge должны
// отражаться в registry. Это сигналы стрэндящейся LRO — без них они невидимы.
func TestLRORecorder_MetricsAreLive(t *testing.T) {
	reg := NewRegistry()
	rec := reg.NewLRORecorder()

	rec.IncTerminalWriteFailures("role.create")
	rec.IncTerminalWriteFailures("role.create")
	rec.IncTerminalWriteRetries("role.create")
	rec.SetInflight(3)
	rec.IncReconcileRuns()
	rec.IncOrphansRecovered("recovered")

	got := gatherCounter(t, reg, "kacho_iam_lro_terminal_write_failures_total")
	require.Equal(t, 2.0, got, "terminal-write failures must be recorded, not dropped")
	require.Equal(t, 3.0, gatherGauge(t, reg, "kacho_iam_lro_inflight"), "inflight gauge must be live")
	require.Equal(t, 1.0, gatherCounter(t, reg, "kacho_iam_lro_reconcile_runs_total"))
	require.Equal(t, 1.0, gatherCounter(t, reg, "kacho_iam_lro_orphans_recovered_total"))
}

func gatherCounter(t *testing.T, r *Registry, name string) float64 {
	t.Helper()
	return sumMetric(t, r, name, func(m *prometheus.Metric) {})
}

func gatherGauge(t *testing.T, r *Registry, name string) float64 {
	t.Helper()
	return sumMetric(t, r, name, func(m *prometheus.Metric) {})
}

func sumMetric(t *testing.T, r *Registry, name string, _ func(*prometheus.Metric)) float64 {
	t.Helper()
	mfs, err := r.reg.Gather()
	require.NoError(t, err)
	var total float64
	var found bool
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		found = true
		for _, m := range mf.GetMetric() {
			if c := m.GetCounter(); c != nil {
				total += c.GetValue()
			}
			if g := m.GetGauge(); g != nil {
				total += g.GetValue()
			}
		}
	}
	require.True(t, found, "metric %s must be registered (not a dead NopRecorder series)", name)
	return total
}
