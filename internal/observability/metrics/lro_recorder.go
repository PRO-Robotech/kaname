// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// LRORecorder is the Prometheus implementation of operations.Recorder. Without it
// the operations default-registry keeps a NopRecorder, so the live LRO-worker
// signals (terminal-write retries/failures, the in-flight gauge, orphan recovery,
// reconcile runs/errors) — the exact signals for a stranding operation — are
// invisible on /metrics. Wired once at the composition root via ConfigureDefault.
type LRORecorder struct {
	terminalRetries  *prometheus.CounterVec
	terminalFailures *prometheus.CounterVec
	inflight         prometheus.Gauge
	orphansRecovered *prometheus.CounterVec
	reconcileRuns    prometheus.Counter
	reconcileErrors  prometheus.Counter
}

var _ operations.Recorder = (*LRORecorder)(nil)

// NewLRORecorder registers the LRO collectors in this registry and returns the
// operations.Recorder adapter. Call once at boot.
func (r *Registry) NewLRORecorder() *LRORecorder {
	l := &LRORecorder{
		terminalRetries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kacho_iam_lro_terminal_write_retries_total",
			Help: "Retries of the durable terminal write (MarkDone/MarkError) by operation type.",
		}, []string{"op_type"}),
		terminalFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kacho_iam_lro_terminal_write_failures_total",
			Help: "Terminal writes that exhausted their retry budget by operation type — a stranded operation.",
		}, []string{"op_type"}),
		inflight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kacho_iam_lro_inflight",
			Help: "Operations currently dispatched to the worker pool.",
		}),
		orphansRecovered: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kacho_iam_lro_orphans_recovered_total",
			Help: "Orphaned operations (done=false past their lease) recovered by the reconciler, by outcome.",
		}, []string{"outcome"}),
		reconcileRuns: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "kacho_iam_lro_reconcile_runs_total",
			Help: "Reconciler sweep runs.",
		}),
		reconcileErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "kacho_iam_lro_reconcile_errors_total",
			Help: "Reconciler sweep runs that ended in error.",
		}),
	}
	r.reg.MustRegister(l.terminalRetries, l.terminalFailures, l.inflight,
		l.orphansRecovered, l.reconcileRuns, l.reconcileErrors)
	return l
}

// IncTerminalWriteRetries — operations.Recorder.
func (l *LRORecorder) IncTerminalWriteRetries(opType string) {
	l.terminalRetries.WithLabelValues(opType).Inc()
}

// IncTerminalWriteFailures — operations.Recorder.
func (l *LRORecorder) IncTerminalWriteFailures(opType string) {
	l.terminalFailures.WithLabelValues(opType).Inc()
}

// SetInflight — operations.Recorder.
func (l *LRORecorder) SetInflight(n float64) { l.inflight.Set(n) }

// IncOrphansRecovered — operations.Recorder.
func (l *LRORecorder) IncOrphansRecovered(outcome string) {
	l.orphansRecovered.WithLabelValues(outcome).Inc()
}

// IncReconcileRuns — operations.Recorder.
func (l *LRORecorder) IncReconcileRuns() { l.reconcileRuns.Inc() }

// IncReconcileErrors — operations.Recorder.
func (l *LRORecorder) IncReconcileErrors() { l.reconcileErrors.Inc() }
