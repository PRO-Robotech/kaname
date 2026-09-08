// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// RegisterPostCommitSteps / RegisterPostCommitOutcomes — ЗАКРЫТЫЙ набор лейблов
// счётчика, объявленный ОДИН раз.
//
// Значения приходят из констант use-case, никогда из данных запроса, поэтому
// кардинальность не растёт с трафиком. Набор объявлен здесь, а не пересказан в
// строке помощи: прежняя редакция перечисляла шаги прозой и уже разошлась с
// кодом — шагов стало шесть, а текст называл четыре. Перечень читают обе стороны:
// коллектор — чтобы инициализировать каждую клетку нулём, проба use-case — чтобы
// доказать, что его собственные константы этому набору равны в ОБЕ стороны
// (TestPostCommitStepConstantsMatchTheDeclaredLabelSet).
var (
	RegisterPostCommitSteps = []string{
		"forward_additive", "forward_guarded",
		"residual_read", "residual_withdraw",
	}
	RegisterPostCommitOutcomes = []string{"ok", "error"}
)

// RegisterPostCommitRecorder counts the POST-COMMIT accelerators of the cross-service
// registration path — the forward reconcile that materializes the owner's per-object
// access, and the direct apply of the containment pointer.
//
// WHY A COUNTER AND NOT JUST THE LOG LINE. Both steps are best-effort by design: they
// front a durable queue, so a failure costs latency and never the change itself. That is
// exactly what makes a permanently broken one invisible — one WARN per occurrence, a
// product that keeps working more slowly, and nothing that says so. A control that has
// never refused in its whole life is indistinguishable from one that was never reached
// unless RUNS are counted alongside OUTCOMES (security.md §Hardening-инвариант 8, the
// same requirement as "zero rows ever delivered" for a queue).
//
// WHY EVERY CELL STARTS AT ZERO RATHER THAN APPEARING ON FIRST USE. An absent series
// answered two different questions at once — "this step never ran" and "this collector
// is not wired at all" — and telling those apart is the whole point. Measured on a
// stand: the ADDITIVE forward entry fired ZERO times across 367 registrations, and that
// was establishable only because its sibling had a series; on its own the proven entry
// looked like code that does not exist. With the closed label set initialised at
// construction, presence answers "is it wired?" and the VALUE answers "was it ever
// reached?" — so `forward_additive == 0` beside a growing `forward_guarded` is a
// FINDING stated by the metric, not a silence somebody has to interpret.
//
// The `step` label additionally exposes WHICH materialization path each registration
// took. That is not decoration: `forward_additive` is the fast path a redelivery is
// supposed to stay on, and `forward_guarded` is the one that may escalate to the FULL
// EXCLUSIVE recompute every object of an account queues behind. A regression that pushes
// registrations back onto the guarded path shows up as a shift between two series, rather
// than as a latency somebody has to notice.
//
// The label set is CLOSED and declared once above — the count is not repeated in prose
// here, because the prose already drifted from the code once.
type RegisterPostCommitRecorder struct {
	steps *prometheus.CounterVec
}

// NewRegisterPostCommitRecorder registers the collector in this registry and returns the
// adapter the register use-case consumes through its narrow port. Call once at boot.
func (r *Registry) NewRegisterPostCommitRecorder() *RegisterPostCommitRecorder {
	rec := &RegisterPostCommitRecorder{
		steps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: Namespace + "_register_postcommit_steps_total",
			Help: "Post-commit materialization steps of RegisterResource/UnregisterResource, " +
				"by step (" + strings.Join(RegisterPostCommitSteps, "|") + ") and outcome (" +
				strings.Join(RegisterPostCommitOutcomes, "|") + "). Counts runs as well as failures, " +
				"and every cell starts at zero, so a step that never ran is distinguishable both " +
				"from one that never failed and from a collector that is not wired.",
		}, []string{"step", "outcome"}),
	}
	// Каждая клетка закрытого набора заводится нулём. Иначе отсутствие серии
	// означает сразу и «не исполнялось», и «не провязано», а различать эти два
	// состояния — единственная причина, по которой считаются ЗАПУСКИ, а не только
	// отказы. Locked by TestRegisterPostCommitRecorder_ZeroIsVisibleNotAbsent.
	for _, step := range RegisterPostCommitSteps {
		for _, outcome := range RegisterPostCommitOutcomes {
			rec.steps.WithLabelValues(step, outcome)
		}
	}
	r.reg.MustRegister(rec.steps)
	return rec
}

// ObserveRegisterPostCommit records one post-commit step outcome.
func (rec *RegisterPostCommitRecorder) ObserveRegisterPostCommit(step, outcome string) {
	rec.steps.WithLabelValues(step, outcome).Inc()
}
