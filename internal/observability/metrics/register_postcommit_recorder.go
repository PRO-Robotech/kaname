// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
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
// same requirement as "zero rows ever delivered" for a queue). Both are counted here, so
// `sum by (outcome)` answers "does it still work?" and the absence of the series
// altogether answers "is it even wired?".
//
// The `step` label additionally exposes WHICH materialization path each registration
// took. That is not decoration: `forward_additive` is the fast path a redelivery is
// supposed to stay on, and `forward_guarded` is the one that may escalate to the FULL
// EXCLUSIVE recompute every object of an account queues behind. A regression that pushes
// registrations back onto the guarded path shows up as a shift between two series, rather
// than as a latency somebody has to notice.
//
// Label set is CLOSED (4 steps × 2 outcomes): the values come from constants in the
// use-case, never from request data, so cardinality cannot grow with traffic.
type RegisterPostCommitRecorder struct {
	steps *prometheus.CounterVec
}

// NewRegisterPostCommitRecorder registers the collector in this registry and returns the
// adapter the register use-case consumes through its narrow port. Call once at boot.
func (r *Registry) NewRegisterPostCommitRecorder() *RegisterPostCommitRecorder {
	rec := &RegisterPostCommitRecorder{
		steps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kacho_iam_register_postcommit_steps_total",
			Help: "Post-commit materialization steps of RegisterResource/UnregisterResource, " +
				"by step (forward_additive|forward_guarded|tuple_write|tuple_delete) and outcome (ok|error). " +
				"Counts runs as well as failures, so a step that has never failed stays distinguishable " +
				"from one that never ran.",
		}, []string{"step", "outcome"}),
	}
	r.reg.MustRegister(rec.steps)
	return rec
}

// ObserveRegisterPostCommit records one post-commit step outcome.
func (rec *RegisterPostCommitRecorder) ObserveRegisterPostCommit(step, outcome string) {
	rec.steps.WithLabelValues(step, outcome).Inc()
}
