// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// BindingMaterializationRecorder measures HOW BIG one binding's materialization is:
// how many objects its selectors matched, and how many tuples those objects produce.
//
// WHY THIS IS MEASURED AT ALL. Access below the three cascading levels is materialized
// PER OBJECT, so a single grant expands into as many tuples as the selector matches
// objects, times the verbs the rule carries. Nothing counted that expansion, which made
// "this grant grew large" indistinguishable from "this grant is ordinary" — right up
// until the size stops fitting whatever the model can hold. And it does not stop there
// where the grant was issued: the expansion is written by the reconciler, so the wall is
// hit later, on somebody else's request, by a path that never mentions the binding.
//
// WHY NO CEILING IS ENFORCED HERE. The size a binding may reach has not been measured,
// and a limit picked before the measurement would either refuse legitimate grants or sit
// above everything and refuse nothing — the second being the more expensive mistake,
// because it looks like a control. So: measure first, then decide the number. This
// recorder is the measurement; it refuses nothing.
//
// WHY HISTOGRAMS AND NOT GAUGES. The question is a distribution — «how large do bindings
// get, and is the tail moving?» — not a last-value. A gauge would report whichever
// binding the reconciler happened to touch last, which answers nothing about the tail
// that matters. Buckets are exponential and reach four figures, so a binding an order of
// magnitude past the ordinary lands in its own bucket rather than in `+Inf` together
// with everything else large.
//
// The label set is EMPTY on purpose: binding id, scope and role would be unbounded
// cardinality straight from tenant data. The distribution answers the question; naming
// the individual binding is the job of the trail the reconciler already writes.
type BindingMaterializationRecorder struct {
	objects prometheus.Histogram
	tuples  prometheus.Histogram
}

// bindingSizeBuckets — общие корзины для обеих величин. Одинаковые намеренно:
// величины сравнивают друг с другом (кортежей на объект — это их отношение), и
// разные корзины сделали бы сравнение неверным на глаз.
var bindingSizeBuckets = []float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

// NewBindingMaterializationRecorder registers the collectors in this registry and
// returns the adapter the reconciler consumes through its narrow port. Call once at boot.
func (r *Registry) NewBindingMaterializationRecorder() *BindingMaterializationRecorder {
	rec := &BindingMaterializationRecorder{
		objects: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    Namespace + "_binding_materialization_objects",
			Help:    "Objects matched by one access binding's selectors during a reconcile pass.",
			Buckets: bindingSizeBuckets,
		}),
		tuples: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: Namespace + "_binding_materialization_tuples",
			Help: "Authorization tuples one access binding's reconcile pass materializes " +
				"(objects × the verbs of the rule that matched them).",
			Buckets: bindingSizeBuckets,
		}),
	}
	r.reg.MustRegister(rec.objects, rec.tuples)
	return rec
}

// ObserveBindingMaterialization records the size of ONE binding's desired set.
//
// A pass that matched nothing is recorded too, as a zero: «this binding materializes
// nothing» is a real and interesting state — a selector that stopped matching looks
// exactly like a binding nobody reconciles unless the empty pass is counted.
func (rec *BindingMaterializationRecorder) ObserveBindingMaterialization(objects, tuples int) {
	rec.objects.Observe(float64(objects))
	rec.tuples.Observe(float64(tuples))
}
