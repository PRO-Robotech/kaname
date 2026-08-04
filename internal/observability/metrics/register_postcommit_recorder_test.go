// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package metrics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// labelledCounter reads ONE labelled series out of the registry. Absent series read as 0
// — which is exactly the state the test below has to be able to distinguish from a
// present-but-zero one, so the caller asserts on presence separately.
func labelledCounter(t *testing.T, r *Registry, name string, labels map[string]string) (value float64, present bool) {
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
				return m.GetCounter().GetValue(), true
			}
		}
	}
	return 0, false
}

// TestRegisterPostCommitRecorder_RunsAndFailuresAreBothLive — the recorder must emit a
// series for a step that SUCCEEDED as well as for one that failed.
//
// The failure count alone would not close the gap it exists for: a step that never ran —
// unwired, short-circuited, or reached by no traffic at all — also reports zero failures,
// and those two states are precisely the ones that must be told apart. Counting runs is
// what makes "never refused" different from "never reached".
func TestRegisterPostCommitRecorder_RunsAndFailuresAreBothLive(t *testing.T) {
	reg := NewRegistry()
	rec := reg.NewRegisterPostCommitRecorder()

	rec.ObserveRegisterPostCommit("forward_additive", "ok")
	rec.ObserveRegisterPostCommit("forward_additive", "ok")
	rec.ObserveRegisterPostCommit("forward_guarded", "error")
	rec.ObserveRegisterPostCommit("tuple_write", "ok")

	const name = "kacho_iam_register_postcommit_steps_total"

	v, ok := labelledCounter(t, reg, name, map[string]string{"step": "forward_additive", "outcome": "ok"})
	require.True(t, ok, "a SUCCESSFUL run must produce a series — otherwise a step that "+
		"never ran is indistinguishable from one that never failed")
	require.Equal(t, 2.0, v)

	v, ok = labelledCounter(t, reg, name, map[string]string{"step": "forward_guarded", "outcome": "error"})
	require.True(t, ok, "a FAILED post-commit step must be counted, not only logged")
	require.Equal(t, 1.0, v)

	v, ok = labelledCounter(t, reg, name, map[string]string{"step": "tuple_write", "outcome": "ok"})
	require.True(t, ok)
	require.Equal(t, 1.0, v)

	// A step never observed carries NO series — the honest reading of "never reached",
	// readable as such only because the reached ones do carry one.
	_, ok = labelledCounter(t, reg, name, map[string]string{"step": "tuple_delete", "outcome": "error"})
	require.False(t, ok, "an unobserved step must not fabricate a zero sample")

	require.Equal(t, 4.0, gatherCounter(t, reg, name), "every observation reaches the registry")
}
