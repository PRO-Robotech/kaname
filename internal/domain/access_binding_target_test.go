// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// access_binding_target_test.go — unit tests for the per-object target membership
// helpers the reconciler uses to enforce the least-privilege spine (IAM-1-21):
// Contains (exact object membership) + ResourceIDsForTypes (ARM_ANCHOR id-resolution
// so a per-object target never expands to MatchAllInScope).

import (
	"fmt"
	"reflect"
	"strconv"
	"testing"
)

func perObjectTarget() AccessTarget {
	return AccessTarget{Resources: []ResourceRef{
		{Type: "compute.instance", ID: "ins-abc"},
		{Type: "compute.instance", ID: "ins-def"},
		{Type: "vpc.network", ID: "net-1"},
	}}
}

func TestAccessTarget_Contains(t *testing.T) {
	tgt := perObjectTarget()
	cases := []struct {
		dotted, id string
		want       bool
	}{
		{"compute.instance", "ins-abc", true},
		{"compute.instance", "ins-def", true},
		{"vpc.network", "net-1", true},
		{"compute.instance", "ins-other", false}, // in-scope but unlisted
		{"vpc.network", "ins-abc", false},        // right id, wrong type (no cross-type alias)
		{"compute.instance", "", false},
	}
	for _, c := range cases {
		if got := tgt.Contains(c.dotted, c.id); got != c.want {
			t.Errorf("Contains(%q,%q) = %v, want %v", c.dotted, c.id, got, c.want)
		}
	}
	// AllInScope / empty carry NO explicit object membership here.
	if (AccessTarget{AllInScope: true}).Contains("compute.instance", "ins-abc") {
		t.Error("AllInScope target must not report explicit object membership")
	}
	if (AccessTarget{}).Contains("compute.instance", "ins-abc") {
		t.Error("empty target must not report explicit object membership")
	}
}

func TestAccessTarget_ResourceIDsForTypes(t *testing.T) {
	tgt := perObjectTarget()
	cases := []struct {
		name  string
		types []string
		want  []string
	}{
		{"single type", []string{"compute.instance"}, []string{"ins-abc", "ins-def"}},
		{"other type", []string{"vpc.network"}, []string{"net-1"}},
		{"both types (order-preserving)", []string{"compute.instance", "vpc.network"}, []string{"ins-abc", "ins-def", "net-1"}},
		{"unknown type", []string{"registry.repository"}, nil},
		{"empty types", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := tgt.ResourceIDsForTypes(c.types)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("ResourceIDsForTypes(%v) = %v, want %v", c.types, got, c.want)
			}
		})
	}

	// De-duplication: the same id listed twice under the requested type yields one entry.
	dup := AccessTarget{Resources: []ResourceRef{
		{Type: "compute.instance", ID: "ins-x"},
		{Type: "compute.instance", ID: "ins-x"},
	}}
	if got := dup.ResourceIDsForTypes([]string{"compute.instance"}); !reflect.DeepEqual(got, []string{"ins-x"}) {
		t.Errorf("ResourceIDsForTypes dedup = %v, want [ins-x]", got)
	}
	// AllInScope carries no per-object ids.
	if got := (AccessTarget{AllInScope: true}).ResourceIDsForTypes([]string{"compute.instance"}); got != nil {
		t.Errorf("AllInScope ResourceIDsForTypes = %v, want nil", got)
	}
}

// TestAccessTarget_Validate_ResourceCardinality — the per-object target set is
// BOUNDED (anti-DoS + tractable materialization), mirroring MaxSubjectsPerBinding.
// The reconciler intersects every rule-matched object with the target via the linear
// Contains, and the whole materialization runs inside ONE synchronous create writer-tx
// under an advisory lock — an unbounded resources[] turns that into |matched|×|target|
// string comparisons plus an unbounded JSONB row.
func TestAccessTarget_Validate_ResourceCardinality(t *testing.T) {
	mk := func(n int) AccessTarget {
		out := AccessTarget{Resources: make([]ResourceRef, 0, n)}
		for i := 0; i < n; i++ {
			out.Resources = append(out.Resources, ResourceRef{
				Type: "compute.instance", ID: "ins-" + strconv.Itoa(i),
			})
		}
		return out
	}
	if err := mk(MaxTargetResourcesPerBinding).Validate(); err != nil {
		t.Fatalf("target with exactly %d resources must validate: %v", MaxTargetResourcesPerBinding, err)
	}
	err := mk(MaxTargetResourcesPerBinding + 1).Validate()
	if err == nil {
		t.Fatalf("target with %d resources must be rejected", MaxTargetResourcesPerBinding+1)
	}
	want := fmt.Sprintf("Illegal argument target.resources (must be 1..%d)", MaxTargetResourcesPerBinding)
	if err.Error() != want {
		t.Errorf("Validate() message = %q, want %q", err.Error(), want)
	}
}
