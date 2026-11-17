// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestResourceRetainedCapabilitiesRequiresExactLiveOriginal(t *testing.T) {
	old := domain.GrantCapabilityRule{RuleFP: "old", Kind: domain.GrantCapabilityBindRole, BoundRoleID: "target"}
	replacement := old
	replacement.RuleFP = "new"
	for _, tc := range []struct {
		name         string
		actual       []domain.GrantCapabilityRule
		axis, target bool
		want         int
	}{
		{"present", []domain.GrantCapabilityRule{old}, true, true, 1},
		{"removed", nil, true, true, 0},
		{"different fingerprint", []domain.GrantCapabilityRule{replacement}, true, true, 0},
		{"retired axis", []domain.GrantCapabilityRule{old}, false, true, 0},
		{"retired or foreign target", []domain.GrantCapabilityRule{old}, true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resourceRetainedCapabilities(tc.actual, []domain.GrantCapabilityRule{old}, []domain.GrantCapabilityRule{replacement}, map[domain.GrantCapabilityKind]bool{old.Kind: tc.axis}, map[domain.RoleID]bool{old.BoundRoleID: tc.target})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.want {
				t.Fatalf("retained=%+v", got)
			}
			if tc.want == 1 && got[0] != replacement {
				t.Fatalf("retained old fingerprint: %+v", got)
			}
		})
	}
}

func TestResourceRetainedCapabilitiesSequentialRemovalCannotResurrect(t *testing.T) {
	first := domain.GrantCapabilityRule{RuleFP: "first", Kind: domain.GrantCapabilityCreateBinding}
	next := first
	next.RuleFP = "second"
	axes := map[domain.GrantCapabilityKind]bool{first.Kind: true}
	retained, err := resourceRetainedCapabilities([]domain.GrantCapabilityRule{first}, []domain.GrantCapabilityRule{first}, nil, axes, nil)
	if err != nil {
		t.Fatal(err)
	}
	later, err := resourceRetainedCapabilities(retained, []domain.GrantCapabilityRule{first}, []domain.GrantCapabilityRule{next}, axes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(later) != 0 {
		t.Fatalf("removed source resurrected: %+v", later)
	}
}
