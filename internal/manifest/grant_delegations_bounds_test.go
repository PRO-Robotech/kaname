// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

import (
	"fmt"
	"testing"
)

func TestInstallationDelegationAxisBounds(t *testing.T) {
	makeManifest := func(nroles, ntypes int) *Manifest {
		m := &Manifest{Module: "ridaux", Seed: &Seed{ServiceAccounts: []ServiceAccount{{Name: "svc-ridaux", Account: "system"}}}}
		d := GrantDelegation{Delegate: SubjectRef{Account: "system", Name: "svc-ridaux"}, SubjectTypes: []string{"SUBJECT_TYPE_USER", "SUBJECT_TYPE_SERVICE_ACCOUNT", "SUBJECT_TYPE_GROUP", "SUBJECT_TYPE_SYSTEM_CLASS"}}
		for i := 0; i < nroles; i++ {
			id := fmt.Sprintf("ridaux.role%02d", i)
			m.Roles = append(m.Roles, Role{ID: id})
			d.RoleIDs = append(d.RoleIDs, id)
		}
		for i := 0; i < ntypes; i++ {
			name := fmt.Sprintf("objects%02d", i)
			m.Resources = append(m.Resources, Resource{Name: name})
			d.TargetTypes = append(d.TargetTypes, "ridaux."+name)
		}
		m.Seed.GrantDelegations = []GrantDelegation{d}
		return m
	}
	for _, tc := range []struct {
		name         string
		roles, types int
		valid        bool
	}{
		{"minimum", 1, 1, true}, {"maximum", 16, 16, true},
		{"roles zero", 0, 1, false}, {"roles above", 17, 1, false},
		{"types zero", 1, 0, false}, {"types above", 1, 17, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			faults := validateGrantDelegations(makeManifest(tc.roles, tc.types), nil)
			if (len(faults) == 0) != tc.valid {
				t.Fatalf("valid=%v faults=%v", tc.valid, faults)
			}
		})
	}
	for _, n := range []int{0, 5} {
		m := makeManifest(1, 1)
		m.Seed.GrantDelegations[0].SubjectTypes = make([]string, n)
		if len(validateGrantDelegations(m, nil)) == 0 {
			t.Fatalf("subject count %d accepted", n)
		}
	}
}
