// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestInstallationPairPreservesCreatorAxesAndRetirement(t *testing.T) {
	wanted := domain.GrantDelegation{Module: "registry", Status: domain.GrantDelegationActive, DelegatedBy: domain.GrantDelegationActor{Type: "service_account", ID: "creator"}, RoleIDs: []domain.RoleID{"r1", "r2"}, TargetTypes: []string{"registry.r1", "registry.r2"}, SubjectTypes: []domain.SubjectType{domain.SubjectTypeUser, domain.SubjectTypeServiceAccount}}
	for _, tc := range []struct {
		name   string
		change func(*domain.GrantDelegation)
		valid  bool
	}{
		{"exact", func(*domain.GrantDelegation) {}, true},
		{"permuted", func(d *domain.GrantDelegation) {
			d.RoleIDs = []domain.RoleID{"r2", "r1"}
			d.TargetTypes = []string{"registry.r2", "registry.r1"}
			d.SubjectTypes = []domain.SubjectType{domain.SubjectTypeServiceAccount, domain.SubjectTypeUser}
		}, true},
		{"revoked", func(d *domain.GrantDelegation) { d.Status = domain.GrantDelegationRevoked }, false},
		{"different creator", func(d *domain.GrantDelegation) { d.DelegatedBy.ID = "replacement" }, false},
		{"different creator type", func(d *domain.GrantDelegation) { d.DelegatedBy.Type = "user" }, false},
		{"different roles", func(d *domain.GrantDelegation) { d.RoleIDs = []domain.RoleID{"r1"} }, false},
		{"different types", func(d *domain.GrantDelegation) { d.TargetTypes = []string{"registry.r1"} }, false},
		{"different subjects", func(d *domain.GrantDelegation) { d.SubjectTypes = []domain.SubjectType{domain.SubjectTypeUser} }, false},
		{"different module", func(d *domain.GrantDelegation) { d.Module = "ridaux" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := wanted
			tc.change(&current)
			if installationPairMatches(current, wanted) != tc.valid {
				t.Fatalf("pair valid=%v", tc.valid)
			}
		})
	}
}
