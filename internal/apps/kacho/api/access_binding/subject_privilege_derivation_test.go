// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// subject_privilege_derivation_test.go — "what can this user do" must not be blind
// to access held through a group.
//
// The failure being locked out: an administrator puts a user in a group, grants
// the group a role, then opens the user's privileges and sees an EMPTY list —
// while the user demonstrably holds the access (enforcement resolves the group
// userset; only this REPORT did not). That is a WRONG answer, not an incomplete
// one, and it is the exact question an administrator asks before an audit or an
// off-boarding.
//
// The row must also say WHICH group carries the access — otherwise the finding is
// un-actionable: the binding's own subject is the group, so the row alone does not
// tell the administrator which membership to remove.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

func TestSubjectPrivilegeToProto_GroupDerivationSurfaced(t *testing.T) {
	got := subjectPrivilegeToProto(domain.SubjectPrivilege{
		BindingID:    "acb0000000000grp01",
		RoleID:       "rol0000000000edit1",
		ResourceType: "project",
		ResourceID:   "prj-9",
		Scope:        domain.ScopeProject,
		Status:       domain.AccessBindingStatusActive,
		CreatedAt:    time.Now(),
		Derivation:   domain.DerivationGroup,
		ViaGroupID:   "grp0000000000team1",
	})

	assert.Equal(t, iamv1.Derivation_GROUP, got.GetDerivation(),
		"a group-derived privilege must NOT be reported as DIRECT")
	assert.Equal(t, "grp0000000000team1", got.GetViaGroupId(),
		"the carrying group must be named so the finding is actionable")
}

func TestSubjectPrivilegeToProto_DirectDerivationUnchanged(t *testing.T) {
	got := subjectPrivilegeToProto(domain.SubjectPrivilege{
		BindingID:    "acb0000000000dir01",
		RoleID:       "rol0000000000view1",
		ResourceType: "account",
		ResourceID:   "acc-9",
		Scope:        domain.ScopeAccount,
		Status:       domain.AccessBindingStatusActive,
		CreatedAt:    time.Now(),
		Derivation:   domain.DerivationDirect,
	})

	assert.Equal(t, iamv1.Derivation_DIRECT, got.GetDerivation())
	assert.Empty(t, got.GetViaGroupId(), "a direct grant has no carrying group")
}

// Defensive: a zero-value Derivation (rows produced before the field existed, or a
// projection that forgot to set it) must report DIRECT, never UNSPECIFIED — the
// enum's zero value is UNSPECIFIED and leaking it would make every legacy row look
// like an unknown derivation.
func TestSubjectPrivilegeToProto_ZeroDerivationReportsDirect(t *testing.T) {
	got := subjectPrivilegeToProto(domain.SubjectPrivilege{
		BindingID:    "acb0000000000zer01",
		ResourceType: "account",
		ResourceID:   "acc-0",
		Scope:        domain.ScopeAccount,
		Status:       domain.AccessBindingStatusActive,
		CreatedAt:    time.Now(),
	})
	assert.Equal(t, iamv1.Derivation_DIRECT, got.GetDerivation())
}
