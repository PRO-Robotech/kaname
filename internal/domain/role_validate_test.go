// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// role_validate_test.go — Role.Validate must
// accept a rules-role whose rules ALL compile to an EMPTY permission set — i.e. a
// label-only role (every rule is ARM_LABELS, which by design is NOT compiled into
// permissions). The compiled-permission lower-bound of ≥1 only
// applies to LEGACY permissions-only roles (no Rules).

import (
	"strings"
	"testing"
)

// A-10 positive: a single ARM_LABELS rule on a label-selectable type compiles to
// an empty permission set; the role MUST still validate. Before the fix
// Role.Validate called Permissions.Validate() unconditionally → "must contain at
// least 1" → the role was falsely rejected.
func TestRole_A10_LabelOnlyRoleValidates(t *testing.T) {
	rules := Rules{
		{
			Module:      "iam",
			Resources:   []string{"project"},
			Verbs:       []string{"get"},
			MatchLabels: map[string]string{"tier": "gold"},
		},
	}
	compiled, err := CompileRules(rules)
	if err != nil {
		t.Fatalf("CompileRules() = %v, want nil", err)
	}
	if len(compiled) != 0 {
		t.Fatalf("label-only rule compiled to %v, want empty (ARM_LABELS excluded)", compiled)
	}

	r := Role{
		ID:          RoleID("rol0000000000000lbl0"),
		AccountID:   AccountID("acc00000000000000000A"),
		Name:        RoleName("label_only"),
		Rules:       rules,
		Permissions: compiled, // empty — must NOT trip the ≥1 lower bound
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Role.Validate() = %v, want nil (label-only rules-role must be accepted)", err)
	}
}

// A mixed role whose rules also include a compilable arm keeps a non-empty
// compiled set — still valid (regression guard alongside the label-only case).
func TestRole_A10_MixedArmRoleValidates(t *testing.T) {
	rules := Rules{
		{Module: "compute", Resources: []string{"image"}, Verbs: []string{"get"}},                                                // ANCHOR → compiles
		{Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"create"}, MatchLabels: map[string]string{"env": "prod"}}, // LABELS → excluded
	}
	compiled, err := CompileRules(rules)
	if err != nil {
		t.Fatalf("CompileRules() = %v, want nil", err)
	}
	if len(compiled) == 0 {
		t.Fatalf("mixed-arm rule compiled to empty, want the anchor arm present")
	}
	r := Role{
		ID:          RoleID("rol0000000000000mix0"),
		AccountID:   AccountID("acc00000000000000000A"),
		Name:        RoleName("mixed_arm"),
		Rules:       rules,
		Permissions: compiled,
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Role.Validate() = %v, want nil", err)
	}
}

// A LEGACY permissions-only role (no Rules) with an EMPTY permission set is still
// invalid — the ≥1 lower bound is retained for the back-compat path so a degenerate
// legacy role cannot exist.
func TestRole_LegacyEmptyPermissionsRejected(t *testing.T) {
	r := Role{
		ID:        RoleID("rol0000000000000leg0"),
		AccountID: AccountID("acc00000000000000000A"),
		Name:      RoleName("legacy_empty"),
		// No Rules; empty Permissions.
	}
	err := r.Validate()
	if err == nil {
		t.Fatalf("Role.Validate() = nil, want error (legacy permissions-only role with empty set)")
	}
	if !strings.Contains(err.Error(), "at least 1") {
		t.Fatalf("Role.Validate() = %v, want the legacy ≥1 lower-bound error", err)
	}
}

// A rules-role whose compiled permissions exceed the grammar/cap is still rejected
// — the rules path validates the compiled projection as a 4-seg grammar + cap, just
// without the ≥1 lower bound. Pin that an INVALID compiled token is still caught.
func TestRole_RulesRoleInvalidCompiledRejected(t *testing.T) {
	r := Role{
		ID:        RoleID("rol0000000000000bad0"),
		AccountID: AccountID("acc00000000000000000A"),
		Name:      RoleName("bad_compiled"),
		Rules: Rules{
			{Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"get"}},
		},
		// Hand-built malformed compiled token (3-seg) — must be rejected by the
		// grammar validation even on the rules path.
		Permissions: Permissions{"vpc.subnet.get"},
	}
	if err := r.Validate(); err == nil {
		t.Fatalf("Role.Validate() = nil, want grammar error for malformed compiled token")
	}
}
