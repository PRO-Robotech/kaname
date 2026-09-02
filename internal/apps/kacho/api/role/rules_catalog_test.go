// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// rules_catalog_test.go — Role.Create / Role.Update MUST reject an authored rule
// whose `(module, resource)` pair is not in the published grantable catalog
// (authzmap.Catalog(), served publicly as GET /iam/v1/permissionCatalog).
//
// WHY (the silent-empty-grant class this locks): `domain.Rule.Validate` checks the
// module against the closed module-set and the verbs against the closed verb-set,
// but the RESOURCE segment only against a token GRAMMAR. A typo'd or
// wrongly-numbered token ("instances" instead of "instance") therefore passes
// Create with 200, passes AccessBinding.Create with 200 (the structural
// RoleCoversType gate compares the target type against the SAME typo and matches),
// and then the reconciler's `fgaObjectType` returns ok=false and the tuple emission
// is SKIPPED fail-closed → the grantee gets 403 forever with no signal anywhere
// (not on the role, not on the binding, not on the Operation).
//
// The likelihood is high because the canonical spelling is deliberately
// inconsistent across modules (compute.instance / iam.serviceAccount are singular;
// storage.volumes / registry.registries / loadbalancer.networkLoadBalancers are
// plural) — a human cannot guess it, they must read the catalog.
//
// The reject is SYNC (before the Operation) and names the catalog endpoint, per
// api-conventions error-tone.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/catalogfixture"
)

// ── Create: unknown (module,resource) → sync INVALID_ARGUMENT ────────────────────

// The plural typo of a singular catalog token. `compute.instance` is grantable;
// `compute.instances` is not, and today it silently compiles into a grant that
// materializes nothing.
func TestCreateRole_UnknownResourceToken_RejectedSync(t *testing.T) {
	uc := &CreateRoleUseCase{} // nil repo/opsRepo: the reject must be a sync pre-check
	_, err := uc.Execute(authnCtx(), domain.Role{
		AccountID: "acc0000000000000abcd",
		Name:      "typo_role",
		Rules: domain.Rules{
			{Module: "compute", Resources: []string{"instances"}, Verbs: []string{"get", "list"}},
		},
	})
	st, _ := status.FromError(err)
	require.Equal(t, codes.InvalidArgument, st.Code(),
		"unknown (module,resource) must be rejected SYNC, not accepted into a silent empty grant; err=%v", err)
	assert.Contains(t, st.Message(), "compute.instances",
		"the message must name the offending token so the author can fix it")
	assert.Contains(t, st.Message(), "/iam/v1/permissionCatalog",
		"the message must point at the public grantable catalog (the author cannot guess the spelling)")
}

// Same class through the OTHER inconsistent direction: a singular token where the
// catalog is plural (`storage.volumes`). Locks that the check is a table lookup,
// not a pluralisation heuristic.
func TestCreateRole_UnknownResourceToken_SingularOfPluralType_RejectedSync(t *testing.T) {
	uc := &CreateRoleUseCase{}
	_, err := uc.Execute(authnCtx(), domain.Role{
		AccountID: "acc0000000000000abcd",
		Name:      "typo_role_2",
		Rules: domain.Rules{
			{Module: "storage", Resources: []string{"volume"}, Verbs: []string{"get"}},
		},
	})
	st, _ := status.FromError(err)
	require.Equal(t, codes.InvalidArgument, st.Code(), "err=%v", err)
	assert.Contains(t, st.Message(), "storage.volume")
}

// ── Update: the same gate on the mutable rules[] ─────────────────────────────────

func TestUpdateRole_UnknownResourceToken_RejectedSync(t *testing.T) {
	repo := newRlUpdRepo(domain.Labels{})
	uc := NewUpdateRoleUseCase(repo, newRlFakeOps(), catalogfixture.Source())

	_, err := uc.Execute(ownerCtx(), UpdateRoleInput{
		ID: rlUpdRoleID,
		Rules: domain.Rules{
			{Module: "vpc", Resources: []string{"security_group"}, Verbs: []string{"get"}},
		},
		UpdateMask: []string{"rules"},
	})
	st, _ := status.FromError(err)
	require.Equal(t, codes.InvalidArgument, st.Code(),
		"Update must gate rules[] on the catalog exactly like Create; err=%v", err)
	assert.Contains(t, st.Message(), "vpc.security_group",
		"snake_case is NOT the catalog spelling (vpc.securityGroup is)")
}

// ── Positive: every published catalog token is accepted ──────────────────────────

// Conformance both ways: the gate must accept EXACTLY the published catalog. If it
// rejected a grantable token the platform would lose a legitimate grant, which is a
// worse failure than the one being fixed.
func TestRuleCatalogGate_AcceptsEveryPublishedCatalogToken(t *testing.T) {
	for _, e := range authzmap.Catalog() {
		rules := domain.Rules{{Module: e.Module, Resources: []string{e.Resource}, Verbs: []string{"get"}}}
		assert.NoErrorf(t, validateRuleCatalog(rules, false),
			"catalog token %s.%s is published as grantable but the gate rejects it", e.Module, e.Resource)
	}
}

// Wildcards are the system-role shape and are policed by domain.Rule.Validate
// (system-only); the catalog gate must not double-reject them, else a system role
// or the wildcard policy error would be masked by a spurious catalog error.
func TestRuleCatalogGate_SkipsWildcards(t *testing.T) {
	assert.NoError(t, validateRuleCatalog(
		domain.Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}}, true))
	assert.NoError(t, validateRuleCatalog(
		domain.Rules{{Module: "compute", Resources: []string{"*"}, Verbs: []string{"get"}}}, true))
}

// ── System roles: the seeded catalog must stay valid ─────────────────────────────

// The 58 seeded system roles carry a DIFFERENT taxonomy in their rules[] — they
// mirror their permission strings verbatim for tier-parity (`iam.service_account`,
// `vpc.subnetses`, `loadbalancer.operations`, `compute.zones`, …), none of which is
// an authzmap object type. They are seeded by migration, are read-only through the
// API (Create forces is_system=false; Update rejects a system role sync), and their
// access is carried by permissions[]/tier tuples — so the catalog gate is scoped to
// custom roles. This pins that scoping so a future change cannot brick the seed.
func TestRuleCatalogGate_SystemContextExempt(t *testing.T) {
	seeded := domain.Rules{
		{Module: "iam", Resources: []string{"service_account"}, Verbs: []string{"get"}},
		{Module: "loadbalancer", Resources: []string{"operations"}, Verbs: []string{"get"}},
		{Module: "vpc", Resources: []string{"subnetses"}, Verbs: []string{"list"}},
	}
	assert.NoError(t, validateRuleCatalog(seeded, true),
		"a seeded system role's permission-derived tokens must not be rejected")
	assert.Error(t, validateRuleCatalog(seeded, false),
		"the same tokens authored into a CUSTOM role must be rejected")
}
