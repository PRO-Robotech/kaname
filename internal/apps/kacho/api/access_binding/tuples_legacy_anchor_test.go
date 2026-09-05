// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// tuples_legacy_anchor_test.go — the legacy (permissions-only) projection must
// not SYNTHESIZE the third tier of super-access.
//
// `account:<A>#admin` is level 3, the account administrator. Since the cascade
// landed it is a real cascade source: the model derives
// `project.super_admin: admin from account`, and every leaf type reads
// `super_admin from project`. One tuple is every resource in the account.
//
// The legacy projection picks its tier from the VERB alone, ignoring which module
// and resource the permission names, so `vpc.network.*.*` — a verb-position
// wildcard — read as the admin tier and landed on whatever anchor the binding
// named. Before the cascade that tuple reached the account object and stopped.
// Afterwards it reaches everything beneath it, which is why the cap is part of
// the cascade rather than a separate cleanup.
//
// What is deliberately NOT changed: the anchor tier itself. A legacy role over
// `iam.accessBinding` bound at a project or account still projects its tier onto
// that anchor — that is the established legacy semantics, pinned by the E-30 and
// orphan-symmetry tests, and `project:<P>#admin` is not a cascade source (the
// project's own admin is excluded by design). Only the account rung is capped,
// and only downwards.
//
// Reachability, measured rather than assumed: RoleService.Create requires a
// non-empty rules[], and every seeded row carries rules (0 of 121 rows read back
// rules='[]' on a freshly migrated database). So this path is latent, not live —
// and the structural gates keep it accepted for an allInScope target
// (f9_perms_only_target_integration_test.go), which is why it is corrected rather
// than removed.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	abrepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
)

// legacyRole — a permissions-only role (no rules[]), the only shape that reaches
// the projection under test. Permissions use the 4-segment form the seeds store:
// module.resource.<group>.<verb>, e.g. "vpc.network.*.*".
func legacyRole(permissions ...string) domain.Role {
	perms := make(domain.Permissions, len(permissions))
	for i, p := range permissions {
		perms[i] = domain.Permission(p)
	}
	return domain.Role{ID: "rol_legacy_test000001", Permissions: perms}
}

func bindingOn(resourceType domain.ResourceType, resourceID string) domain.AccessBinding {
	return domain.AccessBinding{
		ID:           "abc_legacy_test00001",
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    "usr_legacy_test00001",
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}
}

// tierTuples — the tuples that carry ACCESS, i.e. everything except the
// binding-lifecycle hierarchy parent-pointer (whose User is the anchor itself and
// whose Object is the binding). Isolating them keeps the assertions about access
// rather than about bookkeeping.
func tierTuples(t *testing.T, got []abrepo.RelationTuple, anchor string) []abrepo.RelationTuple {
	t.Helper()
	var out []abrepo.RelationTuple
	for _, tp := range got {
		if tp.User == anchor {
			continue
		}
		out = append(out, tp)
	}
	return out
}

// The amplification: a role that only ever named vpc networks must not become the
// account administrator. Before the cap the verb-position wildcard classified the
// whole role as admin and put that tuple on the account anchor, which the cascade
// turns into every project and every resource beneath it.
func TestBuildBindingTuples_LegacyNarrowRole_DoesNotSynthesizeAccountAdmin(t *testing.T) {
	b := bindingOn("account", "acc_legacy_test00001")
	got, err := buildBindingTuples(b, legacyRole("vpc.network.*.*"))
	require.NoError(t, err)

	access := tierTuples(t, got, "account:acc_legacy_test00001")
	require.Len(t, access, 1, "exactly one tier tuple on the anchor")
	assert.Equal(t, "editor", access[0].Relation,
		"a role naming only vpc networks may not become the account administrator; "+
			"account:<A>#admin cascades to every project and every resource beneath it")
	assert.Equal(t, "account:acc_legacy_test00001", access[0].Object)
}

// The positive control that keeps the cap honest: a role that DOES cover the
// account keeps level 3, because then the delegation is authored rather than
// synthesized. Without this pair the assertion above would also pass if admin
// were simply never emitted on an account.
func TestBuildBindingTuples_LegacyAccountRole_KeepsAuthoredAccountAdmin(t *testing.T) {
	b := bindingOn("account", "acc_legacy_test00002")
	got, err := buildBindingTuples(b, legacyRole("iam.account.*.*"))
	require.NoError(t, err)

	assert.Contains(t, got, abrepo.RelationTuple{
		User:     "user:usr_legacy_test00001",
		Relation: "admin",
		Object:   "account:acc_legacy_test00002",
	}, "a role over iam.account names the account, so level 3 is authored and kept")
}

// A global wildcard names everything, the account included.
func TestBuildBindingTuples_LegacyGlobalWildcard_KeepsAccountAdmin(t *testing.T) {
	b := bindingOn("account", "acc_legacy_test00003")
	got, err := buildBindingTuples(b, legacyRole("*.*.*.*"))
	require.NoError(t, err)

	assert.Contains(t, got, abrepo.RelationTuple{
		User:     "user:usr_legacy_test00001",
		Relation: "admin",
		Object:   "account:acc_legacy_test00003",
	}, "*.*.*.* covers every type, the account among them")
}

// Partial wildcards are expanded by the closed table, never by a substring guess:
// `iam.*` reaches the account because "iam.account" is in the table, and
// `*.account` because some module pairs with that resource.
func TestBuildBindingTuples_LegacyPartialWildcards_KeepAccountAdmin(t *testing.T) {
	for _, perm := range []string{"iam.*.*.*", "*.account.*.*"} {
		b := bindingOn("account", "acc_legacy_test00004")
		got, err := buildBindingTuples(b, legacyRole(perm))
		require.NoError(t, err)

		assert.Contains(t, got, abrepo.RelationTuple{
			User:     "user:usr_legacy_test00001",
			Relation: "admin",
			Object:   "account:acc_legacy_test00004",
		}, "%s expands over the closed table onto iam.account", perm)
	}
}

// The cap is the account rung only. A project anchor is untouched, because the
// project's own admin is not a cascade source — project scope and below stay
// flat, and narrowing here would rewrite established legacy semantics instead of
// closing an amplification.
func TestBuildBindingTuples_LegacyNarrowRole_ProjectAnchorUnchanged(t *testing.T) {
	b := bindingOn("project", "prj_legacy_test00001")
	got, err := buildBindingTuples(b, legacyRole("iam.access_bindings.admin"))
	require.NoError(t, err)

	assert.Contains(t, got, abrepo.RelationTuple{
		User:     "user:usr_legacy_test00001",
		Relation: "admin",
		Object:   "project:prj_legacy_test00001",
	}, "project:<P>#admin derives nothing, so the legacy anchor tier stays as it was")
}

// A leaf anchor is untouched for the same reason.
func TestBuildBindingTuples_LegacyNarrowRole_LeafAnchorUnchanged(t *testing.T) {
	b := bindingOn("vpc_network", "net_legacy_test00001")
	got, err := buildBindingTuples(b, legacyRole("vpc.network.*.*"))
	require.NoError(t, err)

	assert.Contains(t, got, abrepo.RelationTuple{
		User:     "user:usr_legacy_test00001",
		Relation: "admin",
		Object:   "vpc_network:net_legacy_test00001",
	}, "a leaf anchor is not a cascade source")
}

// A MIXED role is the route the first version of this cap left open: one
// permission names the account with a read verb, another carries an admin verb
// and never mentions the account. Testing only that SOME permission covers the
// anchor would let the second one set the tier — the same synthesis, one
// indirection further out.
func TestBuildBindingTuples_LegacyMixedRole_TierComesFromTheCoveringHalf(t *testing.T) {
	b := bindingOn("account", "acc_legacy_test00007")
	got, err := buildBindingTuples(b, legacyRole("iam.account.*.get", "vpc.network.*.*"))
	require.NoError(t, err)

	access := tierTuples(t, got, "account:acc_legacy_test00007")
	require.Len(t, access, 1, "exactly one tier tuple on the anchor")
	assert.Equal(t, "viewer", access[0].Relation,
		"the permission that NAMES the account carries a read verb; the admin verb "+
			"belongs to one that never mentions it and must not reach this anchor")
}

// The mirror image: the covering half is the strong one, so it keeps its rung
// even though the role also carries a weaker permission elsewhere.
func TestBuildBindingTuples_LegacyMixedRole_CoveringHalfStrong_KeepsAdmin(t *testing.T) {
	b := bindingOn("account", "acc_legacy_test00008")
	got, err := buildBindingTuples(b, legacyRole("iam.account.*.*", "vpc.network.*.get"))
	require.NoError(t, err)

	assert.Contains(t, got, abrepo.RelationTuple{
		User:     "user:usr_legacy_test00001",
		Relation: "admin",
		Object:   "account:acc_legacy_test00008",
	}, "the covering permission authors the delegation, so its rung stands")
}

// The cap moves one rung down the declared ladder, it does not erase the grant.
// A read-only role on an account it does not name keeps viewer — capping admin is
// a reduction, not a rewrite of every tier.
func TestBuildBindingTuples_LegacyReadOnlyRole_AccountTierUnaffected(t *testing.T) {
	b := bindingOn("account", "acc_legacy_test00005")
	got, err := buildBindingTuples(b, legacyRole("vpc.network.*.get"))
	require.NoError(t, err)

	access := tierTuples(t, got, "account:acc_legacy_test00005")
	require.Len(t, access, 1)
	assert.Equal(t, "viewer", access[0].Relation,
		"only the admin rung is capped; the rest of the ladder is untouched")
}
