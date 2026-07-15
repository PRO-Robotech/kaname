// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list_objects_role_owner_fga_integration_test.go — role-owner visibility on the
// flat OpenFGA model. REAL OpenFGA proof that under the flat model a
// custom role's owner/creator resolves both the `viewer` tier AND the `v_list` verb
// on the role they own via the PER-OBJECT materialized owner tuples — so the
// per-object filtered RoleService.List/Get read-surface shows the
// owner their own role and no one else's.
//
// Flat-model reality (fga_model.fga in kacho-proto):
//
//	type iam_role
//	  define account: [account]                              // hierarchy/lineage only
//	  define admin:  [user, service_account, group#member]   // NO `from account`
//	  define editor: admin
//	  define viewer: editor
//	  define v_get/v_list/v_create/v_update/v_delete: [user, service_account, group#member]
//
// The `<rel> from account` ACCESS cascade that the earlier fix relied on was
// REMOVED. The hierarchy pointer
// `account:<acc>#account@iam_role:<id>` is now lineage-only and grants nobody
// anything. The owner's access is instead MATERIALIZED per-object by the reconciler:
// the owner `*.*` ARM_ANCHOR binding forward-materializes, on each role
// inside the account, the back-compat tier tuple (`admin`, since `*` verbs → admin
// tier; admin→editor→viewer) PLUS the closed per-verb v_* tuples — exactly the tuple
// set the forward-mat path (role/create.go EmitReconcileEvent → ReconcileObject
// → applyDiff) emits. See repo/kacho/pg/reconcile_owner_iam_content_integration_test.go
// for the materialization engine; THIS test pins the resulting FGA RESOLUTION shape.
//
// These tests load the REAL canonical (flat) model into a REAL OpenFGA, write ONLY
// the per-object tuples the reconciler materializes for the owner, and assert the
// flat resolution:
//   - owner's `viewer` ListObjects/Check INCLUDES the own role (tier admin→editor→viewer
//     over the materialized per-object `admin` tuple — flat, NOT a cascade).
//   - owner's `v_list` ListObjects/Check INCLUDES the own role (direct per-object v_list).
//   - a FOREIGN owner (materialized on nothing) has NEITHER viewer NOR v_list on the
//     role (no-leak preserved — the wildcard never became cluster-wide).
//   - read==enforce parity: ListObjects(viewer) == Check(viewer) over the owner's set.
//
// Reuses the flat real-FGA harness (startOpenFGA / fgaClient / write / listObjects /
// check). Skipped under -short (needs Docker / colima).

import (
	"testing"

	"github.com/stretchr/testify/require"

	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// ownRoleMaterializedTuples returns the EXACT per-object tuple set the reconciler
// materializes on a role for the account owner under the FLAT model:
// the back-compat tier `admin` (owner `*.*` → all verbs → admin tier;
// admin→editor→viewer) PLUS the closed per-verb v_* relations (iam_role is
// verb-bearing, authzmap.TypeHasVerbRelations). This is the exact output of
// access_binding/reconcile.ruleObjectTuples for subject=owner, verbs=["*"] on
// iam_role:<id> — the single materialization path that replaces the removed
// `<rel> from account` cascade.
//
// The inert hierarchy pointer (`account:<acc>#account@iam_role:<id>`) is
// DELIBERATELY omitted: it grants nothing under the flat model, so including it
// would not change any assertion (and asserting it grants access would re-encode
// the removed cascade).
func ownRoleMaterializedTuples(roleID, ownerUser string) []abrepo.RelationTuple {
	obj := "iam_role:" + roleID
	user := "user:" + ownerUser
	return []abrepo.RelationTuple{
		{User: user, Relation: "admin", Object: obj}, // tier admin→editor→viewer
		{User: user, Relation: "v_get", Object: obj},
		{User: user, Relation: "v_list", Object: obj},
		{User: user, Relation: "v_create", Object: obj},
		{User: user, Relation: "v_update", Object: obj},
		{User: user, Relation: "v_delete", Object: obj},
	}
}

// TestIntegration_ListObjects_Role_OwnerViewerCascade_193 — role-owner visibility under the flat
// model. The account owner who created a custom role in their account resolves BOTH
// `viewer` (via the materialized per-object `admin` tier tuple, admin→editor→viewer)
// AND `v_list` (direct per-object v_list tuple) on that role, so the role appears in
// ListObjects(subject,<rel>,"iam_role") and Check allows under EITHER relation. This
// is the flat replacement for the original cascade-based fix: per-object
// materialization makes the owner see their own role; no `from account` derivation
// is involved.
//
// (Name kept for traceability; the resolution path is now per-object, not a cascade.)
func TestIntegration_ListObjects_Role_OwnerViewerCascade_193(t *testing.T) {
	c := startOpenFGA(t)

	const (
		role  = "rol_owner_193"
		owner = "usr_admin_A"
	)
	// The reconciler has materialized the owner's per-object tuples on the role
	// (forward-mat C-01b). NO account-tier / hierarchy tuple is needed for access.
	c.write(t, ownRoleMaterializedTuples(role, owner))

	// ── `viewer` (the role read-surface filter relation) resolves the own role via
	// the materialized `admin` tier tuple (admin→editor→viewer) — FLAT, per-object.
	viewerList := c.listObjects(t, "user:"+owner, "viewer", "iam_role")
	require.Contains(t, viewerList, role,
		"#193 (flat): the owner resolves `viewer` on their own role via the materialized "+
			"per-object `admin` tier tuple (admin→editor→viewer) — per-object, not a `from account` cascade")
	require.True(t, c.check(t, "user:"+owner, "viewer", "iam_role:"+role),
		"#193 (flat): Check(viewer, own role) allows for the owner (read==enforce by viewer)")

	// ── `v_list` (the per-verb relation) ALSO resolves the own role now: under the
	// flat model the owner's v_list is materialized as a DIRECT per-object tuple by
	// the reconciler (no `from account` bridge exists anymore, but none is needed).
	vlist := c.listObjects(t, "user:"+owner, "v_list", "iam_role")
	require.Contains(t, vlist, role,
		"#193 (flat): the owner resolves `v_list` on their own role via the DIRECT materialized "+
			"per-object v_list tuple — the removed cascade is replaced by per-object materialization")
	require.True(t, c.check(t, "user:"+owner, "v_list", "iam_role:"+role),
		"#193 (flat): Check(v_list, own role) allows for the owner (direct per-object verb tuple)")
}

// TestIntegration_ListObjects_Role_ForeignAdmin_NoLeak_193 — the no-leak side of the
// flat model. A FOREIGN owner (materialized on nothing in account A) resolves NEITHER
// `viewer` NOR `v_list` on the role, so per-object materialization does NOT widen
// visibility across accounts (Get→404, absent from List). The owner `*.*` wildcard is
// scope-bounded by the reconciler (containment), never cluster-wide.
func TestIntegration_ListObjects_Role_ForeignAdmin_NoLeak_193(t *testing.T) {
	c := startOpenFGA(t)

	const (
		role  = "rol_owner_193"
		admnB = "usr_admin_B"
	)
	// Role A is materialized for owner A only. The foreign owner B is materialized on
	// its OWN account's content (here: nothing relevant) — never on role A.
	c.write(t, ownRoleMaterializedTuples(role, "usr_admin_A"))

	// Foreign owner resolves role A under NEITHER relation → no-leak preserved.
	require.NotContains(t, c.listObjects(t, "user:"+admnB, "viewer", "iam_role"), role,
		"#193 no-leak (flat): a foreign owner must NOT resolve `viewer` on account A's role (no per-object tuple)")
	require.False(t, c.check(t, "user:"+admnB, "viewer", "iam_role:"+role),
		"#193 no-leak (flat): Check(viewer, foreign role) DENIES for the foreign owner (Get→404 preserved)")
	require.False(t, c.check(t, "user:"+admnB, "v_list", "iam_role:"+role),
		"#193 no-leak (flat): foreign owner resolves no v_list either (no materialized per-object tuple)")
}

// TestIntegration_ListObjects_Role_ViewerReadEnforce_193 — read==enforce parity under
// the flat model. For the owner, the set of roles in ListObjects(viewer) is exactly
// the set Check(viewer) allows (List-visibility == Get-success when both filter by
// `viewer`). A second, unrelated role in a foreign account (materialized for a
// different owner) is in neither set.
func TestIntegration_ListObjects_Role_ViewerReadEnforce_193(t *testing.T) {
	c := startOpenFGA(t)

	const (
		role1 = "rol_own_1_193"
		role2 = "rol_own_2_193"
		other = "rol_foreign_193"
		owner = "usr_admin_A"
	)
	// Two own roles materialized for owner A + a foreign role materialized for a
	// DIFFERENT owner (so it must be absent from owner A's resolved set).
	c.write(t, ownRoleMaterializedTuples(role1, owner))
	c.write(t, ownRoleMaterializedTuples(role2, owner))
	c.write(t, ownRoleMaterializedTuples(other, "usr_admin_Z"))

	viewerSet := map[string]bool{}
	for _, id := range c.listObjects(t, "user:"+owner, "viewer", "iam_role") {
		viewerSet[id] = true
	}
	// read==enforce: every id in the List set is Check-allowed; the foreign role is
	// in neither set.
	for _, id := range []string{role1, role2} {
		require.True(t, viewerSet[id], "#193 (flat): own role %s present in ListObjects(viewer)", id)
		require.True(t, c.check(t, "user:"+owner, "viewer", "iam_role:"+id),
			"#193 read==enforce (flat): Check(viewer,%s) must agree with ListObjects(viewer)", id)
	}
	require.False(t, viewerSet[other], "#193 (flat): foreign-account role absent from owner's viewer List")
	require.False(t, c.check(t, "user:"+owner, "viewer", "iam_role:"+other),
		"#193 read==enforce (flat): Check(viewer) denies the foreign-account role (parity with List)")
}
