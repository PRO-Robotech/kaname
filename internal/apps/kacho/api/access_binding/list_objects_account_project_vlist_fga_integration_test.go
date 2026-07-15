// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list_objects_account_project_vlist_fga_integration_test.go — rbac-2026 P7
// (acceptance rbac-B-01 / rbac-B-02). REAL OpenFGA proof of the flat-model
// "see account/project in the selector WITHOUT access to its contents" mechanic
// that AccountService.List / ProjectService.List rely on (the viewer ∪ v_list
// union at the use-case layer).
//
// On the flat explicit model (P2/P3), account/project are verb-bearing (D-6):
// they carry the closed v_* relation set with NO `from account`/`from project`
// access-cascade. A grant of `iam.account.{get,list}` with a names/labels
// selector materializes ONLY an OBJECT-ONLY tuple
//
//	account:<A> # v_list @ user:U
//	account:<A> # v_get  @ user:U
//
// and crucially NO tuple on the account's contents and NO `viewer` tuple. So:
//   - ListObjects(U, "v_list", "account") INCLUDES A  → A shows up in the selector.
//   - ListObjects(U, "viewer",  "account") EXCLUDES A → no cascade-into-contents.
//   - Check(U, v_get, vpc_network inside A) DENIES     → contents stay private.
//
// This is exactly why the P7 List filter must union viewer ∪ v_list: the
// viewer-only pre-P7 filter hid an object-only v_list grant. These tests pin the
// model-side guarantee end-to-end against a real OpenFGA loaded with the
// canonical fga_model.fga. Skipped under -short (needs Docker / colima).

import (
	"testing"

	"github.com/stretchr/testify/require"

	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// TestIntegration_ListObjects_Account_VListOnly_SeeWithoutContents_P7 — an
// object-only v_list grant on an account resolves v_list (selector-visible) but
// NEITHER viewer NOR any relation on the account's contents (no cascade, D-2).
func TestIntegration_ListObjects_Account_VListOnly_SeeWithoutContents_P7(t *testing.T) {
	c := startOpenFGA(t)

	const (
		acc = "acc_p7_A"
		net = "net_p7_inside_A"
		u   = "usr_p7_u1"
	)
	// Topology: account A → project → network (contents), and the OBJECT-ONLY
	// v_list/v_get grant on the account itself (what a names/labels grant of
	// iam.account.{get,list} materializes on the flat model — no contents tuple,
	// no viewer tuple).
	c.write(t, []abrepo.RelationTuple{
		{User: "account:" + acc, Relation: "account", Object: "project:prj_p7_A"},
		{User: "project:prj_p7_A", Relation: "project", Object: "vpc_network:" + net},
		// object-only grant on the account:
		{User: "user:" + u, Relation: "v_list", Object: "account:" + acc},
		{User: "user:" + u, Relation: "v_get", Object: "account:" + acc},
	})

	// v_list resolves the account → it appears in the selector.
	require.Contains(t, c.listObjects(t, "user:"+u, "v_list", "account"), acc,
		"P7/B-01: object-only v_list grant makes the account selector-visible (ListObjects v_list)")
	require.True(t, c.check(t, "user:"+u, "v_list", "account:"+acc),
		"P7/B-01: Check(v_list, account) allows (the granted relation)")

	// viewer does NOT resolve (no cascade tuple, account is verb-bearing flat).
	require.NotContains(t, c.listObjects(t, "user:"+u, "viewer", "account"), acc,
		"P7/B-01: v_list grant does NOT imply viewer on the account (flat model, no cascade) — "+
			"this is why the List filter must union viewer ∪ v_list")

	// Contents stay private: no access to the network inside A.
	require.False(t, c.check(t, "user:"+u, "v_get", "vpc_network:"+net),
		"P7/B-01: Check on the account's CONTENTS DENIES (see-in-selector-without-contents, D-2)")
	require.False(t, c.check(t, "user:"+u, "viewer", "vpc_network:"+net),
		"P7/B-01: no viewer cascade into contents either")
}

// TestIntegration_ListObjects_Project_VListOnly_SeeWithoutContents_P7 — same
// mechanic for project (rbac-B-02): object-only v_list grant on a project →
// selector-visible, contents private.
func TestIntegration_ListObjects_Project_VListOnly_SeeWithoutContents_P7(t *testing.T) {
	c := startOpenFGA(t)

	const (
		prj  = "prj_p7_P"
		inst = "inst_p7_inside_P"
		u    = "usr_p7_u2"
	)
	c.write(t, []abrepo.RelationTuple{
		{User: "project:" + prj, Relation: "project", Object: "compute_instance:" + inst},
		// object-only grant on the project itself:
		{User: "user:" + u, Relation: "v_list", Object: "project:" + prj},
		{User: "user:" + u, Relation: "v_get", Object: "project:" + prj},
	})

	require.Contains(t, c.listObjects(t, "user:"+u, "v_list", "project"), prj,
		"P7/B-02: object-only v_list grant makes the project selector-visible")
	require.True(t, c.check(t, "user:"+u, "v_get", "project:"+prj),
		"P7/B-02: Check(v_get, project) allows the project object itself")

	require.NotContains(t, c.listObjects(t, "user:"+u, "viewer", "project"), prj,
		"P7/B-02: v_list grant does NOT imply viewer on the project (flat model)")

	require.False(t, c.check(t, "user:"+u, "v_get", "compute_instance:"+inst),
		"P7/B-02: Check on a resource INSIDE the project DENIES (contents private, D-2)")
}

// TestIntegration_ListObjects_Account_Foreign_NoLeak_P7 — no-leak: a subject
// with a v_list grant on account A resolves NEITHER v_list NOR viewer on a
// foreign account B.
func TestIntegration_ListObjects_Account_Foreign_NoLeak_P7(t *testing.T) {
	c := startOpenFGA(t)

	const (
		accA = "acc_p7_A"
		accB = "acc_p7_B_foreign"
		u    = "usr_p7_u3"
	)
	c.write(t, []abrepo.RelationTuple{
		{User: "user:" + u, Relation: "v_list", Object: "account:" + accA},
	})

	got := c.listObjects(t, "user:"+u, "v_list", "account")
	require.Contains(t, got, accA, "P7 no-leak: subject sees own granted account A")
	require.NotContains(t, got, accB,
		"P7 no-leak: a v_list grant on A does NOT surface foreign account B in the selector")
	require.False(t, c.check(t, "user:"+u, "v_list", "account:"+accB),
		"P7 no-leak: Check(v_list, foreign account) DENIES")
	require.False(t, c.check(t, "user:"+u, "viewer", "account:"+accB),
		"P7 no-leak: Check(viewer, foreign account) DENIES")
}
