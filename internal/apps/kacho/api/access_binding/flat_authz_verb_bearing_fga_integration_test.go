// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// flat_authz_verb_bearing_fga_integration_test.go — REAL OpenFGA proof of the
// Design-B verb-bearing enforcement invariants (acceptance VBC-01/02/04/06/10/
// 11/12). Loads the canonical fga_model.fga (kacho-proto sibling) into a real
// openfga/openfga server and evaluates Check / ListObjects against it.
//
// The CORE invariant (D-6a, anti-Design-A): on the flat explicit model the
// per-verb v_* relations are DECOUPLED from the tier relations
// (viewer/editor/admin). A v_list grant makes the object selector-visible but
// gives NO content access (v_get) and does NOT resolve `viewer`. Design A
// (viewer ⊇ v_get/v_list union) COLLAPSED this separation; these tests are RED
// against any model that unions v_* into a tier and GREEN against the decoupled
// Design-B model. They are the permanent model-shape regression guard.
//
// Skipped under -short (needs Docker / colima).

import (
	"testing"

	"github.com/stretchr/testify/require"

	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// TestFGAModel_VBC01_VGetSatisfies_VListNoGet_NoViewerUnion — VBC-01: a v_get
// grant satisfies Check(v_get); a v_list-only grant does NOT satisfy Check(v_get)
// (verb-precision) and does NOT resolve `viewer` (D-6a decoupling, anti-#241).
func TestFGAModel_VBC01_VGetSatisfies_VListNoGet_NoViewerUnion(t *testing.T) {
	c := startOpenFGA(t)

	const (
		uObj = "usr_vbc01_obj"
		rObj = "rol_vbc01_obj"
		u1   = "usr_vbc01_u1"
		u2   = "usr_vbc01_u2"
	)
	c.write(t, []abrepo.RelationTuple{
		// U1 holds v_get on an iam_user object (grant verbs:["get"]).
		{User: "user:" + u1, Relation: "v_get", Object: "iam_user:" + uObj},
		// U2 holds v_list ONLY on an iam_role object (grant verbs:["list"], no get).
		{User: "user:" + u2, Relation: "v_list", Object: "iam_role:" + rObj},
	})

	// VBC-01 (a): v_get grant satisfies Check(v_get) — catalog iam.users.get → v_get.
	require.True(t, c.check(t, "user:"+u1, "v_get", "iam_user:"+uObj),
		"VBC-01: v_get grant satisfies Check(v_get) (catalog gates v_get, F-1)")

	// VBC-01 (b): v_list-only grant does NOT satisfy Check(v_get) — verb-precision.
	require.False(t, c.check(t, "user:"+u2, "v_get", "iam_role:"+rObj),
		"VBC-01: v_list grant does NOT satisfy v_get (verb-precision, no union)")

	// VBC-01 (c): v_list grant satisfies Check(v_list).
	require.True(t, c.check(t, "user:"+u2, "v_list", "iam_role:"+rObj),
		"VBC-01: v_list grant satisfies Check(v_list)")

	// VBC-01 (d) — ANTI-#241 control: v_list grant does NOT resolve `viewer`
	// (D-6a decoupling). On the Design-A union model (viewer ⊇ v_list) this would
	// be true; on Design-B it MUST be false.
	require.False(t, c.check(t, "user:"+u2, "viewer", "iam_role:"+rObj),
		"VBC-01: v_list grant does NOT resolve `viewer` (D-6a decoupling, anti-Design-A)")
}

// TestFGAModel_VBC02_OwnerVGetAllLeafTypes — VBC-02: an owner-materialized
// per-object v_get tuple satisfies Check(v_get) on every leaf verb-bearing type.
// The catalog gates `<domain>.<res>.get` on v_get (F-1), so owner content access
// resolves via the materialized v_get tuple, INDEPENDENT of any tier-tuple.
func TestFGAModel_VBC02_OwnerVGetAllLeafTypes(t *testing.T) {
	c := startOpenFGA(t)

	const uc = "usr_vbc02_owner"
	// Representative object per leaf verb-bearing domain (acceptance VBC-02 table).
	objects := []string{
		"iam_user:usr_vbc02_x",
		"iam_role:rol_vbc02_x",
		"iam_group:grp_vbc02_x",
		"iam_service_account:sva_vbc02_x",
		"iam_access_binding:acb_vbc02_x",
		"vpc_route_table:rtb_vbc02_x",
		"vpc_network_interface:nic_vbc02_x",
		"vpc_gateway:gtw_vbc02_x",
		"compute_instance:inst_vbc02_x",
		"nlb_network_load_balancer:lbn_vbc02_x",
	}
	tuples := make([]abrepo.RelationTuple, 0, len(objects))
	for _, o := range objects {
		tuples = append(tuples, abrepo.RelationTuple{User: "user:" + uc, Relation: "v_get", Object: o})
	}
	c.write(t, tuples)

	for _, o := range objects {
		require.True(t, c.check(t, "user:"+uc, "v_get", o),
			"VBC-02: owner materialized v_get → Check(v_get) ALLOW on %s (catalog gates v_get, not tier)", o)
	}
}

// TestFGAModel_VBC04_UpdateDeleteVerbPrecision — VBC-04: v_update and v_delete
// are enforced separately. A v_update grant does NOT satisfy v_delete and vice
// versa (catalog vpc.networks.update→v_update, …delete→v_delete, F-1).
func TestFGAModel_VBC04_UpdateDeleteVerbPrecision(t *testing.T) {
	c := startOpenFGA(t)

	const (
		net = "vpcn_vbc04"
		u2  = "usr_vbc04_u2"
		u3  = "usr_vbc04_u3"
	)
	c.write(t, []abrepo.RelationTuple{
		{User: "user:" + u2, Relation: "v_update", Object: "vpc_network:" + net},
		{User: "user:" + u3, Relation: "v_delete", Object: "vpc_network:" + net},
	})

	require.True(t, c.check(t, "user:"+u2, "v_update", "vpc_network:"+net), "VBC-04: U2 v_update ALLOW")
	require.False(t, c.check(t, "user:"+u2, "v_delete", "vpc_network:"+net), "VBC-04: U2 v_delete DENY (verb-precision)")
	require.True(t, c.check(t, "user:"+u3, "v_delete", "vpc_network:"+net), "VBC-04: U3 v_delete ALLOW")
	require.False(t, c.check(t, "user:"+u3, "v_update", "vpc_network:"+net), "VBC-04: U3 v_update DENY (verb-precision)")
}

// TestFGAModel_VBC06_VListSelectorNoContent_NoViewerUnion — VBC-06 (CRITICAL,
// D-6a): a v_list-only grant on a vpc_network makes it selector-visible
// (ListObjects v_list) but Check(v_get) DENIES (content private) and
// Check(viewer) DENIES (no union). This is the invariant Design A broke.
func TestFGAModel_VBC06_VListSelectorNoContent_NoViewerUnion(t *testing.T) {
	c := startOpenFGA(t)

	const (
		net = "vpcn_vbc06"
		u1  = "usr_vbc06_u1"
	)
	c.write(t, []abrepo.RelationTuple{
		{User: "user:" + u1, Relation: "v_list", Object: "vpc_network:" + net},
	})

	// (a) selector-visible via v_list.
	require.Contains(t, c.listObjects(t, "user:"+u1, "v_list", "vpc_network"), net,
		"VBC-06(a): v_list-only grant makes the network selector-visible (ListObjects v_list, F-4)")

	// (b) content DENY — no v_get.
	require.False(t, c.check(t, "user:"+u1, "v_get", "vpc_network:"+net),
		"VBC-06(b): Check(v_get) DENIES — content not accessible without v_get (D-6a)")

	// (c) tier DENY — viewer does NOT union v_list (anti-Design-A).
	require.False(t, c.check(t, "user:"+u1, "viewer", "vpc_network:"+net),
		"VBC-06(c): Check(viewer) DENIES — viewer does NOT union v_list (F-2 decoupling). "+
			"On Design A (viewer ⊇ v_list) this would be true and content would leak via viewer.")
}

// TestFGAModel_VBC10_VGetNoEscalation — VBC-10: a v_get-only grant does NOT
// escalate to v_create/v_update/v_delete or editor/admin (no union, F-2).
func TestFGAModel_VBC10_VGetNoEscalation(t *testing.T) {
	c := startOpenFGA(t)

	const (
		r  = "rol_vbc10"
		u1 = "usr_vbc10_u1"
	)
	c.write(t, []abrepo.RelationTuple{
		{User: "user:" + u1, Relation: "v_get", Object: "iam_role:" + r},
	})

	require.True(t, c.check(t, "user:"+u1, "v_get", "iam_role:"+r), "VBC-10: v_get available")
	for _, rel := range []string{"v_create", "v_update", "v_delete", "editor", "admin"} {
		require.False(t, c.check(t, "user:"+u1, rel, "iam_role:"+r),
			"VBC-10: v_get grant must NOT escalate to %q (no-escalation, no union)", rel)
	}
}

// TestFGAModel_VBC11_NoCrossObject — VBC-11: a v_get grant on object X gives no
// access to object Y (per-object, no cross-object cascade, D-2).
func TestFGAModel_VBC11_NoCrossObject(t *testing.T) {
	c := startOpenFGA(t)

	const (
		x  = "usr_vbc11_x"
		y  = "usr_vbc11_y"
		u1 = "usr_vbc11_u1"
	)
	c.write(t, []abrepo.RelationTuple{
		{User: "user:" + u1, Relation: "v_get", Object: "iam_user:" + x},
	})

	require.True(t, c.check(t, "user:"+u1, "v_get", "iam_user:"+x), "VBC-11: access to granted object X")
	require.False(t, c.check(t, "user:"+u1, "v_get", "iam_user:"+y),
		"VBC-11: v_get on X gives NO v_get on Y (no cross-object, D-2)")
	require.False(t, c.check(t, "user:"+u1, "v_list", "iam_user:"+y),
		"VBC-11: v_get on X gives NO v_list on Y")
}

// TestFGAModel_VBC12_ForeignAccountDenied — VBC-12: a user with no tuple on an
// object inside a foreign account, who is not a cluster-admin, is denied (no
// implicit cross-account access, D-2).
func TestFGAModel_VBC12_ForeignAccountDenied(t *testing.T) {
	c := startOpenFGA(t)

	const (
		accA  = "acc_vbc12_A"
		userA = "usr_vbc12_inA"
		uf    = "usr_vbc12_foreign"
	)
	// Topology: account A → iam_user inside it. The foreign user holds NO tuple.
	c.write(t, []abrepo.RelationTuple{
		{User: "account:" + accA, Relation: "account", Object: "iam_user:" + userA},
	})

	require.False(t, c.check(t, "user:"+uf, "v_get", "iam_user:"+userA),
		"VBC-12: foreign user (no tuple, not cluster-admin) → Check(v_get) DENIES (D-2)")
	require.False(t, c.check(t, "user:"+uf, "viewer", "iam_user:"+userA),
		"VBC-12: foreign user → Check(viewer) DENIES")
}
