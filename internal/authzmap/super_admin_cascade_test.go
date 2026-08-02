// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzmap_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// super_admin_cascade_test.go — behavioural lock for the owner directive
// "Три уровня супер-доступа — КАСКАДОМ, ниже — плоско по выдаче"
// (.claude/rules/security.md).
//
// The model is a FLAT INDEX: access is materialized per-object by the iam
// reconciler. That stays true for TENANT roles. It is deliberately NOT true for
// the three top levels, because materializing them breaks the exact scenario they
// exist for: with a lagging or broken drainer the person who has to fix
// everything is himself locked out. Those three resolve at request time:
//
//	1. cloud administrator  — cluster:cluster_kacho_root#system_admin, cascades onto everything;
//	2. bootstrap identity   — the same relation (migration 0058 / bootstrap reconciler
//	                          seed it on cluster:cluster_kacho_root), so it is covered
//	                          by the same disjunct — no separate carrier;
//	3. account administrator — account:<id>#admin, cascades WITHIN its own account only.
//
// The incident this locks (2026-07-26): every verb on iam_access_binding was a
// direct userset with no `or`, so a cluster administrator could see every grant
// but revoke only his own — 652 denials against 32 allows in one run. Practically:
// an employee grants a colleague access and leaves → the administrator cannot
// revoke, and the only way out is editing the database by hand.
//
// The checks below run against the DEPLOYED artifact — the openfga-bootstrap
// ConfigMap `model.json` block, which is what the bootstrap Job actually POSTs to
// OpenFGA — loaded into a real OpenFGA container. Reading the DSL would only
// prove the shape of the source file; this proves the thing that is enforced.
//
// Nothing here writes a v_*/tier tuple on the target object: every allow below
// must come from the cascade alone, and every deny must survive the cascade.

const (
	saCluster   = "cluster:cluster_kacho_root"
	saAccountA  = "account:acc-sacascadea"
	saAccountB  = "account:acc-sacascadeb"
	saProjectA  = "project:prj-sacascadea"
	saProjectB  = "project:prj-sacascadeb"
	saBindingA  = "iam_access_binding:abn-sacascadea"
	saBindingB  = "iam_access_binding:abn-sacascadeb"
	saNetworkA  = "vpc_network:net-sacascadea"
	saVolumeA   = "storage_volume:vol-sacascadea"
	saUserA     = "iam_user:usr-sacascadea"
	saGroupA    = "iam_group:grp-sacascadea"
	saRegistryA = "registry_registry:reg-sacascadea"
	saRepoA     = "registry_repository:reg-sacascadea/app"
	saLbA       = "nlb_network_load_balancer:nlb-sacascadea"

	subjCloudAdmin  = "user:usr-sacloudadmin" // level 1 — cluster#system_admin
	subjBootstrapSA = "service_account:sva-sabootstrap"
	subjAccAdminA   = "user:usr-saaccadmina" // level 3 — account A#admin
	subjAccOwnerA   = "user:usr-saaccownera" // level 3 via account A#owner
	subjProjAdminA  = "user:usr-saprojadmina"
	subjStranger    = "user:usr-sastranger"
)

// verbs — the closed CRUD verb set every verb-bearing type declares.
var saVerbs = []string{"v_get", "v_list", "v_create", "v_update", "v_delete"}

// seedSuperAdminWorld builds the two-account hierarchy the directive talks about,
// using ONLY the structural parent-pointer tuples that production actually emits
// (account/create.go, project/create.go, access_binding/tuples.go, the module
// fgaregister/fgaintent emitters and registry fga_intent) plus the three
// top-level grants. No per-object v_*/tier tuple is written anywhere.
func seedSuperAdminWorld(t *testing.T, h *fgatest.Harness) {
	t.Helper()

	// Structural hierarchy: cluster ▶ account ▶ project ▶ resource.
	h.Write(t, saCluster, "cluster", saAccountA)
	h.Write(t, saCluster, "cluster", saAccountB)
	h.Write(t, saAccountA, "account", saProjectA)
	h.Write(t, saAccountB, "account", saProjectB)
	h.Write(t, saCluster, "cluster", saProjectA)
	h.Write(t, saCluster, "cluster", saProjectB)

	// AccessBinding carries exactly ONE parent-pointer, named after its own scope
	// (access_binding/tuples.go::hierarchyParentTuple) — project-scoped here, which
	// is the common case and the one the incident hit.
	h.Write(t, saProjectA, "project", saBindingA)
	h.Write(t, saProjectB, "project", saBindingB)

	// Leaf resources, as their owning modules register them.
	h.Write(t, saProjectA, "project", saNetworkA)  // vpc fgaregister
	h.Write(t, saProjectA, "project", saVolumeA)   // storage fgaregister
	h.Write(t, saProjectA, "project", saLbA)       // nlb fga_intent
	h.Write(t, saProjectA, "project", saRegistryA) // registry fga_intent
	h.Write(t, saRegistryA, "parent", saRepoA)     // repo is a child of its registry
	h.Write(t, saAccountA, "account", saUserA)     // iam relationhook
	h.Write(t, saAccountA, "account", saGroupA)    //

	// Level 1 + 2 — cloud administrator and the bootstrap identity share one
	// relation (migration 0058 seeds system_admin for the bootstrap SA).
	h.Write(t, subjCloudAdmin, "system_admin", saCluster)
	h.Write(t, subjBootstrapSA, "system_admin", saCluster)

	// Level 3 — account administrator of account A only, plus an account owner
	// (account.admin derives `or owner`, so the owner is an account administrator).
	h.Write(t, subjAccAdminA, "admin", saAccountA)
	h.Write(t, subjAccOwnerA, "owner", saAccountA)

	// NOT a super level: a project administrator. Project scope and below stay
	// flat — this subject is the anti-over-grant probe.
	h.Write(t, subjProjAdminA, "admin", saProjectA)
}

func saCheck(t *testing.T, h *fgatest.Harness, subject, relation, object string) bool {
	t.Helper()
	ok, err := h.Client.CheckWithContextConsistent(context.Background(), subject, relation, object, nil)
	require.NoError(t, err, "Check(%s, %s, %s)", subject, relation, object)
	return ok
}

// TestSuperAdminCascade_CloudAdminRevokesForeignBinding is the incident itself, at
// the observable level: the cloud administrator deletes a grant he did not create,
// in an account he holds no per-object tuple in. Before the cascade this is a
// denial (all five verbs on iam_access_binding were direct usersets without a
// single `or`); after it, it resolves.
func TestSuperAdminCascade_CloudAdminRevokesForeignBinding(t *testing.T) {
	h := fgatest.NewFromModelJSON(t, readConfigMapModelJSON(t))
	seedSuperAdminWorld(t, h)

	require.Truef(t, saCheck(t, h, subjCloudAdmin, "v_delete", saBindingA),
		"the cloud administrator must be able to revoke a grant he did not create "+
			"(iam_access_binding v_delete) — this is the 2026-07-26 incident: 652 denials "+
			"against 32 allows, an employee leaves and his colleague's access cannot be revoked")

	for _, v := range saVerbs {
		require.Truef(t, saCheck(t, h, subjCloudAdmin, v, saBindingA),
			"cloud administrator must resolve %s on a foreign binding", v)
		require.Truef(t, saCheck(t, h, subjBootstrapSA, v, saBindingA),
			"the bootstrap identity must resolve %s within the cloud", v)
	}

	// The account administrator revokes inside his own account — and only there.
	require.True(t, saCheck(t, h, subjAccAdminA, "v_delete", saBindingA),
		"the account administrator must be able to revoke a grant inside his own account")
	require.True(t, saCheck(t, h, subjAccOwnerA, "v_delete", saBindingA),
		"the account owner is an account administrator (account.admin derives `or owner`)")
}

// TestSuperAdminCascade_ReachesEveryVerbBearingType — the cascade is only worth
// something if it covers the whole surface, not the one type the incident hit.
// Every verb-bearing type is reached over the structural pointer it really
// declares: project-anchored leaves over `project`, iam resources over `account`,
// the repository over `parent` (it has no project pointer of its own).
func TestSuperAdminCascade_ReachesEveryVerbBearingType(t *testing.T) {
	h := fgatest.NewFromModelJSON(t, readConfigMapModelJSON(t))
	seedSuperAdminWorld(t, h)

	objects := []string{
		saProjectA, saNetworkA, saVolumeA, saLbA, saRegistryA, saRepoA,
		saBindingA, saUserA, saGroupA,
	}
	for _, obj := range objects {
		for _, v := range saVerbs {
			require.Truef(t, saCheck(t, h, subjCloudAdmin, v, obj),
				"cloud administrator must resolve %s on %s", v, obj)
			require.Truef(t, saCheck(t, h, subjAccAdminA, v, obj),
				"account A administrator must resolve %s on %s (inside his own account)", v, obj)
		}
		// The permission catalog gates 101 of its entries on the tier relations
		// (editor 60 / viewer 40 / admin 1), not on v_* — a cascade that only
		// covered the verbs would leave those RPCs denied.
		for _, rel := range []string{"viewer", "editor", "admin"} {
			require.Truef(t, saCheck(t, h, subjCloudAdmin, rel, obj),
				"cloud administrator must resolve tier %s on %s", rel, obj)
		}
	}

	// The account object itself: the cloud administrator manages accounts.
	for _, v := range saVerbs {
		require.Truef(t, saCheck(t, h, subjCloudAdmin, v, saAccountA),
			"cloud administrator must resolve %s on the account object", v)
	}
}

// TestSuperAdminCascade_DoesNotLeakBelowThreeLevels is the regression that matters
// more than the change: the cascade must stop at the account. A project
// administrator is an ordinary tenant — his access to the contents of his project
// stays MATERIALIZED per object, never derived. If this ever goes green by
// derivation, the anti-over-grant boundary recorded in data-integrity.md is gone
// (the editor role co-materializes delete on object rights but deliberately NOT on
// hierarchy scopes).
func TestSuperAdminCascade_DoesNotLeakBelowThreeLevels(t *testing.T) {
	h := fgatest.NewFromModelJSON(t, readConfigMapModelJSON(t))
	seedSuperAdminWorld(t, h)

	contents := []string{saNetworkA, saVolumeA, saLbA, saRegistryA, saRepoA, saBindingA}
	for _, obj := range contents {
		for _, v := range saVerbs {
			require.Falsef(t, saCheck(t, h, subjProjAdminA, v, obj),
				"a PROJECT administrator must NOT reach %s on %s by derivation — project "+
					"scope and below stay flat, access is materialized per object", v, obj)
		}
		for _, rel := range []string{"viewer", "editor", "admin"} {
			require.Falsef(t, saCheck(t, h, subjProjAdminA, rel, obj),
				"a PROJECT administrator must NOT reach tier %s on %s by derivation", rel, obj)
		}
	}

	// And an ordinary tenant with nothing at all reaches nothing at all.
	for _, obj := range append(contents, saAccountA, saProjectA, saUserA, saGroupA) {
		for _, v := range saVerbs {
			require.Falsef(t, saCheck(t, h, subjStranger, v, obj),
				"a subject with no tuple must not resolve %s on %s", v, obj)
		}
	}
}

// TestSuperAdminCascade_StopsAtTheAccountBoundary — level 3 is bounded by its own
// account. Otherwise the cascade would hand one tenant's administrator the whole
// cloud, which is the opposite of what it is for.
func TestSuperAdminCascade_StopsAtTheAccountBoundary(t *testing.T) {
	h := fgatest.NewFromModelJSON(t, readConfigMapModelJSON(t))
	seedSuperAdminWorld(t, h)

	foreign := []string{saAccountB, saProjectB, saBindingB}
	for _, obj := range foreign {
		for _, v := range saVerbs {
			require.Falsef(t, saCheck(t, h, subjAccAdminA, v, obj),
				"the administrator of account A must NOT reach %s on %s in account B", v, obj)
			require.Falsef(t, saCheck(t, h, subjAccOwnerA, v, obj),
				"the owner of account A must NOT reach %s on %s in account B", v, obj)
		}
		for _, rel := range []string{"viewer", "editor", "admin"} {
			require.Falsef(t, saCheck(t, h, subjAccAdminA, rel, obj),
				"the administrator of account A must NOT reach tier %s on %s in account B", rel, obj)
		}
	}

	// Levels 1-2 are cloud-wide by construction — account B is theirs too.
	for _, v := range saVerbs {
		require.Truef(t, saCheck(t, h, subjCloudAdmin, v, saBindingB),
			"the cloud administrator spans accounts — %s on a binding in account B", v)
	}

	// The account administrator does NOT gain the account OBJECT's own verbs: his
	// authority is "everything WITHIN the account", and the account object is the
	// boundary of that scope, not something inside it. Only levels 1-2 reach it.
	require.False(t, saCheck(t, h, subjAccAdminA, "v_delete", saAccountA),
		"the account administrator must not delete the account object itself — the "+
			"cascade runs WITHIN the account, the account is its boundary")
}

// TestSuperAdminCascade_DoesNotTouchNonCrudRelations — the cascade covers the CRUD
// surface (the five verbs and the three tiers the permission catalog gates on) and
// nothing else. The relations excluded here are deliberate least-privilege
// contracts that a "can do everything" reading would quietly dissolve:
// announce_writer belongs to the data plane alone, fga_writer to the proxy,
// member is a membership fact, owner is an identity fact.
func TestSuperAdminCascade_DoesNotTouchNonCrudRelations(t *testing.T) {
	h := fgatest.NewFromModelJSON(t, readConfigMapModelJSON(t))
	seedSuperAdminWorld(t, h)

	require.False(t, saCheck(t, h, subjCloudAdmin, "announce_writer", saLbA),
		"announce_writer is the data plane's alone — no human principal may forge "+
			"announce state, not even a cloud administrator")
	require.False(t, saCheck(t, h, subjCloudAdmin, "member", saGroupA),
		"membership is a fact about a subject, not a permission — the cascade must not "+
			"make the cloud administrator a member of every group")
	require.False(t, saCheck(t, h, subjCloudAdmin, "owner", saRegistryA),
		"ownership is an identity fact — the cascade must not rewrite who owns a resource")
	require.False(t, saCheck(t, h, subjAccAdminA, "owner", saRegistryA),
		"ownership is an identity fact — an account administrator does not become owner")
}

// TestSuperAdminCascade_ProjectIsNotACascadeSource is the structural half of the
// leak proof, read off the canonical DSL: `project`'s cascade source must be its
// ACCOUNT and the CLUSTER — never its own `admin`. A single `or admin` slipped into
// that line would silently turn every project administrator into a super
// administrator over his project's contents, and the behavioural test above would
// still pass for the allow cases while quietly losing its deny cases.
func TestSuperAdminCascade_ProjectIsNotACascadeSource(t *testing.T) {
	dsl := modelDSL(t)

	body := typeBody(t, dsl, "project")
	line := regexp.MustCompile(`(?m)^\s*define super_admin:\s*(.*)$`).FindStringSubmatch(body)
	require.Lenf(t, line, 2, "project must define super_admin — the cascade carrier. body:\n%s", body)

	rhs := line[1]
	require.Contains(t, rhs, "from account",
		"project's cascade must come from its account (level 3)")
	require.Contains(t, rhs, "from cluster",
		"project's cascade must come from the cluster (levels 1-2)")

	// Every disjunct must be a derivation over a parent pointer — `<rel> from
	// account|cluster`. A bare `admin` / `editor` / `viewer` / `[…]` disjunct would
	// be the project's OWN tier, which is exactly the leak this forbids: it would
	// silently promote every project administrator to a super administrator over
	// his project's contents, and the allow-side behavioural checks would still pass.
	overParent := regexp.MustCompile(`^\w+ from (account|cluster)$`)
	for _, d := range strings.Split(rhs, " or ") {
		d = strings.TrimSpace(d)
		require.Truef(t, overParent.MatchString(d),
			"project's cascade disjunct %q is not a derivation over a parent pointer — "+
				"the project's own tier must NEVER be a cascade source (anti-over-grant "+
				"boundary, data-integrity.md). full rhs: %q", d, rhs)
	}

	// Symmetrically: every leaf type cascades from its PARENT's super_admin, so it
	// inherits the same exclusion. A leaf reading `admin from project` instead
	// would re-open the leak one type at a time.
	for _, leaf := range []string{
		"vpc_network", "vpc_subnet", "compute_instance", "storage_volume",
		"nlb_network_load_balancer", "nlb_listener", "registry_registry",
	} {
		lb := typeBody(t, dsl, leaf)
		m := regexp.MustCompile(`(?m)^\s*define super_admin:\s*(.*)$`).FindStringSubmatch(lb)
		require.Lenf(t, m, 2, "%s must define super_admin. body:\n%s", leaf, lb)
		require.Equalf(t, "super_admin from project", m[1],
			"%s must cascade from its project's super_admin (which excludes the project's "+
				"own tier), never from `admin from project`", leaf)
	}
}
