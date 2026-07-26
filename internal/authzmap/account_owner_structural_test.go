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

// account_owner_structural_test.go — behavioural + structural lock for the owner
// refinement "Владелец — СТРУКТУРНЫЙ источник прав на СВОЁМ аккаунте"
// (.claude/rules/security.md, 2026-07-27).
//
// An account is the user's own area and it is created by self-service: a freshly
// authenticated person creates his account himself. Deletion therefore has to be
// as reliable as creation — and it was not. The right to delete arrived with the
// owner ROLE BINDING, materialized per object by the reconciler out of the
// fga_outbox; until that pipeline caught up, the account the user had just
// created could not be deleted by the only person who owns it. The cloud
// administrator, by contrast, has held a cascading right since the three-tier
// change — an asymmetry with no justification: both are "authority that must not
// depend on a queue".
//
// The model made the gap visible from the other side too: `account.admin` derives
// `or owner`, so the owner IS an account administrator — while the verbs read no
// administrator tier at all (`v_delete: […] or super_admin`). Being an
// administrator of one's own account granted nothing.
//
// WHY `owner` DIRECTLY AND NOT "make the verbs read the admin tier".
// Routing the verbs through `admin` would have been the wider fix and it is the
// wrong one: `account.admin` also accepts DIRECT subjects
// (`[user, service_account, group#member]`), i.e. the DELEGATED account
// administrator. He would then delete the account object itself, which the
// recorded picture forbids in as many words — "администратор аккаунта — каскадом
// внутрь аккаунта, но не на сам аккаунт (делегированный управляющий не сносит
// тенантность — это остаётся за владельцем и облаком)". The tenancy is torn down
// by whoever created it, and by the cloud. So the source is `owner`, and
// TestAccountOwner_VerbsReadOwnerNotTheAdminTier keeps it that way structurally —
// a later `or admin` on those lines would pass every allow-side check below while
// silently handing the delegated manager the account itself.
//
// The behavioural checks run against the DEPLOYED artifact — the
// openfga-bootstrap ConfigMap `model.json` block, which is what the bootstrap Job
// POSTs to OpenFGA — loaded into a real OpenFGA container. Reading the DSL alone
// would only prove the shape of the source file.

const (
	aoAccountA = "account:acc-aoownera"
	aoAccountB = "account:acc-aoownerb"
	aoProjectA = "project:prj-aoownera"
	aoBindingA = "iam_access_binding:abn-aoownera"
	aoCluster  = "cluster:cluster_kacho_root"

	aoOwnerA    = "user:usr-aoownera"   // created account A, holds account:A#owner
	aoOwnerB    = "user:usr-aoownerb"   // created account B — a peer tenant
	aoDelegAdmA = "user:usr-aodelegadm" // DELEGATED account administrator of A (not the owner)
	aoStranger  = "user:usr-aostranger" // no tuple anywhere
)

var aoVerbs = []string{"v_get", "v_list", "v_create", "v_update", "v_delete"}

func aoCheck(t *testing.T, h *fgatest.Harness, subject, relation, object string) bool {
	t.Helper()
	ok, err := h.Client.CheckWithContextConsistent(context.Background(), subject, relation, object, nil)
	require.NoError(t, err, "Check(%s, %s, %s)", subject, relation, object)
	return ok
}

// aoSeedFreshAccount writes EXACTLY the tuples account.Create co-commits in the
// writer-tx (apps/kacho/api/account/create.go::ownerTuples) and NOTHING else:
//
//	user:<owner>            # owner   @ account:<A>   — the owner self-grant
//	cluster:cluster_kacho_root # cluster @ account:<A> — the SEC-L cluster pointer
//
// No v_* tuple on the account, no owner-AccessBinding membership — that is the
// reconciler's output, and the whole point is that the owner must not wait for it.
func aoSeedFreshAccount(t *testing.T, h *fgatest.Harness, owner, account string) {
	t.Helper()
	h.Write(t, owner, "owner", account)
	h.Write(t, aoCluster, "cluster", account)
}

// TestAccountOwner_DeletesFreshAccountBeforeAnyMaterialization is the change
// itself, at the observable level: the owner creates his account and deletes it
// IMMEDIATELY, with the materialization pipeline having produced nothing at all.
// Before the refinement this is a denial (the account's verbs read only direct
// usersets and the cluster tier); after it, it resolves by construction.
func TestAccountOwner_DeletesFreshAccountBeforeAnyMaterialization(t *testing.T) {
	h := fgatest.NewFromModelJSON(t, readConfigMapModelJSON(t))
	aoSeedFreshAccount(t, h, aoOwnerA, aoAccountA)

	require.Truef(t, aoCheck(t, h, aoOwnerA, "v_delete", aoAccountA),
		"the owner of a FRESHLY created account must be able to delete it with NOTHING "+
			"materialized — the account is created by self-service, so tearing it down cannot "+
			"depend on the reconciler having drained the owner binding first")

	for _, v := range aoVerbs {
		require.Truef(t, aoCheck(t, h, aoOwnerA, v, aoAccountA),
			"the owner must resolve %s on his own account object without materialization", v)
	}

	// The tiers the permission catalog gates on already derived from `owner`
	// (`define admin: … or owner`) — pinned so the refinement cannot be read as
	// replacing that.
	for _, rel := range []string{"viewer", "editor", "admin"} {
		require.Truef(t, aoCheck(t, h, aoOwnerA, rel, aoAccountA),
			"the owner must still resolve tier %s on his own account", rel)
	}
}

// TestAccountOwner_ScopeIsExactlyHisOwnAccount is the half that matters more than
// the change: everything the refinement must NOT hand out. The delegated account
// administrator manages what is INSIDE the account and must not delete the account
// itself; a peer tenant's owner reaches nothing here; a subject with no tuple
// reaches nothing anywhere.
func TestAccountOwner_ScopeIsExactlyHisOwnAccount(t *testing.T) {
	h := fgatest.NewFromModelJSON(t, readConfigMapModelJSON(t))
	aoSeedFreshAccount(t, h, aoOwnerA, aoAccountA)
	aoSeedFreshAccount(t, h, aoOwnerB, aoAccountB)

	// Contents of account A, wired by the structural pointers production emits.
	h.Write(t, aoAccountA, "account", aoProjectA)
	h.Write(t, aoCluster, "cluster", aoProjectA)
	h.Write(t, aoProjectA, "project", aoBindingA)

	// A DELEGATED account administrator: a direct `admin` tuple, no ownership.
	h.Write(t, aoDelegAdmA, "admin", aoAccountA)

	// (1) He does NOT reach the account OBJECT — the tenancy is not his to tear
	//     down. This is exactly what routing the verbs through the `admin` tier
	//     would have broken.
	for _, v := range aoVerbs {
		require.Falsef(t, aoCheck(t, h, aoDelegAdmA, v, aoAccountA),
			"a DELEGATED account administrator must NOT resolve %s on the account object "+
				"itself — his authority runs WITHIN the account, the account is its boundary", v)
	}

	// (2) …while his cascade INWARDS is untouched (the three-tier change stands).
	for _, v := range aoVerbs {
		require.Truef(t, aoCheck(t, h, aoDelegAdmA, v, aoProjectA),
			"the delegated account administrator must still resolve %s inside his account "+
				"(project) — the refinement must not narrow the level-3 cascade", v)
		require.Truef(t, aoCheck(t, h, aoDelegAdmA, v, aoBindingA),
			"the delegated account administrator must still resolve %s on a grant inside "+
				"his account", v)
	}

	// (3) The owner of ANOTHER account is an ordinary stranger here — `owner` is a
	//     per-object relation, it does not travel between accounts.
	for _, v := range aoVerbs {
		require.Falsef(t, aoCheck(t, h, aoOwnerB, v, aoAccountA),
			"the owner of account B must NOT resolve %s on account A", v)
		require.Falsef(t, aoCheck(t, h, aoOwnerA, v, aoAccountB),
			"the owner of account A must NOT resolve %s on account B", v)
		require.Falsef(t, aoCheck(t, h, aoOwnerB, v, aoProjectA),
			"the owner of account B must NOT resolve %s inside account A", v)
	}
	for _, rel := range []string{"viewer", "editor", "admin"} {
		require.Falsef(t, aoCheck(t, h, aoOwnerB, rel, aoAccountA),
			"the owner of account B must NOT resolve tier %s on account A", rel)
	}

	// (4) An ordinary tenant with no tuple at all reaches nothing.
	for _, obj := range []string{aoAccountA, aoProjectA, aoBindingA} {
		for _, v := range aoVerbs {
			require.Falsef(t, aoCheck(t, h, aoStranger, v, obj),
				"a subject with no tuple must not resolve %s on %s", v, obj)
		}
	}

	// (5) Ownership stays an identity fact: the refinement makes `owner` a SOURCE
	//     of verbs, it must not make anyone an owner.
	require.False(t, aoCheck(t, h, aoDelegAdmA, "owner", aoAccountA),
		"a delegated account administrator does not become the owner")
}

// TestAccountOwner_VerbsReadOwnerNotTheAdminTier is the structural half, read off
// the canonical DSL — the deliberate choice between the two possible fixes, made
// unmaintainable to reverse by accident.
//
// Every verb on `account` must derive from `owner` (that is the refinement) and
// its disjuncts must be exactly {owner, super_admin} — never `admin`. `or admin`
// there would keep every allow-side check above green while silently granting the
// DELEGATED account administrator the account object itself, contradicting
// "администратор аккаунта — … не на сам аккаунт".
func TestAccountOwner_VerbsReadOwnerNotTheAdminTier(t *testing.T) {
	body := typeBody(t, modelDSL(t), "account")

	for _, v := range aoVerbs {
		re := regexp.MustCompile(`(?m)^\s*define ` + v + `:\s*(.*)$`)
		m := re.FindStringSubmatch(body)
		require.Lenf(t, m, 2, "account must define %s. body:\n%s", v, body)

		disjuncts := strings.Split(m[1], " or ")
		require.Greaterf(t, len(disjuncts), 1, "account.%s has no derivation at all: %q", v, m[1])

		require.Truef(t, strings.HasPrefix(strings.TrimSpace(disjuncts[0]), "["),
			"account.%s must keep its DIRECT userset (materialized tenant grants stay flat): %q", v, m[1])

		derived := map[string]bool{}
		for _, d := range disjuncts[1:] {
			derived[strings.TrimSpace(d)] = true
		}
		require.Truef(t, derived["owner"],
			"account.%s must derive from `owner` — the account is created by self-service and "+
				"tearing it down must not wait for the reconciler. rhs: %q", v, m[1])
		require.Truef(t, derived["super_admin"],
			"account.%s must keep `super_admin` (levels 1-2 reach every account). rhs: %q", v, m[1])
		require.Lenf(t, derived, 2,
			"account.%s must derive from `owner` and `super_admin` and NOTHING else — in "+
				"particular not from `admin`, which accepts DIRECT subjects and would hand the "+
				"DELEGATED account administrator the account object itself. rhs: %q", v, m[1])
	}
}

// TestAccountOwner_RefinementIsConfinedToTheAccountType — the refinement is about
// the account object alone. `project` (and everything below it) stays flat: its
// verbs may derive from `super_admin` and nothing else, so no tier of its own and
// no ownership notion can creep in one type at a time.
func TestAccountOwner_RefinementIsConfinedToTheAccountType(t *testing.T) {
	body := typeBody(t, modelDSL(t), "project")

	for _, v := range aoVerbs {
		re := regexp.MustCompile(`(?m)^\s*define ` + v + `:\s*(.*)$`)
		m := re.FindStringSubmatch(body)
		require.Lenf(t, m, 2, "project must define %s. body:\n%s", v, body)

		disjuncts := strings.Split(m[1], " or ")
		derived := map[string]bool{}
		for _, d := range disjuncts[1:] {
			derived[strings.TrimSpace(d)] = true
		}
		require.Equalf(t, map[string]bool{"super_admin": true}, derived,
			"project.%s must derive from `super_admin` alone — project scope and below stay "+
				"flat, access is materialized per object (anti-over-grant, data-integrity.md). "+
				"rhs: %q", v, m[1])
	}
}
