// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package reconcile

// forward_binding_test.go — use-case unit tests for the ADDITIVE forward fast-path of a
// freshly-CREATED binding (ReconcileBindingForward), the create-path replacement for the
// FULL EXCLUSIVE ReconcileBinding (sub-phase IAM-FMB). Driven against the in-memory
// fakeStore (no Postgres — a service-layer test requiring Postgres would be adapter
// leakage). The pg integration twin (reconcile_binding_forward_integration_test.go)
// exercises the real advisory-lock + concurrency (exactly-once, deadlock-free).
//
// These pin the create-forward contract (mirror of the object-forward contract):
//   - it materializes the binding's desired ACTIVE per-object members ADDITIVELY, taking
//     ONLY the SHARE advisory lock (never the EXCLUSIVE full-path lock) — the throughput
//     property under a mass-binding-create burst (IAM-FMB-01);
//   - a matched-but-foreign (cross-scope) object is NOT granted (additive-only leaves the
//     REJECTED member + containment audit to the async full backstop) (IAM-FMB-03);
//   - a binding that ALREADY has materialized members (replay / call on an existing
//     binding) transparently delegates to the FULL ReconcileBinding so delete-stale is not
//     lost (defensive-delegation guard, IAM-FMB-10).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// TestReconcileBindingForward_MaterializesDesired_NoExclusiveLock (IAM-FMB-01 unit) — the
// create-forward materializes the binding's desired ACTIVE members + per-object tuples and
// takes NO EXCLUSIVE advisory lock (f.locks stays 0), only the SHARE lock
// (f.sharedLocks>=1); it reads the binding via the UNLOCKED load (no FOR UPDATE). This is
// the throughput-critical property: SHARE ∥ SHARE do not conflict, so a burst of
// concurrent binding-creates never serializes on the full path's EXCLUSIVE lock.
//
// RED against the pre-IAM-FMB create-path (post-commit FULL ReconcileBinding): that path
// takes the EXCLUSIVE lock (f.locks==1) → this asserts f.locks==0 → RED. GREEN once the
// create-path runs the additive SHARE-lock forward.
func TestReconcileBindingForward_MaterializesDesired_NoExclusiveLock(t *testing.T) {
	fp := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "update"},
	}.Fingerprint()
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmAnchor, RuleFP: fp,
			ObjectTypes: []string{"compute.instance"},
			Verbs:       []string{"get", "update"},
		}},
		mirror: map[string][]domain.MirrorObject{
			"compute.instance": {
				{ObjectType: "compute.instance", ObjectID: "iX", ParentProjectID: "prj-1"},
			},
		},
		// Brand-new binding — no materialized members yet (the create hot-path).
		current: nil,
	}
	rec := New(fakeRunner{s: f}, nil)
	require.NoError(t, rec.ReconcileBindingForward(context.Background(), "acb-new"))

	// NO EXCLUSIVE advisory lock — the additive create-forward removes the serialization
	// point; it takes only the SHARE lock (coexists with sibling create-forwards).
	assert.Equal(t, 0, f.locks, "create-forward must NOT take the EXCLUSIVE advisory lock (throughput)")
	assert.GreaterOrEqual(t, f.sharedLocks, 1, "create-forward takes the SHARE advisory lock (mutual-exclusion vs FULL only)")
	assert.GreaterOrEqual(t, f.unlockedLoads, 1, "create-forward reads the binding via the UNLOCKED load (no FOR UPDATE)")

	// The desired ACTIVE member is materialized additively.
	require.Len(t, f.upserts, 1, "the in-scope object is materialized")
	assert.Equal(t, "iX", f.upserts[0].ObjectID)
	assert.Equal(t, domain.VerificationActive, f.upserts[0].VerificationStatus)
	assert.Equal(t, fp, f.upserts[0].RuleFP)

	w := allWrites(f)
	assert.True(t, hasTuple(w, "v_get", "compute_instance:iX"), "v_get materialized")
	assert.True(t, hasTuple(w, "v_update", "compute_instance:iX"), "v_update materialized")
	assert.True(t, hasTuple(w, "v_delete", "compute_instance:iX"), "v_update⟹v_delete co-materialized (leaf editor)")
	assert.True(t, hasTuple(w, "editor", "compute_instance:iX"), "back-compat tier materialized")
	// The tuples are co-committed into the ledger in the SAME pass (symmetric-revoke lineage).
	require.NotEmpty(t, f.recorded, "create-forward co-commits the emitted tuples into the ledger")
	// Additive-only: nothing revoked / deleted / audited on the create hot-path.
	assert.Empty(t, f.tdeletes, "create-forward never revokes (additive-only, no delete-stale)")
	assert.Empty(t, f.deletes, "create-forward never deletes a member")
	assert.Empty(t, f.audits, "create-forward never audits (async FULL backstop owns REJECTED)")
}

// TestReconcileBindingForward_ForeignScope_SkipsNoTuple (IAM-FMB-03 unit) — a matched-but-
// foreign object (a label/name arm can match cross-scope) is NOT granted by the additive
// create-forward: no tuple, no member, no audit. The REJECTED member + containment audit
// are LEFT to the async FULL backstop (byte-identical grant equivalence: forward never
// grants beyond what FULL grants — REJECTED is never an ACTIVE grant on either path).
func TestReconcileBindingForward_ForeignScope_SkipsNoTuple(t *testing.T) {
	fp := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"},
	}.Fingerprint()
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmLabels, RuleFP: fp, ObjectTypes: []string{"compute.instance"},
			MatchLabels: map[string]string{"env": "prod"}, Verbs: []string{"get"},
		}},
		mirror: map[string][]domain.MirrorObject{
			"compute.instance": {
				// matches labels but lives under a FOREIGN project → REJECTED containment.
				{ObjectType: "compute.instance", ObjectID: "i-foreign", ParentProjectID: "prj-OTHER", Labels: map[string]string{"env": "prod"}},
			},
		},
		current: nil,
	}
	rec := New(fakeRunner{s: f}, nil)
	require.NoError(t, rec.ReconcileBindingForward(context.Background(), "acb-new"))

	assert.Empty(t, f.upserts, "additive create-forward does NOT write a REJECTED member")
	assert.Empty(t, allWrites(f), "foreign-scope object gets NO tuple")
	assert.Empty(t, f.audits, "create-forward defers the containment audit to the async FULL backstop")
	assert.Equal(t, 0, f.locks, "still no EXCLUSIVE advisory lock")
	assert.GreaterOrEqual(t, f.sharedLocks, 1, "the SHARE lock is still taken for the fresh binding")
}

// TestReconcileBindingForward_ExistingMembers_DelegatesToFull (IAM-FMB-10 unit) — the
// DELETE-STALE GUARD (create-only). When the binding ALREADY has materialized members
// (a replay create / a call on an existing binding), the additive path is UNSAFE (it
// cannot delete-stale a now-unmatched grant). It must transparently delegate to the FULL
// ReconcileBinding (EXCLUSIVE lock + delete-stale) so the stale grant is revoked.
//
// Setup: a label-selector member O is CURRENTLY materialized ACTIVE, but O's mirror label
// has FLIPPED so it no longer matches → the FULL recompute must drop O and revoke its
// ledger tuple. The guard is discriminated by CurrentMembers being non-empty.
func TestReconcileBindingForward_ExistingMembers_DelegatesToFull(t *testing.T) {
	fp := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "a"},
	}.Fingerprint()
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmLabels, RuleFP: fp, ObjectTypes: []string{"compute.instance"},
			MatchLabels: map[string]string{"team": "a"}, Verbs: []string{"get"},
		}},
		// O's label has FLIPPED to team=b → it no longer matches the team=a selector.
		mirror: map[string][]domain.MirrorObject{
			"compute.instance": {
				{ObjectType: "compute.instance", ObjectID: "i-flip", ParentProjectID: "prj-1", Labels: map[string]string{"team": "b"}},
			},
		},
		// The binding ALREADY has a materialized ACTIVE member (from when it was team=a) →
		// this is a replay/existing-binding call, NOT a create → routes to FULL.
		current: []domain.TargetMember{
			{BindingID: "acb-1", RuleFP: fp, ObjectType: "compute.instance", ObjectID: "i-flip", VerificationStatus: domain.VerificationActive},
		},
		ledger: []domain.MembershipTuple{
			{User: "user:usr-1", Relation: "v_get", Object: "compute_instance:i-flip"},
			{User: "user:usr-1", Relation: "viewer", Object: "compute_instance:i-flip"},
		},
	}
	rec := New(fakeRunner{s: f}, nil)
	require.NoError(t, rec.ReconcileBindingForward(context.Background(), "acb-1"))

	// Routed to the FULL path: EXCLUSIVE advisory lock taken (delete-stale serialization);
	// the additive SHARE-lock forward path was NOT taken (guard bailed before it).
	assert.Greater(t, f.locks, 0, "existing-members binding must route to the FULL ReconcileBinding (EXCLUSIVE lock, delete-stale)")
	assert.Equal(t, 0, f.sharedLocks, "the additive SHARE-lock forward path must NOT run for a binding with existing members")

	// The now-unmatched grant is REVOKED (the revoke additive-forward could never do).
	var revoked []domain.MembershipTuple
	for _, batch := range f.tdeletes {
		revoked = append(revoked, batch...)
	}
	assert.True(t, hasTuple(revoked, "v_get", "compute_instance:i-flip"),
		"the label-flipped stale grant is eager-revoked via the FULL delete-stale diff")
	assert.Contains(t, f.deletes, memberKey("compute.instance", "i-flip"), "stale member deleted")
}
