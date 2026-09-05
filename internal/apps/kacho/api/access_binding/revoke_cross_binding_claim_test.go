// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// revoke_cross_binding_claim_test.go — REVOKING ONE BINDING MUST NOT STRIP AN
// ACCESS ANOTHER *ACTIVE* BINDING STILL GRANTS (access-loss regression).
//
// THE DEFECT (observed live). The emitted-tuple ledger
// (kacho_iam.access_binding_emitted_tuples) is keyed PER BINDING
// (binding_id, fga_user, relation, object), while the fact a verdict resolves
// against is NOT refcounted — it is one row per (object, relation, subject). Two
// bindings of the SAME subject on the SAME scope with the same role therefore hold
// TWO ledger rows for ONE live fact. Delete/Revoke replayed its own ledger set
// verbatim, so tearing down binding A removed the access binding B — still ACTIVE —
// also grants: the subject silently lost v_get/v_list/v_update while its ACTIVE
// binding claimed to give them. Live proof: two subjects holding `edit` on one
// project, both ledgers listing v_get/v_list/v_update/editor, yet all four resolving
// for one subject and only `editor` for the other — the one whose sibling bindings
// the fixture preclean had revoked.
//
// SELF-SUSTAINING: the ledger is treated as the mirror of the materialized state, so
// no reconcile pass ever notices the divergence and re-states the lost tuple.
//
// THE RULE (already enforced INSIDE the reconciler by
// ReconcileStore.TuplesStillClaimedByOtherBindings — this suite extends the very
// same rule to the Delete/Revoke use-cases): a tuple is removed only when the LAST
// ACTIVE binding claiming it releases it.
//
// NOT to be confused with the deliberate anti-over-grant boundary on hierarchical
// scopes: nothing here widens a grant — the retained tuple is one an ACTIVE
// binding independently entitles the subject to.
//
// # Where these assertions used to look, and where they look now
//
// The contract was pinned on TWO removal paths: what the use-case asked of the
// external relation engine straight after commit (clients.RelationStore.DeleteTuples)
// and what it stated in the journal for the drainer. Stage S6 removed the engine —
// the port no longer carries DeleteTuples, and the journal
// (`kacho_iam.fga_outbox`) stopped being a queue toward anything external: a database
// trigger folds each of its rows into `kacho_iam.relation_fact` inside the SAME
// transaction, and that table is what a verdict is read from.
//
// So there is exactly one removal path now, and it is the one that was called the
// "backstop". The engine-side assertions are dropped rather than kept pointing at a
// method nothing can call: with no producer they would have been true by
// construction of the fake's type, unable to go red for any product reason — while
// still reading like proof. Nothing about the RULE changed, and the journal
// assertions below are the same statements, now made about the only path there is.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	ab_repo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
)

// seedTuplesClaimedByOtherActiveBindings sets the tuples some OTHER ACTIVE
// binding also holds a ledger row for (the cross-binding shared-tuple class).
func (r *abFakeRepo) seedTuplesClaimedByOtherActiveBindings(tuples []ab_repo.RelationTuple) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.claimedByOthers = append(r.claimedByOthers[:0], tuples...)
}

// SelectTuplesClaimedByOtherActiveBindings — fake of the cross-binding survivor
// probe: intersects the candidate set with the tuples seeded as "also held by
// another ACTIVE binding" (the real repo joins the per-binding ledger against
// access_bindings WHERE status='ACTIVE' AND binding_id <> $1).
func (rd *fakeABRdr) SelectTuplesClaimedByOtherActiveBindings(_ context.Context, _ domain.AccessBindingID, tuples []ab_repo.RelationTuple) ([]ab_repo.RelationTuple, error) {
	rd.repo.mu.Lock()
	defer rd.repo.mu.Unlock()
	if len(rd.repo.claimedByOthers) == 0 || len(tuples) == 0 {
		return nil, nil
	}
	claimed := make(map[ab_repo.RelationTuple]struct{}, len(rd.repo.claimedByOthers))
	for _, t := range rd.repo.claimedByOthers {
		claimed[t] = struct{}{}
	}
	var out []ab_repo.RelationTuple
	for _, t := range tuples {
		if _, ok := claimed[t]; ok {
			out = append(out, t)
		}
	}
	return out, nil
}

// crossClaimFixture grants one binding and returns the tuple-set it emitted,
// split into the scope-anchor role-relation tuples (the cross-binding SHARED
// class — another binding of the same subject on the same scope emits exactly
// these) and the binding-private hierarchy parent-pointer (object
// iam_access_binding:<id>, unique to this binding — never shared).
type crossClaimFixture struct {
	repo      *abFakeRepo
	opsRepo   *fakeOpsRepo
	fga       *recordingFGA
	bindingID domain.AccessBindingID
	shared    []ab_repo.RelationTuple
	private   []ab_repo.RelationTuple
	subjectID string
}

func newCrossClaimFixture(t *testing.T) crossClaimFixture {
	t.Helper()
	const (
		roleID     = "rol_edit_cross_claim"
		roleName   = "kacho.edit"
		subjectID  = "usr_cross_claim_subject"
		resourceID = "prj_cross_claim_project"
		ownerID    = "usr_cross_claim_owner"
		accountID  = "acc_cross_claim_account"
	)
	perms := domain.Permissions{
		"iam.access_bindings.get",
		"iam.access_bindings.list",
		"iam.access_bindings.update",
	}
	f := crossClaimFixture{
		repo:      newABFakeRepo(ownerID, accountID, resourceID, roleID, roleName, perms),
		opsRepo:   newFakeOpsRepo(),
		fga:       newRecordingFGA(),
		subjectID: subjectID,
	}
	createUC := NewCreateAccessBindingUseCase(f.repo, f.opsRepo).WithRelationStore(f.fga, nil)
	_, err := createUC.Execute(newOwnerContext(ownerID), domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "project",
		ResourceID:   resourceID,
	})
	require.NoError(t, err, "Create.Execute must succeed")

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "async Create worker must complete")

	for _, tup := range f.repo.drainFGAWritten() {
		if strings.HasPrefix(tup.Object, "iam_access_binding:") {
			f.private = append(f.private, tup)
			continue
		}
		f.shared = append(f.shared, tup)
	}
	require.NotEmpty(t, f.shared, "grant must emit scope-anchor role-relation tuples")
	require.NotEmpty(t, f.private, "grant must emit the binding-private hierarchy parent-pointer")

	f.bindingID = f.repo.lastInsertedID()
	require.NotEmpty(t, f.bindingID)
	// The fake Insert stores the row verbatim; the real table DEFAULTs status to
	// ACTIVE. Stamp it so the soft-revoke CAS (`… WHERE status='ACTIVE'`) behaves as
	// it does against Postgres.
	f.repo.mu.Lock()
	f.repo.ab.Status = domain.AccessBindingStatusActive
	f.repo.mu.Unlock()

	// A SECOND, still-ACTIVE binding of the same subject on the same scope
	// materialized the IDENTICAL scope-anchor tuples (its own ledger rows). The
	// teardown of THIS binding must leave them alone.
	f.repo.seedTuplesClaimedByOtherActiveBindings(f.shared)
	return f
}

// assertSharedTuplesSurvive pins the contract on the OBSERVABLE — the revoke set the
// use-case STATES in its writer-tx — and not on an internal code path: the tuples
// another ACTIVE binding still claims are absent from it, while the binding-private
// hierarchy pointer is in it.
//
// That set is the whole removal: a database trigger folds the journal row into the
// fact table inside the same transaction, so a tuple named here is gone at the commit
// and a tuple omitted here is never touched.
//
// The negative arm is kept IN PAIR with the positive one on purpose. "The shared
// tuple was not removed" is the assertion most likely to be satisfied by a revoke
// that removes nothing at all; the private-tuple arm is what makes an empty revoke
// set fail rather than pass.
func assertSharedTuplesSurvive(t *testing.T, f crossClaimFixture, verb string) {
	t.Helper()

	revoked := f.repo.drainFGADeleted()
	require.NotEmpty(t, revoked,
		"%s stated no revoke set at all — every assertion below would then hold vacuously", verb)
	for _, s := range f.shared {
		assert.NotContains(t, revoked, s,
			"%s must NOT state a revoke for {User:%q Relation:%q Object:%q} still claimed by an "+
				"ACTIVE binding (the materialized fact is not refcounted, the ledger is per-binding)",
			verb, s.User, s.Relation, s.Object)
	}
	for _, p := range f.private {
		assert.Contains(t, revoked, p,
			"%s must still revoke its OWN unshared tuple {User:%q Relation:%q Object:%q}",
			verb, p.User, p.Relation, p.Object)
	}
}

// TestDeleteAccessBinding_TupleClaimedByAnotherActiveBinding_IsNotRevoked — HARD
// delete: the binding row goes away, but a tuple another ACTIVE binding still claims
// is not named in the revoke set, so the access it grants survives.
func TestDeleteAccessBinding_TupleClaimedByAnotherActiveBinding_IsNotRevoked(t *testing.T) {
	f := newCrossClaimFixture(t)

	deleteUC := NewDeleteAccessBindingUseCase(f.repo, f.opsRepo).WithRelationStore(f.fga, nil)
	_, err := deleteUC.Execute(newOwnerContext(f.subjectID), f.bindingID)
	require.NoError(t, err, "Delete.Execute must succeed")

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "async Delete worker must complete")

	assertSharedTuplesSurvive(t, f, "Delete")
}

// TestRevokeAccessBinding_TupleClaimedByAnotherActiveBinding_IsNotRevoked — SOFT
// revoke (row retained, status ACTIVE→REVOKED) obeys the identical rule: the two
// paths differ only in row-retention, never in which tuples they strip.
func TestRevokeAccessBinding_TupleClaimedByAnotherActiveBinding_IsNotRevoked(t *testing.T) {
	f := newCrossClaimFixture(t)

	revokeUC := NewRevokeAccessBindingUseCase(f.repo, f.opsRepo).WithRelationStore(f.fga, nil)
	_, err := revokeUC.Execute(newOwnerContext(f.subjectID), f.bindingID)
	require.NoError(t, err, "Revoke.Execute must succeed")

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "async Revoke worker must complete")

	assertSharedTuplesSurvive(t, f, "Revoke")
}

// TestDeleteAccessBinding_NoOtherClaim_RevokesWholeEmittedSet — the CONVERSE, so
// the fix cannot degenerate into "never revoke anything": with no other ACTIVE
// binding claiming them, every emitted tuple is removed, byte-symmetric to the
// grant (the pre-existing symmetric-revoke contract).
func TestDeleteAccessBinding_NoOtherClaim_RevokesWholeEmittedSet(t *testing.T) {
	f := newCrossClaimFixture(t)
	// Nobody else claims anything — the sibling binding was itself torn down.
	f.repo.seedTuplesClaimedByOtherActiveBindings(nil)

	deleteUC := NewDeleteAccessBindingUseCase(f.repo, f.opsRepo).WithRelationStore(f.fga, nil)
	_, err := deleteUC.Execute(newOwnerContext(f.subjectID), f.bindingID)
	require.NoError(t, err, "Delete.Execute must succeed")

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "async Delete worker must complete")

	revoked := f.repo.drainFGADeleted()
	want := append(append([]ab_repo.RelationTuple{}, f.shared...), f.private...)
	require.Len(t, revoked, len(want),
		"with no surviving claim the revoke must cover the WHOLE emitted set")
	for _, w := range want {
		assert.Contains(t, revoked, w,
			"unclaimed tuple {User:%q Relation:%q Object:%q} must be revoked", w.User, w.Relation, w.Object)
	}
}
