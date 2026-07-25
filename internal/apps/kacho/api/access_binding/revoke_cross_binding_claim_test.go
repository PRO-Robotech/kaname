// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// revoke_cross_binding_claim_test.go — REVOKING ONE BINDING MUST NOT STRIP AN
// ACCESS ANOTHER *ACTIVE* BINDING STILL GRANTS (access-loss regression).
//
// THE DEFECT (observed live). The emitted-tuple ledger
// (kacho_iam.access_binding_emitted_tuples) is keyed PER BINDING
// (binding_id, fga_user, relation, object), while an OpenFGA tuple is NOT
// refcounted. Two bindings of the SAME subject on the SAME scope with the same
// role therefore hold TWO ledger rows for ONE live tuple. Delete/Revoke replayed
// its own ledger set verbatim onto OpenFGA, so tearing down binding A deleted the
// tuple binding B — still ACTIVE — also grants: the subject silently lost
// v_get/v_list/v_update while its ACTIVE binding claimed to give them. Live proof:
// two subjects holding `edit` on one project, both ledgers listing
// v_get/v_list/v_update/editor, yet OpenFGA holding all four for one subject and
// only `editor` for the other — the one whose sibling bindings the fixture
// preclean had revoked.
//
// SELF-SUSTAINING: the ledger is treated as the mirror of OpenFGA, so no
// reconcile pass ever notices the divergence and re-writes the lost tuple.
//
// THE RULE (already enforced INSIDE the reconciler by
// ReconcileStore.TuplesStillClaimedByOtherBindings — this suite extends the very
// same rule to the Delete/Revoke use-cases): a tuple is removed only when the LAST
// ACTIVE binding claiming it releases it.
//
// NOT to be confused with the deliberate anti-over-grant boundary on hierarchical
// scopes: nothing here widens a grant — the retained tuple is one an ACTIVE
// binding independently entitles the subject to.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	ab_repo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
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

// assertSharedTuplesSurvive pins the contract on the OBSERVABLE (what was asked of
// OpenFGA + what was enqueued for the async drain), not on an internal code path:
// the tuples another ACTIVE binding still claims are absent from BOTH removal
// paths, while the binding-private hierarchy pointer is removed by both.
func assertSharedTuplesSurvive(t *testing.T, f crossClaimFixture, verb string) {
	t.Helper()

	syncDeleted := f.fga.drainDeleted()
	for _, s := range f.shared {
		assert.NotContains(t, syncDeleted,
			clients.RelationTuple{User: s.User, Relation: s.Relation, Object: s.Object},
			"%s must NOT remove {User:%q Relation:%q Object:%q} from OpenFGA — another ACTIVE "+
				"binding still grants it (the OpenFGA tuple is not refcounted, the ledger is per-binding)",
			verb, s.User, s.Relation, s.Object)
	}
	for _, p := range f.private {
		assert.Contains(t, syncDeleted,
			clients.RelationTuple{User: p.User, Relation: p.Relation, Object: p.Object},
			"%s must still remove its OWN unshared tuple {User:%q Relation:%q Object:%q}",
			verb, p.User, p.Relation, p.Object)
	}

	// The at-least-once async backstop must carry the SAME reduced set — otherwise
	// the drainer re-applies the very deletion the sync path correctly skipped and
	// the access is lost a few seconds later instead of immediately.
	asyncDeleted := f.repo.drainFGADeleted()
	for _, s := range f.shared {
		assert.NotContains(t, asyncDeleted, s,
			"%s must NOT enqueue an fga_outbox delete for {User:%q Relation:%q Object:%q} still "+
				"claimed by an ACTIVE binding (async drain would strip it later)",
			verb, s.User, s.Relation, s.Object)
	}
	for _, p := range f.private {
		assert.Contains(t, asyncDeleted, p,
			"%s must keep the async backstop for its OWN unshared tuple {User:%q Relation:%q Object:%q}",
			verb, p.User, p.Relation, p.Object)
	}
}

// TestDeleteAccessBinding_TupleClaimedByAnotherActiveBinding_IsNotRevoked — HARD
// delete: the binding row goes away, but a tuple another ACTIVE binding still
// claims stays live in OpenFGA (and is not enqueued for the async delete).
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

	syncDeleted := f.fga.drainDeleted()
	want := append(append([]ab_repo.RelationTuple{}, f.shared...), f.private...)
	require.Len(t, syncDeleted, len(want),
		"with no surviving claim the revoke must remove the WHOLE emitted set")
	for _, w := range want {
		assert.Contains(t, syncDeleted,
			clients.RelationTuple{User: w.User, Relation: w.Relation, Object: w.Object},
			"unclaimed tuple {User:%q Relation:%q Object:%q} must be revoked", w.User, w.Relation, w.Object)
	}
}
