// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// update_label_rematerialize_test.go — an access-binding label change must
// re-materialize the object IMMEDIATELY, not only through the reconcile queue.
//
// iam.accessBinding is label-selectable (domain.labelSelectableTypes carries
// "iam.accessBinding"; kaname.access_bindings.labels is probed by
// `labels @> match_labels` in MatchIAMDirect), so removing a label that an ARM_LABELS
// grant matches is a REVOCATION: the per-object member row and its FGA tuples must go.
// Two feeds reach the same reconciler for that:
//
//   - CROSS-SERVICE (vpc/compute/nlb): the owning service re-calls
//     InternalIAMService.RegisterResource on a label update, and RegisterResource runs
//     ReconcileObjectForward in-process. The forward's delete-stale guard sees the
//     object already has members, delegates to the FULL ReconcileObject, and the stale
//     grant is revoked there and then.
//
//   - IAM-DIRECT (this path): AccessBinding.Update only co-committed a
//     resource_reconcile_outbox event and returned. Nothing re-materialized the object
//     in-process, so the revoke's latency became the DEPTH OF THE GLOBAL RECONCILE
//     QUEUE. That queue is strictly FIFO and drained by one worker at roughly five
//     events/second, each event a FULL O(scope) recompute, while the e2e suite emits
//     five to eight events/second — so it runs a multi-minute backlog. Measured on the
//     stand for the sibling iam.project path: the label-clear event was enqueued at
//     19:59:18.97 and drained at 20:06:49.82 (7m30s), and the tuple only died at
//     20:00:23 when the 30s periodic sweep happened to reach that binding — 65s after
//     the clear, long past any client budget.
//
// This pins the missing half — iam.accessBinding was the last of the seven
// label-selectable iam-native types without it: the label-update path performs the same
// in-process object re-materialization its cross-service twin performs, so revoke
// latency stops depending on how many unrelated events are queued ahead of it. Like
// every other post-commit pass it runs OFF the Operation.done path (ban #9) — the
// co-committed event and the periodic sweep remain the at-least-once backstop, which is
// why the nil-reconciler case below still has to emit the durable event.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// recordingReconciler (create_forward_new_test.go) already records every reconcile
// entry point, ReconcileObjectForward among them, so it doubles as this path's fake.
var _ ObjectForwardReconciler = (*recordingReconciler)(nil)

// seedLabelledBinding seeds an ACTIVE account-scoped binding that already carries
// labels, so clearing them is the REVOCATION case.
func seedLabelledBinding(repo *abFakeRepo, accountID, roleID string) domain.AccessBindingID {
	id := seedAccountBinding(repo, accountID, roleID, false)
	repo.mu.Lock()
	repo.ab.Labels = domain.Labels{"labelrevoke": "treska"}
	repo.mu.Unlock()
	return id
}

// TestUpdateAccessBinding_LabelChange_RematerializesObjectInProcess — clearing a label
// runs the object-forward pass for THIS binding, so the revoke does not queue behind
// the global reconcile backlog, while the durable event stays co-committed.
func TestUpdateAccessBinding_LabelChange_RematerializesObjectInProcess(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_lblremat", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedLabelledBinding(repo, accountID, roleID)

	rec := &recordingReconciler{}
	uc := NewUpdateAccessBindingUseCase(repo, newFakeOpsRepo()).
		WithRelationStore(newRecordingFGA(), nil).
		WithObjectReconciler(rec)

	_, err := uc.Execute(newOwnerContext(ownerID), id,
		[]string{"labels"}, false, nil) // proto3 map ⇒ nil body; "labels" in the mask means CLEAR
	require.NoError(t, err)

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	want := "object_forward:iam.accessBinding:" + string(id)
	calls := rec.awaitTrace(want, 5*time.Second)
	assert.Contains(t, calls, want,
		"a label change must re-materialize the access binding in-process (the forward's "+
			"delete-stale guard routes an object that already has members onto the FULL "+
			"recompute, which is what actually revokes the now-unmatched grant) — leaving it "+
			"to the FIFO reconcile queue made revoke latency a function of unrelated queue "+
			"depth (measured 7m30s)")
	assert.Contains(t, repo.drainReconcileObjects(), string(id),
		"the durable reconcile event stays co-committed as the at-least-once backstop")
}

// TestUpdateAccessBinding_DeletionProtectionOnly_NoRematerialization — clearing
// deletion_protection cannot change selector membership, so it must neither pay the
// O(scope) pass nor enqueue a reconcile event.
func TestUpdateAccessBinding_DeletionProtectionOnly_NoRematerialization(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_dponly", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedAccountBinding(repo, accountID, roleID, true)

	rec := &recordingReconciler{}
	uc := NewUpdateAccessBindingUseCase(repo, newFakeOpsRepo()).
		WithRelationStore(newRecordingFGA(), nil).
		WithObjectReconciler(rec)

	_, err := uc.Execute(newOwnerContext(ownerID), id,
		[]string{"deletion_protection"}, false, nil)
	require.NoError(t, err)

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	// Give a stray detached pass a chance to show up before asserting its absence.
	time.Sleep(200 * time.Millisecond)
	assert.Empty(t, rec.trace(),
		"only a labels change can flip selector membership — a deletion_protection update "+
			"must not schedule an O(scope) re-materialization")
	assert.Empty(t, repo.drainReconcileObjects(),
		"a deletion_protection update must not enqueue a reconcile event either")
}

// TestUpdateAccessBinding_LabelChange_NilReconciler_DurableEventStillEmitted — the
// in-process pass is an ACCELERATOR and is optional; the co-committed event is the
// at-least-once backstop and is not. An unwired reconciler must therefore leave today's
// behaviour exactly as it was: the durable event is still emitted and nothing panics.
func TestUpdateAccessBinding_LabelChange_NilReconciler_DurableEventStillEmitted(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_nilremat", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedLabelledBinding(repo, accountID, roleID)

	// No WithObjectReconciler — the queue-only wiring every existing test builds.
	uc := NewUpdateAccessBindingUseCase(repo, newFakeOpsRepo()).
		WithRelationStore(newRecordingFGA(), nil)

	_, err := uc.Execute(newOwnerContext(ownerID), id,
		[]string{"labels"}, false, nil)
	require.NoError(t, err)

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	assert.Contains(t, repo.drainReconcileObjects(), string(id),
		"the accelerator is optional, the durable backstop is not — an unwired reconciler "+
			"must still co-commit the reconcile event")
}
