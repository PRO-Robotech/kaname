// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// update_label_rematerialize_test.go — a user label change must re-materialize the
// object IMMEDIATELY, not only through the reconcile queue.
//
// iam.user is label-selectable (domain.labelSelectableTypes carries "iam.user";
// kacho_iam.users.labels — migration 0041 — is probed by `labels @> match_labels` in
// MatchIAMDirect), so removing a label that an ARM_LABELS grant matches is a
// REVOCATION: the per-object member row and its FGA tuples must go. Two feeds reach
// the same reconciler for that:
//
//   - CROSS-SERVICE (vpc/compute/nlb): the owning service re-calls
//     InternalIAMService.RegisterResource on a label update, and RegisterResource runs
//     ReconcileObjectForward in-process. The forward's delete-stale guard sees the
//     object already has members, delegates to the FULL ReconcileObject, and the stale
//     grant is revoked there and then.
//
//   - IAM-DIRECT (this path): User.Update only co-committed a
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
// This pins the missing half: the iam-native label-update path performs the same
// in-process object re-materialization its cross-service twin performs, so revoke
// latency stops depending on how many unrelated events are queued ahead of it. Like
// every other post-commit pass it runs OFF the Operation.done path (ban #9) — the
// co-committed event and the periodic sweep remain the at-least-once backstop.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// recordingObjectReconciler records which object-reconcile entry point the use-case
// picked, if any.
type recordingObjectReconciler struct {
	mu    sync.Mutex
	calls []string
}

func (r *recordingObjectReconciler) record(c string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, c)
}

func (r *recordingObjectReconciler) trace() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.calls))
	copy(out, r.calls)
	return out
}

// awaitTrace waits (bounded) for `want`, then returns the trace. The pass is detached
// from the operation worker, so operations.Wait does not imply it has run.
func (r *recordingObjectReconciler) awaitTrace(want string, budget time.Duration) []string {
	deadline := time.Now().Add(budget)
	for {
		calls := r.trace()
		for _, c := range calls {
			if c == want {
				return calls
			}
		}
		if time.Now().After(deadline) {
			return calls
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *recordingObjectReconciler) ReconcileObjectForward(_ context.Context, objectType, objectID string) error {
	r.record("object_forward:" + objectType + ":" + objectID)
	return nil
}

// ReconcileObjectForwardNoStale — ДОКАЗАННЫЙ вход того же прохода. Дублёр обязан
// отвечать на оба, иначе он не удовлетворяет порту; тела совпадают, потому что
// различие входов — про блокировки и чтение у настоящего реконсайлера, а не про
// то, что видит этот тест.
func (r *recordingObjectReconciler) ReconcileObjectForwardNoStale(_ context.Context, objectType, objectID string) error {
	r.record("object_forward_nostale:" + objectType + ":" + objectID)
	return nil
}

func (r *recordingObjectReconciler) ReconcileObject(_ context.Context, objectType, objectID string) error {
	r.record("object_full:" + objectType + ":" + objectID)
	return nil
}

var _ ObjectForwardReconciler = (*recordingObjectReconciler)(nil)

// TestUpdateUser_LabelChange_RematerializesObjectInProcess — clearing a label runs the
// object-forward pass for THIS user, so the revoke does not queue behind the global
// reconcile backlog.
func TestUpdateUser_LabelChange_RematerializesObjectInProcess(t *testing.T) {
	repo := newUpdUserRepo()
	repo.user.Labels = domain.Labels{"labelrevoke": "treska"}
	rec := &recordingObjectReconciler{}
	uc := NewUpdateUserUseCase(repo, newUpdOpsRepo()).WithObjectReconciler(rec, nil)

	_, err := uc.Execute(ownerCtx(), UpdateUserInput{
		ID:         domain.UserID(updUserID),
		Labels:     nil, // proto3 map ⇒ nil body; "labels" in the mask means CLEAR
		UpdateMask: []string{"labels"},
	})
	require.NoError(t, err)

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	want := "object_forward:iam.user:" + updUserID
	calls := rec.awaitTrace(want, 5*time.Second)
	assert.Contains(t, calls, want,
		"a label change must re-materialize the user in-process (the forward's delete-stale "+
			"guard routes an object that already has members onto the FULL recompute, which is "+
			"what actually revokes the now-unmatched grant) — leaving it to the FIFO reconcile "+
			"queue made revoke latency a function of unrelated queue depth (measured 7m30s)")
	assert.Contains(t, repo.reconcileSnapshot(), updUserID,
		"the durable reconcile event stays co-committed as the at-least-once backstop")
}

// TestUpdateUser_NoLabelChange_NoRematerialization — labels are the ONLY mutable field
// of User.Update, so the non-label analogue is an update that leaves them untouched: it
// cannot flip selector membership and must not pay the O(scope) pass.
func TestUpdateUser_NoLabelChange_NoRematerialization(t *testing.T) {
	repo := newUpdUserRepo()
	repo.user.Labels = domain.Labels{"labelrevoke": "treska"}
	rec := &recordingObjectReconciler{}
	uc := NewUpdateUserUseCase(repo, newUpdOpsRepo()).WithObjectReconciler(rec, nil)

	_, err := uc.Execute(ownerCtx(), UpdateUserInput{
		ID:         domain.UserID(updUserID),
		Labels:     domain.Labels{"labelrevoke": "treska"}, // identical → no-op
		UpdateMask: []string{"labels"},
	})
	require.NoError(t, err)

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	// Give a stray detached pass a chance to show up before asserting its absence.
	time.Sleep(200 * time.Millisecond)
	assert.Empty(t, rec.trace(),
		"unchanged labels cannot flip selector membership — the update must not schedule "+
			"an O(scope) re-materialization")
}
