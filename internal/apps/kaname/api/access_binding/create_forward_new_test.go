// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// create_forward_new_test.go — the create-path must announce that the binding-OBJECT
// it hands to the reconciler is BRAND-NEW.
//
// Create runs two post-commit passes: ReconcileBindingForward (this binding's own
// members) and then the object pass for the binding-AS-OBJECT. The first one writes a
// member row ON THAT OBJECT whenever an anchor/`*.*` role in scope covers
// iam.accessBinding — which is the ordinary account-admin/owner shape. The plain
// object-forward reads such rows as "this object existed before" (its delete-stale
// guard) and falls back to the FULL EXCLUSIVE ReconcileObject, where every
// access_binding of an account queues on the single account-admin binding's advisory
// lock: measured against the Read API, the subject's own tuples landed in ~3s, the
// scope parent-pointer in ~61s and the account-admin's per-object verbs in ~67s,
// against a 25s poll budget.
//
// Swapping the two passes just moves the starvation. The create-path therefore uses
// the PROVEN-NEW entry point, whose contract is "this id was minted in the writer-tx
// that just committed" — nothing stale can exist on it, so the guard is skipped for
// this call and this call only.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// recordingReconciler records which reconcile entry point the use-case picked.
type recordingReconciler struct {
	mu    sync.Mutex
	calls []string
}

func (r *recordingReconciler) record(call string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call)
}

func (r *recordingReconciler) trace() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.calls))
	copy(out, r.calls)
	return out
}

// awaitTrace waits (bounded) for `want` to appear in the trace and returns the trace
// as it stood at that moment — or the final trace if the wait elapsed. The create-path
// materialization passes are DETACHED from the operation worker (shared.GoPostCommit,
// so Operation.done is not gated on them, ban #9), which means operations.Wait no
// longer implies they have run. Polling for the expected call keeps the assertion
// deterministic without weakening it: a pass that never runs still fails, on the
// unchanged assertions below.
func (r *recordingReconciler) awaitTrace(want string, budget time.Duration) []string {
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

func (r *recordingReconciler) ReconcileBindingForward(_ context.Context, id domain.AccessBindingID) error {
	r.record("binding_forward:" + string(id))
	return nil
}

func (r *recordingReconciler) ReconcileBinding(_ context.Context, id domain.AccessBindingID) error {
	r.record("binding_full:" + string(id))
	return nil
}

func (r *recordingReconciler) ReconcileObjectForward(_ context.Context, objectType, objectID string) error {
	r.record("object_forward:" + objectType + ":" + objectID)
	return nil
}

func (r *recordingReconciler) ReconcileObjectForwardNoStale(_ context.Context, objectType, objectID string) error {
	r.record("object_forward_new:" + objectType + ":" + objectID)
	return nil
}

func (r *recordingReconciler) ReconcileObject(_ context.Context, objectType, objectID string) error {
	r.record("object_full:" + objectType + ":" + objectID)
	return nil
}

var _ SelectorReconciler = (*recordingReconciler)(nil)

// TestCreateAccessBinding_ObjectPass_UsesProvenNewEntryPoint — the create-path hands
// the freshly-minted binding-object to the PROVEN-NEW forward, never to the
// guard-bearing entry point that would bounce it onto the FULL EXCLUSIVE recompute,
// and never to the full path directly.
func TestCreateAccessBinding_ObjectPass_UsesProvenNewEntryPoint(t *testing.T) {
	const (
		roleID     = "rol_fwdnew_role"
		roleName   = "kacho.edit"
		subjectID  = "usr_fwdnew_subject"
		resourceID = "prj_fwdnew_project"
		ownerID    = "usr_fwdnew_owner"
		accountID  = "acc_fwdnew_account"
	)
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID, roleName,
		domain.Permissions{"iam.access_bindings.get", "iam.access_bindings.update"})
	rec := &recordingReconciler{}

	createUC := NewCreateAccessBindingUseCase(repo, newFakeOpsRepo()).
		WithRelationStore(newRecordingFGA(), nil).
		WithReconciler(rec)
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

	id := string(repo.lastInsertedID())
	require.NotEmpty(t, id)

	calls := rec.awaitTrace("object_forward_new:iam.accessBinding:"+id, 5*time.Second)
	assert.Contains(t, calls, "object_forward_new:iam.accessBinding:"+id,
		"the create-path must declare the binding-object PROVEN-NEW, so the delete-stale guard "+
			"cannot mistake this same create's member rows for pre-existing state")
	assert.NotContains(t, calls, "object_forward:iam.accessBinding:"+id,
		"the guard-bearing entry point defeats the create fast-path (members written by the "+
			"sibling ReconcileBindingForward pass bounce it onto the FULL EXCLUSIVE recompute)")
	assert.NotContains(t, calls, "object_full:iam.accessBinding:"+id,
		"the create hot-path must never call the FULL EXCLUSIVE object recompute synchronously "+
			"— it is the async at-least-once backstop")
}
