// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// create_op_done_not_gated_test.go — Operation.done reports DURABILITY of the
// binding row, never the visibility of its FGA materialization.
//
// The create-path runs two post-commit materialization passes
// (ReconcileBindingForward for this binding's own members, then the object pass for
// the binding-AS-OBJECT). Both are O(scope): a broad role bound at account scope
// materializes every in-scope object of every selectable type. While those passes
// ran INSIDE the operation worker-fn, `done` did not flip until the whole scope had
// been walked and materialized — i.e. `done` was gated on exactly the
// eventually-consistent downstream side-effect it is forbidden to gate on.
//
// Measured on the stand: an `admin` (verbs `*`) binding at account scope took 29.06s
// to report done, while its `view` sibling created 0.4s earlier on the SAME scope
// took 4.3s — the difference is the per-object tuple count each role emits, i.e.
// pure materialization volume. That measurement was taken against the external
// relation engine of the day; stage S6 removed it and materialization is cheaper
// now. The numbers stay as the ORIGIN of the rule, not as a current benchmark —
// what makes the rule stand is the contract (`done` = durability of the row), and
// that does not depend on how expensive the pass happens to be. A client polling a 15s budget times out on the first
// and not the second, and the binding row was durable within milliseconds in both.
//
// The contract this pins: the worker-fn returns once the writer-tx commits. The
// materialization passes still run — immediately, off the done-path — and the
// co-committed journal rows + reconcile event + periodic sweep remain the
// at-least-once backstop.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// blockingReconciler holds every materialization pass until released, standing in
// for the O(scope) walk the real reconciler performs.
type blockingReconciler struct {
	release chan struct{}
	entered chan struct{}
}

func newBlockingReconciler() *blockingReconciler {
	return &blockingReconciler{release: make(chan struct{}), entered: make(chan struct{}, 8)}
}

func (b *blockingReconciler) block() {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
}

func (b *blockingReconciler) ReconcileBindingForward(context.Context, domain.AccessBindingID) error {
	b.block()
	return nil
}

func (b *blockingReconciler) ReconcileBinding(context.Context, domain.AccessBindingID) error {
	b.block()
	return nil
}

func (b *blockingReconciler) ReconcileObjectForward(context.Context, string, string) error {
	b.block()
	return nil
}

func (b *blockingReconciler) ReconcileObjectForwardNoStale(context.Context, string, string) error {
	b.block()
	return nil
}

func (b *blockingReconciler) ReconcileObject(context.Context, string, string) error {
	b.block()
	return nil
}

var _ SelectorReconciler = (*blockingReconciler)(nil)

// TestCreateAccessBinding_OperationDoneNotGatedOnMaterialization — the Operation
// reports done as soon as the binding row is committed, even while the post-commit
// materialization passes are still running.
func TestCreateAccessBinding_OperationDoneNotGatedOnMaterialization(t *testing.T) {
	const (
		roleID     = "rol_opgate_role"
		roleName   = "kacho.admin"
		subjectID  = "usr_opgate_subject"
		resourceID = "prj_opgate_project"
		ownerID    = "usr_opgate_owner"
		accountID  = "acc_opgate_account"
	)
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID, roleName,
		domain.Permissions{"iam.access_bindings.get", "iam.access_bindings.update"})
	rec := newBlockingReconciler()
	ops := newFakeOpsRepo()

	createUC := NewCreateAccessBindingUseCase(repo, ops).
		WithRelationStore(newRecordingFGA(), nil).
		WithReconciler(rec)

	op, err := createUC.Execute(newOwnerContext(ownerID), domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "project",
		ResourceID:   resourceID,
	})
	require.NoError(t, err, "Create.Execute must succeed")
	require.NotNil(t, op)

	// The materialization pass must actually be in flight, otherwise the assertion
	// below would pass vacuously (nothing to be blocked behind).
	select {
	case <-rec.entered:
	case <-time.After(5 * time.Second):
		close(rec.release)
		t.Fatal("post-commit materialization pass never ran — test fixture is wrong")
	}

	// The binding row is committed by now; done must not wait for the pass.
	done := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, gerr := ops.Get(context.Background(), op.ID)
		require.NoError(t, gerr)
		if got.Done {
			done = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Release before asserting so a failure cannot leak the blocked goroutine.
	close(rec.release)

	assert.True(t, done,
		"Operation.done must report that the binding row is DURABLE (writer-tx committed), "+
			"never that its FGA tuples are visible — gating done on the O(scope) post-commit "+
			"materialization is what pushed a broad account-scoped grant past the client poll budget")

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "async Create worker must drain")
}
