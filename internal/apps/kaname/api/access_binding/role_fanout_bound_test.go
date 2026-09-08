// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// role_fanout_bound_test.go — bound-check for a Role.Update rules change. A
// Role.Update whose rules change is rejected FAILED_PRECONDITION when the
// role is carried by more than the contract limit (10000) of active bindings, BEFORE
// any fan-out work (the Operation is not even created). Unit test over the fake repo
// + a fake fanout; no Postgres (a service-layer Postgres dependency would be adapter
// leakage).

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// fakeFanout — a role.RulesMembershipFanout returning a fixed active-binding count
// and recording whether the post-commit reconcile was invoked.
//
// The pass runs on a goroutine DETACHED from the operation (shared.GoPostCommit), so
// the fact it records is written by a goroutine other than the one that asserts on
// it, and awaitOpDone is NOT a barrier for it: done means the row is durable, never
// that the detached pass has been observed (ban #9). A plain bool field is therefore
// two defects at once — a data race, and an assertion free to read `false` while the
// pass is still in flight. The record is a channel the pass closes: the close
// publishes everything before it, so the wait is race-free AND deterministic, ending
// the instant the pass runs, with no polling and no sleep.
type fakeFanout struct {
	count int
	err   error

	once sync.Once
	ran  chan struct{} // closed by the first ReconcileActiveBindings
}

func newFakeFanout(count int) *fakeFanout {
	return &fakeFanout{count: count, ran: make(chan struct{})}
}

func (f *fakeFanout) CountActiveBindings(context.Context, domain.RoleID) (int, error) {
	return f.count, f.err
}
func (f *fakeFanout) ReconcileActiveBindings(context.Context, domain.RoleID) error {
	f.once.Do(func() { close(f.ran) })
	return nil
}

// reconciled reports whether the pass has run BY NOW, without blocking.
func (f *fakeFanout) reconciled() bool {
	select {
	case <-f.ran:
		return true
	default:
		return false
	}
}

// awaitReconciled blocks until the detached pass has run, or until the budget
// expires, and reports which happened. Expiry is a real failure of the property
// under test, not a flake to be papered over.
func (f *fakeFanout) awaitReconciled(budget time.Duration) bool {
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-f.ran:
		return true
	case <-timer.C:
		return false
	}
}

func TestRoleUpdate_C21_FanoutBoundExceeded_FailedPrecondition(t *testing.T) {
	const ownerID, accountID, resourceID = "usr_owner_c21a", "acc_c21a", "prj_c21a"
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID178a, "viewer",
		domain.Permissions{"compute.instance.*.get"})
	repo.setRoleCustom(accountID) // custom role → Role.Update account-owner gate passes
	opsRepo := newFakeOpsRepo()
	fan := newFakeFanout(roleapp.MaxRoleFanoutBindings + 1)

	uc := roleapp.NewUpdateRoleUseCase(repo, opsRepo, catalogfixture.Source()).
		WithTupleReconciler(NewRoleTupleReconciler()).
		WithMembershipFanout(fan)

	_, err := uc.Execute(newOwnerContext(ownerID), roleUpdateInput(roleID178a, domain.Rules{
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"env": "prod"}},
	}))
	require.Error(t, err, "a role over the fan-out limit must be rejected SYNC")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "too many bindings")
	// Rejected synchronously, before the Operation exists, so nothing is in flight
	// to be waited on: the pass either never started or the bound did not hold.
	assert.False(t, fan.reconciled(), "the fan-out must NOT run when the bound is exceeded")
}

func TestRoleUpdate_C21_FanoutWithinBound_Runs(t *testing.T) {
	const ownerID, accountID, resourceID = "usr_owner_c21b", "acc_c21b", "prj_c21b"
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID178b, "viewer",
		domain.Permissions{"compute.instance.*.get"})
	repo.setRoleCustom(accountID)
	opsRepo := newFakeOpsRepo()
	fan := newFakeFanout(3)

	uc := roleapp.NewUpdateRoleUseCase(repo, opsRepo, catalogfixture.Source()).
		WithTupleReconciler(NewRoleTupleReconciler()).
		WithMembershipFanout(fan)

	op, err := uc.Execute(newOwnerContext(ownerID), roleUpdateInput(roleID178b, domain.Rules{
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"env": "prod"}},
	}))
	require.NoError(t, err)
	awaitOpDone(t, opsRepo, op.ID)
	// op-done is the barrier for the COMMITTED change, not for the detached pass;
	// the pass has its own.
	assert.True(t, fan.awaitReconciled(5*time.Second),
		"within-bound rules change runs the membership fan-out")
}
