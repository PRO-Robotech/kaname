// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// role_fanout_bound_test.go — bound-check for a Role.Update rules change. A
// Role.Update whose rules change is rejected FAILED_PRECONDITION when the
// role is carried by more than the contract limit (10000) of active bindings, BEFORE
// any fan-out work (the Operation is not even created). Unit test over the fake repo
// + a fake fanout; no Postgres (a service-layer Postgres dependency would be adapter
// leakage).

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	roleapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// fakeFanout — a role.RulesMembershipFanout returning a fixed active-binding count
// and recording whether the post-commit reconcile was invoked.
type fakeFanout struct {
	count      int
	reconciled bool
	err        error
}

func (f *fakeFanout) CountActiveBindings(context.Context, domain.RoleID) (int, error) {
	return f.count, f.err
}
func (f *fakeFanout) ReconcileActiveBindings(context.Context, domain.RoleID) error {
	f.reconciled = true
	return nil
}

func TestRoleUpdate_C21_FanoutBoundExceeded_FailedPrecondition(t *testing.T) {
	const ownerID, accountID, resourceID = "usr_owner_c21a", "acc_c21a", "prj_c21a"
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID178a, "viewer",
		domain.Permissions{"compute.instance.*.get"})
	repo.setRoleCustom(accountID) // custom role → Role.Update account-owner gate passes
	opsRepo := newFakeOpsRepo()
	fan := &fakeFanout{count: roleapp.MaxRoleFanoutBindings + 1}

	uc := roleapp.NewUpdateRoleUseCase(repo, opsRepo).
		WithTupleReconciler(NewRoleTupleReconciler()).
		WithMembershipFanout(fan)

	_, err := uc.Execute(newOwnerContext(ownerID), roleUpdateInput(roleID178a, domain.Rules{
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"env": "prod"}},
	}))
	require.Error(t, err, "a role over the fan-out limit must be rejected SYNC")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "too many bindings")
	assert.False(t, fan.reconciled, "the fan-out must NOT run when the bound is exceeded")
}

func TestRoleUpdate_C21_FanoutWithinBound_Runs(t *testing.T) {
	const ownerID, accountID, resourceID = "usr_owner_c21b", "acc_c21b", "prj_c21b"
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID178b, "viewer",
		domain.Permissions{"compute.instance.*.get"})
	repo.setRoleCustom(accountID)
	opsRepo := newFakeOpsRepo()
	fan := &fakeFanout{count: 3}

	uc := roleapp.NewUpdateRoleUseCase(repo, opsRepo).
		WithTupleReconciler(NewRoleTupleReconciler()).
		WithMembershipFanout(fan)

	op, err := uc.Execute(newOwnerContext(ownerID), roleUpdateInput(roleID178b, domain.Rules{
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"env": "prod"}},
	}))
	require.NoError(t, err)
	awaitOpDone(t, opsRepo, op.ID)
	assert.True(t, fan.reconciled, "within-bound rules change runs the membership fan-out")
}
