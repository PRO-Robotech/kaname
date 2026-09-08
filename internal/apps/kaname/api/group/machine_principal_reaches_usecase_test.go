// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

// machine_principal_reaches_usecase_test.go — GroupService Update / Delete /
// AddMember / RemoveMember must not re-decide authorization in-service.
//
// These four RPCs are gated by the MODEL: the api-gateway resolves the target
// group from the request and Checks `v_update` / `v_delete` on
// `iam_group:<group_id>` before iam is ever dialed (permission catalog; locked
// by gateway/internal/middleware/authz_iam_owner_guard_model_gate_test.go).
// The use-case therefore sees only callers the model already admitted.
//
// The removed `authzguard.RequireOwnerMatchesPrincipal` re-decided that on its
// own, comparing the caller's id against `accounts.owner_user_id`. Because a
// service-account id can never equal an account's owner user-id, every machine
// principal was rejected here BY CONSTRUCTION — with `InvalidArgument` naming a
// field (`owner_user_id`) the caller never sent, and regardless of what the
// model had granted it. It also nullified any delegation the owner made through
// an AccessBinding, and locked out cluster-admins on accounts they do not own.
//
// These tests assert the use-case no longer forms an opinion about identity: a
// model-admitted machine principal reaches the Operation. They say nothing
// about who the model SHOULD admit — that is the gateway test's job.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// machineCtx — a service-account principal, i.e. one that can never equal
// `accounts.owner_user_id` (metaOwner). The gateway has already Checked
// `v_update`/`v_delete` on the target group for it.
func machineCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva0000000000000bot1"})
}

// delegatedUserCtx — a HUMAN who is not the account owner but holds the verb
// through an AccessBinding the owner created. The removed guard denied this
// caller too, which silently voided a grant the owner had deliberately made.
func delegatedUserCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000dlgt"})
}

func nonOwnerCtxs() map[string]context.Context {
	return map[string]context.Context{
		"service_account": machineCtx(),
		"delegated_user":  delegatedUserCtx(),
	}
}

func TestUpdateGroup_NonOwnerPrincipal_NotRejectedInService(t *testing.T) {
	for name, ctx := range nonOwnerCtxs() {
		t.Run(name, func(t *testing.T) {
			newName := domain.GroupName("renamed")
			uc := NewUpdateGroupUseCase(newFakeGrpRepo(), newFakeGrpOps())
			op, err := uc.Execute(ctx, UpdateGroupInput{
				ID: metaGrp, Name: &newName, UpdateMask: []string{"name"},
			})
			require.NoError(t, err,
				"GroupService.Update is gated by v_update@iam_group at the gateway; "+
					"the use-case must not re-decide access from accounts.owner_user_id")
			assert.NotNil(t, op)
		})
	}
}

func TestDeleteGroup_NonOwnerPrincipal_NotRejectedInService(t *testing.T) {
	for name, ctx := range nonOwnerCtxs() {
		t.Run(name, func(t *testing.T) {
			uc := NewDeleteGroupUseCase(newFakeGrpRepo(), newFakeGrpOps())
			op, err := uc.Execute(ctx, metaGrp)
			require.NoError(t, err,
				"GroupService.Delete is gated by v_delete@iam_group at the gateway")
			assert.NotNil(t, op)
		})
	}
}

func TestAddGroupMember_NonOwnerPrincipal_NotRejectedInService(t *testing.T) {
	for name, ctx := range nonOwnerCtxs() {
		t.Run(name, func(t *testing.T) {
			uc := NewAddMemberUseCase(newFakeGrpRepo(), newFakeGrpOps())
			op, err := uc.Execute(ctx, AddMemberInput{
				GroupID: metaGrp, MemberType: domain.SubjectTypeUser, MemberID: "usr0000000000000mmmm",
			})
			require.NoError(t, err,
				"GroupService.AddMember is gated by v_update@iam_group at the gateway — "+
					"membership changes ride the group's update verb")
			assert.NotNil(t, op)
		})
	}
}

func TestRemoveGroupMember_NonOwnerPrincipal_NotRejectedInService(t *testing.T) {
	for name, ctx := range nonOwnerCtxs() {
		t.Run(name, func(t *testing.T) {
			uc := NewRemoveMemberUseCase(newFakeGrpRepo(), newFakeGrpOps())
			op, err := uc.Execute(ctx, RemoveMemberInput{
				GroupID: metaGrp, MemberType: domain.SubjectTypeUser, MemberID: "usr0000000000000mmmm",
			})
			require.NoError(t, err,
				"GroupService.RemoveMember is gated by v_update@iam_group at the gateway")
			assert.NotNil(t, op)
		})
	}
}

// An ANONYMOUS caller must still be rejected in-service: RequireAuthenticated is
// a separate, still-live floor (defence-in-depth against a mis-wired listener),
// not part of the removed owner-equality guard.
func TestGroupMutations_AnonymousStillRejected(t *testing.T) {
	t.Run("update", func(t *testing.T) {
		uc := NewUpdateGroupUseCase(newFakeGrpRepo(), newFakeGrpOps())
		_, err := uc.Execute(context.Background(), UpdateGroupInput{
			ID: metaGrp, UpdateMask: []string{"labels"},
		})
		require.Error(t, err)
	})
	t.Run("delete", func(t *testing.T) {
		uc := NewDeleteGroupUseCase(newFakeGrpRepo(), newFakeGrpOps())
		_, err := uc.Execute(context.Background(), metaGrp)
		require.Error(t, err)
	})
	t.Run("add_member", func(t *testing.T) {
		uc := NewAddMemberUseCase(newFakeGrpRepo(), newFakeGrpOps())
		_, err := uc.Execute(context.Background(), AddMemberInput{
			GroupID: metaGrp, MemberType: domain.SubjectTypeUser, MemberID: "usr0000000000000mmmm",
		})
		require.Error(t, err)
	})
	t.Run("remove_member", func(t *testing.T) {
		uc := NewRemoveMemberUseCase(newFakeGrpRepo(), newFakeGrpOps())
		_, err := uc.Execute(context.Background(), RemoveMemberInput{
			GroupID: metaGrp, MemberType: domain.SubjectTypeUser, MemberID: "usr0000000000000mmmm",
		})
		require.Error(t, err)
	})
}
