// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

// remove_member.go — RemoveMemberUseCase.
// Идемпотентен: 0 rows affected — НЕ ошибка.

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

type RemoveMemberInput struct {
	GroupID    domain.GroupID
	MemberType domain.SubjectType
	MemberID   domain.SubjectID
}

type RemoveMemberUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

func NewRemoveMemberUseCase(r Repo, opsRepo operations.Repo) *RemoveMemberUseCase {
	return &RemoveMemberUseCase{repo: r, opsRepo: opsRepo}
}

func (u *RemoveMemberUseCase) Execute(ctx context.Context, in RemoveMemberInput) (*operations.Operation, error) {
	if err := shared.ValidateResourceID(string(in.GroupID), domain.PrefixGroup, "group"); err != nil {
		return nil, err
	}
	if in.MemberID == "" {
		return nil, shared.InvalidArg("member_id", "member_id required")
	}
	if err := in.MemberType.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}
	// Anti-anon + ownership check на group.account.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	g, err := rd.Groups().Get(ctx, in.GroupID)
	if err != nil {
		_ = rd.Rollback(ctx)
		return nil, shared.MapRepoErr(err)
	}
	acct, err := rd.Accounts().Get(ctx, g.AccountID)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if err := authzguard.RequireOwnerMatchesPrincipal(ctx, string(acct.OwnerUserID)); err != nil {
		return nil, err
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Remove member %s/%s from group %s", in.MemberType, in.MemberID, in.GroupID),
		// account_id from the group loaded sync for authz (g.AccountID) so member-
		// change ops also surface in the account-scoped list (BLOCK-1 1.2-11e, D-8).
		&iamv1.RemoveGroupMemberMetadata{GroupId: string(in.GroupID), MemberId: string(in.MemberID), AccountId: string(g.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doRemove(ctx, in)
	})
	return &op, nil
}

func (u *RemoveMemberUseCase) doRemove(ctx context.Context, in RemoveMemberInput) (*anypb.Any, error) {
	m := domain.GroupMember{
		GroupID:    in.GroupID,
		MemberType: in.MemberType,
		MemberID:   in.MemberID,
	}
	if err := shared.DoWithWriteTxVoid(ctx, u.repo,
		func(ctx context.Context, w Writer) error {
			if err := w.GroupsW().RemoveMember(ctx, in.GroupID, in.MemberType, in.MemberID); err != nil {
				return err
			}
			// Symmetric co-commit of the FGA member-tuple DELETE intent in the SAME
			// writer-tx (запрет #10): removing the membership row revokes the
			// `group:<gid>#member@<member>` userset tuple so the member loses any
			// access a GROUP-subject binding granted via the group. Idempotent at the
			// drainer (a missing tuple delete is a no-op); rollback discards both.
			return w.EmitFGARelationDelete(ctx, []service.RelationTuple{memberFGATuple(m)})
		}); err != nil {
		return nil, err
	}
	return anypb.New(&emptypb.Empty{})
}
