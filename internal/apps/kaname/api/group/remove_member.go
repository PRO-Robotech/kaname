// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

// remove_member.go — RemoveMemberUseCase.
// Идемпотентен: 0 rows affected — НЕ ошибка.

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/service"
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
	// Anti-anon floor only. WHO may change this group's membership is decided by
	// the MODEL: the api-gateway Checks `v_update@iam_group:<group_id>` before
	// iam is dialed (security.md «Авторизация живёт в МОДЕЛИ, а не в самодельных
	// проверках»).
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	g, err := rd.Groups().Get(ctx, in.GroupID)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
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
			if err := w.EmitFGARelationDelete(ctx, []service.RelationTuple{memberFGATuple(m)}); err != nil {
				return err
			}
			// Drop the member's cached verdicts. The tuple intent above travels to
			// the relation store; it reaches NO verdict cache, and verdict caches are
			// dropped by exactly one path — a subject_change_outbox row drained to the
			// journal read by the edge itself. Same writer-tx as the membership DML (ban #10):
			// a rolled-back change must not announce an invalidation that had no cause.
			//
			// The subject is the MEMBER: the edge keys cached verdicts by whoever
			// presented the token, and the member is who gains or loses access through
			// the `group:<gid>#member` userset.
			return w.AccessBindingsW().EmitSubjectChangeEvent(ctx, abrepo.SubjectChangeEvent{
				SubjectID:   string(in.MemberID),
				SubjectType: string(in.MemberType),
				EventType:   "group_member_change",
				Op:          "group_member_change",
			})
		}); err != nil {
		return nil, err
	}
	return anypb.New(&emptypb.Empty{})
}
