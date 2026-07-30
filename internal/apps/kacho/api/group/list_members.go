// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

// list_members.go — ListMembersUseCase.

import (
	"context"

	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repogroup "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
)

// ListMembersInput — one page of a group's membership.
type ListMembersInput struct {
	GroupID   domain.GroupID
	PageSize  int64
	PageToken string
}

// ListMembersOutput — the page plus the continuation token, empty on the last page.
type ListMembersOutput struct {
	Members       []domain.GroupMember
	NextPageToken string
}

type ListMembersUseCase struct {
	repo Repo
}

func NewListMembersUseCase(r Repo) *ListMembersUseCase {
	return &ListMembersUseCase{repo: r}
}

// Execute returns one page of the membership.
//
// page_size is validated HERE, before the storage is touched: an out-of-range value
// is a refusal, never a clamp (a clamped page makes the caller believe it received
// everything it asked for), and the refusal must not depend on how far down the
// call the storage happens to check. The adapter keeps its own check as the
// authoritative backstop.
func (u *ListMembersUseCase) Execute(ctx context.Context, in ListMembersInput) (ListMembersOutput, error) {
	if err := shared.ValidateResourceID(string(in.GroupID), domain.PrefixGroup, "group"); err != nil {
		return ListMembersOutput{}, err
	}
	size, err := corevalidate.PageSize("page_size", in.PageSize)
	if err != nil {
		return ListMembersOutput{}, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return ListMembersOutput{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	out, next, err := rd.Groups().ListMembers(ctx, in.GroupID, repogroup.MemberPage{
		PageSize:  size,
		PageToken: in.PageToken,
	})
	if err != nil {
		return ListMembersOutput{}, shared.MapRepoErr(err)
	}
	return ListMembersOutput{Members: out, NextPageToken: next}, nil
}
