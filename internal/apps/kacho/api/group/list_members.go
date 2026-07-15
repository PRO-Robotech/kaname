// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

// list_members.go — ListMembersUseCase.

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

type ListMembersUseCase struct {
	repo Repo
}

func NewListMembersUseCase(r Repo) *ListMembersUseCase {
	return &ListMembersUseCase{repo: r}
}

func (u *ListMembersUseCase) Execute(ctx context.Context, groupID domain.GroupID) ([]domain.GroupMember, error) {
	if err := shared.ValidateResourceID(string(groupID), domain.PrefixGroup, "group"); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	out, err := rd.Groups().ListMembers(ctx, groupID)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	return out, nil
}
