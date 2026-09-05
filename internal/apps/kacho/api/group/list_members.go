// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

// list_members.go — ListMembersUseCase.

import (
	"context"

	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	repogroup "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/group"
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
	// relations — the relation-Check port this read re-asks about the group NAMED
	// IN THE REQUEST. See Execute.
	relations authzguard.RelationChecker
}

func NewListMembersUseCase(r Repo) *ListMembersUseCase {
	return &ListMembersUseCase{repo: r}
}

// WithRelationStore wires the relation-Check port. Unwired, the roster is served
// to nobody: a read whose remaining authorization lives one layer up must not
// quietly become a read with none.
func (u *ListMembersUseCase) WithRelationStore(relations authzguard.RelationChecker) *ListMembersUseCase {
	u.relations = relations
	return u
}

// Execute returns one page of the membership.
//
// page_size is validated HERE, before the storage is touched: an out-of-range value
// is a refusal, never a clamp (a clamped page makes the caller believe it received
// everything it asked for), and the refusal must not depend on how far down the
// call the storage happens to check. The adapter keeps its own check as the
// authoritative backstop.
//
// Then the group NAMED IN THE REQUEST is re-asked about, on `v_list` — the same
// relation the front door requires of this RPC, so a caller admitted there is
// admitted here. Both sibling reads of this resource already do it (`Get` on
// `v_get`, `List` through the per-object page filter); this one did not, and it is
// also the only one of the three whose name the List-surface analyser cannot see.
// A denial is the resource's own miss, verbatim, so it cannot be told from the
// group not existing; a model that could not be ASKED is an outage, never a miss.
func (u *ListMembersUseCase) Execute(ctx context.Context, in ListMembersInput) (ListMembersOutput, error) {
	if err := shared.ValidateResourceID(string(in.GroupID), domain.PrefixGroup, "group"); err != nil {
		return ListMembersOutput{}, err
	}
	size, err := corevalidate.PageSize("page_size", in.PageSize)
	if err != nil {
		return ListMembersOutput{}, err
	}
	// Authorized BEFORE the storage is read: a refusal that has already fetched
	// the roster has paid for the answer it claims to withhold.
	allowed, azErr := authzguard.AllowsVerb(ctx, u.relations, "v_list", "iam_group", string(in.GroupID))
	if azErr != nil {
		return ListMembersOutput{}, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	if !allowed {
		return ListMembersOutput{}, shared.MapRepoErr(
			iamerr.Wrapf(iamerr.ErrNotFound, "Group %s not found", in.GroupID))
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
