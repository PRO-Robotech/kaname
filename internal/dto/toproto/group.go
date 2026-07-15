// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package toproto

// group.go — Transfer domain.Group → *iamv1.Group + GroupMember → *iamv1.GroupMember.

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"
)

type groupObj struct{}

func (groupObj) toPb(g domain.Group) (*iamv1.Group, error) {
	var createdAt *timestamppb.Timestamp
	if !g.CreatedAt.IsZero() {
		createdAt = timestamppb.New(g.CreatedAt.Truncate(tsTruncate))
	}
	return &iamv1.Group{
		Id:          string(g.ID),
		AccountId:   string(g.AccountID),
		Name:        string(g.Name),
		Description: string(g.Description),
		Labels:      labelsToStringMap(g.Labels),
		CreatedAt:   createdAt,
	}, nil
}

type groupMemberObj struct{}

func (groupMemberObj) toPb(m domain.GroupMember) (*iamv1.GroupMember, error) {
	var addedAt *timestamppb.Timestamp
	if !m.AddedAt.IsZero() {
		addedAt = timestamppb.New(m.AddedAt.Truncate(tsTruncate))
	}
	return &iamv1.GroupMember{
		MemberType: string(m.MemberType),
		MemberId:   string(m.MemberID),
		AddedAt:    addedAt,
	}, nil
}

func init() {
	dto.RegTransfer(dto.Fn2Face(groupObj{}.toPb))
	dto.RegTransfer(dto.Fn2Face(groupMemberObj{}.toPb))
}
