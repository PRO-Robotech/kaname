// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package toproto

// user.go — Transfer domain.User → *iamv1.User.

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"
)

type userObj struct{}

func (userObj) toPb(u domain.User) (*iamv1.User, error) {
	var createdAt *timestamppb.Timestamp
	if !u.CreatedAt.IsZero() {
		createdAt = timestamppb.New(u.CreatedAt.Truncate(tsTruncate))
	}
	return &iamv1.User{
		Id:           string(u.ID),
		AccountId:    string(u.AccountID),
		ExternalId:   string(u.ExternalID),
		Email:        string(u.Email),
		DisplayName:  string(u.DisplayName),
		CreatedAt:    createdAt,
		InviteStatus: inviteStatusToPb(u.InviteStatus),
		InvitedBy:    string(u.InvitedBy),
		Labels:       labelsToStringMap(u.Labels),
	}, nil
}

func inviteStatusToPb(s domain.InviteStatus) iamv1.User_InviteStatus {
	switch s {
	case domain.InviteStatusPending:
		return iamv1.User_PENDING
	case domain.InviteStatusActive:
		return iamv1.User_ACTIVE
	case domain.InviteStatusBlocked:
		return iamv1.User_BLOCKED
	default:
		return iamv1.User_INVITE_STATUS_UNSPECIFIED
	}
}

func init() {
	dto.RegTransfer(dto.Fn2Face(userObj{}.toPb))
}
