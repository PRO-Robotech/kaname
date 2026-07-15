// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package toproto

// service_account.go — Transfer domain.ServiceAccount → *iamv1.ServiceAccount.

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"
)

type saObj struct{}

func (saObj) toPb(sa domain.ServiceAccount) (*iamv1.ServiceAccount, error) {
	var createdAt *timestamppb.Timestamp
	if !sa.CreatedAt.IsZero() {
		createdAt = timestamppb.New(sa.CreatedAt.Truncate(tsTruncate))
	}
	return &iamv1.ServiceAccount{
		Id:          string(sa.ID),
		AccountId:   string(sa.AccountID),
		Name:        string(sa.Name),
		Description: string(sa.Description),
		CreatedAt:   createdAt,
		Labels:      labelsToStringMap(sa.Labels),
	}, nil
}

func init() {
	dto.RegTransfer(dto.Fn2Face(saObj{}.toPb))
}
