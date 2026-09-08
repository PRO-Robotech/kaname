// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package toproto

// service_account.go — Transfer domain.ServiceAccount → *iamv1.ServiceAccount.

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
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
		// Whether the account may authenticate. Reported because the issuance
		// paths now decide on it: a state that changes what the platform does
		// but that no reader can observe leaves an operator guessing why a
		// machine flow stopped working.
		Enabled: sa.Enabled,
	}, nil
}

func init() {
	dto.RegTransfer(dto.Fn2Face(saObj{}.toPb))
}
