// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package toproto

// account.go — Transfer domain.Account → *iamv1.Account.
// Registered via init() (use-cases blank-import the package).
// Parity with kacho-vpc/internal/dto/toproto/network.go.

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"
)

type accountObj struct{}

func (accountObj) toPb(a domain.Account) (*iamv1.Account, error) {
	// timestamppb is routed through the DTO registry in kacho-vpc; here we
	// inline truncate-to-seconds for simplicity (Kachō timestamp convention).
	var createdAt *timestamppb.Timestamp
	if !a.CreatedAt.IsZero() {
		createdAt = timestamppb.New(a.CreatedAt.Truncate(tsTruncate))
	}
	return &iamv1.Account{
		Id:          string(a.ID),
		Name:        string(a.Name),
		Description: string(a.Description),
		Labels:      labelsToStringMap(a.Labels),
		OwnerUserId: string(a.OwnerUserID),
		CreatedAt:   createdAt,
	}, nil
}

func labelsToStringMap(l domain.Labels) map[string]string {
	if len(l) == 0 {
		return nil
	}
	m := make(map[string]string, len(l))
	for k, v := range l {
		m[string(k)] = string(v)
	}
	return m
}

func init() {
	dto.RegTransfer(dto.Fn2Face(accountObj{}.toPb))
}
