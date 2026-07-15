// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package toproto

// project.go — Transfer domain.Project → *iamv1.Project.

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"
)

type projectObj struct{}

func (projectObj) toPb(p domain.Project) (*iamv1.Project, error) {
	var createdAt *timestamppb.Timestamp
	if !p.CreatedAt.IsZero() {
		createdAt = timestamppb.New(p.CreatedAt.Truncate(tsTruncate))
	}
	return &iamv1.Project{
		Id:          string(p.ID),
		AccountId:   string(p.AccountID),
		Name:        string(p.Name),
		Description: string(p.Description),
		Labels:      labelsToStringMap(p.Labels),
		CreatedAt:   createdAt,
	}, nil
}

func init() {
	dto.RegTransfer(dto.Fn2Face(projectObj{}.toPb))
}
