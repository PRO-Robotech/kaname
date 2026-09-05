// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package project

// helpers.go — marshalProject DTO-обертка.

import (
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/dto"

	_ "github.com/PRO-Robotech/kacho-iam/internal/dto/toproto"
)

func marshalProject(p domain.Project) (*anypb.Any, error) {
	var dst *iamv1.Project
	if err := dto.Transfer(dto.FromTo(p, &dst)); err != nil {
		return nil, fmt.Errorf("dto.Transfer Project: %w", err)
	}
	return anypb.New(dst)
}

// labelsChanged reports whether "labels" is among the changed fields of a
// Project.Update — the only change that can flip iam-direct selector membership
// (T3/Q2). name/description do not affect selector matching.
func labelsChanged(changed []string) bool {
	for _, f := range changed {
		if f == "labels" {
			return true
		}
	}
	return false
}
