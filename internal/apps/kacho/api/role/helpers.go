// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

import (
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"

	_ "github.com/PRO-Robotech/kacho/services/iam/internal/dto/toproto"
)

func marshalRole(r domain.Role) (*anypb.Any, error) {
	var dst *iamv1.Role
	if err := dto.Transfer(dto.FromTo(r, &dst)); err != nil {
		return nil, fmt.Errorf("dto.Transfer Role: %w", err)
	}
	return anypb.New(dst)
}

// labelsFromProto converts a protobuf own-resource label map into domain.Labels
// (parity with account/serviceAccount/user handlers). nil/empty → empty (non-nil)
// map. Maps the Role's OWN labels (CreateRoleRequest.labels / UpdateRoleRequest.labels)
// — NOT Rule.MatchLabels (the object-selector inside a grant rule).
func labelsFromProto(m map[string]string) domain.Labels {
	if len(m) == 0 {
		return domain.Labels{}
	}
	out := make(domain.Labels, len(m))
	for k, v := range m {
		out[domain.LabelKey(k)] = domain.LabelVal(v)
	}
	return out
}
