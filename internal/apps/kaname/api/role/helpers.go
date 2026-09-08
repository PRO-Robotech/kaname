// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

import (
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"

	_ "github.com/PRO-Robotech/kaname/internal/dto/toproto"
)

// marshalRole — проекция роли для ответа операции.
//
// Вычисленное состояние снимается ЯВНО ([domain.Role.WithoutComputedState]), а
// не «не проставляется»: второе держалось тем, что производителя никто не звал
// на этом пути, и снималось одной строкой молча. Довод целиком — там же.
func marshalRole(r domain.Role) (*anypb.Any, error) {
	var dst *iamv1.Role
	if err := dto.Transfer(dto.FromTo(r.WithoutComputedState(), &dst)); err != nil {
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
