// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

import (
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"

	_ "github.com/PRO-Robotech/kacho/services/iam/internal/dto/toproto"
)

func marshalUser(u domain.User) (*anypb.Any, error) {
	var dst *iamv1.User
	if err := dto.Transfer(dto.FromTo(u, &dst)); err != nil {
		return nil, fmt.Errorf("dto.Transfer User: %w", err)
	}
	return anypb.New(dst)
}

// labelsFromProto converts a protobuf label map into domain.Labels (parity with
// account/serviceAccount handlers). nil/empty → empty (non-nil) map.
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
