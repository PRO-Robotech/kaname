// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package toproto

// grant_delegation.go — Transfer domain.GrantDelegation → *iamv1.GrantDelegation
// (задача PRO-Robotech/kaname#986, Р1 приёмки).

import (
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
)

type grantDelegationObj struct{}

// toPb — проекция делегирования. Оси — наборы: отдаются по возрастанию строки
// (`domain.SortedGrantDelegationAxes`), порядок входа не хранится. Моменты
// усечены до секунды; `revokedAt` и `revokedBy` заданы только у отозванного.
func (grantDelegationObj) toPb(d domain.GrantDelegation) (*iamv1.GrantDelegation, error) {
	d = domain.SortedGrantDelegationAxes(d)
	roles := make([]string, 0, len(d.RoleIDs))
	for _, r := range d.RoleIDs {
		roles = append(roles, string(r))
	}
	subjects := make([]iamv1.SubjectType, 0, len(d.SubjectTypes))
	for _, s := range d.SubjectTypes {
		subjects = append(subjects, subjectTypeToProtoDTO(s))
	}
	out := &iamv1.GrantDelegation{
		Id:        string(d.ID),
		AccountId: string(d.AccountID),
		Delegate: &iamv1.Subject{
			Type: iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT,
			Id:   string(d.DelegateID),
		},
		RoleIds:      roles,
		TargetTypes:  append([]string(nil), d.TargetTypes...),
		SubjectTypes: subjects,
		Module:       d.Module,
		Status:       grantDelegationStatusToProto(d.Status),
		DelegatedBy:  &iamv1.GrantDelegation_Actor{Type: d.DelegatedBy.Type, Id: d.DelegatedBy.ID},
		CreatedAt:    tsTrunc(d.CreatedAt),
		RevokedAt:    nullableTsTrunc(d.RevokedAt),
	}
	if d.RevokedBy != nil {
		out.RevokedBy = &iamv1.GrantDelegation_Actor{Type: d.RevokedBy.Type, Id: d.RevokedBy.ID}
	}
	return out, nil
}

func grantDelegationStatusToProto(s domain.GrantDelegationStatus) iamv1.GrantDelegation_Status {
	switch s {
	case domain.GrantDelegationActive:
		return iamv1.GrantDelegation_ACTIVE
	case domain.GrantDelegationRevoked:
		return iamv1.GrantDelegation_REVOKED
	default:
		return iamv1.GrantDelegation_STATUS_UNSPECIFIED
	}
}

func init() {
	dto.RegTransfer(dto.Fn2Face(grantDelegationObj{}.toPb))
}
