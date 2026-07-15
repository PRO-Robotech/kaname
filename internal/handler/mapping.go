// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"github.com/PRO-Robotech/kacho/pkg/operations"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
)

// operationToProto конвертирует domain Operation в proto Operation
// (parity с kacho-vpc/internal/handler/mapping.go). Proto-response timestamps
// truncate'аются до секунд через shared.TimestampProto (api-conventions: «в
// proto-ответе truncate до секунд»; БД хранит микросекунды).
func operationToProto(op *operations.Operation) *operationpb.Operation {
	p := &operationpb.Operation{
		Id:                   op.ID,
		Description:          op.Description,
		CreatedAt:            shared.TimestampProto(op.CreatedAt),
		CreatedBy:            op.CreatedBy,
		ModifiedAt:           shared.TimestampProto(op.ModifiedAt),
		Done:                 op.Done,
		Metadata:             op.Metadata,
		PrincipalType:        op.Principal.Type,
		PrincipalId:          op.Principal.ID,
		PrincipalDisplayName: op.Principal.DisplayName,
	}
	if op.Error != nil {
		p.Result = &operationpb.Operation_Error{Error: op.Error}
	} else if op.Response != nil {
		p.Result = &operationpb.Operation_Response{Response: op.Response}
	}
	return p
}
