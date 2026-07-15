// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package shared — proto.go: общие helper'ы для конверсии domain ↔ proto.
//
// Заменяет:
//   - 7 копий `tsProto(t)` truncate-to-seconds timestamp helper'ов
//     (account/handler.go, project/handler.go, user/handler.go,
//     role/helpers.go, group/helpers.go, service_account/helpers.go,
//     access_binding/helpers.go);
//   - копии `operationToProto(op)` corelib.Operation → proto.Operation
//     mapping функций (account, access_binding, group, sa_keys,
//     internal_authorize, project, user, conditions, role, service_account).
//
// Все копии — bit-for-bit идентичны; разные имена per-package — единственное
// отличие.
package shared

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// TimestampProto конвертирует time.Time в *timestamppb.Timestamp с truncate'ом
// до секунд (конвенция Kachō: timestamp precision = seconds, не nanoseconds).
// Zero-time → nil (parity с handler-стиль омитом null timestamp полей).
func TimestampProto(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t.Truncate(time.Second))
}

// OperationToProto маппит corelib.Operation в proto.Operation. Используется
// всеми handler'ами для возврата операций в gRPC-response (Create/Update/
// Delete/etc — async-API contract).
//
// nil-input → nil (caller обычно проверяет на nil сразу после).
func OperationToProto(op *operations.Operation) *operationpb.Operation {
	if op == nil {
		return nil
	}
	p := &operationpb.Operation{
		Id:                   op.ID,
		Description:          op.Description,
		CreatedAt:            TimestampProto(op.CreatedAt),
		CreatedBy:            op.CreatedBy,
		ModifiedAt:           TimestampProto(op.ModifiedAt),
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
