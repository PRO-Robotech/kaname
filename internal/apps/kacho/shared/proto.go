// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"github.com/PRO-Robotech/kacho/pkg/operations/operationspb"
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

// OperationToProto — прослойка к общему слою: перевод строки операции в контракт
// объявлен в дереве ОДИН раз (`pkg/operations/operationspb`, задача #1369).
//
// До сведения объявлений было двенадцать, а смысловых версий — пять; расходились
// они именем помощника усечения времени и охраной пустого значения, то есть там,
// где расхождение не ломает сборку и видно только тому, кто сравнит копии.
func OperationToProto(op *operations.Operation) *operationpb.Operation {
	return operationspb.ToProto(op)
}
