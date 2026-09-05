// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package handler

import (
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/operations/operationspb"
)

// operationToProto — прослойка к общему слою: перевод строки операции в контракт
// объявлен в дереве ОДИН раз (`pkg/operations/operationspb`, задача #1369).
//
// До сведения объявлений было двенадцать, а смысловых версий — пять; расходились
// они именем помощника усечения времени и охраной пустого значения, то есть там,
// где расхождение не ломает сборку и видно только тому, кто сравнит копии.
func operationToProto(op *operations.Operation) *operationpb.Operation {
	return operationspb.ToProto(op)
}
