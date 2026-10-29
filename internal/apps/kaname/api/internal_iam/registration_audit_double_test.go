// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// noAudit — двойник аудита регистрации для проб, которые судят не аудит: кортеж
// не стоит, строка аудита принимается и забывается. Аудит судит мировая проба
// `access_binding/registration_audit_world_integration_test.go` (kaname#1005).
type noAudit struct{}

func (noAudit) TupleStandsTx(context.Context, service.Tx, service.RelationTuple) (bool, error) {
	return false, nil
}

func (noAudit) EmitTx(context.Context, service.Tx, service.AuditEvent) error { return nil }
