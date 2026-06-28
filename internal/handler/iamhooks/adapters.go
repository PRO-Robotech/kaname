// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// adapters.go — thin shims между port-iface'ами handler-слоя и repo adapter'ами
// из internal/repo/kacho/pg.
//
// Эти shim'ы избегают cyclic dependency (handler/internal не импортирует
// repo/kacho/pg напрямую) и позволяют main.go подключать pg-adapters к
// handler ports.
package iamhooks

import "context"

// AuditAdapter — функциональный adapter, превращающий callback в AuditEmitter.
type AuditAdapter struct {
	EmitFn func(ctx context.Context, eventType string, tenantAccountID string, payload map[string]any) error
}

func (a *AuditAdapter) Emit(ctx context.Context, evt AuditEvent) error {
	if a == nil || a.EmitFn == nil {
		return nil
	}
	return a.EmitFn(ctx, evt.EventType, evt.TenantAccountID, evt.Payload)
}
