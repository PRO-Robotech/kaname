// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// GrantReferenceReader — same-TX порт kaname#1034: настоящие строки роли и
// владельца удерживаются до commit; зеркало ресурса не является источником.
type GrantReferenceReader interface {
	LockGrantAuthoringAxes(context.Context, []domain.GrantCapabilityRule) error
	LockGrantReference(context.Context, domain.RoleID) (GrantReference, error)
	LockGrantOwnerAccount(context.Context, domain.Role) (domain.AccountID, error)
}
type GrantReference struct {
	Role      domain.Role
	AccountID domain.AccountID
	Live      bool
}

// CommonGrantAnchor проверяет существование общей законной области выдачи.
// Account-role вправе назвать project-role своего аккаунта (kaname#1034).
func CommonGrantAnchor(a domain.Role, accountA domain.AccountID, b domain.Role, accountB domain.AccountID) bool {
	if a.IsSystem || b.IsSystem {
		return true
	}
	if accountA == "" || accountA != accountB {
		return false
	}
	return a.ProjectID == "" || b.ProjectID == "" || a.ProjectID == b.ProjectID
}

// GrantProjectionRetainer разрешает автоматическому сужению перенести FP,
// сохранив только уже существовавшие точные исходные строки. Не возрождает
// снятые ссылки и не порождает новые полномочия (kaname#1034).
type GrantProjectionRetainer interface {
	RetainGrantCapabilities(context.Context, domain.RoleID, []domain.GrantCapabilityRule, []domain.GrantCapabilityRule) error
}
