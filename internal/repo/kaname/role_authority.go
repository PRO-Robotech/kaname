// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package kaname

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// RoleAuthorityWriterFactory — только active coordinated decision mode.
// Participant и обычный Writer не являются fallback при неготовом protocol.
type RoleAuthorityWriterFactory interface {
	RoleAuthorityWriter(context.Context, domain.Role, bool, domain.Subject) (SemanticAuthorityWriter, error)
}
type GroupAdditionAuthorityWriterFactory interface {
	GroupAdditionAuthorityWriter(context.Context, domain.GroupMember, domain.Subject) (SemanticAuthorityWriter, error)
}

// RoleCapabilityPromoter вызывается после полной D3 проверки всех носителей.
// Metadata-only update не вызывает этот порт.
type RoleCapabilityPromoter interface {
	PromoteRoleCapabilities(context.Context, domain.RoleID) error
}
