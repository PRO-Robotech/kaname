// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package kaname

import (
	"context"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Отдельный prepared порт состояния; enabled не является metadata PATCH.
type ServiceAccountStateWriterFactory interface {
	ServiceAccountStateWriter(context.Context, domain.ServiceAccountID, bool, domain.Subject) (SemanticAuthorityWriter, error)
}
