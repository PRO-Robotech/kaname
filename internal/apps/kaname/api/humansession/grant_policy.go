// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает единственный RPC внутренней службы сессий;
// HTTP-церемонии создания и изменения сессии этим чтением не объявляются.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// ResolveUseCase.Execute вызывает Store.Resolve; производственный
			// pg.HumanSessionRepo.Resolve читает human_sessions вместе с users
			// и проверяет срок и состояние. Срок, last_presented_at и уровень
			// сессии не обновляются, нового носителя ответ не создаёт.
			FullMethod: iamv1.InternalHumanSessionService_Resolve_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
	}
}
