// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

import (
	"context"

	"github.com/PRO-Robotech/corelib/operations"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// IsAnonymousSelfCheck допускает только форму Check без учётных данных и субъекта
// (kaname#959). Этим предикатом пользуются публичный unary-допуск и обработчик.
// Он не даёт разрешения на ресурс: обычный сервис решения
// оценивает выбранный сервером анонимный субъект.
func IsAnonymousSelfCheck(ctx context.Context, req *iamv1.AuthorizeCheckRequest, modules moduleidentity.Roster) bool {
	if req == nil || req.GetSubject() != "" || req.GetContext() != nil ||
		req.GetRequiredRelation() != "" || req.GetResource() == nil || req.GetAction() == "" {
		return false
	}
	// Наличие, а не principal по умолчанию или распознанная схема учётных данных:
	// даже пустой/неподдерживаемый Authorization не должен становиться анонимным.
	if _, present := operations.PrincipalFromContextOK(ctx); present {
		return false
	}
	if _, present := callerorigin.From(ctx); present {
		return false
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if _, present := md[presentedcred.MetadataKey]; present {
			return false
		}
	}
	// Проверенный модуль — другой вызывающий. Сертификат не модуля, используемый
	// нашим собственным REST-входом, обозначает транспортный переход, а не личность пользователя.
	// Модуль — объявленная пара перечня (kaname#984): тот же разбор, что у
	// политик вызывающего обоих слушателей.
	if _, module := modules.FromContext(ctx); module {
		return false
	}
	return true
}
