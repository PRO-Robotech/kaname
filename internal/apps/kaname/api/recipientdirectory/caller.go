// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package recipientdirectory

// caller.go — право вызывающего на справочник (приёмка NTF-3 Р7, Р28).
//
// Вопрос один на оба метода: `reader` на `notification_recipient_directory:root`
// той же дверью, что отвечает `InternalIAMService/Check`. Субъект вызывающего —
// `authz.CallerSubject` (служебный субъект звена Р2 либо пересланный доверенным
// принципал); субъекта нет — отказ сразу, дверь не спрашивается. Тип
// справочника — в перечне без надзора (`authzguard.SuperGateExempt`), поэтому
// администратор облака без кортежа получает тот же отказ.
//
// Право решается ПЕРВЫМ, до проверки входа: ответ «вход негоден» — тоже
// сведение о справочнике, и вызывающему без права оно не отдаётся.

import (
	"context"
	"log/slog"

	"github.com/PRO-Robotech/corelib/authz"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/service"
)

const (
	// relationDirectoryReader — отношение модели: право читать адреса.
	relationDirectoryReader = "reader"
	// objectDirectory — единственный объект справочника в модели прав.
	objectDirectory = "notification_recipient_directory:root"
)

// callerGate — вопрос о праве вызывающего.
type callerGate struct {
	door   door
	logger *slog.Logger
}

// require — nil, если вызывающему дано читать справочник; иначе отказ метода
// fullMethod формы двери (PERMISSION_DENIED, AUTHZ_DENIED) либо UNAVAILABLE,
// если дверь не ответила.
func (g callerGate) require(ctx context.Context, fullMethod string) error {
	caller, named := authz.CallerSubject(ctx)
	if !named {
		return authzguard.HandlerDecidedDenial(fullMethod)
	}
	verdict, err := g.door.CheckRelation(ctx, service.CheckRelationRequest{
		Subject:  caller.Subject(),
		Relation: relationDirectoryReader,
		Object:   objectDirectory,
	})
	if err != nil {
		g.logger.ErrorContext(ctx, "recipient directory: caller right unanswered",
			"method", fullMethod, "err", err.Error())
		return authzguard.AuthzBackendUnavailable()
	}
	if verdict == nil || !verdict.Allowed {
		return authzguard.HandlerDecidedDenial(fullMethod)
	}
	return nil
}
