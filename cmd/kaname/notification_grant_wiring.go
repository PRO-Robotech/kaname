// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notification_grant_wiring.go — сборка InternalNotificationGrantService
// (приёмка NTF-1 Р5; замысел З18).
//
// Полоса `notifications.cutoff-guard` — ручка без умолчания в границах
// [1s..10m]: судит её ЗДЕСЬ строитель, у единственного читателя, как
// `invite.ttl` судит сборка служб. Незаданная либо вне границы — отказ старта
// с именем ключа и границей (NTF1-F20). Суждение стоит до сборки чего-либо и
// базы не касается.
package main

import (
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/notificationgrant"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// buildNotificationGrantServer — служба выдачи над пулом службы, дверью решения
// (`ResolveSend` спрашивает её так же, как `InternalIAMService/Check`) и
// носителем вопроса «администратор ли кластера» (`Revoke`/`Restore`).
func buildNotificationGrantServer(pool *pgxpool.Pool, door *service.AuthorizeService,
	relations *authzcascade.Client, cfg config.Config, logger *slog.Logger,
) (iamv1.InternalNotificationGrantServiceServer, error) {
	guard, err := cfg.Notifications.CutoffGuardValue()
	if err != nil {
		return nil, fmt.Errorf("служба выдачи уведомлений: %w", err)
	}
	if pool == nil || door == nil || relations == nil {
		return nil, fmt.Errorf("служба выдачи уведомлений: зависимость не подана (pool %t, door %t, relations %t)",
			pool != nil, door != nil, relations != nil)
	}
	repo := kanamepg.NewNotificationGrantRepo(pool)
	emitter := kanamepg.NewFGAOutboxEmitter()
	ops := kanamepg.NewOperationTxCreator(shared.NewTerminalRefusalTxRepo(operations.NewRepo(pool, "kaname")))
	txb := kanamepg.NewPoolTxBeginner(pool)
	return notificationgrant.NewHandler(
		notificationgrant.NewResolveSendUseCase(repo, door, guard, logger),
		notificationgrant.NewRevokeUseCase(repo, emitter, ops, txb, relations),
		notificationgrant.NewRestoreUseCase(repo, emitter, ops, txb, relations),
	), nil
}
