// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recipient_directory_wiring.go — сборка InternalNotificationRecipientService
// (приёмка NTF-3 Р7, Р28; замысел З27).
package main

import (
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/recipientdirectory"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// buildRecipientDirectoryServer — справочник адресов над пулом службы и дверью
// решения: оба вопроса справочника (право вызывающего на
// `notification_recipient_directory:root` и `v_get` получателя на ресурс)
// задаются той же дверью, что отвечает `InternalIAMService/Check`.
//
// relations и cfg подаются той же формой, что строителю службы выдачи: справочник
// своей ручки не держит и вопроса администратора кластера не задаёт, поэтому
// судится только их наличие — сборка без носителя отношений означала бы корень,
// поднятый без формы модели.
func buildRecipientDirectoryServer(pool *pgxpool.Pool, door *service.AuthorizeService,
	relations *authzcascade.Client, _ config.Config, logger *slog.Logger,
) (iamv1.InternalNotificationRecipientServiceServer, error) {
	if pool == nil || door == nil || relations == nil || logger == nil {
		return nil, fmt.Errorf("справочник адресов: зависимость не подана (pool %t, door %t, relations %t, logger %t)",
			pool != nil, door != nil, relations != nil, logger != nil)
	}
	repo := kanamepg.NewRecipientDirectoryRepo(pool)
	return recipientdirectory.NewHandler(
		recipientdirectory.NewResolveUseCase(door, repo, logger),
		recipientdirectory.NewListProjectAudienceUseCase(door, repo, logger),
	), nil
}
