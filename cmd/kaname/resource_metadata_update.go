// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/corelib/authz/catalogderive"
	"github.com/PRO-Robotech/corelib/operations"
	resourcemetadataapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/resource_metadata"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

type resourceMetadataUpdateInstaller interface {
	InstalledResourceMetadataUpdate(context.Context) (kaname.ResourceMetadataUpdateWriter, error)
}

// Подключаем правку в профиле с участником пересчёта и штатным допуском
// PostgreSQL. Тот же каталог обслуживает публичную проверку уровня доверия.
func (s *services) wireResourceMetadataUpdate(ctx context.Context, catalog *seed.PermissionRegistry,
	writers resourceMetadataUpdateInstaller, ops operations.FullRepo,
) error {
	if writers == nil {
		return nil
	}
	fqn := strings.TrimPrefix(iamv1.ResourceMetadataService_Update_FullMethodName, "/")
	entry, exists := catalog.LookupFQN(fqn)
	if !exists {
		return fmt.Errorf("в общем каталоге отсутствует %s", fqn)
	}
	if entry.Permission != catalogderive.ExemptPermission || entry.ExemptReason != "HANDLER_DECIDES" ||
		entry.RequiredRelation != "" || entry.ScopeFiltered {
		return fmt.Errorf("общий каталог не передаёт полный пообъектный допуск обработчику %s", fqn)
	}

	writer, err := writers.InstalledResourceMetadataUpdate(ctx)
	if err != nil {
		return err
	}
	command, err := resourcemetadataapp.NewUpdateUseCase(writer, ops)
	if err != nil {
		return err
	}
	handler, err := s.resourceMetadata.WithUpdate(command, catalog)
	if err != nil {
		return err
	}
	s.resourceMetadata = handler
	return nil
}
