// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorize

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// PublicationUnary закрепляет модель до первого решения о правах вызывающего.
// Звено ставится после извлечения личности, перед стражами обоих слушателей.
// Один снимок покрывает все проверки в вызове, включая OwnDoor для CRUD.
// Перед возвратом отдельного вердикта или каталога редакция сверяется повторно.
func PublicationUnary(store *authzsnapshot.Store) (grpc.UnaryServerInterceptor, error) {
	if store == nil {
		return nil, errors.New("authorize: published model store is required")
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		confirmResult := false
		switch info.FullMethod {
		case iamv1.AuthorizeService_Check_FullMethodName,
			iamv1.AuthorizeService_BatchCheck_FullMethodName,
			iamv1.AuthorizeService_ListSubjects_FullMethodName,
			iamv1.AuthorizeService_ExpandRelations_FullMethodName,
			iamv1.InternalIAMService_Check_FullMethodName,
			iamv1.PermissionCatalogService_ListPermissionCatalog_FullMethodName:
			confirmResult = true
		}
		if err := ctx.Err(); err != nil {
			return nil, status.FromContextError(err).Err()
		}
		if grpcsrv.IsPublicPlatformMethod(info.FullMethod) {
			// Проверка живости процесса не зависит от активации модели.
			return handler(ctx, req)
		}
		pinned, err := store.Pin(ctx)
		if err != nil {
			return nil, authzguard.AuthzBackendUnavailable()
		}
		if !confirmResult {
			// Успешная мутация может сменить редакцию, закреплённую на входе.
			// Контракт записи повторно сверяет полномочия в транзакции.
			return handler(pinned, req)
		}
		result, err := handler(pinned, req)
		if ctxErr := pinned.Err(); ctxErr != nil {
			return nil, status.FromContextError(ctxErr).Err()
		}
		if store.ConfirmPin(pinned) != nil {
			return nil, authzguard.AuthzBackendUnavailable()
		}
		return result, err
	}, nil
}
