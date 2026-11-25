// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_metadata

import (
	"context"
	"errors"
	"strings"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const metadataUpdateRequiredACR = "1"

// UpdateInput несёт только координату и выбранную замену карт; nil сохраняет.
// Личность и допуск сценарий получает из доверенного контекста вызова.
type UpdateInput struct {
	ResourceType, ResourceID string
	Labels, AccessLabels     domain.Labels
	UpdateMask               []string
}

// UpdateUseCase реализует подготовленную команду, проверяющую право update и
// добавленные эффекты Grant в том же протоколе владельца, что и запись.
type UpdateUseCase interface {
	Execute(context.Context, UpdateInput) (*operations.Operation, error)
}

// WithUpdate не меняет read-only handler. Корень обязан передать реальный
// подготовленный сценарий и registry из выпущенного общего каталога края.
// Здесь проверяется строка ACR; происхождение каталога проверяет выпуск.
func (h *Handler) WithUpdate(update UpdateUseCase, catalog authzguard.ACRRequirementLookup) (*Handler, error) {
	if h == nil || update == nil || !metadataUpdateCatalogReady(catalog) {
		return nil, errors.New("resource metadata update admission unavailable")
	}
	next := *h
	next.update, next.updateCatalog = update, catalog
	return &next, nil
}

func metadataUpdateCatalogReady(catalog authzguard.ACRRequirementLookup) bool {
	if catalog == nil {
		return false
	}
	// Отсутствующая FQN возвращает пустой пол, что обычная ACR-полоса
	// трактует как отсутствие требования. На новом Update это закрытый отказ.
	fqn := strings.TrimPrefix(iamv1.ResourceMetadataService_Update_FullMethodName, "/")
	return catalog.RequiredACRMin(fqn) == metadataUpdateRequiredACR
}

// Update не открывает fallback на обычный Reader или прямой UPDATE зеркала.
func (h *Handler) Update(ctx context.Context, req *iamv1.UpdateResourceMetadataRequest) (*operationpb.Operation, error) {
	if _, ok := authzguard.PrincipalSubject(ctx); !ok {
		return nil, authzguard.PermissionDenied()
	}
	if h.update == nil || !metadataUpdateCatalogReady(h.updateCatalog) {
		return nil, status.Error(codes.Unavailable, shared.UnavailableMessage)
	}
	labels, access, mask, err := parseMetadataPatch(req.GetPatch())
	if err != nil {
		return nil, shared.MapRepoErrAt(ctx, err)
	}
	op, err := h.update.Execute(ctx, UpdateInput{
		ResourceType: req.GetResourceType(), ResourceID: req.GetResourceId(),
		Labels: labels, AccessLabels: access, UpdateMask: mask,
	})
	if err != nil {
		return nil, shared.MapRepoErrAt(ctx, err)
	}
	if op == nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return shared.OperationToProto(op), nil
}
