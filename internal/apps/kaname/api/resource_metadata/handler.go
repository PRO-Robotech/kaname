// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_metadata

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Reader атомарно проверяет право вызывающего на объект и читает его зеркало.
// Тип, объект и v_get разрешаются по живому каталогу внутри одного снимка.
type Reader interface {
	ReadAuthorizedMirrorMetadata(ctx context.Context, subject, dottedType, objectID string) (domain.ResourceMetadata, error)
}

// Handler обслуживает метки внешнего ресурса; субъект задаёт аутентификация.
type Handler struct {
	iamv1.UnimplementedResourceMetadataServiceServer
	reader        Reader
	update        UpdateUseCase
	updateCatalog authzguard.ACRRequirementLookup
}

// NewHandler собирает обработчик над атомарным чтением хранилища.
func NewHandler(reader Reader) *Handler {
	return &Handler{reader: reader}
}

// Get возвращает описательные метки и метки доступа отдельными картами.
func (h *Handler) Get(ctx context.Context, req *iamv1.GetResourceMetadataRequest) (*iamv1.ResourceMetadata, error) {
	subject, ok := authzguard.PrincipalSubject(ctx)
	if !ok {
		return nil, authzguard.PermissionDenied()
	}
	metadata, err := h.reader.ReadAuthorizedMirrorMetadata(ctx, subject, req.GetResourceType(), req.GetResourceId())
	if err != nil {
		return nil, shared.MapRepoErrAt(ctx, err)
	}
	return &iamv1.ResourceMetadata{
		ResourceType: metadata.ResourceType,
		ResourceId:   metadata.ResourceID,
		Labels:       metadata.Labels,
		AccessLabels: metadata.AccessLabels,
	}, nil
}
