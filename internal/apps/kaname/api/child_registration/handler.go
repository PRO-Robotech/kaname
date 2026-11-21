// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package child_registration

// handler.go — тонкий публичный транспорт ChildRegistrationService.
// Проверка личности человека, вывод родителя и решение о праве остаются
// в сценарии UserChildRegistration. Корень регистрирует службу только
// на публичном слушателе.

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Handler реализует публичную службу регистрации потомков.
type Handler struct {
	iamv1.UnimplementedChildRegistrationServiceServer

	register *internaliam.UserChildRegistration
}

// NewHandler подключает сценарий, собранный композиционным корнем.
func NewHandler(register *internaliam.UserChildRegistration) *Handler {
	return &Handler{register: register}
}

// Register переносит только координату потомка в сценарий и возвращает версию.
func (h *Handler) Register(ctx context.Context, req *iamv1.RegisterChildRequest) (*iamv1.RegisterChildResponse, error) {
	// Неизвестные protobuf-поля не принимаются молча: ими нельзя передать
	// второй источник родителя, цепи или области. Форма отказа совпадает
	// с остальными отказами по правилам регистрации.
	if req == nil || len(req.ProtoReflect().GetUnknown()) != 0 {
		return nil, authzguard.PermissionDenied()
	}
	if h == nil {
		return nil, authzguard.AuthzBackendUnavailable()
	}
	version, err := h.register.Register(ctx, internaliam.UserChildRegistrationInput{
		ResourceType: req.GetResourceType(),
		ResourceID:   req.GetResourceId(),
	})
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	stamp := timestamppb.New(version)
	if err := stamp.CheckValid(); err != nil {
		return nil, authzguard.AuthzBackendUnavailable()
	}
	return &iamv1.RegisterChildResponse{Version: stamp}, nil
}
