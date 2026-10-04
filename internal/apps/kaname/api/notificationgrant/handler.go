// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package notificationgrant

// handler.go — тонкий gRPC-транспорт InternalNotificationGrantService:
// разбор запроса → use-case → ответ. Регистрируется ТОЛЬКО на внутреннем
// слушателе (запрет #6).

import (
	"context"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Handler реализует iamv1.InternalNotificationGrantServiceServer.
type Handler struct {
	iamv1.UnimplementedInternalNotificationGrantServiceServer

	resolve *ResolveSendUseCase
	revoke  *TransitionUseCase
	restore *TransitionUseCase
}

// NewHandler — сборка из трёх use-case'ов. Композиционный корень — cmd/kaname.
func NewHandler(resolve *ResolveSendUseCase, revoke, restore *TransitionUseCase) *Handler {
	return &Handler{resolve: resolve, revoke: revoke, restore: restore}
}

// ResolveSend — решение о письме строки ленты.
func (h *Handler) ResolveSend(ctx context.Context, req *iamv1.ResolveSendRequest) (*iamv1.ResolveSendResponse, error) {
	var enqueuedAt *time.Time
	if ts := req.GetEnqueuedAt(); ts != nil {
		at := ts.AsTime()
		enqueuedAt = &at
	}
	d, err := h.resolve.Execute(ctx, req.GetNamespace(), req.GetTemplate(), enqueuedAt)
	if err != nil {
		return nil, err
	}
	return &iamv1.ResolveSendResponse{Decision: decisionToProto(d)}, nil
}

// Revoke — надгробие на выдаче пространства либо записи шаблона.
func (h *Handler) Revoke(ctx context.Context, req *iamv1.NotificationGrantRequest) (*operationpb.Operation, error) {
	return h.revoke.Execute(ctx, req.GetNamespace(), templateOf(req))
}

// Restore — снятие надгробия и отсечка.
func (h *Handler) Restore(ctx context.Context, req *iamv1.NotificationGrantRequest) (*operationpb.Operation, error) {
	return h.restore.Execute(ctx, req.GetNamespace(), templateOf(req))
}

// templateOf — шаблон, если задан: незаданный и пустой различаются.
func templateOf(req *iamv1.NotificationGrantRequest) *string {
	if req.Template == nil {
		return nil
	}
	t := req.GetTemplate()
	return &t
}

func decisionToProto(d domain.SendDecision) iamv1.SendDecision {
	switch d {
	case domain.SendAllow:
		return iamv1.SendDecision_ALLOW
	case domain.SendNotYetGranted:
		return iamv1.SendDecision_NOT_YET_GRANTED
	case domain.SendRevoked:
		return iamv1.SendDecision_REVOKED
	default:
		return iamv1.SendDecision_SEND_DECISION_UNSPECIFIED
	}
}
