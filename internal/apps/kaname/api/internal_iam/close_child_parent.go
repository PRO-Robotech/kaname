// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// WithChildParentClose вызывается корнем только при полной сборке писателя,
// до регистрации слушателей и конкурентного использования обработчика.
func (h *Handler) WithChildParentClose(tx kaname.ChildParentCloseTransactions) *Handler {
	h.childParentClose = tx
	return h
}

// CloseChildParent передаёт immutable намерение. Принадлежность каталога,
// область и installation-допуск проверяет runner в одной RR→RC попытке.
func (h *Handler) CloseChildParent(ctx context.Context, req *iamv1.CloseChildParentRequest) (*iamv1.CloseChildParentResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, shared.MapRepoErrAt(ctx, err)
	}
	if h == nil {
		return nil, authzguard.AuthzBackendUnavailable()
	}
	if _, err := h.authorizeRegistration(ctx); err != nil {
		return nil, shared.MapRepoErrAt(ctx, err)
	}
	if h.childParentClose == nil {
		return nil, authzguard.AuthzBackendUnavailable()
	}
	if req == nil {
		return nil, shared.InvalidArg("request", "request is required")
	}
	if len(req.ProtoReflect().GetUnknown()) != 0 {
		return nil, shared.InvalidArg("request", "unknown fields are not accepted")
	}
	if req.GetResourceType() == "" {
		return nil, shared.InvalidArg("resource_type", "resource type is required")
	}
	if req.GetResourceId() == "" {
		return nil, shared.InvalidArg("resource_id", "resource ID is required")
	}
	stamp := req.GetSourceVersion()
	if stamp == nil || stamp.CheckValid() != nil || stamp.AsTime().IsZero() {
		return nil, shared.InvalidArg("source_version", "a finite nonzero parent registration version is required")
	}
	closedAt, err := h.childParentClose.RunChildParentClose(ctx, kaname.ChildParentCloseInput{
		ResourceType: req.GetResourceType(), ResourceID: req.GetResourceId(), SourceVersion: stamp.AsTime(),
	})
	if err != nil {
		if canceled := ctx.Err(); canceled != nil {
			return nil, shared.MapRepoErrAt(ctx, canceled)
		}
		// Ошибка cleanup/источника остаётся системной, даже если её цепочка
		// содержит предшествовавший отказ по полю запроса.
		if errors.Is(err, iamerr.ErrUnavailable) {
			return nil, authzguard.AuthzBackendUnavailable()
		}
		if errors.Is(err, iamerr.ErrAborted) || errors.Is(err, iamerr.ErrInternal) {
			return nil, shared.MapRepoErrAt(ctx, err)
		}
		var field *kaname.ResourceDecisionFieldError
		if errors.As(err, &field) {
			return nil, shared.InvalidArg(field.Field, field.Description)
		}
		return nil, shared.MapRepoErrAt(ctx, err)
	}
	result := timestamppb.New(closedAt)
	if closedAt.IsZero() || result.CheckValid() != nil {
		return nil, authzguard.AuthzBackendUnavailable()
	}
	return &iamv1.CloseChildParentResponse{ClosedAt: result}, nil
}
