// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// resolve.go — ОТВЕТ КРАЮ о сессии (Р7; Ф3-09, Ф3-10): вариант использования и
// gRPC-обработчик `InternalHumanSessionService.Resolve`. Два исхода: сессия —
// состав Р1 с читателем на крае; «сессии нет» — один ответ на все причины.
// Отсечку не применяет (§8 инв. 8) и момент последнего предъявления не двигает.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// ResolveUseCase — чтение сессии по носителю.
type ResolveUseCase struct {
	store    Store
	observer Observer
	now      func() time.Time
}

// NewResolveUseCase — построение.
func NewResolveUseCase(store Store, observer Observer, now func() time.Time) (*ResolveUseCase, error) {
	if store == nil {
		return nil, fmt.Errorf("resolve: session store required")
	}
	if observer == nil {
		observer = NopObserver{}
	}
	if now == nil {
		now = time.Now
	}
	return &ResolveUseCase{store: store, observer: observer, now: now}, nil
}

// Execute — сессия либо «сессии нет» (found=false). Ошибка — хранилище не
// ответило.
func (uc *ResolveUseCase) Execute(ctx context.Context, bearer domain.SessionBearer) (SessionView, bool, error) {
	if bearer.IsZero() {
		uc.observer.NoSessionObserved(NoSessionUnknown)
		return SessionView{}, false, nil
	}
	resolved, reason, err := uc.store.Resolve(ctx, bearer.Digest(), uc.now().UTC())
	if err != nil {
		return SessionView{}, false, ErrStoreUnavailable
	}
	if reason != SessionFound {
		uc.observer.NoSessionObserved(reason)
		return SessionView{}, false, nil
	}
	return SessionView{User: resolved.User, Session: resolved.Session, EmailVerified: resolved.EmailVerified}, true, nil
}

// Handler — gRPC-обработчик внутреннего слушателя.
type Handler struct {
	iamv1.UnimplementedInternalHumanSessionServiceServer
	resolve *ResolveUseCase
}

// NewHandler — обработчик над вариантом использования.
func NewHandler(resolve *ResolveUseCase) *Handler { return &Handler{resolve: resolve} }

// Resolve — см. контракт.
func (h *Handler) Resolve(ctx context.Context, req *iamv1.ResolveHumanSessionRequest) (*iamv1.ResolveHumanSessionResponse, error) {
	bearer := strings.TrimSpace(req.GetBearer())
	if bearer == "" {
		return nil, shared.InvalidArg("bearer", "required")
	}
	if h.resolve == nil {
		return nil, status.Error(codes.Unavailable, "human session reader not configured")
	}
	view, found, err := h.resolve.Execute(ctx, domain.PresentedSessionBearer(bearer))
	if err != nil {
		return nil, status.Error(codes.Unavailable, "human session lookup did not answer")
	}
	if !found {
		return &iamv1.ResolveHumanSessionResponse{Found: false}, nil
	}
	return &iamv1.ResolveHumanSessionResponse{Found: true, Session: sessionProto(view)}, nil
}

// sessionProto — состав Р1 на проводе. Момент аутентификации — НЕ усечён
// (§4.1 п.19, названное отступление); срок — по конвенции, до секунды.
func sessionProto(v SessionView) *iamv1.HumanSession {
	return &iamv1.HumanSession{
		UserId:          string(v.User.ID),
		Email:           string(v.User.Email),
		DisplayName:     string(v.User.DisplayName),
		AuthenticatedAt: timestamppb.New(v.Session.AuthenticatedAt),
		ExpiresAt:       shared.TimestampProto(v.Session.ExpiresAt),
		AssuranceLevel:  v.Session.AssuranceLevel,
		EmailVerified:   v.EmailVerified,
	}
}
