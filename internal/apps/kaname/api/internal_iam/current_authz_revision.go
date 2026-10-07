// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// current_authz_revision.go — InternalIAMService.CurrentAuthzRevision: токен
// версии прав `R_E` для модуля-владельца вида (приёмка NTF-3, Р30 «Производитель
// токена»; сценарий NTF3-179 (г)).
//
// Круг вызывающих — тот же, что у RegisterResource, и судит его ТА ЖЕ дверь
// (`authorizeRegistration`: сертификат → служебная учётка → `fga_writer` на
// `cluster:cluster_root`): второе описание круга разошлось бы с первым молча.
// Прочие — PERMISSION_DENIED, в том числе notify: токен он берёт из строки
// события, а не у службы доступа.

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
)

// authzRevisionReader — узкий порт чтения токена. Реализует
// *pg.AuthzRevisionReader.
type authzRevisionReader interface {
	Current(ctx context.Context) (string, error)
}

// WithAuthzRevision — читатель токена версии прав. nil → метод fail-closed
// Unavailable.
func (h *Handler) WithAuthzRevision(r authzRevisionReader) *Handler {
	h.authzRevision = r
	return h
}

// CurrentAuthzRevision — полный снимок транзакций базы службы доступа на момент
// вызова. Дверь — ДО чтения: вызывающий вне круга не узнаёт и того, что база
// жива.
func (h *Handler) CurrentAuthzRevision(ctx context.Context, _ *iamv1.CurrentAuthzRevisionRequest) (*iamv1.CurrentAuthzRevisionResponse, error) {
	if _, err := h.authorizeRegistration(ctx); err != nil {
		// Отказ двери — с машинным признаком контракта (NTF3-179 (г)); прочие
		// исходы двери (база прав недоступна — UNAVAILABLE) идут как есть.
		if status.Code(err) == codes.PermissionDenied {
			return nil, authzguard.HandlerDenied(iamv1.InternalIAMService_CurrentAuthzRevision_FullMethodName)
		}
		return nil, err
	}
	if h.authzRevision == nil {
		return nil, status.Error(codes.Unavailable, "authz revision reader not configured")
	}
	tok, err := h.authzRevision.Current(ctx)
	if err != nil {
		return nil, shared.MapRepoErrAt(ctx, err)
	}
	return &iamv1.CurrentAuthzRevisionResponse{AuthzRev: tok}, nil
}
