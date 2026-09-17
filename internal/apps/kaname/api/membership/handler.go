// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

// handler.go — тонкий транспорт MembershipService: разобрать → use-case →
// сформатировать. Решений здесь нет ни одного.

import (
	"context"
	"fmt"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/safeconv"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	_ "github.com/PRO-Robotech/kaname/internal/dto/toproto" // регистрация переводов реестра
	repomembership "github.com/PRO-Robotech/kaname/internal/repo/kaname/membership"
)

type Handler struct {
	iamv1.UnimplementedMembershipServiceServer

	get    *GetMembershipUseCase
	list   *ListMembershipsUseCase
	mine   *ListMyMembershipsUseCase
	create Creator
}

// NewHandler — все чтения и создание. Создание приходит ПОРТОМ: поток
// приглашения живёт у ресурса человека до стадии S4 (см. create.go).
func NewHandler(g *GetMembershipUseCase, l *ListMembershipsUseCase, m *ListMyMembershipsUseCase, c Creator) *Handler {
	return &Handler{get: g, list: l, mine: m, create: c}
}

// Create — POST /iam/v1/memberships. Разобрать → порт → операция.
func (h *Handler) Create(ctx context.Context, req *iamv1.CreateMembershipRequest) (*operationpb.Operation, error) {
	op, err := h.create.CreateMembership(ctx, CreateInput{
		AccountID:   domain.AccountID(req.GetAccountId()),
		Email:       domain.Email(req.GetEmail()),
		DisplayName: domain.DisplayName(req.GetDisplayName()),
		ProjectID:   domain.ProjectID(req.GetProjectId()),
		RoleID:      domain.RoleID(req.GetRoleId()),
	})
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Get(ctx context.Context, req *iamv1.GetMembershipRequest) (*iamv1.Membership, error) {
	m, err := h.get.Execute(ctx,
		domain.AccountID(req.GetAccountId()), domain.MembershipID(req.GetMembershipId()))
	if err != nil {
		return nil, err
	}
	pb, err := ToProto(m)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	return pb, nil
}

func (h *Handler) List(ctx context.Context, req *iamv1.ListMembershipsRequest) (*iamv1.ListMembershipsResponse, error) {
	// Формат СЫРОГО запроса судится здесь, ДО насыщающего сужения размера
	// страницы: насыщение — не проверка, и отрицательное значение стало бы нулём,
	// то есть «умолчанием», ещё до того, как его кто-нибудь рассмотрел.
	if err := shared.ValidateRawPagination(req.GetPageToken(), req.GetPageSize()); err != nil {
		return nil, err
	}
	rows, next, err := h.list.Execute(ctx, repomembership.ListFilter{
		AccountID: domain.AccountID(req.GetAccountId()),
		Filter:    req.GetFilter(),
		PageSize:  safeconv.ClampNonNegInt32(req.GetPageSize()),
		PageToken: req.GetPageToken(),
	})
	if err != nil {
		return nil, err
	}
	out := make([]*iamv1.Membership, 0, len(rows))
	for _, m := range rows {
		pb, perr := ToProto(m)
		if perr != nil {
			return nil, shared.MapRepoErr(perr)
		}
		out = append(out, pb)
	}
	return &iamv1.ListMembershipsResponse{Memberships: out, NextPageToken: next}, nil
}

// ListMine — GET /iam/v1/me/memberships. Разобрать → use-case → сформатировать;
// личность вызывающего use-case берёт из контекста сам — запрос её не несёт.
func (h *Handler) ListMine(ctx context.Context, req *iamv1.ListMyMembershipsRequest) (*iamv1.ListMyMembershipsResponse, error) {
	if err := shared.ValidateRawPagination(req.GetPageToken(), req.GetPageSize()); err != nil {
		return nil, err
	}
	rows, next, err := h.mine.Execute(ctx, repomembership.MinePage{
		PageSize:  safeconv.ClampNonNegInt32(req.GetPageSize()),
		PageToken: req.GetPageToken(),
	})
	if err != nil {
		return nil, err
	}
	out := make([]*iamv1.Membership, 0, len(rows))
	for _, m := range rows {
		pb, perr := ToProto(m)
		if perr != nil {
			return nil, shared.MapRepoErr(perr)
		}
		out = append(out, pb)
	}
	return &iamv1.ListMyMembershipsResponse{Memberships: out, NextPageToken: next}, nil
}

// ToProto — перевод членства в контракт: ОДНА проекция на все чтения, на
// ответ операции создания и на разрешение осиротевшей операции.
//
// Сам перевод объявлен в реестре (`internal/dto/toproto`, membership.go) и здесь
// только зовётся: второй перевод разошёлся бы с первым молча. Экспорт нужен
// потоку приглашения, собирающему ответ создания (kaname#181).
func ToProto(m domain.Membership) (*iamv1.Membership, error) {
	var dst *iamv1.Membership
	if err := dto.Transfer(dto.FromTo(m, &dst)); err != nil {
		return nil, fmt.Errorf("dto.Transfer Membership: %w", err)
	}
	return dst, nil
}
