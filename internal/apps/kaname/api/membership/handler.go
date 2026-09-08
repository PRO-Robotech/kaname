// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

// handler.go — тонкий транспорт MembershipService: разобрать → use-case →
// сформатировать. Решений здесь нет ни одного.

import (
	"context"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	repomembership "github.com/PRO-Robotech/kaname/internal/repo/kaname/membership"
)

type Handler struct {
	iamv1.UnimplementedMembershipServiceServer

	get  *GetMembershipUseCase
	list *ListMembershipsUseCase
}

func NewHandler(g *GetMembershipUseCase, l *ListMembershipsUseCase) *Handler {
	return &Handler{get: g, list: l}
}

func (h *Handler) Get(ctx context.Context, req *iamv1.GetMembershipRequest) (*iamv1.Membership, error) {
	m, err := h.get.Execute(ctx,
		domain.AccountID(req.GetAccountId()), domain.MembershipID(req.GetMembershipId()))
	if err != nil {
		return nil, err
	}
	return membershipToPb(m), nil
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
		out = append(out, membershipToPb(m))
	}
	return &iamv1.ListMembershipsResponse{Memberships: out, NextPageToken: next}, nil
}

// membershipToPb — ОДНА проекция на оба чтения.
//
// Одиночное чтение и список отдают одно сообщение с одинаково заполненными
// полями; расхождение проекций законно только там, где контракт назвал их
// разными, а он их разными не называет. Держится это тем, что перевод здесь
// один — второй перевод разошёлся бы с первым молча.
func membershipToPb(m domain.Membership) *iamv1.Membership {
	return &iamv1.Membership{
		Id:          string(m.ID),
		AccountId:   string(m.AccountID),
		AccountName: string(m.AccountName),
		UserId:      string(m.UserID),
		State:       membershipStateToPb(m.State),
		InvitedBy:   string(m.InvitedBy),
		// Усечение до секунд — конвенция ответа: микросекунды хранилища на
		// провод не текут.
		CreatedAt: shared.TimestampProto(m.CreatedAt),
		UpdatedAt: shared.TimestampProto(m.UpdatedAt),
	}
}

// membershipStateToPb — словарь состояний, и он ЗАКРЫТ.
//
// Значение вне словаря даёт `STATE_UNSPECIFIED`, а не выдуманное состояние:
// придумать его значило бы сообщить вызывающему факт, которого в строке нет.
// Третьего значения в колонке не появится — оно закреплено CHECK'ом, — поэтому
// ветка умолчания недостижима by construction и стоит здесь ради полноты
// перевода, а не как ожидаемый исход.
func membershipStateToPb(s domain.MembershipState) iamv1.Membership_State {
	switch s {
	case domain.MembershipStatePending:
		return iamv1.Membership_PENDING
	case domain.MembershipStateActive:
		return iamv1.Membership_ACTIVE
	default:
		return iamv1.Membership_STATE_UNSPECIFIED
	}
}
