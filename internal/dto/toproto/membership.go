// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package toproto

// membership.go — Transfer domain.Membership → *iamv1.Membership.
//
// ОДНА проекция на ВСЕ дороги к ответу: одиночное чтение, список, `response`
// операции создания (kaname#181) и разрешение осиротевшей операции. Расхождение
// проекций законно только там, где контракт назвал их разными, а он их разными
// не называет; держится это тем, что перевод объявлен здесь один раз, а
// потребители зовут реестр. Прежде перевод жил у обработчика чтений — второму
// потребителю пришлось бы завести второй, и разошлись бы они молча.

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
)

type membershipObj struct{}

func (membershipObj) toPb(m domain.Membership) (*iamv1.Membership, error) {
	return &iamv1.Membership{
		Id:          string(m.ID),
		AccountId:   string(m.AccountID),
		AccountName: string(m.AccountName),
		UserId:      string(m.UserID),
		State:       membershipStateToProto(m.State),
		InvitedBy:   string(m.InvitedBy),
		// Усечение до секунд — конвенция ответа: микросекунды хранилища на
		// провод не текут. Нулевое время — отсутствие отметки, а не эпоха.
		CreatedAt: tsTrunc(m.CreatedAt),
		UpdatedAt: tsTrunc(m.UpdatedAt),
	}, nil
}

// membershipStateToProto — словарь состояний, и он ЗАКРЫТ.
//
// Значение вне словаря даёт `STATE_UNSPECIFIED`, а не выдуманное состояние:
// придумать его значило бы сообщить вызывающему факт, которого в строке нет.
// Третьего значения в колонке не появится — оно закреплено CHECK'ом, — поэтому
// ветка умолчания недостижима by construction и стоит здесь ради полноты
// перевода, а не как ожидаемый исход.
func membershipStateToProto(s domain.MembershipState) iamv1.Membership_State {
	switch s {
	case domain.MembershipStatePending:
		return iamv1.Membership_PENDING
	case domain.MembershipStateActive:
		return iamv1.Membership_ACTIVE
	default:
		return iamv1.Membership_STATE_UNSPECIFIED
	}
}

// tsTrunc — отметка по значению: нулевое время означает «отметки нет».
func tsTrunc(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t.Truncate(tsTruncate))
}

func init() {
	dto.RegTransfer(dto.Fn2Face(membershipObj{}.toPb))
}
