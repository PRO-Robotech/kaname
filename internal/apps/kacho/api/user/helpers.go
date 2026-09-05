// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/dto"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"

	_ "github.com/PRO-Robotech/kacho-iam/internal/dto/toproto"
)

// pendingRefusal — отказ на строке приглашения, которое ещё никто не подтвердил.
//
// Текст совпадает с тем, что уже отдаёт резолв субъекта на этом же состоянии
// (`internal_iam.userStateReason`): одно состояние — один ответ, каким бы путём
// его ни спросили. «Заблокирован» здесь было бы неверно и отправило бы
// администратора снимать запрет, которого нет: неподтверждённое приглашение не
// разблокируют, а снимают вместе с членством — `RemoveFromAccount`. Прежняя
// редакция говорила «отзывают», называя глагол, которого у людей нет ни в
// контракте, ни на краю (#1442).
//
// Тот же текст на обоих направлениях: асимметрия между `:block` и `:unblock` —
// не экономия, а разное объяснение одной и той же причины отказа.
func pendingRefusal(id domain.UserID) error {
	return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "User %s is not active", id)
}

func marshalUser(u domain.User) (*anypb.Any, error) {
	var dst *iamv1.User
	if err := dto.Transfer(dto.FromTo(u, &dst)); err != nil {
		return nil, fmt.Errorf("dto.Transfer User: %w", err)
	}
	return anypb.New(dst)
}

// labelsFromProto converts a protobuf label map into domain.Labels (parity with
// account/serviceAccount handlers). nil/empty → empty (non-nil) map.
func labelsFromProto(m map[string]string) domain.Labels {
	if len(m) == 0 {
		return domain.Labels{}
	}
	out := make(domain.Labels, len(m))
	for k, v := range m {
		out[domain.LabelKey(k)] = domain.LabelVal(v)
	}
	return out
}
