// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package toproto

// access_key.go — Transfer domain.AccessKey → *iamv1.AccessKey (Ф7, kacho#1273).
//
// ОДНА проекция на ВСЕ дороги к ответу: перечень ключей, `response` операции
// регистрации и разрешение осиротевшей операции. Наружу выходит только
// публичная проекция (Р10): идентификатор удостоверения, открытый ключ,
// счётчик подписи и рукоятка пользователя — материал проверяющего, а не
// арендатора, и в контракте у них поля нет by construction.

import (
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
)

type accessKeyObj struct{}

func (accessKeyObj) toPb(k domain.AccessKey) (*iamv1.AccessKey, error) {
	out := &iamv1.AccessKey{
		Id:          string(k.ID),
		UserId:      string(k.UserID),
		Name:        string(k.Name),
		Description: string(k.Description),
		CreatedAt:   tsTrunc(k.CreatedAt),
	}
	if k.LastUsedAt != nil {
		out.LastUsedAt = tsTrunc(*k.LastUsedAt)
	}
	return out, nil
}

func init() {
	dto.RegTransfer(dto.Fn2Face(accessKeyObj{}.toPb))
}
