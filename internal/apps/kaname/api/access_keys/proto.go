// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// keyToProto — публичная проекция строки: идентификатор удостоверения,
// открытый ключ, счётчик и рукоятка наружу не выходят (Р10). Моменты усечены
// до секунды (`api-conventions.md`).
func keyToProto(k domain.AccessKey) *iamv1.AccessKey {
	out := &iamv1.AccessKey{
		Id: string(k.ID), UserId: string(k.UserID), Name: string(k.Name), Description: string(k.Description),
		CreatedAt: timestamppb.New(k.CreatedAt.Truncate(time.Second)),
	}
	if k.LastUsedAt != nil {
		out.LastUsedAt = timestamppb.New(k.LastUsedAt.Truncate(time.Second))
	}
	return out
}
