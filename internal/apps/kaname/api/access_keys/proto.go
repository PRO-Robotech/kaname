// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

import (
	"fmt"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	_ "github.com/PRO-Robotech/kaname/internal/dto/toproto" // регистрация перевода ключа
)

// KeyToProto — публичная проекция строки ОДНИМ переводом реестра
// (`dto/toproto/access_key.go`): та же у перечня, у ответа операции
// регистрации и у резолвера осиротевших операций.
func KeyToProto(k domain.AccessKey) (*iamv1.AccessKey, error) {
	var dst *iamv1.AccessKey
	if err := dto.Transfer(dto.FromTo(k, &dst)); err != nil {
		return nil, fmt.Errorf("access key %s: projection: %w", k.ID, err)
	}
	return dst, nil
}
