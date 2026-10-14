// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

import (
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"

	// Blank-import регистрирует трансферы Account/time через init().
	_ "github.com/PRO-Robotech/kaname/internal/dto/toproto"
)

// reservedAccountNameRefusal — текст отказа резерва пространства личных аккаунтов
// (Ф4 Р9 п.3). Часть контракта — сверяется побайтово (пробы Ф4-29/30). Собран из
// ЕДИНСТВЕННОГО источника написания префикса (`domain.PersonalAccountNamePrefix`),
// чтобы текст и проверка не разошлись с генератором имени зеркала.
var reservedAccountNameRefusal = fmt.Sprintf(
	"Illegal argument name: prefix '%s' is reserved for personal accounts",
	domain.PersonalAccountNamePrefix)

// marshalAccount конвертирует domain.Account в *anypb.Any через DTO-реестр.
// Используется worker'ами Create/Update для запихивания результата в Operation.response.
func marshalAccount(a domain.Account) (*anypb.Any, error) {
	var dst *iamv1.Account
	if err := dto.Transfer(dto.FromTo(a, &dst)); err != nil {
		return nil, fmt.Errorf("dto.Transfer Account: %w", err)
	}
	return anypb.New(dst)
}
