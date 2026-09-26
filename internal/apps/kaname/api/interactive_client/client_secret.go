// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package interactiveclient

import (
	"errors"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// ClientSecret — секрет конфиденциального клиента, выданный реестром.
type ClientSecret struct {
	value string
}

// NewClientSecret — секрет, отчеканенный реестром. Пустой отвергается.
func NewClientSecret(value string) (ClientSecret, error) {
	if value == "" {
		return ClientSecret{}, errors.New("interactive client secret: empty")
	}
	return ClientSecret{value: value}, nil
}

// IsZero — секрета нет.
func (s ClientSecret) IsZero() bool { return s.value == "" }

// IntoResponse кладёт секрет в поле ответа.
func (s ClientSecret) IntoResponse(resp *iamv1.CreateInteractiveClientResponse) {
	resp.ClientSecret = s.value
}
