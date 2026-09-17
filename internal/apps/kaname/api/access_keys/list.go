// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

// list.go — ПЕРЕЧЕНЬ КЛЮЧЕЙ ЧЕЛОВЕКА: наблюдаемое, которым §3.0 определяет
// «ключ принят». Каждый ключ назван своим `id` (Р10); формат страницы судится
// у транспорта по сырому запросу, здесь — чтение.

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ListInput — чей перечень и страница.
type ListInput struct {
	UserID    domain.UserID
	PageSize  int32
	PageToken string
}

// ListUseCase — перечень ключей.
type ListUseCase struct{ deps Deps }

// NewListUseCase — построение с проверкой зависимостей.
func NewListUseCase(d Deps) (*ListUseCase, error) {
	d, err := d.validate("access key list")
	if err != nil {
		return nil, err
	}
	return &ListUseCase{deps: d}, nil
}

// Execute — постраничное чтение.
func (uc *ListUseCase) Execute(ctx context.Context, in ListInput) ([]domain.AccessKey, string, error) {
	if in.UserID == "" {
		return nil, "", fieldRequired("user_id")
	}
	if err := shared.ValidatePagination(in.PageToken, in.PageSize); err != nil {
		return nil, "", err
	}
	keys, next, err := uc.deps.Store.KeysOf(ctx, in.UserID, in.PageToken, in.PageSize)
	if err != nil {
		return nil, "", mapStoreErr(uc.deps, "access_keys.List", err)
	}
	return keys, next, nil
}
