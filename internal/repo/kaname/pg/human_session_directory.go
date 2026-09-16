// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// UserDirectory — порт чтения человека по адресу для полосы входа (Ф3) над
// существующим репозиторием зеркала: своего оператора не заводит.
type UserDirectory struct {
	repo kaname.Repository
}

// NewUserDirectory — адаптер над репозиторием.
func NewUserDirectory(repo kaname.Repository) *UserDirectory { return &UserDirectory{repo: repo} }

// UserByEmail — см. порт: NOT_FOUND, если адреса нет.
func (d *UserDirectory) UserByEmail(ctx context.Context, email domain.Email) (domain.User, error) {
	rd, err := d.repo.Reader(ctx)
	if err != nil {
		return domain.User{}, err
	}
	defer func() { _ = rd.Rollback(ctx) }()
	return rd.Users().GetByEmail(ctx, email)
}

var _ humansession.UserDirectory = (*UserDirectory)(nil)
