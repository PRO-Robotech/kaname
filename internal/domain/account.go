// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"time"

	"go.uber.org/multierr"
)

// Account — top-level tenant («организация» как товар продукта IAM).
// Замещает прежнюю связку tenant+folder из retired kacho-resource-manager.
// Уникальное имя глобально (DB UNIQUE accounts_name_unique).
//
// FK: owner_user_id → users(id) ON DELETE RESTRICT.
// Удаление RESTRICT при наличии Project / ServiceAccount / Group / custom Role.
type Account struct {
	ID          AccountID
	Name        AccountName
	Description Description
	Labels      Labels
	OwnerUserID UserID
	CreatedAt   time.Time
}

// Validate — multierr.Combine всех полей.
// owner_user_id-existence — это cross-row проверка, делается через FK на
// repo-уровне (`accounts_owner_fk`); здесь только проверка, что значение
// непустое.
func (a Account) Validate() error {
	var errs error
	errs = multierr.Append(errs, a.Name.Validate())
	errs = multierr.Append(errs, a.Description.Validate())
	errs = multierr.Append(errs, a.Labels.Validate())
	if a.OwnerUserID == "" {
		errs = multierr.Append(errs, ErrEmpty)
	}
	return errs
}
