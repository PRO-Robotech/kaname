// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"errors"
	"time"

	"go.uber.org/multierr"

	"github.com/PRO-Robotech/corelib/ids"
)

// ErrAccountNameOfTheIDForm — имя формы идентификатора аккаунта, не равное
// собственному идентификатору (приёмка «идентификатор аккаунта можно указать
// при создании», Р6).
//
// Имя аккаунта уникально на весь кластер, а имя по умолчанию — сам
// идентификатор. Пока идентификатор может прислать вызывающий, имя формы
// идентификатора, взятое другим аккаунтом, выдавало бы занятость идентификатора
// любому, кто создаёт аккаунт, и заранее отнимало бы у будущего аккаунта его имя
// по умолчанию. С правилом владелец такого имени — только аккаунт с этим самым
// идентификатором. Тот же предикат стоит в схеме проверкой
// `accounts_name_is_not_a_foreign_id`; текст отказа у обоих один.
var ErrAccountNameOfTheIDForm = errors.New(
	"Illegal argument name: the account id form is reserved for the account's own id")

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
	// Форма — ровно форма генератора (`ids.IsValid`), второго её написания в Go
	// нет. Пустой идентификатор именем формы идентификатора не владеет: создание
	// назначает идентификатор ДО проверки, поэтому пустым он сюда не приходит.
	if ids.IsValid(string(a.Name), PrefixAccount) && string(a.Name) != string(a.ID) {
		errs = multierr.Append(errs, ErrAccountNameOfTheIDForm)
	}
	errs = multierr.Append(errs, a.Description.Validate())
	errs = multierr.Append(errs, a.Labels.Validate())
	if a.OwnerUserID == "" {
		errs = multierr.Append(errs, ErrEmpty)
	}
	return errs
}
