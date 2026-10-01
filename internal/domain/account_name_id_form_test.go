// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// account_name_id_form_test.go — правило имени аккаунта (задача kaname#549,
// приёмка `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`,
// Р6; сценарии AID-21…23 уровнем типа).
//
// Имя формы идентификатора допустимо, только если равно собственному
// идентификатору аккаунта. Правило живёт в Account.Validate, поэтому его зовут и
// создание, и правка; пробы ниже судят тип, а не путь запроса.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	nameRuleOwnID     = "acc7m3k9q2x5v8b4n6t1"
	nameRuleForeignID = "accq2x5v8b4n6t17m3k9"
	nameRuleRefusal   = "Illegal argument name: the account id form is reserved for the account's own id"
)

func nameRuleAccount(id, name string) Account {
	return Account{ID: AccountID(id), Name: AccountName(name), Labels: Labels{}, OwnerUserID: "usr00000000000000000"}
}

// TestAccountNameOfTheIDFormMustBeTheAccountsOwnID — имя формы идентификатора,
// не равное своему идентификатору, отвергается дословным текстом правила.
func TestAccountNameOfTheIDFormMustBeTheAccountsOwnID(t *testing.T) {
	err := nameRuleAccount(nameRuleOwnID, nameRuleForeignID).Validate()
	require.Error(t, err, "имя формы чужого идентификатора принято")
	require.Equal(t, nameRuleRefusal, err.Error())

	// Пустой идентификатор (тип судится до назначения) тоже не владеет именем
	// формы идентификатора.
	err = nameRuleAccount("", nameRuleForeignID).Validate()
	require.Error(t, err)
	require.Equal(t, nameRuleRefusal, err.Error())
}

// TestAccountNameRuleTwinsAreAccepted — законные близнецы, каждый на одно
// различие: имя равно своему идентификатору; имя отличается от формы последним
// знаком вне алфавита генератора; обычное имя.
func TestAccountNameRuleTwinsAreAccepted(t *testing.T) {
	for _, tc := range []struct{ id, name, why string }{
		{nameRuleOwnID, nameRuleOwnID, "имя равно собственному идентификатору (умолчание)"},
		{nameRuleOwnID, "accq2x5v8b4n6t17m3ku", "последний знак `u` вне алфавита — не форма идентификатора"},
		{nameRuleOwnID, "acc7m3k9q2x5v8b4n6t", "19 знаков — не форма идентификатора"},
		{nameRuleOwnID, "aid23-tenant", "обычное имя"},
		{"acc1a18042d81fb438d6", "kacho-system", "посеянный служебный аккаунт"},
	} {
		require.NoError(t, nameRuleAccount(tc.id, tc.name).Validate(), tc.why)
	}
}
