// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// rule_verbs_delete_names_only_test.go — глагол удаления в правиле роли даёт
// только удаление (приёмка docs/engineering/acceptance/role-rights-stay-within-what-is-named.md,
// решения Р1 и В1; задачи PRO-Robotech/kaname#1035, PRO-Robotech/kaname#1039).
//
// Ярус правила выводится из его глаголов. Прежде `delete` давал ярус `admin`, а
// ярус `admin` на области — это право выдавать доступ и всё, что модель выводит из
// администратора. Здесь закреплено, что из одного `delete` не выводится НИ ОДНОГО
// яруса, а соседние глаголы и подстановка `*` дают тот же ярус, что и прежде.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// fiveVerbs — набор типа, который объявляют сегодня типы области и листа.
var fiveVerbs = []string{"get", "list", "create", "update", "delete"}

// TestResolveVerbsAndTier_DeleteNamesOnlyDeletion — ярус по глаголам правила:
// строки отличаются от соседней ровно одним глаголом.
func TestResolveVerbsAndTier_DeleteNamesOnlyDeletion(t *testing.T) {
	cases := []struct {
		name     string
		authored []string
		wantTier string // "" — ярус не выводится вовсе
	}{
		{"одно удаление", []string{"delete"}, ""},
		{"удаление в другом написании", []string{"Delete"}, ""},
		{"правка и удаление", []string{"update", "delete"}, "editor"},
		{"чтение и удаление", []string{"get", "delete"}, "viewer"},
		{"одна правка", []string{"update"}, "editor"},
		{"одно чтение", []string{"get"}, "viewer"},
		{"подстановка", []string{"*"}, "admin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verbs, tier := domain.ResolveVerbsAndTier(c.authored, fiveVerbs)
			require.Equalf(t, c.wantTier, tier, "ярус правила с глаголами %v", c.authored)
			if c.authored[0] != "*" {
				require.Equalf(t, c.authored, verbs, "глаголы правила без подстановки не меняются")
			}
		})
	}
}

// TestScopeSelfTier_AccountDeleteIsNotACascadeSource — роль `{iam, [account],
// [delete]}`, выданная на аккаунт, не даёт яруса на объекте аккаунта: ярус
// `admin` там — источник каскада третьего уровня, то есть весь аккаунт.
// Близнец — та же роль с подстановкой `*` вместо `delete`.
func TestScopeSelfTier_AccountDeleteIsNotACascadeSource(t *testing.T) {
	tierOn := func(rs domain.Rules) string {
		verbs := rs.ScopeSelfVerbs("account", fiveVerbs)
		require.NotNilf(t, verbs, "правило над iam.account обязано проецироваться на объект аккаунта: %v", rs)
		_, tier := domain.ResolveVerbsAndTier(verbs, fiveVerbs)
		return tier
	}
	del := domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"delete"}}}
	star := domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"*"}}}

	require.Equal(t, "admin", tierOn(star), "близнец: роль с `*` на аккаунте остаётся администратором")
	require.Equal(t, "", tierOn(del),
		"роль с одним `delete` на аккаунте не даёт яруса на объекте аккаунта (ярус admin — весь аккаунт)")
}
