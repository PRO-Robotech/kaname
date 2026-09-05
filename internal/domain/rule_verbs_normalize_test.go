// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// rule_verbs_normalize_test.go — имя глагола приводится к канонической форме в
// ОДНОЙ точке.
//
// Разрыв был двусторонним. Проверка принадлежности приводила вход к нижнему
// регистру, а индекс словаря строился ДОСЛОВНО — значит словарная запись с
// заглавной буквой не нашлась бы НИКОГДА. И наоборот: имя отношения собиралось из
// АВТОРСКОГО написания, поэтому написание, отличающееся регистром, проходило
// проверку и адресовало отношение, которого не существует. Превью не приводило
// вовсе — то же слово в двух написаниях давало две записи.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNormalizeVerb_IsIdentityOnPlatformVerbs — БЕЗОПАСНОСТЬ ПРАВКИ: приведение
// тождественно на всех существующих глаголах ⇒ ни одно отношение, ни один кортеж и
// ни одна запись каталога не меняются. Перечислением, не образцом.
func TestNormalizeVerb_IsIdentityOnPlatformVerbs(t *testing.T) {
	// Перечисление по ДЕРЕВУ живёт в пакете таблицы
	// (authzmap: TestNormalizeVerb_IsIdentityOnEveryDeclaredVerb) — там оно
	// охватывает наборы всех типов. Здесь — быстрый доменный дубль на той пятёрке,
	// которую типы объявляют сегодня; домен таблицу звать не вправе.
	verbs := []string{"get", "list", "create", "update", "delete"}
	require.NotEmpty(t, verbs, "перечислять нечего — предпосылка сломана")
	for _, v := range verbs {
		require.Equalf(t, v, NormalizeVerb(v),
			"приведение изменило существующий глагол %q — правка перестала быть безопасной", v)
	}
	t.Logf("перепись: глаголов проверено на тождественность: %d", len(verbs))
}

// TestNormalizeVerb_FoldsSpellingDifferences — парный положительный: приведение
// действительно что-то делает. Без него тождественность выше зеленела бы и на
// функции, возвращающей вход как есть.
func TestNormalizeVerb_FoldsSpellingDifferences(t *testing.T) {
	require.Equal(t, "update", NormalizeVerb("Update"))
	require.Equal(t, "update", NormalizeVerb("UPDATE"))
	require.Equal(t, "update", NormalizeVerb("  update "))
	require.Equal(t, "", NormalizeVerb("   "))
}

// TestIsVerbOfType_UsesTheSameNormalizationOnBothSides — обе стороны сверки
// приводятся ОДНОЙ точкой: запись набора с заглавной буквой обязана находиться.
func TestIsVerbOfType_UsesTheSameNormalizationOnBothSides(t *testing.T) {
	require.True(t, IsVerbOfType("update", []string{"Get", "Update"}),
		"запись набора в другом написании не нашлась — индекс строится не через ту же точку приведения")
	require.True(t, IsVerbOfType("Update", []string{"get", "update"}))
	require.False(t, IsVerbOfType("delete", []string{"get", "update"}))
}

// TestResolveVerbsAndTier_TierIsSpellingInsensitive — вывод яруса тоже приводится:
// иначе `Delete` дал бы ярус редактора вместо администратора.
func TestResolveVerbsAndTier_TierIsSpellingInsensitive(t *testing.T) {
	_, tier := ResolveVerbsAndTier([]string{"Delete"}, []string{"get", "delete"})
	require.Equal(t, "admin", tier)
}

// TestAuthoredVerbs_FoldsSpellingIntoOneEntry — превью не показывает одно и то же
// слово дважды в разных написаниях.
func TestAuthoredVerbs_FoldsSpellingIntoOneEntry(t *testing.T) {
	role := Role{Rules: Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"Get", "get"}}}}
	require.Equal(t, []string{"get"}, role.AuthoredVerbs(lookupFive))
}
