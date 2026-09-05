// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// rule_verbs_typeset_test.go — подстановка в правиле разворачивается в набор
// СВОЕГО типа, а не в платформенный словарь.
//
// Предмет. `*` разворачивался в глобальный литерал, поэтому правило на ЛЮБОМ типе
// давало один и тот же набор. Набор теперь приходит от вызывающего, который тип уже
// знает; домен остаётся без внешних зависимостей (объявление файла «pure domain,
// stdlib only» обязано остаться правдой — иначе фаза чинит один класс
// doc-truthfulness и тут же заводит другой).

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestResolveVerbsAndTier_WildcardExpandsToTypeSet — несущий кейс фазы.
func TestResolveVerbsAndTier_WildcardExpandsToTypeSet(t *testing.T) {
	five := []string{"get", "list", "create", "update", "delete"}

	got, tier := ResolveVerbsAndTier([]string{"*"}, five)
	require.ElementsMatch(t, five, got)
	require.Equal(t, "admin", tier)

	// Несущий кейс: у типа набор ШИРЕ — `*` обязан развернуться в НЕГО, а не в
	// платформенную пятёрку. Такого типа сегодня нет; кейс синтетический и охраняет
	// свойство ДО появления первого пользователя.
	wide := []string{"get", "list", "create", "update", "delete", "addtargets"}
	gotWide, tierWide := ResolveVerbsAndTier([]string{"*"}, wide)
	require.ElementsMatch(t, wide, gotWide,
		"`*` развернулась не в набор типа — правило на расширенном типе не выдаст обещанного глагола")
	require.Equal(t, "admin", tierWide)

	// Парный кейс сужения: у типа набор УЖЕ — `*` не вправе выдать глагол, которого
	// тип не объявляет. Без него «развернулось в набор» неотличимо от «развернулось
	// в объединение с прежней пятёркой».
	narrow := []string{"get", "list"}
	gotNarrow, tierNarrow := ResolveVerbsAndTier([]string{"*"}, narrow)
	require.ElementsMatch(t, narrow, gotNarrow,
		"`*` выдала глагол, которого тип не объявляет — это ровно висячий кортеж")
	require.Equal(t, "viewer", tierNarrow)
}

// TestResolveVerbsAndTier_AuthoredVerbsPassThroughUnchanged — правило без
// подстановки набором типа не сужается: сужение — забота эмиссии
// (IsVerbOfType), а не разворота. Парный положительный к кейсам выше.
func TestResolveVerbsAndTier_AuthoredVerbsPassThroughUnchanged(t *testing.T) {
	got, tier := ResolveVerbsAndTier([]string{"get", "start"}, []string{"get", "list"})
	require.ElementsMatch(t, []string{"get", "start"}, got,
		"явно названные глаголы обязаны дойти до вызывающего: доменный глагол несёт доступ ярусным кортежем")
	require.Equal(t, "editor", tier)
}

// TestIsVerbOfType_IsScopedToTheTypeSet — принадлежность решается набором ТИПА.
func TestIsVerbOfType_IsScopedToTheTypeSet(t *testing.T) {
	five := []string{"get", "list", "create", "update", "delete"}
	require.True(t, IsVerbOfType("delete", five))
	require.False(t, IsVerbOfType("addtargets", five))

	// у типа набор ШИРЕ — глагол принадлежит
	require.True(t, IsVerbOfType("addtargets", []string{"get", "addtargets"}))
	// у типа набор УЖЕ — тот же глагол НЕ принадлежит; это и есть разница,
	// невыразимая глобальным словарём
	require.False(t, IsVerbOfType("delete", []string{"get", "list"}))
	// пустой набор не принадлежит никому — fail-closed
	require.False(t, IsVerbOfType("get", nil))
}

// TestScopeSelfVerbs_ExpandsWildcardToTheScopeTypeSet — проекция на собственный
// якорь привязки тоже разворачивает `*` по набору ТИПА якоря.
func TestScopeSelfVerbs_ExpandsWildcardToTheScopeTypeSet(t *testing.T) {
	superuser := Rules{{Module: wildcard, Resources: []string{wildcard}, Verbs: []string{wildcard}}}
	wide := []string{"get", "list", "create", "update", "delete", "addtargets"}
	require.ElementsMatch(t, wide, superuser.ScopeSelfVerbs("account", wide))

	narrow := []string{"get", "list"}
	require.ElementsMatch(t, narrow, superuser.ScopeSelfVerbs("account", narrow))
}

// TestDomainStaysStdlibOnly — объявление файла обязано остаться правдой.
// Проверяется декларативно: набор приходит ПАРАМЕТРОМ именно ради этого, и если
// кто-то развернёт стрелку зависимости внутрь домена, объявление станет ложным.
func TestDomainStaysStdlibOnly(t *testing.T) {
	assertNoRepoImports(t, "rule_verbs.go")
	assertNoRepoImports(t, "role_effective_verbs.go")
}
