// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// role_effective_verbs_typeset_test.go — превью роли разворачивает подстановку по
// набору СВОЕГО типа.
//
// Почему это несущее, а не косметика. Превью — ПУБЛИЧНЫЙ контракт: поле объявлено
// честным показом того, что роль на самом деле даёт. Пятая таблица была
// единственной, у которой не было сверяющего ни с эмиттером, ни с моделью: она
// жила в одном файле всего дерева, и её собственное зеркало ловило правку САМОЙ
// таблицы, но расхождение с эмиттером не ловило ничто. Отставшее превью — роль,
// чьё обещание и чья материализация разошлись.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// lookupFive — набор типа на этой стадии: та же пятёрка у любого типа.
func lookupFive(module, resource string) ([]string, bool) {
	_, _ = module, resource
	return []string{"get", "list", "create", "update", "delete"}, true
}

// TestAuthoredVerbs_WildcardExpandsToRuleTypeSet — несущий кейс.
//
// Сегодня зелено при ЛЮБОМ наборе, потому что превью держало собственный литерал.
// После перевода обязано следовать набору ТИПА, на который адресовано правило.
func TestAuthoredVerbs_WildcardExpandsToRuleTypeSet(t *testing.T) {
	role := Role{Rules: Rules{{Module: "loadbalancer", Resources: []string{"targetGroups"}, Verbs: []string{"*"}}}}

	// у типа набор ШИРЕ платформенной пятёрки
	wide := func(module, resource string) ([]string, bool) {
		_, _ = module, resource
		return []string{"get", "list", "create", "update", "delete", "addtargets"}, true
	}
	require.ElementsMatch(t,
		[]string{"get", "list", "create", "update", "delete", "addtargets"},
		role.AuthoredVerbs(wide),
		"превью не показало глагол, который роль на этом типе РЕАЛЬНО даёт — "+
			"обещание и материализация разошлись")

	// у типа набор УЖЕ — превью не вправе обещать лишнего
	narrow := func(module, resource string) ([]string, bool) {
		_, _ = module, resource
		return []string{"get", "list"}, true
	}
	require.ElementsMatch(t, []string{"get", "list"}, role.AuthoredVerbs(narrow),
		"превью пообещало глагол, которого тип не объявляет — обещание шире материализации")
}

// unknownLookup — ни одна пара не резолвится. Общий вход обоих кейсов ниже:
// различает их ФОРМА правила, а не поведение резолва.
func unknownLookup(module, resource string) ([]string, bool) {
	_, _ = module, resource
	return nil, false
}

// commonVocabulary — запасной словарь, общий для всех ресурсов.
var commonVocabulary = []string{"get", "list", "create", "update", "delete"}

// TestAuthoredVerbs_WildcardRuleFallsBackToCommon — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ
// запасного словаря: правило-подстановка (`*.*` роли-суперпользователя) своего
// набора не имеет by construction — перечислить ресурсы подстановки домену
// нечем, — поэтому получает общий словарь. Пустое превью читалось бы как «роль
// ничего не даёт».
//
// Парный к кейсу ниже: без него «названный ресурс не разворачивается» было бы
// неотличимо от «запасной словарь не работает вовсе».
func TestAuthoredVerbs_WildcardRuleFallsBackToCommon(t *testing.T) {
	role := Role{Rules: Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}}}
	got := role.AuthoredVerbs(WithCommonFallback(unknownLookup, commonVocabulary))
	require.Equal(t, commonVocabulary, got,
		"правило-подстановка осталось без превью — роль выглядит ничего не дающей")
}

// TestAuthoredVerbs_NamedUnresolvedTypeContributesNothing — НАЗВАННЫЙ ресурс,
// который не резолвится (снят с каталога либо не существовал), не разворачивается
// НИ ВО ЧТО (kacho#1814).
//
// Прежде запасной словарь выдавался ЛЮБОЙ нерезолвящейся паре, и это переворачивало
// смысл снятия ресурса: после снятия превью роли показывало не «меньше», а БОЛЬШЕ —
// глаголы всей платформы вместо набора одного типа. Роль обещала арендатору то,
// чего материализация не даёт, причём тем громче, чем меньше правило адресует.
//
// Здесь стоял кейс, ЗАКРЕПЛЯВШИЙ это поведение: он подавал пару `nosuch.thing` —
// названную, а не подстановку — и требовал общий словарь. Кейс переписан на
// подстановку (выше), потому что запасной словарь объявлялся именно для неё.
func TestAuthoredVerbs_NamedUnresolvedTypeContributesNothing(t *testing.T) {
	role := Role{Rules: Rules{{Module: "compute", Resources: []string{"disk"}, Verbs: []string{"*"}}}}
	got := role.AuthoredVerbs(WithCommonFallback(unknownLookup, commonVocabulary))
	require.Empty(t, got,
		"правило, называющее снятый ресурс, развернулось в глаголы ВСЕЙ платформы: "+
			"снятие ресурса расширяет обещание роли вместо того, чтобы сужать его")
}

// TestAuthoredVerbs_NamedResolvedTypeIsUnaffected — второй положительный
// контроль: сужение выше касается ТОЛЬКО нерезолвящейся пары. Названный ресурс,
// который резолвится, разворачивается своим набором, как и прежде.
func TestAuthoredVerbs_NamedResolvedTypeIsUnaffected(t *testing.T) {
	role := Role{Rules: Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"*"}}}}
	got := role.AuthoredVerbs(WithCommonFallback(lookupFive, commonVocabulary))
	require.Equal(t, commonVocabulary, got,
		"резолвящийся тип потерял свой набор — сужение задело законную полосу")
}

// TestAuthoredVerbs_MultiTypeRuleTakesTheUnion — правило адресует НЕСКОЛЬКО типов:
// подстановка разворачивается в ОБЪЕДИНЕНИЕ их наборов. Решение принято планом и
// вынесено ревьюеру: на этой стадии любой вариант даёт прежний результат, но он
// станет наблюдаемым в первый же день после первого расширенного типа.
func TestAuthoredVerbs_MultiTypeRuleTakesTheUnion(t *testing.T) {
	role := Role{Rules: Rules{{
		Module:    "loadbalancer",
		Resources: []string{"targetGroups", "listeners"},
		Verbs:     []string{"*"},
	}}}
	byResource := func(module, resource string) ([]string, bool) {
		_ = module
		if resource == "targetGroups" {
			return []string{"get", "addtargets"}, true
		}
		return []string{"get", "list"}, true
	}
	require.ElementsMatch(t, []string{"get", "list", "addtargets"}, role.AuthoredVerbs(byResource))
}

// TestEffectiveVerbs_UnchangedForEveryRuleShape — ЗАМОК стадии.
//
// Для каждой формы правила превью байт-в-байт прежнее при наборе, равном
// платформенной пятёрке. Число форм — перепись, а не константа: ноль форм ⇒ отказ
// на предпосылке, иначе «замок» запирал бы пустоту.
func TestEffectiveVerbs_UnchangedForEveryRuleShape(t *testing.T) {
	shapes := []struct {
		name          string
		rules         Rules
		wantAuthored  []string
		wantEffective []string
	}{
		{
			name:          "подстановка → полный набор, ярус администратора",
			rules:         Rules{{Module: wildcard, Resources: []string{wildcard}, Verbs: []string{wildcard}}},
			wantAuthored:  []string{"get", "list", "create", "update", "delete"},
			wantEffective: []string{"get", "list", "create", "update", "delete"},
		},
		{
			name:          "редактор без удаления → квалификатор delete*",
			rules:         Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "update"}}},
			wantAuthored:  []string{"get", "update"},
			wantEffective: []string{"get", "update", EditorDeleteVerb},
		},
		{
			name:          "только чтение → без квалификатора",
			rules:         Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "list"}}},
			wantAuthored:  []string{"get", "list"},
			wantEffective: []string{"get", "list"},
		},
		{
			name:          "доменный глагол сортируется в хвост стабильно",
			rules:         Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"start", "get"}}},
			wantAuthored:  []string{"get", "start"},
			wantEffective: []string{"get", "start"},
		},
		{
			name:          "роль без правил → пусто",
			rules:         Rules{},
			wantAuthored:  []string{},
			wantEffective: []string{},
		},
	}
	require.NotEmpty(t, shapes, "форм правил ноль — замок запирал бы пустоту")
	for _, sh := range shapes {
		role := Role{Rules: sh.rules}
		require.Equalf(t, sh.wantAuthored, role.AuthoredVerbs(lookupFive), "%s: authored", sh.name)
		require.Equalf(t, sh.wantEffective, role.EffectiveVerbs(lookupFive), "%s: effective", sh.name)
	}
	t.Logf("перепись: форм правил заперто: %d", len(shapes))
}

// TestVerbNotes_UnchangedForEditorTier — заметка редактора не изменилась.
func TestVerbNotes_UnchangedForEditorTier(t *testing.T) {
	editor := Role{Rules: Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"update"}}}}
	require.Equal(t, map[string]string{EditorDeleteVerb: EditorDeleteNote}, editor.VerbNotes(lookupFive))

	admin := Role{Rules: Rules{{Module: wildcard, Resources: []string{wildcard}, Verbs: []string{wildcard}}}}
	require.Empty(t, admin.VerbNotes(lookupFive))
}
