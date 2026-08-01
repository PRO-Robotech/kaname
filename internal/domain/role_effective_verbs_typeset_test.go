// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

// TestAuthoredVerbs_UnknownTypeFallsBackToCommon — правило, не резолвящееся ни в
// один известный тип, разворачивается общим для всех ресурсов словарём. Парный к
// кейсу выше: без него «следует набору» было бы неотличимо от «молчит на незнакомом».
func TestAuthoredVerbs_UnknownTypeFallsBackToCommon(t *testing.T) {
	role := Role{Rules: Rules{{Module: "nosuch", Resources: []string{"thing"}, Verbs: []string{"*"}}}}
	unknown := func(module, resource string) ([]string, bool) {
		_, _ = module, resource
		return nil, false
	}
	got := role.AuthoredVerbs(WithCommonFallback(unknown, []string{"get", "list", "create", "update", "delete"}))
	require.Equal(t, []string{"get", "list", "create", "update", "delete"}, got)
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
