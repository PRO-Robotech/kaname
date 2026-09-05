// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap

// role_verbs_test.go — предикат «что роль разрешает на типе» один, и обе стороны
// им отвечают одинаково.
//
// Утверждается ИСХОД предиката, а не то, что функция вызвана: «зовут одну
// функцию» остаётся верным и тогда, когда она отвечает неверно.

import (
	"sort"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// Подстановка разворачивается в набор ТИПА. Это и был дефект: роль-администратор
// (`verbs: ["*"]`) давала движку весь набор, а проекции — ни одной пары.
func TestGrantedVerbs_WildcardExpandsToTheTypeSet(t *testing.T) {
	const fgaType = "vpc_network"
	typeVerbs := VerbsOfType(fgaType)
	if len(typeVerbs) == 0 {
		t.Fatalf("у типа %s нет объявленного набора глаголов — предпосылка пробы не выполнена, "+
			"и её «ноль» ничего не утверждал бы", fgaType)
	}

	got := GrantedVerbs(fgaType, []string{"*"}, typeVerbs)
	if len(got) != len(typeVerbs) {
		t.Fatalf("подстановка дала %v (глаголов %d), набор типа — %v (%d)",
			sortedCopy(got), len(got), sortedCopy(typeVerbs), len(typeVerbs))
	}

	// Отрицание рядом: чужой глагол не появляется оттого, что его назвали.
	if extra := GrantedVerbs(fgaType, []string{"teleport"}, typeVerbs); len(extra) != 0 {
		t.Errorf("глагол вне набора типа дал %v", extra)
	}
}

// Правка влечёт удаление НА ЛИСТЕ и не влечёт на области иерархии.
func TestGrantedVerbs_UpdateImpliesDeleteOnLeavesOnly(t *testing.T) {
	leaf := GrantedVerbs("vpc_network", []string{"update"}, VerbsOfType("vpc_network"))
	if !contains(leaf, "delete") {
		t.Errorf("редактор листа не получил удаления: %v — уборка за своим же ресурсом "+
			"отказывает", sortedCopy(leaf))
	}
	if !contains(leaf, "update") {
		t.Errorf("названный глагол потерян: %v", sortedCopy(leaf))
	}

	// Законный близнец: область иерархии удаления не получает — снос области
	// принадлежит владельцу, а не редактору содержимого.
	for _, scope := range []string{"account", "project"} {
		got := GrantedVerbs(scope, []string{"update"}, VerbsOfType(scope))
		if contains(got, "delete") {
			t.Errorf("редактор получил удаление области %s: %v", scope, sortedCopy(got))
		}
	}
}

// Тип, не объявивший набора глаголов, не получает ни одного: отношения `v_*` у
// него нет, и пара в проекции адресовала бы то, чего в модели не существует.
func TestGrantedVerbs_TypeWithoutDeclaredVerbsGetsNone(t *testing.T) {
	const undeclared = "iam_fgaproxy"
	if len(VerbsOfType(undeclared)) != 0 {
		t.Skipf("у типа %s появился набор глаголов — предпосылка пробы истекла", undeclared)
	}
	if got := GrantedVerbs(undeclared, []string{"*"}, CommonVerbVocabulary()); len(got) != 0 {
		t.Errorf("тип без объявленного набора получил %v", sortedCopy(got))
	}
}

// Проекция несёт ТОЧЕЧНУЮ форму типа — ту же, какой её читает вердикт. Форма
// модели в этой колонке не совпала бы с вопросом НИКОГДА и молча.
func TestRoleVerbsFromSelectors_KeepsTheDottedTypeAndExpandsTheWildcard(t *testing.T) {
	dotted, ok := DottedType("vpc_network")
	if !ok {
		t.Fatal("у vpc_network нет точечного имени — предпосылка пробы не выполнена")
	}
	pairs := RoleVerbsFromSelectors([]domain.RuleSelector{
		{ObjectTypes: []string{dotted}, Verbs: []string{"*"}},
	})
	if len(pairs) == 0 {
		t.Fatal("роль с подстановкой не дала ни одной пары — ровно этот дефект и чинится")
	}
	for _, p := range pairs {
		if p.ObjectType != dotted {
			t.Errorf("тип в проекции %q, ожидалась точечная форма %q", p.ObjectType, dotted)
		}
		if p.Verb != domain.NormalizeVerb(p.Verb) {
			t.Errorf("глагол %q не приведён — неприведённая строка не будет найдена запросом", p.Verb)
		}
	}

	// Отрицание: тип, которого каталог не знает, пар не даёт. Выдумать за него
	// набор значило бы дать право, которого движок не даёт.
	if n := len(RoleVerbsFromSelectors([]domain.RuleSelector{
		{ObjectTypes: []string{"nosuch.type"}, Verbs: []string{"get"}},
	})); n != 0 {
		t.Errorf("неизвестный тип дал %d пар", n)
	}

	// Пустой вход — пустая проекция, а не «все права».
	if n := len(RoleVerbsFromSelectors(nil)); n != 0 {
		t.Errorf("пустые селекторы дали %d пар", n)
	}
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
