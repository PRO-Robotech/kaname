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

	"github.com/PRO-Robotech/kaname/internal/domain"
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

	got := GrantedVerbs(fgaType, []string{"*"}, typeVerbs, domain.TenantPolicy())
	if len(got) != len(typeVerbs) {
		t.Fatalf("подстановка дала %v (глаголов %d), набор типа — %v (%d)",
			sortedCopy(got), len(got), sortedCopy(typeVerbs), len(typeVerbs))
	}

	// Отрицание рядом: чужой глагол не появляется оттого, что его назвали.
	if extra := GrantedVerbs(fgaType, []string{"teleport"}, typeVerbs, domain.TenantPolicy()); len(extra) != 0 {
		t.Errorf("глагол вне набора типа дал %v", extra)
	}
}

// Правка влечёт удаление НА ЛИСТЕ и не влечёт на области иерархии.
func TestGrantedVerbs_UpdateImpliesDeleteOnLeavesOnly(t *testing.T) {
	leaf := GrantedVerbs("vpc_network", []string{"update"}, VerbsOfType("vpc_network"), domain.TenantPolicy())
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
		got := GrantedVerbs(scope, []string{"update"}, VerbsOfType(scope), domain.TenantPolicy())
		if contains(got, "delete") {
			t.Errorf("редактор получил удаление области %s: %v", scope, sortedCopy(got))
		}
	}
}

// Роль МОДУЛЯ получает ровно объявленные классы: правка у неё удаления не влечёт
// (kaname#1006). Типы — те, на которых дефект наблюдался: роль публикации образов
// с классом `update` на регистри и его репозиториях получала их удаление.
//
// Близнец меняет ровно один факт — владельца роли: та же правка на том же типе у
// роли платформы и арендатора удаление по-прежнему влечёт. Второй близнец —
// роль модуля, назвавшая удаление классом, его сохраняет: правило снимает только
// ПРИПИСАННОЕ удаление, а не объявленное.
func TestGrantedVerbs_ModuleRoleUpdateDoesNotImplyDelete(t *testing.T) {
	module := domain.PolicyOfRole(true, "registry")
	for _, fgaType := range []string{"registry_repository", "registry_registry"} {
		typeVerbs := VerbsOfType(fgaType)
		if !contains(typeVerbs, "delete") || !contains(typeVerbs, "update") {
			t.Fatalf("у типа %s набор %v без правки или удаления — предпосылка пробы не "+
				"выполнена, и её молчание ничего не утверждало бы", fgaType, sortedCopy(typeVerbs))
		}

		got := GrantedVerbs(fgaType, []string{"get", "list", "update"}, typeVerbs, module)
		if contains(got, "delete") {
			t.Errorf("роль модуля с правкой получила удаление на %s: %v — манифест удаления "+
				"не объявлял", fgaType, sortedCopy(got))
		}
		if !contains(got, "update") {
			t.Errorf("названный глагол потерян на %s: %v", fgaType, sortedCopy(got))
		}

		for name, policy := range map[string]domain.RulePolicy{
			"платформы":  domain.PolicyOfRole(true, ""),
			"арендатора": domain.TenantPolicy(),
		} {
			if twin := GrantedVerbs(fgaType, []string{"update"}, typeVerbs, policy); !contains(twin, "delete") {
				t.Errorf("роль %s с правкой на %s не получила удаления: %v — правило «правка "+
					"влечёт удаление» снято шире предмета", name, fgaType, sortedCopy(twin))
			}
		}

		if named := GrantedVerbs(fgaType, []string{"update", "delete"}, typeVerbs, module); !contains(named, "delete") {
			t.Errorf("роль модуля, назвавшая удаление, его потеряла на %s: %v", fgaType, sortedCopy(named))
		}
	}
}

// Проекция роли модуля — тем же предикатом: пары «тип × delete» у правки нет.
func TestRoleVerbsFromSelectors_ModuleRoleCarriesNoImpliedDelete(t *testing.T) {
	dotted, ok := DottedType("registry_repository")
	if !ok {
		t.Fatal("у registry_repository нет точечного имени — предпосылка пробы не выполнена")
	}
	sel := []domain.RuleSelector{{ObjectTypes: []string{dotted}, Verbs: []string{"get", "list", "update"}}}
	has := func(pairs []domain.RoleVerb) bool {
		for _, p := range pairs {
			if p.Verb == "delete" {
				return true
			}
		}
		return false
	}
	if has(RoleVerbsFromSelectors(sel, domain.PolicyOfRole(true, "registry"))) {
		t.Error("проекция роли модуля несёт удаление, которого манифест не объявлял")
	}
	if !has(RoleVerbsFromSelectors(sel, domain.PolicyOfRole(true, ""))) {
		t.Error("проекция роли платформы с правкой потеряла удаление — правило снято шире предмета")
	}
}

// Тип, не объявивший набора глаголов, не получает ни одного: отношения `v_*` у
// него нет, и пара в проекции адресовала бы то, чего в модели не существует.
func TestGrantedVerbs_TypeWithoutDeclaredVerbsGetsNone(t *testing.T) {
	const undeclared = "iam_fgaproxy"
	if len(VerbsOfType(undeclared)) != 0 {
		t.Skipf("у типа %s появился набор глаголов — предпосылка пробы истекла", undeclared)
	}
	if got := GrantedVerbs(undeclared, []string{"*"}, CommonVerbVocabulary(), domain.TenantPolicy()); len(got) != 0 {
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
	}, domain.TenantPolicy())
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
	}, domain.TenantPolicy())); n != 0 {
		t.Errorf("неизвестный тип дал %d пар", n)
	}

	// Пустой вход — пустая проекция, а не «все права».
	if n := len(RoleVerbsFromSelectors(nil, domain.TenantPolicy())); n != 0 {
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
