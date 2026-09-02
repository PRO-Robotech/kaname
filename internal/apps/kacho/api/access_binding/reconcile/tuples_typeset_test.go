// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package reconcile

// tuples_typeset_test.go — эмиссия сверяет глагол с набором ТИПА во ВСЕХ ТРЁХ
// местах, включая литеральное.
//
// Три места, и третье не похоже на первые два. Два цикла сверялись с ГЛОБАЛЬНЫМ
// словарём; третье — дописывание отношения СТРОКОЙ под собственным условием — не
// сверялось ни с чем. Пока набор был одинаков у всех типов, это было безвредно. С
// набором У ТИПА это ровно тот висячий кортеж, против которого написана под-фаза:
// тип, у которого отношения нет, получил бы его от правила, называющего СОСЕДНИЙ
// глагол. Перепись «трёх мест», снятая по вызовам сверяющей функции, дала бы ДВА.
//
// Несущая половина здесь ОТРИЦАТЕЛЬНАЯ, и каждое отрицание идёт в паре с
// положительным в том же прогоне: «не появилось» иначе неотличимо от «эмиттер не
// работает».

import (
	"sort"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/catalogfixture"
)

// allDottedCatalogKeys — точечные ключи КАЖДОГО грантуемого типа каталога.
// Перечисление берётся из каталога, а не из литерала: литерал сам стал бы
// поверхностью дрейфа и оставил бы новый тип вне инъекции радиуса молча.
func allDottedCatalogKeys() []string {
	entries := authzmap.Catalog()
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Module+"."+e.Resource)
	}
	sort.Strings(out)
	return out
}

// typeVerbRelationsOf — имена `v_*`, объявленные типом.
func typeVerbRelationsOf(fgaType string) []string {
	return authzmap.VerbRelationsOfType(fgaType)
}

// relationsOf — имена отношений набора кортежей, отсортированно.
func relationsOf(tuples []domain.MembershipTuple) []string {
	out := make([]string, 0, len(tuples))
	for _, t := range tuples {
		out = append(out, t.Relation)
	}
	sort.Strings(out)
	return out
}

func containsRel(rels []string, want string) bool {
	for _, r := range rels {
		if r == want {
			return true
		}
	}
	return false
}

// TestRuleObjectTuples_DoesNotEmitVerbNotDeclaredByType — глагол, которого тип не
// объявляет, отношения не порождает.
func TestRuleObjectTuples_DoesNotEmitVerbNotDeclaredByType(t *testing.T) {
	// синтетический тип с УРЕЗАННЫМ набором (без v_delete) — то, чего сегодня в
	// таблице нет и что после переформулировки выразимо.
	narrow := []string{"get", "list", "create", "update"}

	got, ok := ruleObjectTuplesWithTypeVerbs(catalogfixture.Facts(), "user:usr_a", []string{"update", "delete"},
		"vpc_network", "net_1", narrow)
	if !ok {
		t.Fatalf("эмиссия не состоялась вовсе — отрицание ниже было бы бессодержательным")
	}
	rels := relationsOf(got)

	// ОТРИЦАНИЕ: конкретное отношение ОТСУТСТВУЕТ (не «кортежей не стало больше»).
	if containsRel(rels, "v_delete") {
		t.Errorf("эмиттер написал v_delete на типе, который его не объявляет: %v.\n"+
			"Это висячий кортеж: владелец модели отвергает такую запись окончательно, "+
			"и отказ классифицируется как постоянный — строка навсегда блокирует свою "+
			"партицию очереди", rels)
	}
	// ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ в том же прогоне.
	if !containsRel(rels, "v_update") {
		t.Errorf("эмиттер не написал v_update, который тип объявляет: %v — "+
			"отрицание выше зеленело бы просто оттого, что эмиссия мертва", rels)
	}
}

// TestRuleObjectTuples_LiteralDeletePathIsAlsoPaired — ИМЕННО литеральный путь.
//
// Роль объявляет `update` и НЕ объявляет `delete`; тип не объявляет `v_delete` ⇒
// со-материализация не срабатывает. Без этого кейса правка первых двух мест
// выглядела бы полной: цикл отфильтровал бы `delete`, а литерал дописал бы его
// следом — и общий счётчик кортежей это бы не показал.
func TestRuleObjectTuples_LiteralDeletePathIsAlsoPaired(t *testing.T) {
	narrow := []string{"get", "list", "create", "update"}

	got, ok := ruleObjectTuplesWithTypeVerbs(catalogfixture.Facts(), "user:usr_a", []string{"update"},
		"vpc_network", "net_1", narrow)
	if !ok {
		t.Fatalf("эмиссия не состоялась вовсе")
	}
	rels := relationsOf(got)
	if containsRel(rels, "v_delete") {
		t.Errorf("литеральный путь дописал v_delete на типе, который его не объявляет: %v.\n"+
			"Правило назвало СОСЕДНИЙ глагол (update), а отношение появилось у типа, "+
			"который его не несёт", rels)
	}
	if !containsRel(rels, "v_update") {
		t.Errorf("v_update не написан: %v — тогда отрицание выше ничего не утверждает", rels)
	}
}

// TestRuleObjectTuples_OrdinaryUpdateStillEmits — второй парный положительный:
// обычный `update` на обычном типе по-прежнему со-материализует `v_delete`.
// Сужение не задело общий путь — это и есть «поведение не изменилось».
func TestRuleObjectTuples_OrdinaryUpdateStillEmits(t *testing.T) {
	got, ok := ruleObjectTuples(catalogfixture.Facts(), "user:usr_a", []string{"update"}, "vpc.network", "net_1")
	if !ok {
		t.Fatalf("эмиссия на обычном типе не состоялась")
	}
	rels := relationsOf(got)
	for _, want := range []string{"v_update", "v_delete", "editor"} {
		if !containsRel(rels, want) {
			t.Errorf("обычный update на vpc.network обязан дать %s: %v", want, rels)
		}
	}
}

// TestRuleObjectTuples_WildcardRuleEmitsNothingDangling — ИНЪЕКЦИЯ РАДИУСА.
//
// Правило `*` у роли не порождает висячего отношения НИ НА ОДНОМ из
// материализуемых типов — перечислением по каталогу, а не образцом. Число типов
// берётся переписью, а не константой в тексте: «ноль висячих» обязано быть отличимо
// от «ноль проверенных».
func TestRuleObjectTuples_WildcardRuleEmitsNothingDangling(t *testing.T) {
	dotted := allDottedCatalogKeys()
	if len(dotted) == 0 {
		t.Fatalf("каталог пуст — предпосылка инъекции радиуса сломана")
	}
	checked, verbTuples := 0, 0
	for _, key := range dotted {
		got, ok := ruleObjectTuples(catalogfixture.Facts(), "user:usr_a", []string{"*"}, key, "obj_1")
		if !ok {
			t.Errorf("%s: тип каталога не резолвится в FGA-тип — правило молча не материализуется", key)
			continue
		}
		checked++
		fgaType, _ := fgaObjectType(key)
		declared := map[string]bool{}
		for _, r := range typeVerbRelationsOf(fgaType) {
			declared[r] = true
		}
		for _, rel := range relationsOf(got) {
			if len(rel) > 2 && rel[:2] == "v_" {
				verbTuples++
				if !declared[rel] {
					t.Errorf("%s (%s): эмитировано отношение %q, которого тип не объявляет — висячий кортеж",
						key, fgaType, rel)
				}
			}
		}
	}
	t.Logf("перепись: типов каталога проверено: %d из %d; глагольных кортежей осмотрено: %d",
		checked, len(dotted), verbTuples)
}

// TestScopeSelfTuples_DoesNotEmitVerbNotDeclaredByType — третий путь эмиссии
// (якорь собственного охвата привязки) сверяется тем же условием.
func TestScopeSelfTuples_DoesNotEmitVerbNotDeclaredByType(t *testing.T) {
	narrow := []string{"get", "list"}
	got, ok := scopeSelfTuplesWithTypeVerbs(catalogfixture.Facts(), "user:usr_a", "account", "acc_1",
		[]string{"get", "delete"}, narrow)
	if !ok {
		t.Fatalf("эмиссия якоря не состоялась вовсе")
	}
	rels := relationsOf(got)
	if containsRel(rels, "v_delete") {
		t.Errorf("якорь получил v_delete, которого тип не объявляет: %v", rels)
	}
	if !containsRel(rels, "v_get") {
		t.Errorf("якорь не получил v_get, который тип объявляет: %v", rels)
	}
}
