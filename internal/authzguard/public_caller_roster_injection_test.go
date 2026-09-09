// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// public_caller_roster_injection_test.go — ОПЫТ: способен ли перечень отправителей
// публичного листенера упасть на расширенном круге и смолчать на законном (#2376).
//
// Ось заведена вместе с переносом источника перечня: прежде он выводился обходом
// каталога модулей ПЛАТФОРМЫ, и после разреза службы выводить его было бы неоткуда
// — проба объявила бы третий исход и замолчала. Теперь источник — объявление
// фундамента, доступное службе зависимостью; значит и доказательство обязано
// исполняться без дерева платформы: здесь оно и объявление, и таблица подаются
// ВХОДОМ, дерева не читается вовсе.
//
// Каждая инъекция меняет РОВНО ОДИН факт против законного близнеца.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/platformmodules"
)

// rosterTwin — законный близнец: таблица допусков и объявление, сходящиеся между
// собой. Взяты НАСТОЯЩИЕ, а не выдуманные: подделка, снисходительнее продукта,
// сделала бы невидимым ровно тот дефект, ради которого доказательство пишется.
func rosterTwin() (map[string][]string, map[string]struct{}) {
	return PublicPeerCallableRPCs(), declaredPlatformModules()
}

// TestPeerCallableRoster_SilentOnTheLegitimateTwin — контроль. Без него красное
// ниже было бы неотличимо от предиката, который краснеет всегда.
func TestPeerCallableRoster_SilentOnTheLegitimateTwin(t *testing.T) {
	table, declared := rosterTwin()
	found, seen := auditPeerCallableRoster(table, declared)
	if len(found) != 0 {
		t.Fatalf("законный близнец объявлен находкой: %v", found)
	}
	if seen == 0 {
		t.Fatal("контроль осмотрел ноль допусков — его молчание сказано ни о чём")
	}
	t.Logf("контроль: допусков осмотрено %d, находок 0", seen)
}

// TestPeerCallableRoster_FindsACallerOutsideTheDeclaration — ИНЪЕКЦИЯ: круг
// расширен именем, которого объявление не знает.
//
// Вход настоящий по форме: снятый сетевой оператор — ровно тот случай, ради
// которого ось и заведена. Сертификата с таким именем мы не выпускаем, но допуск,
// написанный под него, разрешит всё, что в нём написано, в тот день, когда его
// кто-нибудь выпустит.
func TestPeerCallableRoster_FindsACallerOutsideTheDeclaration(t *testing.T) {
	table, declared := rosterTwin()

	widened := make(map[string][]string, len(table))
	for m, svcs := range table {
		widened[m] = append([]string(nil), svcs...)
	}
	widened[projectGetMethod] = append(widened[projectGetMethod], "vpc-operator")

	found, seen := auditPeerCallableRoster(widened, declared)
	if len(found) != 1 {
		t.Fatalf("одно-фактная инъекция дала %d находок, а обязана одну: %v", len(found), found)
	}
	if !strings.Contains(found[0], "vpc-operator") || !strings.Contains(found[0], projectGetMethod) {
		t.Fatalf("находка не называет координату: %q", found[0])
	}
	if seen == 0 {
		t.Fatal("инъекция осмотрела ноль допусков — красное пришло не от предмета")
	}
}

// TestPeerCallableRoster_FindsAModuleDroppedFromTheDeclaration — ИНЪЕКЦИЯ с
// ДРУГОЙ стороны: таблица прежняя, а модуль перестал быть объявленным.
//
// Ось отдельная и не покрывается первой: там расширяли круг, здесь сузилось
// объявление. Наблюдаемо это одно и то же — допуск предъявителю, которого мы не
// контролируем, — но приходит оно с противоположной стороны шва.
func TestPeerCallableRoster_FindsAModuleDroppedFromTheDeclaration(t *testing.T) {
	table, declared := rosterTwin()

	narrowed := make(map[string]struct{}, len(declared))
	for m := range declared {
		if m == "storage" {
			continue
		}
		narrowed[m] = struct{}{}
	}

	found, _ := auditPeerCallableRoster(table, narrowed)
	if len(found) == 0 {
		t.Fatal("модуль снят из объявления, а допуск ему остался незамеченным")
	}
	for _, f := range found {
		if !strings.Contains(f, "storage") {
			t.Fatalf("находка не о снятом модуле: %q", f)
		}
	}
}

// TestPeerCallableRoster_DeclarationIsReadFromTheFoundation — ПРЕДПОСЫЛКА оси, и
// она несущая: перечень обязан приходить из объявления ФУНДАМЕНТА, а не из дерева
// платформы. Иначе после разреза источник исчезнет, а проба замолчит.
//
// Утверждается наблюдаемое: объявление отдаёт непустой перечень и колонка
// коротких имён в нём совпадает с тем, что читает гейт. Дерева платформы здесь не
// касается ни одна строка.
func TestPeerCallableRoster_DeclarationIsReadFromTheFoundation(t *testing.T) {
	declared := declaredPlatformModules()
	all := platformmodules.All()
	if len(all) == 0 {
		t.Fatal("объявление фундамента пусто — источник перечня беспредметен")
	}
	if len(declared) != len(all) {
		t.Fatalf("гейт прочитал %d модулей из %d объявленных — часть словаря вне наблюдения",
			len(declared), len(all))
	}
	for _, m := range all {
		if _, ok := declared[m.Service]; !ok {
			t.Fatalf("объявленный модуль %q гейту не виден", m.Service)
		}
	}
	t.Logf("перепись: объявление фундамента несёт %d модулей, все прочитаны", len(all))
}
