// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

// condition_model_gate_test.go — набор вычисляемых условий и модель обязаны
// сходиться, и расхождение ловится с ОБЕИХ сторон.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ДВА НАПРАВЛЕНИЯ, А НЕ ОДНО
//
// Одно направление («у каждого условия модели есть вычислитель») ловит появление
// нового условия. Второе («у каждого вычислителя есть условие в модели») ловит
// то, что обычно не ловят вовсе: запись, которой БОЛЬШЕ НЕЧЕГО вычислять. Такая
// запись не мешает и не падает — она просто переживает свой предмет и достаётся
// следующему читателю как действующая. Послабление обязано истекать само.
//
// Проба внутренняя (`package relverdict`), чтобы читать набор напрямую: экспорт
// ради проверки завёл бы поверхность, у которой единственный потребитель — сама
// проверка.

import (
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzplan"
)

// modelConditions — какие условия каноническая модель действительно употребляет,
// и на каких отношениях.
//
// Читается разбором модели, а не поиском слова: слово `with` встречается в прозе
// комментариев, и гейт, считающий вхождения в сыром тексте, краснел бы от
// пояснения к самому себе.
func modelConditions(t *testing.T) (byCondition map[string][]string, types, relations int) {
	t.Helper()
	path, dsl, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("каноническая модель не найдена: %v — гейт, не прочитавший предмет, "+
			"обязан падать, а не зеленеть", err)
	}
	m, err := authzplan.ParseModel(string(dsl))
	if err != nil {
		t.Fatalf("разбор модели %s: %v", path, err)
	}
	byCondition = map[string][]string{}
	for _, tn := range m.TypeNames() {
		types++
		for _, r := range m.Type(tn).Relations {
			relations++
			for _, term := range r.Terms {
				for _, d := range term.Direct {
					if d.Condition == "" {
						continue
					}
					site := tn + "." + r.Name
					if !contains(byCondition[d.Condition], site) {
						byCondition[d.Condition] = append(byCondition[d.Condition], site)
					}
				}
			}
		}
	}
	return byCondition, types, relations
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// TestConditionRegistryMatchesTheModel — набор и модель сходятся в обе стороны.
func TestConditionRegistryMatchesTheModel(t *testing.T) {
	byCondition, types, relations := modelConditions(t)
	if types == 0 || relations == 0 {
		t.Fatal("модель разобрана в ноль типов или ноль отношений — сравнивать не с чем, " +
			"и «расхождений нет» означало бы «ничего не прочитано»")
	}
	if len(byCondition) == 0 {
		t.Fatal("модель не употребляет ни одного условия — тогда вычислитель условий не нужен " +
			"вовсе, и удалять надо его вместе с этим гейтом, а не оставлять зелёным")
	}

	// Направление 1: условие модели без вычислителя.
	for cond, sites := range byCondition {
		if _, ok := conditionRegistry[cond]; !ok {
			sort.Strings(sites)
			t.Errorf("модель употребляет условие %q на %s, а вычислителя у него нет. "+
				"Форма ответит «не знаю» и вердикт по этим отношениям давать не сможет — "+
				"то есть право, объявленное условным, не будет ни выдано, ни отказано",
				cond, strings.Join(sites, ", "))
		}
	}

	// Направление 2: вычислитель, которому больше нечего вычислять.
	for cond := range conditionRegistry {
		if _, ok := byCondition[cond]; !ok {
			t.Errorf("условие %q вычисляется, но модель его больше не употребляет ни на одном "+
				"отношении. Запись, которой нечего исключать, есть находка: она переживёт свой "+
				"предмет и достанется следующему читателю как действующая", cond)
		}
	}

	names := make([]string, 0, len(byCondition))
	for c := range byCondition {
		names = append(names, c)
	}
	sort.Strings(names)
	t.Logf("осмотрено: типов %d, отношений %d; условий в модели %d %v, вычислителей %d",
		types, relations, len(byCondition), names, len(conditionRegistry))
}

// TestNoConditionedRelationIsAVerb — предпосылка, на которой стоит запрос.
//
// Выдача роли условия НЕ несёт: роль раздаёт глаголы, а условия в модели стоят на
// отношениях, глаголами не являющихся. Ветвь выдачи в запросе поэтому объявляет
// «действует всегда». Появится глагол с условием — эта ветвь молча потеряет его
// условие, то есть выдаст право там, где условие не выполнено. Предпосылка
// проверяется, а не предполагается.
func TestNoConditionedRelationIsAVerb(t *testing.T) {
	byCondition, _, relations := modelConditions(t)
	if relations == 0 {
		t.Fatal("прочитано ноль отношений")
	}
	checked := 0
	for cond, sites := range byCondition {
		for _, site := range sites {
			checked++
			rel := site[strings.IndexByte(site, '.')+1:]
			if authzplan.IsVerb(rel) {
				t.Errorf("%s — глагол, и на нём стоит условие %q. Ветвь выдачи в verdictSQL "+
					"объявляет условие пустым, потому что роль его нести не может: право будет "+
					"выдано при НЕВЫПОЛНЕННОМ условии. Либо условие снимается с глагола, либо "+
					"ветвь выдачи учится нести условие — и тогда правится вместе с этим гейтом",
					site, cond)
			}
		}
	}
	t.Logf("осмотрено: мест с условием %d, из них глаголов 0", checked)
}
