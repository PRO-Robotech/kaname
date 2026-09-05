// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ruletranslation_internal_test.go — ПЕРЕВОД правила манифеста в правило домена
// (приёмка `classes-form-of-role-right.md` §3.4; сценарии MOD-RC-06 … MOD-RC-08).
//
// # Почему это ЗАМЕНА изоморфизма по именам, а не его ослабление
//
// Прежняя проба (`TestMODMR10…`) требовала РАВЕНСТВА имён множеств «ключи
// `manifest.Rule`» и «поля `domain.Rule`». Она ловила две настоящие беды: ключ
// без поля («манифест завёл второй словарь») и поле без ключа («правило,
// выразимое в продукте, невыразимо в манифесте»). Ключ `classes` роняет её
// ПЕРВОЙ половиной — и роняет справедливо по букве: имени `classes` в домене
// нет и не будет, потому что хранимая форма несёт для этого значения ОДНО поле.
//
// Ослабить её до членства было бы неверно: ослабленная перестала бы ловить
// вторую беду, ради которой её и писали. Поэтому она ЗАМЕНЕНА тремя
// утверждениями о переводе, и все три выведены обходом типов, а не выписаны:
//
//	тотальность          — каждое экспортируемое поле `domain.Rule` получает значение;
//	непотерянность       — значение каждого ключа `manifest.Rule` найдено в результате;
//	объявленность        — имя ключа либо совпадает с именем поля, либо стои́т в
//	                       словаре расхождений, и ОБЕ стороны записи существуют.
//
// Третье — то самое, ради чего писался изоморфизм, только допускающее
// НАЗВАННОЕ расхождение вместо запрета всякого. Словарь САМОИСТЕКАЕТ: запись,
// чьей стороны в дереве больше нет, роняет пробу.
package manifest

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// yamlKeyNamesOf — ключи, ОБЪЯВЛЕННЫЕ тегами структуры, а не выписанные
// списком: выписанный перечень не сдвинулся бы от нового поля.
func yamlKeyNamesOf(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		tag, ok := t.Field(i).Tag.Lookup("yaml")
		if !ok {
			continue
		}
		if name := strings.Split(tag, ",")[0]; name != "" && name != "-" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// keySpellingOf — имя поля Go в том написании, в каком его несёт ключ YAML.
func keySpellingOf(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	n := 1
	for n < len(r) && unicode.IsUpper(r[n]) && (n+1 == len(r) || unicode.IsUpper(r[n+1])) {
		n++
	}
	for i := 0; i < n; i++ {
		r[i] = unicode.ToLower(r[i])
	}
	return string(r)
}

// filledRule — правило, у которого КАЖДЫЙ ключ заполнен различимым значением.
//
// Значения различимы намеренно: непотерянность утверждается ПО ЗНАЧЕНИЮ, а не
// по имени поля, и совпадающие значения сделали бы её вакуумной.
func filledRule() Rule {
	return Rule{
		Module:        "vpc",
		Resources:     []string{"network"},
		Classes:       []string{"get"},
		ResourceNames: []string{"ntw000000000000001"},
		MatchLabels:   map[string]string{"env": "prod"},
	}
}

// ── MOD-RC-06 ───────────────────────────────────────────────────────────────

// TestMODRC06TranslationIsTotal — перевод ТОТАЛЕН: ни одно экспортируемое поле
// `domain.Rule` не осталось нулевым.
//
// Перепись печатается всегда, а ПУСТОЙ ОБХОД роняет пробу: «ноль ненулевых
// полей» иначе неотличимо от «ноль прочитанных полей».
func TestMODRC06TranslationIsTotal(t *testing.T) {
	got := reflect.ValueOf(filledRule().DomainRule())
	dt := got.Type()

	inspected, filled := 0, 0
	for i := 0; i < dt.NumField(); i++ {
		f := dt.Field(i)
		if !f.IsExported() {
			continue
		}
		inspected++
		if got.Field(i).IsZero() {
			t.Errorf("поле domain.Rule %q осталось нулевым: правило, выразимое в продукте, "+
				"невыразимо в манифесте либо теряется переводом", f.Name)
			continue
		}
		filled++
	}
	if inspected == 0 {
		t.Fatal("полей домена осмотрено ноль — вердикт беспредметен")
	}
	t.Logf("перепись: полей домена осмотрено %d · заполнено %d", inspected, filled)
}

// ── MOD-RC-07 ───────────────────────────────────────────────────────────────

// TestMODRC07NoKeyIsAcceptedAndDropped — значение КАЖДОГО ключа
// `manifest.Rule` найдено в результате ПО ЗНАЧЕНИЮ, а не по имени поля.
//
// # Правил ДВА, потому что форм права две и они взаимоисключающи (kacho#1844)
//
// Прежде здесь стояло одно правило, заполненное всеми ключами разом, и результат
// брался у одного перевода. С возвращением поимённой формы такой вход стал
// НЕПРЕДСТАВИМЫМ: правило с обеими записями права загрузчик отвергает
// (`validateRuleRightForm`), то есть проба судила бы то, чего продукт принять не
// может.
//
// Поэтому вход — ДВА правила, по одному на форму, и у каждого спрашивается тот
// перевод, который эта форма проходит:
//
//	`classes` → `DomainRule()`   — путь ПРИМЕНИТЕЛЯ;
//	`verbs`   → `formRule()`     — путь ПРОВЕРКИ ФОРМЫ; на путь применителя
//	                               поимённое право не выходит несведённым, и это
//	                               fail-closed решение, а не потеря значения
//	                               (сведение к классу требует каталога прав,
//	                               которого у загрузчика нет).
//
// Предмет пробы от этого не сузился: «принято-и-проигнорировано» означает
// отсутствие читателя ВООБЩЕ, а у поимённого права их четыре — проверка формы,
// проверка существования названного, `Right()` и экспортёр. Сузить проверку до
// одного перевода значило бы объявить дефектом само существование второй формы.
func TestMODRC07NoKeyIsAcceptedAndDropped(t *testing.T) {
	// Ключ → правило, его несущее, и перевод, который эта форма проходит.
	forms := []struct {
		name string
		rule Rule
		out  domain.Rule
	}{
		{name: "форма классов", rule: filledRule(), out: filledRule().DomainRule()},
		{name: "форма поимённая", rule: filledNamedRule(), out: filledNamedRule().formRule()},
	}

	inspected, found := 0, 0
	for _, form := range forms {
		src := reflect.ValueOf(form.rule)
		st := src.Type()
		out := reflect.ValueOf(form.out)
		dt := out.Type()
		for i := 0; i < st.NumField(); i++ {
			f := st.Field(i)
			tag, ok := f.Tag.Lookup("yaml")
			if !ok {
				continue
			}
			key := strings.Split(tag, ",")[0]
			if key == "" || key == "-" {
				continue
			}
			// Ключ ЧУЖОЙ формы в этом правиле пуст by construction: формы
			// взаимоисключающи, и требовать его значения здесь значило бы
			// требовать непредставимого входа.
			if src.Field(i).IsZero() {
				continue
			}
			inspected++
			want := src.Field(i).Interface()
			hit := false
			for j := 0; j < dt.NumField(); j++ {
				if !dt.Field(j).IsExported() {
					continue
				}
				if reflect.DeepEqual(out.Field(j).Interface(), want) {
					hit = true
					break
				}
			}
			if !hit {
				t.Errorf("%s: значение ключа %q не найдено ни в одном поле domain.Rule: ключ "+
					"принят и выброшен — «принято-и-проигнорировано» на уровне перевода",
					form.name, key)
				continue
			}
			found++
		}
	}
	if inspected == 0 {
		t.Fatal("ключей правила осмотрено ноль — вердикт беспредметен")
	}
	// Обе формы обязаны быть осмотрены: перепись по одной прошла бы и на
	// правиле, второй формы не несущем вовсе.
	if inspected < 2*len(forms) {
		t.Errorf("ключей осмотрено %d при %d формах — вход не несёт обеих", inspected, len(forms))
	}
	t.Logf("перепись: форм %d · ключей правила осмотрено %d · найдено в результате %d",
		len(forms), inspected, found)
}

// filledNamedRule — то же правило ПОИМЁННОЙ формой. Отличается от `filledRule`
// ровно записью права: иначе пара различала бы не форму, а содержимое.
func filledNamedRule() Rule {
	r := filledRule()
	r.Classes = nil
	r.Verbs = []string{"getNetwork"}
	return r
}

// ── MOD-RC-08 ───────────────────────────────────────────────────────────────

// TestMODRC08NameDivergenceIsDeclaredAndSelfExpiring — расхождение имён
// ОБЪЯВЛЕНО, и запись словаря, потерявшая сторону, роняет пробу.
func TestMODRC08NameDivergenceIsDeclaredAndSelfExpiring(t *testing.T) {
	manifestKeys := yamlKeyNamesOf(reflect.TypeOf(Rule{}))
	if len(manifestKeys) == 0 {
		t.Fatal("ключей правила прочитано ноль — вердикт беспредметен")
	}

	dt := reflect.TypeOf(domain.Rule{})
	domainFields := map[string]bool{}
	var domainKeys []string
	for i := 0; i < dt.NumField(); i++ {
		if f := dt.Field(i); f.IsExported() {
			domainFields[f.Name] = true
			domainKeys = append(domainKeys, keySpellingOf(f.Name))
		}
	}
	sort.Strings(domainKeys)
	sameName := map[string]bool{}
	for _, k := range domainKeys {
		sameName[k] = true
	}

	// Сторона 1: у каждого ключа манифеста есть либо одноимённое поле домена,
	// либо ЗАПИСЬ СЛОВАРЯ. Второй словарь, заведённый молча, роняет пробу здесь.
	declared := 0
	for _, key := range manifestKeys {
		switch {
		case sameName[key]:
			declared++
		case ruleKeyToDomainField[key] != "":
			declared++
		default:
			t.Errorf("ключ правила %q не имеет ни одноимённого поля domain.Rule, ни записи "+
				"в словаре расхождений: манифест заводит второй словарь для того же предмета", key)
		}
	}

	// Сторона 2: у КАЖДОЙ записи словаря существуют ОБЕ стороны. Запись,
	// пережившая свой предмет, роняет пробу здесь — словарь самоистекает.
	inManifest := map[string]bool{}
	for _, k := range manifestKeys {
		inManifest[k] = true
	}
	for key, field := range ruleKeyToDomainField {
		if !inManifest[key] {
			t.Errorf("запись словаря %q → %q: ключа %q у manifest.Rule больше нет — "+
				"запись пережила свой предмет", key, field, key)
		}
		if !domainFields[field] {
			t.Errorf("запись словаря %q → %q: поля %q у domain.Rule больше нет — "+
				"запись пережила свой предмет", key, field, field)
		}
	}

	// Сторона 3: поле домена, у которого нет ни одноимённого ключа, ни записи
	// словаря, невыразимо манифестом. Эту половину прежний изоморфизм ловил, и
	// она обязана сохраниться — иначе замена стала бы ослаблением.
	expressible := map[string]bool{}
	for _, k := range manifestKeys {
		expressible[k] = true
	}
	for key, field := range ruleKeyToDomainField {
		if inManifest[key] {
			expressible[keySpellingOf(field)] = true
		}
	}
	for _, k := range domainKeys {
		if !expressible[k] {
			t.Errorf("поле domain.Rule %q не имеет ключа в правиле манифеста: правило, "+
				"выразимое в продукте, невыразимо в манифесте", k)
		}
	}

	t.Logf("перепись: ключей правила %d (%v) · полей domain.Rule %d (%v) · "+
		"записей словаря расхождений %d · ключей с объявленной стороной %d",
		len(manifestKeys), manifestKeys, len(domainKeys), domainKeys,
		len(ruleKeyToDomainField), declared)
}
