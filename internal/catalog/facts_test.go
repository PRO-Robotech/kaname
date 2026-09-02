// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package catalog_test

// facts_test.go — сценарии IAM-CT-2-05 · -06 · -07 на уровне ФАКТА
// (kacho#1816, приёмка
// `services/iam/docs/engineering/acceptance/catalog-readers-move-to-the-table.md`).
//
// Строки для проб производит `seed.LiteralRows()` — тот же перечень, которым
// миграция посеяла каталог и с которым его сверяет страж старта. Второй
// производитель того же перечня разошёлся бы с первым молча.

import (
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func literalFacts(t *testing.T) *catalog.Facts {
	t.Helper()
	f, err := catalog.NewFacts(seed.LiteralRows())
	if err != nil {
		t.Fatalf("снимок из перечня литерала: %v", err)
	}
	return f
}

// modelTypes — имена типов МОДЕЛИ, по которым спрашивают наборы глаголов.
// Выводятся из перечня литерала переходником, а не выписываются.
func modelTypes(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, r := range authzmap.CatalogSeedResources() {
		fgaType, ok := authzmap.FGAObjectType(r.Dotted)
		if !ok {
			t.Fatalf("переходник не знает %q — перечень посева и словарь разошлись", r.Dotted)
		}
		out = append(out, fgaType)
	}
	sort.Strings(out)
	return out
}

// TestIAMCT2_05_FactsFromRowsAnswerAsTheLiteral — `-05`: ответ не меняется.
//
// Это ПОЛОЖИТЕЛЬНЫЙ контроль ко всему переезду: пока литерал и живые строки
// равны (а страж старта отказывает в пуске при расхождении), читатель на строках
// обязан отвечать ровно то же, что читатель на литерале. Проба, утверждающая
// только отличие снятого типа (`-06`), зеленела бы и на порте, который не
// отвечает НИЧЕГО.
func TestIAMCT2_05_FactsFromRowsAnswerAsTheLiteral(t *testing.T) {
	f := literalFacts(t)
	types := modelTypes(t)
	if len(types) == 0 {
		t.Fatalf("типов ноль — сверять нечего, вердикт беспредметен")
	}

	for _, fgaType := range types {
		want := authzmap.VerbsOfType(fgaType)
		got := f.VerbsOfType(fgaType)
		if strings.Join(want, ",") != strings.Join(got, ",") {
			t.Errorf("VerbsOfType(%q): литерал %v, строки %v", fgaType, want, got)
		}
	}
	if w, g := authzmap.CommonVerbVocabulary(), f.CommonVerbVocabulary(); strings.Join(w, ",") != strings.Join(g, ",") {
		t.Errorf("CommonVerbVocabulary: литерал %v, строки %v", w, g)
	}
	if w, g := authzmap.AllVerbVocabulary(), f.AllVerbVocabulary(); strings.Join(w, ",") != strings.Join(g, ",") {
		t.Errorf("AllVerbVocabulary: литерал %v, строки %v", w, g)
	}

	// GrantedVerbs — на подстановке и на явном перечне, по каждому типу.
	for _, fgaType := range types {
		typeVerbs := authzmap.VerbsOfType(fgaType)
		for _, authored := range [][]string{{"*"}, {"update"}, {"get", "list"}, {"nosuchverb"}} {
			want := authzmap.GrantedVerbs(fgaType, authored, typeVerbs)
			got := f.GrantedVerbs(fgaType, authored, typeVerbs)
			if strings.Join(want, ",") != strings.Join(got, ",") {
				t.Errorf("GrantedVerbs(%q, %v): литерал %v, строки %v", fgaType, authored, want, got)
			}
		}
	}

	// RoleVerbsFromSelectors — по КАЖДОЙ грантуемой паре, подстановкой.
	for _, r := range authzmap.CatalogSeedResources() {
		sel := []domain.RuleSelector{{ObjectTypes: []string{r.Dotted}, Verbs: []string{"*"}}}
		want := authzmap.RoleVerbsFromSelectors(sel)
		got := f.RoleVerbsFromSelectors(sel)
		if pairsKey(want) != pairsKey(got) {
			t.Errorf("RoleVerbsFromSelectors(%q): литерал %v, строки %v", r.Dotted, want, got)
		}
	}
}

func pairsKey(pairs []domain.RoleVerb) string {
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.ObjectType+"."+p.Verb)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// TestIAMCT2_06_RetiredResourceProducesNoPairs — `-06`: тип, снятый в строках,
// до проекции не доезжает.
//
// Приёмка называет здесь `compute.disk`, и на нём проба была бы ВАКУУМНОЙ:
// этой пары в литерале нет вовсе (§0.7 приёмки), поэтому переходник не резолвит
// её ни до снятия, ни после, и «пар не произведено» верно при любом порте.
// Поэтому снимается ЖИВАЯ пара — та, что до снятия пары даёт.
func TestIAMCT2_06_RetiredResourceProducesNoPairs(t *testing.T) {
	const dotted = "vpc.cidrGroup"
	fgaType, ok := authzmap.FGAObjectType(dotted)
	if !ok {
		t.Fatalf("переходник не знает %q — проба потеряла свой предмет", dotted)
	}
	sel := []domain.RuleSelector{{ObjectTypes: []string{dotted}, Verbs: []string{"*"}}}

	// ДО снятия — пары есть (положительный контроль: без него «пар ноль»
	// зеленело бы и на порте, который их не производит никогда).
	live := literalFacts(t)
	if len(live.VerbsOfType(fgaType)) == 0 {
		t.Fatalf("до снятия у %q ноль глаголов — контроль не выполнен", fgaType)
	}
	if len(live.RoleVerbsFromSelectors(sel)) == 0 {
		t.Fatalf("до снятия у %q ноль пар — контроль не выполнен", dotted)
	}

	retired, err := catalog.NewFacts(withoutResource(seed.LiteralRows(), dotted))
	if err != nil {
		t.Fatalf("снимок без снятой строки: %v", err)
	}
	if got := retired.VerbsOfType(fgaType); len(got) != 0 {
		t.Errorf("после снятия строки %q набор глаголов %v — снятый тип доехал до проекции", dotted, got)
	}
	if got := retired.RoleVerbsFromSelectors(sel); len(got) != 0 {
		t.Errorf("после снятия строки %q пары %v — снятый тип доехал до проекции", dotted, got)
	}

	// `-07`: ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ. Читатель, оставленный на литерале,
	// по-прежнему считает тип живым, и это ОЖИДАЕМОЕ различие, а не дефект: оно
	// и есть предмет задачи.
	if len(authzmap.VerbsOfType(fgaType)) == 0 {
		t.Errorf("литерал перестал знать %q — тогда различие снимка и литерала "+
			"неотличимо от общего отсутствия типа, и `-06` больше ничего не утверждает", fgaType)
	}
}

// withoutResource — строки каталога БЕЗ одной пары: ровно то, что увидит
// читатель после того, как административный путь снимет её строку (`retired_at`
// проставлен, `live` снят). Фикстура не снисходительнее продукта: она снимает и
// строку ресурса, и его строки глаголов — согласие, которое в базе держит
// внешний ключ.
func withoutResource(rows catalog.Rows, dotted string) catalog.Rows {
	out := catalog.Rows{Modules: rows.Modules}
	for _, r := range rows.Resources {
		if r.Module+"."+r.Resource == dotted {
			continue
		}
		out.Resources = append(out.Resources, r)
	}
	for _, v := range rows.Verbs {
		if v.Module+"."+v.Resource == dotted {
			continue
		}
		out.Verbs = append(out.Verbs, v)
	}
	return out
}

// TestIAMCT2_02_EmptyRowsAreNotASnapshot — `-02`: пустого снимка не бывает.
//
// Пустой снимок отверг бы ВСЕ правила разом, и снаружи это читалось бы как
// «продукт сломан», а не «условие не создано». Старт до этого не доходит —
// страж отказывает в пуске, — но порт обязан отвергать пустое множество и сам:
// он читается ещё и обновлением, у которого стража перед ним нет.
func TestIAMCT2_02_EmptyRowsAreNotASnapshot(t *testing.T) {
	if _, err := catalog.NewFacts(catalog.Rows{}); err == nil {
		t.Fatalf("пустые строки приняты как снимок — пустой снимок отверг бы все правила разом")
	}
	// Законный близнец: непустые строки принимаются. Без него отрицание выше
	// зеленело бы и на конструкторе, отвергающем ВСЁ.
	if _, err := catalog.NewFacts(seed.LiteralRows()); err != nil {
		t.Fatalf("непустые строки отвергнуты: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ярусная строка в набор глаголов типа НЕ входит (задача продукта #1863)

// TestTierOnlyRowNeverEntersTheVerbSetOfItsType — обе стороны различия.
//
// Строка ярусной половины словаря живёт в каталоге ради КЛЮЧА объявления
// правила: по ней резолвится `role_rule_ref_verb_fk`, и без неё документированный
// пример роли (`verbs: ["create", "list"]`) отвергается. Но в набор глаголов ТИПА
// она входить не вправе: по нему материализуются кортежи, и одна такая строка
// вернула бы `v_create`, снятый с 23 типов осознанно.
//
// Проба подаёт ОДНУ и ту же тройку дважды, различая только признак, — иначе
// «create отсутствует» зеленело бы на факте, который не знает такой пары вовсе.
func TestTierOnlyRowNeverEntersTheVerbSetOfItsType(t *testing.T) {
	const dotted = "vpc.network"
	fgaType, ok := authzmap.FGAObjectType(dotted)
	if !ok {
		t.Fatalf("переходник не знает %q — проба была бы вакуумна", dotted)
	}

	rows := catalog.Rows{
		Modules:   []string{"vpc"},
		Resources: []catalog.ResourceRow{{Module: "vpc", Resource: "network"}},
		Verbs: []catalog.VerbRow{
			{Module: "vpc", Resource: "network", Verb: "get", PerObject: true},
			{Module: "vpc", Resource: "network", Verb: "create"},
		},
	}
	f, err := catalog.NewFacts(rows)
	if err != nil {
		t.Fatalf("снимок: %v", err)
	}

	got := f.VerbsOfType(fgaType)
	t.Logf("осмотрено строк глаголов: %d; набор типа %q: %v", len(rows.Verbs), fgaType, got)

	// Положительный контроль: пообъектная строка ДОХОДИТ. Без него утверждение
	// ниже зеленело бы на факте, который не отдаёт ничего.
	if !containsVerb(got, "get") {
		t.Fatalf("пообъектная строка обязана входить в набор типа; получено %v", got)
	}
	if containsVerb(got, "create") {
		t.Errorf("ярусная строка попала в набор типа %q: набор типа — то, по чему "+
			"материализуются кортежи, и одна такая строка возвращает снятое отношение; "+
			"получено %v", fgaType, got)
	}

	// Та же величина с другой стороны: словари объединения и пересечения строятся
	// из наборов типов, и ярусной строки в них тоже быть не должно — иначе
	// подстановка `*` развернулась бы в неё у якоря без собственного набора.
	if containsVerb(f.AllVerbVocabulary(), "create") {
		t.Errorf("ярусная строка попала в объединение словарей: подстановка `*` "+
			"развернулась бы в неё; получено %v", f.AllVerbVocabulary())
	}
	if containsVerb(f.CommonVerbVocabulary(), "create") {
		t.Errorf("ярусная строка попала в пересечение словарей; получено %v",
			f.CommonVerbVocabulary())
	}

	// И то, ради чего признак заведён: правило, назвавшее ярусный глагол, не даёт
	// пообъектного кортежа, а названный рядом пообъектный — даёт.
	granted := f.GrantedVerbs(fgaType, []string{"create", "get"}, got)
	if containsVerb(granted, "create") {
		t.Errorf("правило с ярусным глаголом дало пообъектную пару: %v", granted)
	}
	if !containsVerb(granted, "get") {
		t.Errorf("положительный контроль: пообъектный глагол правила обязан даваться; "+
			"получено %v", granted)
	}
}

func containsVerb(set []string, verb string) bool {
	for _, v := range set {
		if v == verb {
			return true
		}
	}
	return false
}
