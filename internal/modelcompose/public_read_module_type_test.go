// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelcompose_test

// public_read_module_type_test.go — контейнер публичного чтения у типа вне
// канона допускается сборкой модели (задача PRO-Robotech/kaname#866).
//
// Приёмка docs/engineering/acceptance/public-read-container-of-a-module-type-is-admitted.md,
// отпечаток a129f53c4c46525b390d5f71bda31866e43e0776c6c556326806ce313836babf:
// PM-01, PM-02, PM-05, PM-07, PM-08, PM-10 — исходы допуска на манифесте П1 и его
// правках; CE-01, CE-02 разбора классов — обходы допуска законным термом, набранным
// рукой (авторское отношение с именем следствия ключа, чужой манифест).
//
// Цепочка — та же, что у старта (`cmd/kaname/model_compose.go`,
// `installComposedModel`): `manifest.LoadDelivered` → `modelcompose.Compose` →
// `authzmodel.Admit(composed, rep.KeyTerms...)`. Провязку перечня в самом корне
// держит проба пакета `cmd/kaname` (`TestPM_StartChain…`); здесь утверждаются
// ПОЛЯ находок, которых строка отказа пуска не несёт.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// Строки действий фикстуры П1 — точки правок «заменой ровно одного вхождения».
const (
	pmBoxVerbs   = "    verbs: [get, list, create, update, delete]"
	pmItemsVerbs = "    verbs: [get, list, update, delete]"
	pmClassGet   = "{name: get, subjects: [system_class, user, service_account, 'group#member']}"
)

// pmOutcome — исход цепочки старта на одной доставке.
type pmOutcome struct {
	composed string
	compose  modelcompose.Report
	admit    authzmodel.AdmissionReport
}

// pmBase — П1 как есть.
func pmBase(t *testing.T) []byte {
	t.Helper()
	b, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	if err != nil {
		t.Fatalf("фикстура П1: %v", err)
	}
	return b
}

// pmKeyless — П1 без строки ключа (дельта сверяется фикстурой).
func pmKeyless(t *testing.T) []byte {
	t.Helper()
	b, err := publicreadfixture.WithoutKey(pmBase(t))
	if err != nil {
		t.Fatalf("фикстура П1 без ключа: %v", err)
	}
	return b
}

// pmEdit — замена ровно одного вхождения.
func pmEdit(t *testing.T, doc []byte, old, repl string) []byte {
	t.Helper()
	if n := strings.Count(string(doc), old); n != 1 {
		t.Fatalf("фикстура: %q встречается %d раз, нужна одна замена", old, n)
	}
	return []byte(strings.Replace(string(doc), old, repl, 1))
}

// pmChain — доставка → композиция → допуск с перечнем той же композиции.
// Загрузка и композиция обязаны пройти: отказ на них — не исход предмета.
func pmChain(t *testing.T, docs map[string][]byte) pmOutcome {
	t.Helper()
	root := t.TempDir()
	for mod, doc := range docs {
		dir := filepath.Join(root, mod)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("фикстура: каталог доставки: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), doc, 0o600); err != nil {
			t.Fatalf("фикстура: манифест доставки: %v", err)
		}
	}
	rep, err := manifest.LoadDelivered(root)
	if err != nil {
		t.Fatalf("условие не создано: доставка отвергнута загрузкой: %v", err)
	}
	composed, crep, err := modelcompose.Compose(authzmodel.DSL, rep.Manifests)
	if err != nil {
		t.Fatalf("условие не создано: композиция отвергнута: %v", err)
	}
	adm, err := authzmodel.Admit(composed, crep.KeyTerms...)
	if err != nil {
		t.Fatalf("допуск вернул ошибку, а ожидался отчёт: %v", err)
	}
	return pmOutcome{composed: composed, compose: crep, admit: adm}
}

func pmOne(t *testing.T, doc []byte) pmOutcome {
	t.Helper()
	return pmChain(t, map[string][]byte{"probemod": doc})
}

// pmFinding — находка в форме сравнения.
type pmFinding struct{ rule, typ, rel, term string }

// pmFindings — МНОЖЕСТВО находок, отсортированное (держатели утверждают множество).
func pmFindings(o pmOutcome) []pmFinding {
	out := make([]pmFinding, 0, len(o.admit.Findings))
	for _, f := range o.admit.Findings {
		out = append(out, pmFinding{string(f.Rule), f.Type, f.Relation, f.Term})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.rule+a.typ+"."+a.rel+a.term < b.rule+b.typ+"."+b.rel+b.term
	})
	return out
}

func pmRequireFindings(t *testing.T, o pmOutcome, want ...pmFinding) {
	t.Helper()
	got := pmFindings(o)
	sort.Slice(want, func(i, j int) bool {
		a, b := want[i], want[j]
		return a.rule+a.typ+"."+a.rel+a.term < b.rule+b.typ+"."+b.rel+b.term
	})
	if len(got) != len(want) {
		t.Fatalf("находок %d, ждали %d:\n  получено %v\n  ждали    %v\n  %s", len(got), len(want), got, want, o.admit.Census())
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("множество находок расходится:\n  получено %v\n  ждали    %v", got, want)
		}
	}
	if len(want) > 0 && o.admit.Admitted() {
		t.Fatal("при находках допуск не вправе отвечать «допущено»")
	}
}

func pmRequireAdmitted(t *testing.T, o pmOutcome) {
	t.Helper()
	if !o.admit.Admitted() {
		t.Fatalf("модель обязана быть допущена; находки %v; %s", pmFindings(o), o.admit.Census())
	}
	if _, err := authzmodel.New(o.composed); err != nil {
		t.Fatalf("допущенная модель обязана ставиться (разбор модели процесса): %v", err)
	}
}

// pmBlock — блок собранной модели по типу.
func pmBlock(t *testing.T, composed, typ string) string {
	t.Helper()
	for _, b := range modelrender.SplitCanon([]byte(composed)) {
		if b.Type == typ {
			return string(b.Body)
		}
	}
	t.Fatalf("собранная модель не объявляет %s", typ)
	return ""
}

func d3(typ, rel, term string) pmFinding {
	return pmFinding{string(authzmodel.RuleD3), typ, rel, term}
}

// TestPM01_ModuleTypeWithTheKeyStarts — PM-01; близнец PM-02.
func TestPM01_ModuleTypeWithTheKeyStarts(t *testing.T) {
	o := pmOne(t, pmBase(t))
	pmRequireAdmitted(t, o)
	if !strings.Contains(o.admit.Census(), "новых 2, находок 0") {
		t.Fatalf("перепись допуска обязана говорить «новых 2, находок 0», получено %s", o.admit.Census())
	}
	box := pmBlock(t, o.composed, "probemod_box")
	for _, line := range []string{
		"define public_reader: [system_class]",
		"define v_get: [system_class, user, service_account, group#member] or super_admin",
		"define v_list: [system_class, user, service_account, group#member] or super_admin",
	} {
		if !strings.Contains(box, line+"\n") {
			t.Fatalf("блок probemod_box обязан нести %q:\n%s", line, box)
		}
	}
	item := pmBlock(t, o.composed, "probemod_item")
	for _, line := range []string{
		"define v_get: [user, service_account, group#member] or super_admin or public_reader from box",
		"define v_list: [user, service_account, group#member] or super_admin or public_reader from box",
	} {
		if !strings.Contains(item, line+"\n") {
			t.Fatalf("блок probemod_item обязан нести %q:\n%s", line, item)
		}
	}
}

// TestPM02_SameModuleWithoutTheKeyCarriesNoClass — PM-02.
func TestPM02_SameModuleWithoutTheKeyCarriesNoClass(t *testing.T) {
	o := pmOne(t, pmKeyless(t))
	pmRequireAdmitted(t, o)
	for _, typ := range []string{"probemod_box", "probemod_item"} {
		blk := pmBlock(t, o.composed, typ)
		if strings.Contains(blk, "system_class") || strings.Contains(blk, "public_reader") {
			t.Fatalf("без ключа блок %s не вправе нести класс либо public_reader:\n%s", typ, blk)
		}
	}
	if len(o.compose.KeyTerms) != 0 {
		t.Fatalf("без ключа перечень термов обязан быть пуст, получено %v", o.compose.KeyTerms)
	}
}

// TestPM05_ClassNamedByAModuleWithoutTheKeyIsRefused — PM-05; близнец PM-02.
func TestPM05_ClassNamedByAModuleWithoutTheKeyIsRefused(t *testing.T) {
	o := pmOne(t, pmEdit(t, pmKeyless(t), pmItemsVerbs, "    verbs: ["+pmClassGet+", list, update, delete]"))
	pmRequireFindings(t, o, d3("probemod_item", "v_get", "system_class"))
}

// TestPM07_WriteVerbDerivedFromAReadVerbIsAFinding — PM-07 и его «И».
func TestPM07_WriteVerbDerivedFromAReadVerbIsAFinding(t *testing.T) {
	o := pmOne(t, pmEdit(t, pmBase(t), pmItemsVerbs,
		"    verbs: [get, list, {name: update, from: [super_admin, v_get]}, delete]"))
	pmRequireFindings(t, o, d3("probemod_item", "v_update", "system_class"))
	f := o.admit.Findings[0]
	const path = "probemod_item.v_update → probemod_item.v_get → probemod_box.public_reader"
	if !strings.Contains(f.Text, path) {
		t.Fatalf("находка обязана называть путь %q, получено %q", path, f.Text)
	}

	o = pmOne(t, pmEdit(t, pmBase(t), pmBoxVerbs,
		"    verbs: [get, list, create, update, {name: delete, from: [super_admin, v_list]}]"))
	pmRequireFindings(t, o, d3("probemod_box", "v_delete", "system_class"))
}

// TestPM08_AuthoredRelationReachingTheClassIsRefused — PM-08 и оба «И».
func TestPM08_AuthoredRelationReachingTheClassIsRefused(t *testing.T) {
	o := pmOne(t, pmEdit(t, pmBase(t), pmItemsVerbs,
		pmItemsVerbs+"\n    relations:\n      - {name: peek, definition: 'public_reader from box'}"))
	pmRequireFindings(t, o, d3("probemod_item", "peek", "system_class"))

	// «И» (без ключа, одно отношение) и его близнец — запись субъекта.
	o = pmOne(t, pmEdit(t, pmKeyless(t), pmBoxVerbs,
		pmBoxVerbs+"\n    relations:\n      - {name: public_reader, definition: '[system_class]'}"))
	pmRequireFindings(t, o, d3("probemod_box", "public_reader", "system_class"))
	o = pmOne(t, pmEdit(t, pmKeyless(t), pmBoxVerbs,
		pmBoxVerbs+"\n    relations:\n      - {name: public_reader, definition: '[user]'}"))
	pmRequireAdmitted(t, o)

	// «И» (без ключа, все три следствия рукой): блок побайтово равен блоку PM-01,
	// а исход — три находки; держит Р4 (перечень из объявления ключа).
	hand := pmOne(t, pmEdit(t, pmKeyless(t), pmBoxVerbs,
		"    verbs: ["+pmClassGet+", {name: list, subjects: [system_class, user, service_account, 'group#member']}, create, update, delete]"+
			"\n    relations:\n      - {name: public_reader, definition: '[system_class]'}"))
	if got, want := pmBlock(t, hand.composed, "probemod_box"), pmBlock(t, pmOne(t, pmBase(t)).composed, "probemod_box"); got != want {
		t.Fatalf("условие не создано: блок трёх следствий рукой обязан быть побайтово равен блоку ключа:\n%s\n---\n%s", got, want)
	}
	pmRequireFindings(t, hand,
		d3("probemod_box", "public_reader", "system_class"),
		d3("probemod_box", "v_get", "system_class"),
		d3("probemod_box", "v_list", "system_class"))
}

// TestPM10_ClassInAChildReadVerbBesideTheLawfulTermIsAFinding — PM-10, три
// написания; близнец — длинная форма без класса.
func TestPM10_ClassInAChildReadVerbBesideTheLawfulTermIsAFinding(t *testing.T) {
	cases := []struct{ word, term string }{
		{"system_class", "system_class"},
		{"'system_class:anonymous'", "system_class:anonymous"},
		{"'user:*'", "system_class"},
	}
	for _, c := range cases {
		t.Run(c.word, func(t *testing.T) {
			o := pmOne(t, pmEdit(t, pmBase(t), pmItemsVerbs,
				"    verbs: [{name: get, subjects: ["+c.word+", user, service_account, 'group#member']}, list, update, delete]"))
			pmRequireFindings(t, o, d3("probemod_item", "v_get", c.term))
		})
	}
	o := pmOne(t, pmEdit(t, pmBase(t), pmItemsVerbs,
		"    verbs: [{name: get, subjects: [user, service_account, 'group#member']}, list, update, delete]"))
	pmRequireAdmitted(t, o)
}

// TestCE01_AuthoredRelationNamedLikeAKeyConsequenceIsNotLawful — CE-01 разбора
// классов: законно то, что пишет ветка ключа в рендере, а не отношение с именем
// её следствия. Входы X1, X1b (контейнер без действия get, авторское v_get с
// классом) и X2 (ребёнок без get, авторское v_get с термом ключа), у каждого —
// близнец без класса.
func TestCE01_AuthoredRelationNamedLikeAKeyConsequenceIsNotLawful(t *testing.T) {
	const boxNoGet = "    verbs: [list, create, update, delete]\n    relations:\n      - {name: v_get, definition: '%s'}"
	o := pmOne(t, pmEdit(t, pmBase(t), pmBoxVerbs, strings.Replace(boxNoGet, "%s", "[system_class, user]", 1)))
	pmRequireFindings(t, o, d3("probemod_box", "v_get", "system_class"))
	o = pmOne(t, pmEdit(t, pmBase(t), pmBoxVerbs, strings.Replace(boxNoGet, "%s", "[user, system_class]", 1)))
	pmRequireFindings(t, o, d3("probemod_box", "v_get", "system_class"))
	o = pmOne(t, pmEdit(t, pmBase(t), pmBoxVerbs, strings.Replace(boxNoGet, "%s", "[user]", 1)))
	pmRequireAdmitted(t, o)

	const itemNoGet = "    verbs: [list, update, delete]\n    relations:\n      - {name: v_get, definition: '%s'}"
	o = pmOne(t, pmEdit(t, pmBase(t), pmItemsVerbs, strings.Replace(itemNoGet, "%s", "[user] or public_reader from box", 1)))
	pmRequireFindings(t, o, d3("probemod_item", "v_get", "system_class"))
	o = pmOne(t, pmEdit(t, pmBase(t), pmItemsVerbs, strings.Replace(itemNoGet, "%s", "[user] or super_admin", 1)))
	pmRequireAdmitted(t, o)
}

// TestCE02_ForeignChildOfACanonContainerIsNotLawful — CE-02: перечень
// контейнеров только из новых типов композиции; тип чужого модуля, указывающий
// на канонический контейнер `registry_registry` (вход X4), законного терма не
// получает. Близнец — тот же тип без авторского отношения.
func TestCE02_ForeignChildOfACanonContainerIsNotLawful(t *testing.T) {
	reg, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	other := func(verbs, rel string) []byte {
		s := "apiVersion: iam/v1\nmodule: othermod\n\nresources:\n\n  - name: things\n    objectType: othermod_thing\n" +
			"    parents:\n      - {name: reg, type: registry_registry}\n    producer: derived\n    verbs: " + verbs + "\n"
		if rel != "" {
			s += "    relations:\n      - {name: v_get, definition: '" + rel + "'}\n"
		}
		return []byte(s)
	}

	o := pmChain(t, map[string][]byte{"registry": reg, "othermod": other("[list, update]", "[user] or public_reader from reg")})
	pmRequireFindings(t, o, d3("othermod_thing", "v_get", "system_class"))
	for _, kt := range o.compose.KeyTerms {
		if strings.HasPrefix(kt.Type, "registry_") {
			t.Fatalf("канонический тип (Reaffirmed) не вправе попасть в перечень термов ключа: %+v", kt)
		}
	}

	o = pmChain(t, map[string][]byte{"registry": reg, "othermod": other("[get, list, update]", "")})
	pmRequireAdmitted(t, o)
}

// TestCE02_KeyTermsAreExactlyWhatTheKeyWrote — перечень термов композиции П1:
// ровно три терма Р1 на своих объявлениях, в детерминированном порядке.
func TestCE02_KeyTermsAreExactlyWhatTheKeyWrote(t *testing.T) {
	o := pmOne(t, pmBase(t))
	want := []authzmodel.KeyTerm{
		{Type: "probemod_box", Relation: "public_reader"},
		{Type: "probemod_box", Relation: "v_get"},
		{Type: "probemod_box", Relation: "v_list"},
		{Type: "probemod_item", Relation: "v_get", Pointer: "box"},
		{Type: "probemod_item", Relation: "v_list", Pointer: "box"},
	}
	if len(o.compose.KeyTerms) != len(want) {
		t.Fatalf("перечень термов ключа: получено %v, ждали %v", o.compose.KeyTerms, want)
	}
	for i := range want {
		if o.compose.KeyTerms[i] != want[i] {
			t.Fatalf("перечень термов ключа: получено %v, ждали %v", o.compose.KeyTerms, want)
		}
	}
}
