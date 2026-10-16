// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender_test

// public_read_sc65_sc71_test.go — ключ манифеста `publicReadToChildren` и три его
// следствия в порождённых блоках (стадия S5, задача PRO-Robotech/kaname#856).
//
// Приёмка docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md,
// редакция 10, отпечаток 198db838d0a75b7f5b5bdbd5564bacec23a79cc00550a26e8830f3c6be61aac9:
// SC-71 (а)–(г), SC-65 «И (механизм общий, У1)» — генераторная половина.
//
// # Порядок несущий
//
// Сначала фикстура: прежняя редакция и близнец «без ключа» обязаны загрузиться,
// а рендер прежней редакции — совпасть с байтами Р10 (sha256 блоков канона
// @a7a726802). Сломанная фикстура краснеет здесь и не выдаёт себя за
// отсутствующий ключ. Потом предмет: документ С ключом.
//
// # Дельта — вычисленная, а не объявленная
//
// Утверждается не «следствие есть где-то в блоке», а РАЗНИЦА рендера документа с
// ключом против рендера близнеца без ключа: ровно три следствия Р9 «Способ» и
// ничего больше. Пишущие глаголы, ярусы и каскад ключ не трогает — это видно
// тем, что их строк в разнице нет.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// Байты Р10 «прежняя редакция»: sha256 блоков канона @a7a726802 (строки
// 1303–1332 и 1334–1355 файла proto/kaname/cloud/iam/v1/fga_model.fga).
const (
	priorRegistrySHA   = "b115c3c18f6ffdda0c22c1c742da50fbecd1a1f888d28810663429a97b240359"
	priorRepositorySHA = "d2aafdbdba912a2680d636230bf6e046f7434b057ec77f3070968b35de7aaa69"
)

// prReadFixture — байты фикстуры; отказ чтения — отказ фикстуры.
func prReadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := publicreadfixture.Read(name)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	return b
}

// prLoad — разбор документа загрузчиком; отказ — отказ ФИКСТУРЫ (зовётся только
// на документах, которые сегодняшний загрузчик обязан принимать).
func prLoad(t *testing.T, what string, doc []byte) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load(doc)
	if err != nil {
		t.Fatalf("фикстура (%s): документ без предмета S5 обязан загружаться, отказ: %v", what, err)
	}
	return m
}

// prRenderAll — блоки всех ресурсов документа по типу модели.
func prRenderAll(t *testing.T, what string, m *manifest.Manifest) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, r := range m.Resources {
		b, err := modelrender.Render(r)
		if err != nil {
			t.Fatalf("%s: рендер %s отвергнут: %v", what, r.ObjectType, err)
		}
		out[r.ObjectType] = string(b)
	}
	return out
}

// prSHA — sha256 строки в hex.
func prSHA(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// prControlPriorEdition — положительный контроль фикстуры: прежняя редакция
// загружается, и её рендер равен байтам Р10.
func prControlPriorEdition(t *testing.T) map[string]string {
	t.Helper()
	prior := prRenderAll(t, "контроль: прежняя редакция", prLoad(t, "прежняя редакция",
		prReadFixture(t, publicreadfixture.PriorEditionFile)))
	if got := prSHA(prior["registry_registry"]); got != priorRegistrySHA {
		t.Fatalf("фикстура: рендер registry_registry прежней редакции %s, Р10 требует %s — фикстура не та", got, priorRegistrySHA)
	}
	if got := prSHA(prior["registry_repository"]); got != priorRepositorySHA {
		t.Fatalf("фикстура: рендер registry_repository прежней редакции %s, Р10 требует %s — фикстура не та", got, priorRepositorySHA)
	}
	return prior
}

// prLoadSubject — предмет: документ С ключом обязан загрузиться. Отказ здесь —
// отсутствие ключа у загрузчика, то есть отсутствие предмета S5.
func prLoadSubject(t *testing.T, sc string, doc []byte) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load(doc)
	if err != nil {
		t.Fatalf("%s: загрузчик отверг документ с ключом %s (предмета S5 нет): %v", sc, publicreadfixture.Key, err)
	}
	return m
}

// lineDelta — разница блоков построчно.
func lineDelta(base, twin string) (removed, added []string) {
	return publicreadfixture.Delta([]byte(base), []byte(twin))
}

// subjectsOf — множество субъектов строки `define v_x: [a, b] <хвост>` и её
// хвост после закрывающей скобки.
func subjectsOf(line string) (head string, subjects map[string]bool, tail string, ok bool) {
	open, closing := strings.Index(line, "["), strings.Index(line, "]")
	if open < 0 || closing < open {
		return "", nil, "", false
	}
	subjects = map[string]bool{}
	for _, s := range strings.Split(line[open+1:closing], ",") {
		subjects[strings.TrimSpace(s)] = true
	}
	return line[:open], subjects, line[closing+1:], true
}

// requireContainerConsequences — следствия 1 и 2 в блоке контейнера: отношение
// `public_reader: [system_class]` и `system_class` в составе `v_get`, `v_list`.
// Разница против близнеца — ровно эти строки.
func requireContainerConsequences(t *testing.T, sc, typ, twin, subject string) {
	t.Helper()
	removed, added := lineDelta(twin, subject)
	if len(removed) != 2 || len(added) != 3 {
		t.Fatalf("%s: блок %s против близнеца без ключа: удалено %d строк %q, добавлено %d %q; "+
			"Р9 «Способ» требует ровно: + public_reader, ± v_get, ± v_list", sc, typ, len(removed), removed, len(added), added)
	}
	const wantRelation = "    define public_reader: [system_class]"
	var gotRelation bool
	verbs := map[string]string{}
	for _, l := range added {
		if l == wantRelation {
			gotRelation = true
			continue
		}
		verbs[strings.TrimSpace(strings.SplitN(l, ":", 2)[0])] = l
	}
	if !gotRelation {
		t.Fatalf("%s: в блоке %s нет строки %q; добавлено %q", sc, typ, wantRelation, added)
	}
	for _, r := range removed {
		key := strings.TrimSpace(strings.SplitN(r, ":", 2)[0])
		if key != "define v_get" && key != "define v_list" {
			t.Fatalf("%s: ключ тронул в блоке %s строку %q — кроме v_get и v_list ключ не трогает ничего", sc, typ, r)
		}
		nl, ok := verbs[key]
		if !ok {
			t.Fatalf("%s: в блоке %s строка %q снята и не заменена", sc, typ, r)
		}
		h0, s0, t0, ok0 := subjectsOf(r)
		h1, s1, t1, ok1 := subjectsOf(nl)
		if !ok0 || !ok1 || h0 != h1 || t0 != t1 {
			t.Fatalf("%s: в блоке %s строка %q стала %q — меняться обязан только состав субъектов", sc, typ, r, nl)
		}
		if !s1["system_class"] || s0["system_class"] || len(s1) != len(s0)+1 {
			t.Fatalf("%s: в блоке %s состав %q стал %q — обязан прибавиться ровно system_class", sc, typ, r, nl)
		}
	}
}

// requireChildConsequence — следствие 3 в блоке ребёнка: `or public_reader from
// <указатель>` в правой части `v_get` и `v_list`, и только там.
func requireChildConsequence(t *testing.T, sc, typ, pointer, twin, subject string) {
	t.Helper()
	removed, added := lineDelta(twin, subject)
	if len(removed) != 2 || len(added) != 2 {
		t.Fatalf("%s: блок %s против близнеца без ключа: удалено %q, добавлено %q; "+
			"Р9 «Способ» требует ровно ± v_get и ± v_list", sc, typ, removed, added)
	}
	suffix := " or public_reader from " + pointer
	for i, r := range removed {
		key := strings.TrimSpace(strings.SplitN(r, ":", 2)[0])
		if key != "define v_get" && key != "define v_list" {
			t.Fatalf("%s: ключ тронул в блоке %s строку %q — кроме v_get и v_list ключ не трогает ничего", sc, typ, r)
		}
		if added[i] != r+suffix {
			t.Fatalf("%s: в блоке %s строка %q стала %q, ожидалось %q", sc, typ, r, added[i], r+suffix)
		}
	}
}

// TestRender_SC71_a_RegistryKeyYieldsExactlyThreeConsequences — SC-71 (а):
// рендер новой редакции против рендера манифеста @a95248464 — ровно три
// следствия Р9 «Способ».
func TestRender_SC71_a_RegistryKeyYieldsExactlyThreeConsequences(t *testing.T) {
	prior := prControlPriorEdition(t)
	doc := prReadFixture(t, publicreadfixture.NewEditionFile)
	twinDoc, err := publicreadfixture.WithoutKey(doc)
	if err != nil {
		t.Fatalf("фикстура: близнец без ключа: %v", err)
	}
	twin := prRenderAll(t, "контроль: новая редакция без ключа", prLoad(t, "новая редакция без ключа", twinDoc))
	for _, typ := range []string{"registry_registry", "registry_repository"} {
		if twin[typ] != prior[typ] {
			t.Fatalf("фикстура: близнец без ключа рендерит %s не так, как прежняя редакция — фикстура меняет больше одного факта", typ)
		}
	}

	got := prRenderAll(t, "SC-71 (а)", prLoadSubject(t, "SC-71 (а)", doc))
	requireContainerConsequences(t, "SC-71 (а)", "registry_registry", prior["registry_registry"], got["registry_registry"])
	requireChildConsequence(t, "SC-71 (а)", "registry_repository", "parent", prior["registry_repository"], got["registry_repository"])
}

// TestRender_SC71_b_KeyWithoutAChildIsRefused — SC-71 (б): ключ на типе, на
// который не указывает ни один ресурс того же манифеста, — находка загрузки.
// Близнец — (а): ключ на контейнере, у которого ребёнок есть.
func TestRender_SC71_b_KeyWithoutAChildIsRefused(t *testing.T) {
	doc := prReadFixture(t, publicreadfixture.NewEditionFile)
	twinDoc, err := publicreadfixture.WithoutKey(doc)
	if err != nil {
		t.Fatalf("фикстура: близнец без ключа: %v", err)
	}
	prLoad(t, "новая редакция без ключа", twinDoc)
	moved, err := publicreadfixture.KeyMovedToRepositories(doc)
	if err != nil {
		t.Fatalf("фикстура: ключ на repositories: %v", err)
	}

	prLoadSubject(t, "SC-71 (б) близнец (а)", doc)
	_, err = manifest.Load(moved)
	const want = "resources[1].publicReadToChildren: на тип registry_repository не указывает ни один ресурс модуля registry — объявление без следствия"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("SC-71 (б): отказ загрузки обязан нести находку %q, получено: %v", want, err)
	}
}

// TestRender_SC71_c_FalseIsRefused — SC-71 (в): `false` — второй способ сказать
// «нет», загрузка его отвергает. Близнец — тот же документ без ключа.
func TestRender_SC71_c_FalseIsRefused(t *testing.T) {
	doc := prReadFixture(t, publicreadfixture.NewEditionFile)
	twinDoc, err := publicreadfixture.WithoutKey(doc)
	if err != nil {
		t.Fatalf("фикстура: близнец без ключа: %v", err)
	}
	prLoad(t, "SC-71 (в) близнец: ключ отсутствует", twinDoc)
	falseDoc, err := publicreadfixture.WithKeyValue(doc, "false")
	if err != nil {
		t.Fatalf("фикстура: ключ false: %v", err)
	}

	_, err = manifest.Load(falseDoc)
	const want = "resources[0].publicReadToChildren: значение false не принимается — ключ либо отсутствует, либо равен true"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("SC-71 (в): отказ загрузки обязан нести находку %q, получено: %v", want, err)
	}
}

// TestRender_SC71_d_ModuleNamingAClassIsRefusedAsToday — SC-71 (г): модуль,
// назвавший класс субъекта в составе действия сам, — отказ SC-37, как сегодня
// (находка Д3 допуска собранной модели). Близнец — тот же документ без класса.
func TestRender_SC71_d_ModuleNamingAClassIsRefusedAsToday(t *testing.T) {
	base, err := publicreadfixture.WithoutKey(prReadFixture(t, publicreadfixture.ProbemodFile))
	if err != nil {
		t.Fatalf("фикстура: probemod без ключа: %v", err)
	}
	const (
		plain = "    verbs: [get, list, update, delete]\n"
		named = "    verbs:\n      - {name: get, subjects: [system_class, user, service_account, 'group#member']}\n      - list\n      - update\n      - delete\n"
	)
	if strings.Count(string(base), plain) != 1 {
		t.Fatalf("фикстура: строка действий items не найдена ровно один раз")
	}
	withClass := []byte(strings.Replace(string(base), plain, named, 1))

	d3 := func(doc []byte) (int, error) {
		m, err := manifest.Load(doc)
		if err != nil {
			return 0, err
		}
		composed, _, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
		if err != nil {
			return 0, err
		}
		rep, err := authzmodel.Admit(composed)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, f := range rep.Findings {
			if f.Rule == authzmodel.RuleD3 && f.Type == "probemod_item" && f.Relation == "v_get" {
				n++
			}
		}
		return n, nil
	}
	if n, err := d3(base); err != nil || n != 0 {
		t.Fatalf("SC-71 (г) близнец: модуль без класса обязан пройти без Д3, находок %d, ошибка %v", n, err)
	}
	n, err := d3(withClass)
	if err == nil && n == 0 {
		t.Fatalf("SC-71 (г): класс в составе действия модуля обязан быть отказом (SC-37), а прошёл без находки")
	}
	t.Logf("SC-71 (г): отказ — находок Д3 %d, ошибка %v", n, err)
}

// TestRender_SC65_ProbemodKeyYieldsTheSameThreeConsequences — SC-65 «И»:
// механизм общий, имени модуля в нём нет. Модуль `probemod` получает те же три
// следствия, что registry; без ключа — ни одного. Отличие — один факт: ключ.
func TestRender_SC65_ProbemodKeyYieldsTheSameThreeConsequences(t *testing.T) {
	doc := prReadFixture(t, publicreadfixture.ProbemodFile)
	twinDoc, err := publicreadfixture.WithoutKey(doc)
	if err != nil {
		t.Fatalf("фикстура: probemod без ключа: %v", err)
	}
	twin := prRenderAll(t, "контроль: probemod без ключа", prLoad(t, "probemod без ключа", twinDoc))
	for typ, block := range twin {
		if strings.Contains(block, "public_reader") || strings.Contains(block, "system_class") {
			t.Fatalf("фикстура: близнец без ключа уже несёт следствие в %s:\n%s", typ, block)
		}
	}

	got := prRenderAll(t, "SC-65 «И»", prLoadSubject(t, "SC-65 «И»", doc))
	requireContainerConsequences(t, "SC-65 «И»", "probemod_box", twin["probemod_box"], got["probemod_box"])
	requireChildConsequence(t, "SC-65 «И»", "probemod_item", "box", twin["probemod_item"], got["probemod_item"])
}
