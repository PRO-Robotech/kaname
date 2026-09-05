// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// classfit_test.go — MOD-RL-22 и его парный положительный MOD-RL-22a.
//
// Приёмка: services/iam/docs/engineering/acceptance/module-manifest-roles-and-seed-grants.md
// §3.6 п. 3 (три состояния действия) · §3.6 п. 6 (порядок трёх проверок) ·
// §4.1 (MOD-RL-22, MOD-RL-22a).
//
// # Вход НАСТОЯЩИЙ с обеих сторон, и это здесь несущее
//
// Каталог — встроенный, тот самый, что читает посев; манифест — фикстура
// соседнего пакета. Ни одна пара «отношение + объект» в этих пробах не
// выдумана: `system_admin@cluster` у `addressPool`, `editor@project` у
// `network.create` и `editor@vpc_network_interface` у
// `networkInterface.internalAttach` — записи каталога, а не сочинённые строки.
//
// # Given сценария MOD-RL-22 НЕИСПОЛНИМ дословно — и это перемерено, а не решено
//
// Приёмка описывает вход прототипа (`roles.py`): «действие `listOperations`,
// объявленное СТРОКОЙ; строчная форма ⇒ класс равен имени». В посаженном
// продукте (#1778) такой вход до этой проверки НЕ ДОХОДИТ: короткую форму с
// неканоническим именем отвергает загрузчик (`ErrVerbClassNotDerivable`), а
// объектную с `class: listOperations` — он же (`ErrVerbClassUnknown`, класс вне
// закрытого набора). Обе половины проверены прогоном.
//
// Значит производимый вход этой проверки ровно один: ОБЪЕКТНАЯ форма с
// каноническим классом, гейт которого она не удовлетворяет —
// `{name: listOperations, class: get}` при гейте `v_list`. Сценарий от этого не
// исчезает и не слабеет: его предмет — «класс, объявленный манифестом, обязан
// удовлетворять гейт», а починка та же, что названа приёмкой (`class: list`).
// Ветвь, у входа которой нет производителя, была бы мертва, и её молчание
// выглядело бы работой.
package roleexport_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/catalogfixture"
)

// mustLoadManifest — манифест из текста пробы.
//
// Читается ТЕМ ЖЕ загрузчиком, что и настоящий: второй разборщик той же формы
// принимал бы вход, который продукт отвергает, и проба зеленела бы на
// невозможном.
func mustLoadManifest(t *testing.T, doc string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("манифест пробы отвергнут загрузчиком — вход невоспроизводим: %v", err)
	}
	return m
}

// findingsOf — отказы одного вида, с координатами.
func findingsOf(faults []error, kind error) []roleexport.ClassFinding {
	var out []roleexport.ClassFinding
	for _, f := range faults {
		var cf roleexport.ClassFinding
		if errors.As(f, &cf) && errors.Is(f, kind) {
			out = append(out, cf)
		}
	}
	return out
}

// noteFor — пометка о названном действии.
func noteFor(notes []roleexport.Note, resource, verb string) (roleexport.Note, bool) {
	for _, n := range notes {
		if n.Resource == resource && n.Verb == verb {
			return n, true
		}
	}
	return roleexport.Note{}, false
}

// TestMODRL22aFixtureAsWrittenHasNoClassMismatch — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Он стои́т первым намеренно: отрицание без него зеленело бы на реализации,
// отвергающей всякий класс, — а такая реализация ничем не отличается от рабочей,
// пока смотришь только на красное.
//
// Числа названы дословно и с единицами: «ноль отказов» обязано быть отличимо от
// «ноль прочитанного», а перепись — от впечатления.
func TestMODRL22aFixtureAsWrittenHasNoClassMismatch(t *testing.T) {
	m := mustFixture(t)
	faults, notes, census := roleexport.CheckResourceClasses(catalogfixture.Facts(), m, mustActions(t))

	t.Logf("перепись: %s", census.Summary())
	for _, f := range faults {
		t.Errorf("фикстура написана верно, а отказ есть: %v", f)
	}

	// Единица — ДЕЙСТВИЕ раздела `resources` (§3.6 п. 6). Разложение печатается
	// и сверяется целиком: частичное совпадение скрыло бы перенос действия из
	// одного состояния в другое.
	if got, want := census.VerbsRead, 68; got != want {
		t.Errorf("действий раздела resources осмотрено %d, ожидалось %d", got, want)
	}
	if got, want := census.ClassSatisfies, 41; got != want {
		t.Errorf("класс удовлетворяет гейт у %d действий, ожидалось %d", got, want)
	}
	if got, want := census.Unsuitable, 27; got != want {
		t.Errorf("непригодных для роли %d, ожидалось %d", got, want)
	}
	if census.Unmatched != 0 {
		t.Errorf("не сопоставлено %d — фикстура называет действие, которого каталог не знает: %v",
			census.Unmatched, notes)
	}
	// Сумма печатается в самой пробе: расхождение обязано ломать её, а не
	// прятаться внутри одного слагаемого.
	if sum := census.ClassSatisfies + census.Unsuitable + census.Exempt +
		census.Findings + census.Unmatched; sum != census.VerbsRead {
		t.Errorf("сложение состояний даёт %d при %d осмотренных — состояние потеряно",
			sum, census.VerbsRead)
	}
}

// TestMODRL22DeclaredClassMustSatisfyTheGate — MOD-RL-22, отрицательный.
//
// Вход — фикстура с ОДНОЙ правкой: `network.listOperations` объявлен классом
// `get` вместо `list`. Гейт этого действия спрашивает `v_list` на
// `vpc_network`; правило с классом `get` такого кортежа не пишет.
func TestMODRL22DeclaredClassMustSatisfyTheGate(t *testing.T) {
	m := mustLoadManifest(t, withNetworkListOperationsClass(t, "get"))
	faults, _, census := roleexport.CheckResourceClasses(catalogfixture.Facts(), m, mustActions(t))

	t.Logf("перепись: %s", census.Summary())
	found := findingsOf(faults, roleexport.ErrDeclaredClassDoesNotSatisfyGate)
	if len(found) != 1 {
		t.Fatalf("отказов вида «класс не удовлетворяет гейт» %d, ожидался ровно один: %v",
			len(found), faults)
	}
	f := found[0]
	if f.Resource != "network" || f.Verb != "listOperations" || f.Class != "get" {
		t.Errorf("координаты отказа: ресурс %q, действие %q, класс %q", f.Resource, f.Verb, f.Class)
	}
	if f.Relation != "v_list" || f.Object != "vpc_network" {
		t.Errorf("отказ обязан назвать ПАРУ гейта, назвал %q@%q", f.Relation, f.Object)
	}

	// Текст обязан назвать четыре вещи. Отказ, не назвавший починку, отправляет
	// автора манифеста искать опечатку у себя.
	for _, want := range []string{
		"listOperations", // что именно
		`"get"`,          // чем объявлено
		"v_list",         // чего требует гейт
		"vpc_network",    // на каком объекте
		"class: list",    // чем чинится
	} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("текст отказа не называет %q; текст: %s", want, f.Detail)
		}
	}
	if census.Findings != 1 {
		t.Errorf("перепись насчитала отказов %d при одном найденном", census.Findings)
	}
}

// TestMODRL22aFixedClassIsSilent — законный близнец той же правки.
//
// Тот же ресурс, то же действие, класс `list` — молчание. Без него отказ выше
// зеленел бы на реализации, роняющей всякую объектную форму.
func TestMODRL22aFixedClassIsSilent(t *testing.T) {
	m := mustLoadManifest(t, withNetworkListOperationsClass(t, "list"))
	faults, _, census := roleexport.CheckResourceClasses(catalogfixture.Facts(), m, mustActions(t))
	t.Logf("перепись: %s", census.Summary())
	if len(faults) != 0 {
		t.Fatalf("законный близнец получил отказ: %v", faults)
	}
	if census.VerbsRead == 0 {
		t.Fatal("осмотрено ноль действий: молчание неотличимо от непрочитанного")
	}
}

// TestMODRL22UnproducibleGateIsMarkedNotRefused — второй исход сценария.
//
// `addressPool.get` гейтится `system_admin` на `cluster`: правило роли модуля
// такого кортежа не пишет ни при каком классе. Это НЕ отказ — раздел
// `resources` порождается из аннотаций, и требовать от автора снять действие,
// которого он не писал, было бы объявленной и неисполнимой возможностью внутри
// проверки, заведённой против ровно этого класса.
func TestMODRL22UnproducibleGateIsMarkedNotRefused(t *testing.T) {
	m := mustFixture(t)
	faults, notes, _ := roleexport.CheckResourceClasses(catalogfixture.Facts(), m, mustActions(t))

	for _, f := range findingsOf(faults, roleexport.ErrDeclaredClassDoesNotSatisfyGate) {
		if f.Resource == "addressPool" {
			t.Fatalf("непроизводимое отношение стало отказом: %v", f)
		}
	}
	n, ok := noteFor(notes, "addressPool", "get")
	if !ok {
		t.Fatal("addressPool.get не помечен непригодным — второй исход сценария не наблюдаем")
	}
	if n.Kind != roleexport.NoteUnsuitableForRole {
		t.Errorf("вид пометки %v, ожидался «непригодно для роли»", n.Kind)
	}
	for _, want := range []string{"system_admin", "cluster", "MOD-RL-19"} {
		if !strings.Contains(n.Detail, want) {
			t.Errorf("пометка не называет %q; текст: %s", want, n.Detail)
		}
	}
}

// TestMODRL22SameRelationNameIsSeparatedByObject — пара, различающая ОБЪЕКТ.
//
// Обязательна, и приёмка говорит почему: без неё второй исход был бы объявлен
// по ИМЕНИ отношения и не наблюдаем по паре. `network.create` и
// `networkInterface.internalAttach` спрашивают одно и то же имя `editor`;
// первое — на `project`, второе — на объекте типа ресурса.
func TestMODRL22SameRelationNameIsSeparatedByObject(t *testing.T) {
	m := mustLoadManifest(t, `apiVersion: iam/v1
module: vpc
resources:
  - name: network
    objectType: vpc_network
    parents: [project]
    producer: derived
    verbs: [create]
  - name: networkInterface
    objectType: vpc_network_interface
    parents: [project]
    producer: derived
    verbs: [{name: internalAttach, class: update}]
`)
	faults, notes, census := roleexport.CheckResourceClasses(catalogfixture.Facts(), m, mustActions(t))
	t.Logf("перепись: %s", census.Summary())
	if len(faults) != 0 {
		t.Fatalf("ни одно из двух действий отказом не является: %v", faults)
	}
	if _, ok := noteFor(notes, "network", "create"); !ok {
		t.Error("`editor@project` обязан быть помечен непригодным")
	}
	if n, ok := noteFor(notes, "networkInterface", "internalAttach"); ok {
		t.Errorf("`editor` на объекте ТИПА РЕСУРСА пригоден, а помечен непригодным: %s", n.Detail)
	}
	if census.ClassSatisfies != 1 || census.Unsuitable != 1 {
		t.Errorf("удовлетворяет %d · непригодно %d, ожидалось 1 и 1 — пара по объекту не различает",
			census.ClassSatisfies, census.Unsuitable)
	}
}

// TestMODRL22ExemptActionIsNotJudged — освобождённое действие не судится.
//
// `networkInterface.internalListByInstance` — единственная запись каталога vpc
// с пустым `required_relation`: гейта нет вовсе. Класс объявлен не неверно — у
// класса просто нет предмета, и четвёртой ветвью предиката освобождённое не
// является (§3.6 п. 3, Р19).
func TestMODRL22ExemptActionIsNotJudged(t *testing.T) {
	m := mustLoadManifest(t, `apiVersion: iam/v1
module: vpc
resources:
  - name: networkInterface
    objectType: vpc_network_interface
    parents: [project]
    producer: derived
    verbs: [{name: internalListByInstance, class: list}]
`)
	faults, notes, census := roleexport.CheckResourceClasses(catalogfixture.Facts(), m, mustActions(t))
	t.Logf("перепись: %s", census.Summary())
	if len(faults) != 0 {
		t.Fatalf("освобождённое действие судить нечем, а отказ есть: %v", faults)
	}
	if census.Exempt != 1 {
		t.Fatalf("освобождённых %d, ожидалось 1 — ветвь без входа мертва, и её молчание "+
			"выглядело бы работой", census.Exempt)
	}
	if census.ClassSatisfies != 0 || census.Unsuitable != 0 {
		t.Errorf("освобождённое зачтено состоянием: удовлетворяет %d · непригодно %d",
			census.ClassSatisfies, census.Unsuitable)
	}
	if _, ok := noteFor(notes, "networkInterface", "internalListByInstance"); !ok {
		t.Error("освобождённое действие обязано быть НАЗВАНО: иначе автор пишет его в " +
			"право роли, не получает ни отказа, ни печати, и роль его не выдаёт")
	}
}

// TestMODRL22ActionUnknownToCatalogIsNamedNotSwallowed — «не сопоставлено».
//
// Вход настоящий и взят у черновика воркспейса: он пишет `internalGet`, а
// каталог знает `internalGetNetwork` (правило привязки — attribution.go).
// Проглотить такое молча значило бы вывести действие из-под ВСЕХ трёх проверок:
// не нарушением, а невидимостью.
func TestMODRL22ActionUnknownToCatalogIsNamedNotSwallowed(t *testing.T) {
	m := mustLoadManifest(t, `apiVersion: iam/v1
module: vpc
resources:
  - name: network
    objectType: vpc_network
    parents: [project]
    producer: derived
    verbs: [get, {name: internalGet, class: get}]
`)
	faults, notes, census := roleexport.CheckResourceClasses(catalogfixture.Facts(), m, mustActions(t))
	t.Logf("перепись: %s", census.Summary())
	if len(faults) != 0 {
		t.Fatalf("написание действия — контракт генератора раздела, и генератора нет; "+
			"отказ здесь не имел бы адресата: %v", faults)
	}
	if census.Unmatched != 1 {
		t.Fatalf("не сопоставлено %d, ожидалось 1", census.Unmatched)
	}
	n, ok := noteFor(notes, "network", "internalGet")
	if !ok {
		t.Fatal("несопоставленное действие обязано быть названо пометкой")
	}
	if n.Kind != roleexport.NoteActionUnknownToCatalog {
		t.Errorf("вид пометки %v, ожидался «каталог такого действия не знает»", n.Kind)
	}
	// Положительный контроль в той же пробе: соседнее действие сопоставилось.
	if census.ClassSatisfies != 1 {
		t.Errorf("удовлетворяет %d, ожидалось 1 — иначе проба зеленела бы на реализации, "+
			"не сопоставляющей ничего", census.ClassSatisfies)
	}
}

// withNetworkListOperationsClass — фикстура с ОДНОЙ правкой класса.
//
// Правится текст настоящей фикстуры, а не сочиняется свой манифест: инъекция
// обязана ронять ТОЛЬКО проверяемое, а свой манифест отличался бы от фикстуры
// ещё десятком мест, и красное пришло бы неизвестно от какого.
//
// Правка адресуется БЛОКОМ ресурса, а не строкой: та же строка стои́т и у
// `cidrGroup` — счёт вхождений по файлу дал бы два, и замена «первого» молча
// зависела бы от порядка ресурсов в фикстуре.
func withNetworkListOperationsClass(t *testing.T, class string) string {
	t.Helper()
	const blockHead = "  - name: network\n"
	const anchor = "{name: listOperations,   class: list}"

	src := mustFixtureText(t)
	if strings.Count(src, blockHead) != 1 {
		t.Fatalf("заголовок блока ресурса встречается %d раз — инъекция адресует не то, "+
			"что думает", strings.Count(src, blockHead))
	}
	head := strings.Index(src, blockHead)
	// Блок кончается на заголовке следующего ресурса.
	rest := src[head+len(blockHead):]
	tailAt := strings.Index(rest, "\n  - name: ")
	if tailAt < 0 {
		t.Fatal("блок ресурса `network` не имеет конца — раскладка фикстуры сменилась")
	}
	block := rest[:tailAt]
	if strings.Count(block, anchor) != 1 {
		t.Fatalf("якорь правки встречается в блоке %d раз", strings.Count(block, anchor))
	}
	fixed := strings.Replace(block, anchor,
		"{name: listOperations,   class: "+class+"}", 1)
	return src[:head+len(blockHead)] + fixed + rest[tailAt:]
}

// mustFixtureText — текст той же фикстуры, что читает mustFixture.
//
// Путь назван ОДИН раз на пакет: вторая копия координаты разошлась бы с первой
// молча ровно тогда, когда фикстуру переносят.
func mustFixtureText(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("чтение фикстуры соседнего пакета: %v", err)
	}
	return string(data)
}

// ── Задача #1935: пометка не вправе обещать отказ, которого не будет ────────

// unmatchedNoteOn — сверка ДВУХ проверок на ОДНОМ манифесте: что пометка стадии
// класса обещает про несопоставленное действие, и что соседняя сверка соединения
// про него на самом деле говорит.
//
// Обе зовутся здесь намеренно. Прочитать текст пометки и поверить ему — ровно то,
// из-за чего #1935 и завёлся: посылка о чужом механизме бралась из его назначения,
// а не из его кода. Поэтому обещание проверяется ИСХОДОМ соседа, а не прочтением.
func unmatchedNoteOn(t *testing.T, doc, resource, verb string) (roleexport.Note, roleexport.ClassCensus, []error) {
	t.Helper()
	m := mustLoadManifest(t, doc)
	actions := mustActions(t)
	_, notes, census := roleexport.CheckResourceClasses(catalogfixture.Facts(), m, actions)
	linkFaults, lcensus := roleexport.CheckActionLinkage(m, actions)
	t.Logf("перепись класса:     %s", census.Summary())
	t.Logf("перепись соединения: %s", lcensus.Summary())
	n, ok := noteFor(notes, resource, verb)
	if !ok {
		t.Fatalf("действие %s.%s не получило пометки — вход пробы не производит "+
			"состояния «каталог такого действия не знает», и утверждать ей не о чем",
			resource, verb)
	}
	if n.Kind != roleexport.NoteActionUnknownToCatalog {
		t.Fatalf("вид пометки %v, ожидался «каталог такого действия не знает»", n.Kind)
	}
	return n, census, linkFaults
}

// TestMODRL22NoteOnADerivedResourcePromisesARefusalThatComes — ОТРИЦАТЕЛЬНАЯ
// половина предиката #1935: на ПОРОЖДЁННОМ ресурсе пометка обещает отказ соседней
// сверки, и отказ приходит.
//
// Без этой половины правка свелась бы к «убрать обещание отовсюду», и пометка
// перестала бы говорить правду там, где говорила её.
func TestMODRL22NoteOnADerivedResourcePromisesARefusalThatComes(t *testing.T) {
	const doc = `apiVersion: iam/v1
module: vpc
resources:
  - name: network
    objectType: vpc_network
    parents: [project]
    producer: derived
    verbs: [get, {name: internalGet, class: get}]
`
	n, census, linkFaults := unmatchedNoteOn(t, doc, "network", "internalGet")

	if !strings.Contains(n.Detail, "CheckActionLinkage") ||
		!strings.Contains(n.Detail, "ОТКАЗ") {
		t.Errorf("пометка порождённого ресурса не обещает отказа соседней сверки:\n  %s", n.Detail)
	}
	if census.Unmatched != 1 || census.UnmatchedAuthored != 0 {
		t.Errorf("перепись: не сопоставлено %d (авторских %d), ожидалось 1 (0)",
			census.Unmatched, census.UnmatchedAuthored)
	}
	// ИСХОД соседа, а не его назначение: обещание проверяется прогоном.
	var got int
	for _, f := range linkFaults {
		var lf roleexport.LinkageFinding
		if errors.As(f, &lf) && errors.Is(f, roleexport.ErrActionUnknownToCatalog) &&
			lf.Resource == "network" && lf.Verb == "internalGet" {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("сверка соединения отказов по network.internalGet дала %d, ожидался 1 — "+
			"обещание пометки не сбывается и на порождённом ресурсе, то есть оно ложно "+
			"ВЕЗДЕ, а не наполовину: %v", got, linkFaults)
	}
}

// TestMODRL22aNoteOnAnAuthoredResourceDoesNotPromiseASilentNeighbour —
// ПОЛОЖИТЕЛЬНАЯ половина: на АВТОРСКОМ ресурсе с тем же входом пометка говорит,
// что второго слова не будет, и сосед молчит.
//
// Вход отличается от близнеца выше РОВНО ОДНИМ ключом — `producer`. Свой манифест
// отличался бы ещё десятком мест, и красное пришло бы неизвестно от какого.
func TestMODRL22aNoteOnAnAuthoredResourceDoesNotPromiseASilentNeighbour(t *testing.T) {
	const doc = `apiVersion: iam/v1
module: vpc
resources:
  - name: network
    objectType: vpc_network
    parents: [project]
    producer: authored
    verbs: [get, {name: internalGet, class: get}]
`
	n, census, linkFaults := unmatchedNoteOn(t, doc, "network", "internalGet")

	if strings.Contains(n.Detail, "и там это ОТКАЗ") {
		t.Errorf("пометка авторского ресурса обещает отказ соседней сверки, которая его "+
			"популяции не судит вовсе:\n  %s", n.Detail)
	}
	if !strings.Contains(n.Detail, "producer: authored") {
		t.Errorf("пометка не называет РАЗЛИЧИТЕЛЬ (`producer`), поэтому читатель не может "+
			"проверить её утверждение о соседе:\n  %s", n.Detail)
	}
	// Перепись несёт ОБЕ величины: одно число сделало бы «ноль ложных обещаний»
	// неотличимым от «ноль осмотренных».
	if census.Unmatched != 1 || census.UnmatchedAuthored != 1 {
		t.Errorf("перепись: не сопоставлено %d (авторских %d), ожидалось 1 (1)",
			census.Unmatched, census.UnmatchedAuthored)
	}
	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ стадии класса: соседнее действие того же авторского
	// ресурса сопоставилось и было ОСУЖДЕНО. Стадия класса авторские ресурсы
	// судит — в отличие от сверки соединения, — и без этой строки «не сопоставлено
	// 1» зеленело бы на реализации, до ресурса не дошедшей.
	if census.ClassSatisfies != 1 {
		t.Errorf("удовлетворяет %d, ожидалось 1 — стадия класса до авторского ресурса не "+
			"дошла, и утверждение о её пометке ничего не значит", census.ClassSatisfies)
	}
	// ИСХОД соседа: он молчит — и молчит ПО СУЩЕСТВУ, а не потому, что вход пуст.
	for _, f := range linkFaults {
		var lf roleexport.LinkageFinding
		if errors.As(f, &lf) && lf.Resource == "network" {
			t.Fatalf("сверка соединения судила авторский ресурс: %v", f)
		}
	}
}
