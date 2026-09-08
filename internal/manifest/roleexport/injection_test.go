// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// injection_test.go — доказательство СПОСОБНОСТИ упасть и СПОСОБНОСТИ смолчать.
//
// Порядок обязателен и повторяет `testing.md` §«Гейт на класс», п. 2–4, плюс
// §7 приёмки:
//
//  1. дефект вносится во ВРЕМЕННУЮ копию манифеста (`t.TempDir()`), а не в
//     дерево: правка дерева ради пробы делает вердикт функцией диска;
//  2. у каждой оси стои́т ЗАКОННЫЙ БЛИЗНЕЦ, и он молчит. Отрицание без близнеца
//     зелено на реализации, отвергающей любой вход;
//  3. прогонов ТРИ, а не два: контроль · инъекция нового свойства · инъекция
//     существующего. Без третьего молчание существующего контроля неотличимо от
//     молчания мёртвого;
//  4. распознаватель обязан знать ВСЕ законные формы записи предмета — здесь
//     это обе половины пары «отношение + объект», и близнец ПО ИМЕНИ обязателен:
//     `editor` на объекте типа ресурса производится, `editor` на проекте — нет.
package roleexport_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// injectRules — временная копия фикстуры, где выдачи роли заменены дословно.
//
// Заменяется ровно одна строка на роль, а не собирается новый документ: манифест,
// написанный пробой с нуля, проверял бы её собственное представление о форме.
func injectRules(t *testing.T, replacements ...[2]string) *manifest.Manifest {
	t.Helper()
	data, err := os.ReadFile("../testdata/vpc.resources-fixture.yaml")
	if err != nil {
		t.Fatalf("чтение фикстуры: %v", err)
	}
	text := string(data)
	for _, r := range replacements {
		if !strings.Contains(text, r[0]) {
			t.Fatalf("инъекция беспредметна: строки %q в фикстуре нет — "+
				"проба утверждала бы о документе, которого не читала", r[0])
		}
		text = strings.Replace(text, r[0], r[1], 1)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "injected.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("запись временной копии: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение временной копии: %v", err)
	}
	m, err := manifest.Load(raw)
	if err != nil {
		t.Fatalf("временная копия отвергнута загрузчиком: %v", err)
	}
	return m
}

// emptyClassFindings — находки о пустом классе.
func emptyClassFindings(t *testing.T, m *manifest.Manifest) []roleexport.Finding {
	t.Helper()
	faults, _ := roleexport.CheckRoleRules(catalogfixture.Facts(), m, mustActions(t))
	var out []roleexport.Finding
	for _, f := range faults {
		var got roleexport.Finding
		if errors.As(f, &got) && errors.Is(f, roleexport.ErrClassCoversNoSuitableAction) {
			out = append(out, got)
		}
	}
	return out
}

const (
	consumerRule = "        resources: [address, networkInterface, subnet]\n" +
		"        classes: [get, list]"
	poolRule = "        resources: [addressPool]\n" +
		"        classes: [get, list, create, update, delete]"
)

// ── Прогон 1: КОНТРОЛЬ ──────────────────────────────────────────────────────

// TestInjectionControl_LegalTwinIsSilent — фикстура без инъекции: находки есть
// ровно там, где дефект живёт в дереве, и ни одной у законного близнеца.
func TestInjectionControl_LegalTwinIsSilent(t *testing.T) {
	for _, f := range emptyClassFindings(t, mustFixture(t)) {
		if f.Role == "vpc.internal_consumer" {
			t.Errorf("контроль красен на законном близнеце: %v", f.Detail)
		}
	}
}

// ── Прогон 2: инъекция НОВОГО свойства ──────────────────────────────────────

// TestInjection_ClusterRelationIsRefused — ось «прямой userset на кластере».
func TestInjection_ClusterRelationIsRefused(t *testing.T) {
	m := injectRules(t, [2]string{consumerRule,
		"        resources: [addressPool]\n        classes: [get]"})
	var hit *roleexport.Finding
	for i, f := range emptyClassFindings(t, m) {
		if f.Role == "vpc.internal_consumer" {
			hit = &emptyClassFindings(t, m)[i]
			break
		}
	}
	if hit == nil {
		t.Fatal("инъекция не поймана: класс `get` на `addressPool` пуст — " +
			"все 22 действия ресурса гейтятся отношением кластера")
	}
	for _, want := range []string{"system_admin@cluster", "привязкой ОТНОШЕНИЯ"} {
		if !strings.Contains(hit.Detail, want) {
			t.Errorf("отказ не называет %q; отказ: %s", want, hit.Detail)
		}
	}
}

// TestInjection_ScopeTierIsRefused — ось «ярус ОБЛАСТИ».
//
// Это та ось, которую проверка, читающая отношение по ИМЕНИ, пропускала молча:
// `editor` — имя «наше», и по имени оно проходило.
func TestInjection_ScopeTierIsRefused(t *testing.T) {
	m := injectRules(t, [2]string{consumerRule,
		"        resources: [network]\n        classes: [create]"})
	found := false
	for _, f := range emptyClassFindings(t, m) {
		if f.Role != "vpc.internal_consumer" {
			continue
		}
		found = true
		if !strings.Contains(f.Detail, "editor@project") {
			t.Errorf("отказ не называет пару `editor@project`; отказ: %s", f.Detail)
		}
		if !strings.Contains(f.Detail, "ярусная роль платформы") &&
			!strings.Contains(f.Detail, "ярус на области") {
			t.Errorf("отказ не называет годный способ для яруса области; отказ: %s", f.Detail)
		}
	}
	if !found {
		t.Fatal("инъекция не поймана: класс `create` на `network` покрывает ноль " +
			"пригодных действий — единственное действие класса гейтится `editor` на проекте")
	}
}

// TestInjection_SameRelationNameOnTheResourceTypeIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ ПО
// ИМЕНИ, и он обязателен.
//
// Гейт спрашивает то же имя `editor`, но на объекте ТИПА РЕСУРСА, и правило роли
// этот кортеж пишет. Без этого близнеца проверка зеленела бы на реализации,
// отвергающей ярус ПО ИМЕНИ, — и дефект вернулся бы с другой стороны.
//
// # Почему близнец подаётся ДЕЙСТВИЕМ, а не правилом манифеста (#1835)
//
// Прежняя редакция брала близнеца из настоящего каталога — действия
// `internalAttach` / `internalDetach` ресурса `networkInterface`. Оба живут на
// ПЛОСКОСТИ ИСПОЛНЕНИЯ, а класс её действий больше не покрывает: черновик
// манифеста запрещает автоматическую выдачу таких действий, и запрет исполняется
// с появлением формы `classes` (#1090). То есть прежний близнец проверял ДВА
// свойства сразу и после введения запрета стал отрицать одно из них.
//
// Перепись, из-за которой близнеца нельзя просто перенести на другой ресурс: пар
// «ярус + объект типа ресурса», встречающихся у АРЕНДАТОРСКИХ действий
// встроенного каталога, — ноль; все пять таких пар (editor у storage_volume и
// vpc_network_interface, viewer у storage_image и storage_volume, admin у
// registry_registry) принадлежат только внутренней плоскости. Поэтому близнец
// подаётся синтетическим действием арендаторской плоскости с тем же гейтом —
// свойство остаётся ровно тем же, а плоскость перестаёт в него вмешиваться.
func TestInjection_SameRelationNameOnTheResourceTypeIsSilent(t *testing.T) {
	tenant := roleexport.Action{
		Module:   "vpc",
		Resource: "networkInterface",
		Verb:     "attach",
		FQN:      "kacho.cloud.vpc.v1.NetworkInterfaceService/Attach",
		Relation: "editor",
		Object:   "vpc_network_interface",
	}
	covered := roleexport.Covers(catalogfixture.Facts(),
		[]roleexport.Action{tenant}, "vpc_network_interface", "create")
	if len(covered) != 1 {
		t.Errorf("законный близнец по имени отношения не покрыт: ярус %q спрошен на объекте "+
			"ТИПА РЕСУРСА (%s), и правило роли этот кортеж пишет — значит отвергать его нельзя. "+
			"Покрыто %d действий", tenant.Relation, tenant.Object, len(covered))
	}

	// И то же имя на объекте ОБЛАСТИ по-прежнему НЕ производится: без этой
	// половины близнец доказывал бы, что покрывается всё подряд.
	scope := tenant
	scope.Object = "project"
	if got := roleexport.Covers(catalogfixture.Facts(),
		[]roleexport.Action{scope}, "vpc_network_interface", "create"); len(got) != 0 {
		t.Errorf("ярус %q на объекте ОБЛАСТИ (%s) покрыт — правило роли модуля этого кортежа "+
			"не пишет ни при каком написании", scope.Relation, scope.Object)
	}
}

// TestInjection_UnknownResourceIsItsOwnRefusal — ресурс, которому каталог не
// приписывает ни одного действия, отвергается СВОИМ отказом, а не «классом».
//
// Чинятся они разным: один — именем ресурса, другой — именем класса. Общий
// отказ отправил бы автора искать опечатку в классе.
func TestInjection_UnknownResourceIsItsOwnRefusal(t *testing.T) {
	m := injectRules(t, [2]string{consumerRule,
		"        resources: [networkz]\n        classes: [get]"})
	faults, _ := roleexport.CheckRoleRules(catalogfixture.Facts(), m, mustActions(t))
	kinds := map[string]int{}
	for _, f := range faults {
		var got roleexport.Finding
		if !errors.As(f, &got) || got.Role != "vpc.internal_consumer" {
			continue
		}
		switch {
		case errors.Is(f, roleexport.ErrRuleResourceUnknownToCatalog):
			kinds["ресурс"]++
		case errors.Is(f, roleexport.ErrClassCoversNoSuitableAction):
			kinds["класс"]++
		}
	}
	if kinds["ресурс"] != 1 || kinds["класс"] != 0 {
		t.Errorf("вид находки выбран неверно: %v — ожидалась одна находка о ресурсе "+
			"и ни одной о классе", kinds)
	}
}

// TestInjection_DeprecatedVerbStaysAnAction — снятый глагол ОСТАЁТСЯ действием.
//
// Ярус чтения продукта записан дословно `read` · `list` · `get`, и отказ на
// первом же его глаголе означал бы, что манифест не воспроизводит действующее
// состояние. Раздел `deprecatedVerbs` фикстуры разрешает `read` в класс `get`.
func TestInjection_DeprecatedVerbStaysAnAction(t *testing.T) {
	m := injectRules(t, [2]string{consumerRule,
		"        resources: [network]\n        classes: [read, list, get]"})
	for _, f := range emptyClassFindings(t, m) {
		if f.Role == "vpc.internal_consumer" {
			t.Errorf("снятый глагол прочитан как несуществующий класс: %s", f.Detail)
		}
	}
}

// TestInjection_VerbWildcardIsExpandedNotRefused — подстановка в ГЛАГОЛАХ
// законна и разворачивается набором типа.
//
// Разворачивает её тот же предикат, что у эмиттера кортежей; второй ответ на
// этот вопрос понизил бы роль-суперпользователя с администратора до наблюдателя
// молча.
func TestInjection_VerbWildcardIsExpandedNotRefused(t *testing.T) {
	m := injectRules(t, [2]string{consumerRule,
		"        resources: [network]\n        classes: [\"*\"]"})
	for _, f := range emptyClassFindings(t, m) {
		if f.Role == "vpc.internal_consumer" {
			t.Errorf("подстановка в глаголах прочитана как пустой класс: %s", f.Detail)
		}
	}
}

// TestResourceWildcardCannotReachTheCheck — ПРЕДПОСЫЛКА проверки, а не её
// свойство.
//
// Ветви под `resources: ["*"]` в проверке НЕТ намеренно: разбор судит правило
// роли манифеста в НЕсистемном контексте, а домен объявляет подстановку в
// ресурсах системной, — значит такое правило до проверки не доходит вовсе.
// Запрет обоснован фактом о дереве, факт меняется, и заявлять о нём обязана сама
// проверка: перестанет разбор отвергать подстановку — эта проба покраснеет, и
// ветвь придётся завести вместе с ней.
func TestResourceWildcardCannotReachTheCheck(t *testing.T) {
	data, err := os.ReadFile("../testdata/vpc.resources-fixture.yaml")
	if err != nil {
		t.Fatalf("чтение фикстуры: %v", err)
	}
	text := strings.Replace(string(data), consumerRule,
		"        resources: [\"*\"]\n        classes: [get, list]", 1)
	if text == string(data) {
		t.Fatal("инъекция беспредметна: выдачи роли в фикстуре нет")
	}
	_, err = manifest.Load([]byte(text))
	if err == nil {
		t.Fatal("загрузчик принял подстановку в ресурсах несистемной роли — " +
			"предпосылка снята, и ветвь под подстановку обязана быть заведена")
	}
	if !strings.Contains(err.Error(), "wildcard") {
		t.Errorf("отказ загрузчика не о подстановке: %v", err)
	}
}

// ── Прогон 3: инъекция СУЩЕСТВУЮЩЕГО свойства ───────────────────────────────

// TestInjection_ExistingFormCheckStaysAlive — существующий контроль формы жив.
//
// Без этого прогона молчание загрузчика неотличимо от молчания мёртвого: новая
// проверка могла бы оказаться вакуумной и не показать этого ничем.
//
// # Инъекция ПЕРЕВЕДЕНА на признак, который дерево ещё производит
//
// Здесь инъекцией стоял КЛАСТЕРНЫЙ ЯРУС, и она была верна ровно до тех пор,
// пока загрузчик его отвергал. Приёмка `roles-come-as-data-not-migrations.md`
// §3.2 сняла этот отказ: писателем строки становится применитель манифеста, и
// кластерный ярус — законный вход. Прогон покраснел на том, что перестало быть
// дефектом, — то есть предмет у инъекции исчез.
//
// Исходов было два (`testing.md` §«Гейт на класс», п. 9): снять утверждение
// вместе с предметом либо перевести его на признак, который дерево ПРОИЗВОДИТ.
// Выбран второй: назначение прогона — «загрузчик вообще способен отвергнуть», —
// а не «он отвергает именно ярус. Признак заменён на ФОРМУ идентификатора
// (`RoleIDForm`): заглавная буква во втором сегменте отвергается ограничением
// таблицы `roles_system_name_check`, и загрузчик говорит об этом своим отказом.
func TestInjection_ExistingFormCheckStaysAlive(t *testing.T) {
	data, err := os.ReadFile("../testdata/vpc.resources-fixture.yaml")
	if err != nil {
		t.Fatalf("чтение фикстуры: %v", err)
	}
	broken := strings.Replace(string(data), "id: vpc.internal_consumer", "id: vpc.internalConsumer", 1)
	if broken == string(data) {
		t.Fatal("инъекция беспредметна: строки идентификатора роли в фикстуре нет")
	}
	if _, err = manifest.Load([]byte(broken)); err == nil {
		t.Fatal("загрузчик принял идентификатор вне объявленной формы: существующий " +
			"контроль формы мёртв, и молчание новой проверки неотличимо от его молчания")
	}
	if !errors.Is(err, manifest.ErrRoleIDOutOfForm) {
		t.Errorf("отказ пришёл не от контроля формы: %v", err)
	}

	// Законный близнец той же оси: та же фикстура БЕЗ инъекции обязана
	// загружаться. Без него утверждение выше зеленело бы на загрузчике,
	// отвергающем всё.
	if _, err := manifest.Load(data); err != nil {
		t.Fatalf("неизменённая фикстура отвергнута — отрицание выше вакуумно: %v", err)
	}
}

// ── Антимаска ───────────────────────────────────────────────────────────────

// TestCheckOnAnEmptyCatalogIsVoid_NotClean — «ноль находок» при пустом каталоге
// обязано быть отличимо от «чисто».
//
// Проверка, судившая роли без единого действия, молчит ровно так же уверенно,
// как проверившая все; отличает их перепись, и она обязана это показывать.
func TestCheckOnAnEmptyCatalogIsVoid_NotClean(t *testing.T) {
	faults, census := roleexport.CheckRoleRules(catalogfixture.Facts(), mustFixture(t), nil)
	if census.ActionsAttributed != 0 {
		t.Fatalf("действий привязано %d при пустом каталоге", census.ActionsAttributed)
	}
	if len(faults) == 0 {
		t.Error("на пустом каталоге проверка молчит: вердикт неотличим от чистого. " +
			"Ресурс, которому не приписано ни одного действия, обязан быть находкой")
	}
	if census.PairsJudged != 0 {
		t.Errorf("осмотрено пар %d при пустом каталоге", census.PairsJudged)
	}
}

// ── Привязка: биекция в обе стороны ─────────────────────────────────────────

// TestAttribute_TwoEntriesOneKeyIsAFinding — правило вывода обязано быть
// инъективным, и его негодность обязана быть слышной.
func TestAttribute_TwoEntriesOneKeyIsAFinding(t *testing.T) {
	_, faults := roleexport.Attribute([]roleexport.CatalogEntry{
		{FQN: "kacho.cloud.vpc.v1.NetworkService/Get", RequiredRelation: "v_get", ScopeObjectType: "vpc_network"},
		{FQN: "kacho.cloud.vpc.v1.NetworkService/Get", RequiredRelation: "v_get", ScopeObjectType: "vpc_network"},
	})
	hit := false
	for _, f := range faults {
		if errors.Is(f, roleexport.ErrAttributionNotInjective) {
			hit = true
		}
	}
	if !hit {
		t.Error("совпадение ключа не названо: одно из двух действий стало бы невидимым")
	}
}

// TestAttribute_PlatformEntriesAreNamedNotDropped — запись вне формы модуля
// НАЗЫВАЕТСЯ, а не отбрасывается молча.
func TestAttribute_PlatformEntriesAreNamedNotDropped(t *testing.T) {
	actions, faults := roleexport.Attribute([]roleexport.CatalogEntry{
		{FQN: "kacho.cloud.operation.OperationService/Get"},
	})
	if len(actions) != 0 {
		t.Errorf("платформенная запись привязана к ресурсу модуля: %+v", actions)
	}
	if len(faults) != 1 || !errors.Is(faults[0], roleexport.ErrEntryOutsideModuleShape) {
		t.Errorf("запись вне формы модуля не названа: %v", faults)
	}
}

// TestAttribute_InternalPlaneKeepsItsOwnKey — внутреннее действие не сливается с
// публичным.
//
// У `addressPool` 11 публичных RPC и 11 внутренних под теми же именами методов;
// правило вывода, потерявшее приставку, слило бы их попарно и объявило бы
// ресурс вдвое меньшим.
func TestAttribute_InternalPlaneKeepsItsOwnKey(t *testing.T) {
	actions, faults := roleexport.Attribute([]roleexport.CatalogEntry{
		{FQN: "kacho.cloud.vpc.v1.AddressPoolService/Get", RequiredRelation: "system_admin", ScopeObjectType: "cluster"},
		{FQN: "kacho.cloud.vpc.v1.InternalAddressPoolService/Get", RequiredRelation: "system_admin", ScopeObjectType: "cluster"},
	})
	if len(faults) != 0 {
		t.Fatalf("законный вход дал находки: %v", faults)
	}
	if len(actions) != 2 {
		t.Fatalf("привязано %d действий, ожидалось 2", len(actions))
	}
	got := map[string]bool{actions[0].Verb: true, actions[1].Verb: true}
	if !got["get"] || !got["internalGet"] {
		t.Errorf("действия слились: %v", got)
	}
}

// ── Ветви отказа, у которых свой вход ───────────────────────────────────────

// TestInjection_ResourceWithoutAnObjectTypeSaysSo — ресурс, у пары которого нет
// типа объекта в закрытой таблице, отвергается СВОЕЙ причиной.
//
// `quota` каталог знает (одно действие), а типа объекта у него нет: право на
// квоту проверяется на проекте. Общий текст «класс пуст» отправил бы автора
// искать опечатку в классе, тогда как чинится это не классом вовсе.
func TestInjection_ResourceWithoutAnObjectTypeSaysSo(t *testing.T) {
	m := injectRules(t, [2]string{consumerRule,
		"        resources: [quota]\n        classes: [list]"})
	found := false
	for _, f := range emptyClassFindings(t, m) {
		if f.Role != "vpc.internal_consumer" {
			continue
		}
		found = true
		if !strings.Contains(f.Detail, "нет типа объекта") {
			t.Errorf("отказ не называет причину «типа объекта нет»; отказ: %s", f.Detail)
		}
		if !strings.Contains(f.Detail, "viewer@project") {
			t.Errorf("отказ не называет пару, которую спрашивает гейт; отказ: %s", f.Detail)
		}
	}
	if !found {
		t.Fatal("инъекция не поймана: у пары (vpc, quota) типа объекта нет, " +
			"поэтому правило роли не пишет на ней ни одного кортежа")
	}
}

// TestFullyExemptResourceIsNamedAsSuch — ресурс, все действия которого
// освобождены от гейта, отвергается СВОЕЙ причиной.
//
// Вход синтетический намеренно: сегодня такого ресурса в каталоге нет ни одного,
// а свойство обязано охраняться ДО появления первого. Ветвь без входа была бы
// мёртвой, и её молчание выглядело бы работой.
func TestFullyExemptResourceIsNamedAsSuch(t *testing.T) {
	m := injectRules(t, [2]string{consumerRule,
		"        resources: [network]\n        classes: [get]"})
	actions, faults := roleexport.Attribute([]roleexport.CatalogEntry{
		{FQN: "kacho.cloud.vpc.v1.NetworkService/Get"},
		{FQN: "kacho.cloud.vpc.v1.NetworkService/List"},
	})
	if len(faults) != 0 {
		t.Fatalf("синтетический вход дал находки привязки: %v", faults)
	}
	found, _ := roleexport.CheckRoleRules(catalogfixture.Facts(), m, actions)
	if len(found) == 0 {
		t.Fatal("ресурс, у которого все действия освобождены, не отвергнут: " +
			"правом они не выдаются вовсе, и молчание обещало бы право, которого нет")
	}
	if !strings.Contains(found[0].Error(), "освобождены от гейта") {
		t.Errorf("отказ не называет причину «освобождено»; отказ: %s", found[0])
	}
}
