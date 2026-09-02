// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// resources_test.go — раздел `resources` (приёмка
// services/iam/docs/engineering/acceptance/module-manifest-resources-roles-deprecated.md,
// сценарии MOD-MR-01 … MOD-MR-09 и MOD-MR-27).
//
// Раздел НЕОДНОРОДЕН: часть его ключей порождается из аннотаций контрактов
// (`name`, `verbs`, `parent`, `objectType`), часть пишет человек (`doc`,
// `relations`, `subjects`, `tiers`), и вид каждого ключа называет сам ресурс
// ключом `producer`. Пробы ниже судят ФОРМУ и СВЯЗНОСТЬ — то, что решает
// загрузчик; кто порождает раздел, решает #1092, и здесь этого нет.
//
// Каждое отрицание несёт ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ контроль в том же сценарии: без
// него отрицание зеленело бы на загрузчике, отвергающем всё.
package manifest_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// mustReadResourcesFixture — манифест vpc со всеми четырьмя разделами.
func mustReadResourcesFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/vpc.resources-fixture.yaml")
	if err != nil {
		t.Fatalf("чтение фикстуры: %v", err)
	}
	return string(data)
}

// ── MOD-MR-01 ───────────────────────────────────────────────────────────────

// TestMODMR01GeneratedResourcesSectionLoadsWhole — положительный контроль ВСЕЙ
// полосы `resources`: девять ресурсов vpc проходят загрузчик целиком, и
// значения всех ключей доступны вызывающему.
func TestMODMR01GeneratedResourcesSectionLoadsWhole(t *testing.T) {
	m, err := manifest.Load([]byte(mustReadResourcesFixture(t)))
	if err != nil {
		t.Fatalf("порождённый раздел отвергнут: %v", err)
	}
	if got := len(m.Resources); got != 9 {
		t.Fatalf("ресурсов прочитано %d, а закрытая таблица несёт девять типов vpc", got)
	}

	byName := map[string]manifest.Resource{}
	for _, r := range m.Resources {
		byName[r.Name] = r
	}

	net, ok := byName["network"]
	if !ok {
		t.Fatalf("ресурс network не прочитан: %v", byName)
	}
	if net.ObjectType != "vpc_network" || net.Parent != "project" || net.Producer != "derived" {
		t.Errorf("порождённые ключи network прочитаны неверно: %+v", net)
	}
	if len(net.Verbs) != 8 {
		t.Errorf("глаголов network прочитано %d, в фикстуре восемь", len(net.Verbs))
	}

	pool, ok := byName["addressPool"]
	if !ok {
		t.Fatalf("ресурс addressPool не прочитан")
	}
	// Авторские ключи обязаны доехать до вызывающего: перегенерация #1092 их
	// сохраняет, а сохранять она может только то, что прочитано.
	if pool.Producer != "authored" {
		t.Errorf("ресурс без производителя среди аннотаций помечен %q", pool.Producer)
	}
	if !strings.Contains(pool.Doc, "cluster_kacho_root") {
		t.Errorf("авторский ключ doc потерян: %q", pool.Doc)
	}
	if len(pool.Subjects) != 2 || len(pool.Tiers) != 2 {
		t.Errorf("авторские subjects/tiers прочитаны неверно: %+v / %+v", pool.Subjects, pool.Tiers)
	}
	sub, ok := byName["subnet"]
	if !ok || len(sub.Relations) != 1 || sub.Relations[0].Name != "use" {
		t.Errorf("авторское отношение subnet.use потеряно: %+v", sub.Relations)
	}
}

// ── MOD-MR-02 ───────────────────────────────────────────────────────────────

// TestMODMR02ResourcesSectionMayBeAbsent — модуль без собственных типов —
// законный случай, а не неполный манифест.
//
// «Раздел не объявлен» обязано быть представимо ОТДЕЛЬНО от «объявлен пустым»:
// первое не утверждает ничего, второе есть утверждение автора «типов у меня
// нет».
func TestMODMR02ResourcesSectionMayBeAbsent(t *testing.T) {
	absent, err := manifest.Load([]byte("apiVersion: iam/v1\nmodule: vpc\n"))
	if err != nil {
		t.Fatalf("манифест без раздела resources отвергнут: %v", err)
	}
	if absent.Resources != nil {
		t.Errorf("раздел не объявлен, а прочитан как %+v", absent.Resources)
	}

	empty, err := manifest.Load([]byte("apiVersion: iam/v1\nmodule: vpc\nresources: []\n"))
	if err != nil {
		t.Fatalf("манифест с пустым разделом resources отвергнут: %v", err)
	}
	if empty.Resources == nil || len(empty.Resources) != 0 {
		t.Errorf("«объявлен и пуст» неотличимо от «не объявлен»: %+v", empty.Resources)
	}
}

// ── MOD-MR-03 ───────────────────────────────────────────────────────────────

// TestMODMR03VerbsParseInBothFormsAndClassComesFromOneRule — короткая форма
// (строка) и длинная (отображение) принимаются в ОДНОМ списке, а класс короткой
// выводит экспортируемая функция.
//
// Единственность объявления правила «класс из имени» в дереве — свойство
// ДЕРЕВА, а не пакета, и его держит гейт `internal/repohygiene`
// TestVerbClassRuleIsDeclaredOnce. Здесь проверяется вторая половина: что
// загрузчик зовёт именно её, а не собственную копию.
func TestMODMR03VerbsParseInBothFormsAndClassComesFromOneRule(t *testing.T) {
	doc := "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
		"  - name: network\n    objectType: vpc_network\n    parent: project\n    producer: derived\n" +
		"    verbs:\n      - get\n      - {name: addCidrBlocks, class: update}\n"
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("обе формы `verbs` в одном списке отвергнуты: %v", err)
	}
	verbs := m.Resources[0].Verbs
	if len(verbs) != 2 {
		t.Fatalf("глаголов прочитано %d, подано два: %+v", len(verbs), verbs)
	}
	if verbs[0].Name != "get" || verbs[0].Class != "get" {
		t.Errorf("короткая форма разобрана неверно: %+v", verbs[0])
	}
	if verbs[1].Name != "addCidrBlocks" || verbs[1].Class != "update" {
		t.Errorf("длинная форма разобрана неверно: %+v", verbs[1])
	}

	// Класс короткой формы получен ТОЙ ЖЕ функцией, которую зовёт загрузчик:
	// вторая копия правила разошлась бы с первой молча.
	for _, canonical := range []string{"get", "list", "create", "update", "delete"} {
		class, ok := manifest.ClassOfCanonicalVerb(canonical)
		if !ok || class != canonical {
			t.Errorf("канонический глагол %q не выводит свой класс: %q, ok=%v", canonical, class, ok)
		}
	}
	// Отрицательная сторона той же функции: неканоническое имя класса НЕ даёт.
	if class, ok := manifest.ClassOfCanonicalVerb("addCidrBlocks"); ok {
		t.Errorf("неканоническое имя вывело класс %q — правило перестало быть точным совпадением", class)
	}
}

// ── MOD-MR-04 ───────────────────────────────────────────────────────────────

// TestMODMR04NonCanonicalVerbWithoutClassIsRefused — глаголов, класс которых не
// выводится ни одним действующим правилом, в каталоге 95 из 324 строк; для них
// `class` обязателен.
func TestMODMR04NonCanonicalVerbWithoutClassIsRefused(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
		"  - name: address\n    objectType: vpc_address\n    parent: project\n    producer: derived\n" +
		"    verbs:\n      - get\n      - {name: allocateExternalIp%s}\n"

	_, err := manifest.Load([]byte(strings.Replace(base, "%s", "", 1)))
	if err == nil {
		t.Fatalf("неканонический глагол без класса принят")
	}
	if !errors.Is(err, manifest.ErrVerbClassNotDerivable) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{"resources[0].verbs[1].class", "allocateExternalIp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	// Парный положительный: тот же вход с явным классом.
	if _, err := manifest.Load([]byte(strings.Replace(base, "%s", ", class: update", 1))); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// ── MOD-MR-05 ───────────────────────────────────────────────────────────────

// TestMODMR05ClassOutsideTheClosedSetIsRefused — отказ называет и полученное
// значение, и перечень принимаемых: автор обязан узнать не только что ошибся,
// но и чем это чинится.
func TestMODMR05ClassOutsideTheClosedSetIsRefused(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
		"  - name: network\n    objectType: vpc_network\n    parent: project\n    producer: derived\n" +
		"    verbs:\n      - {name: get, class: %s}\n"

	_, err := manifest.Load([]byte(strings.Replace(base, "%s", "fetch", 1)))
	if err == nil {
		t.Fatalf("класс вне закрытого набора принят")
	}
	if !errors.Is(err, manifest.ErrVerbClassUnknown) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{"fetch", "get", "list", "create", "update", "delete"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	if _, err := manifest.Load([]byte(strings.Replace(base, "%s", "get", 1))); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// ── MOD-MR-06 ───────────────────────────────────────────────────────────────

// TestMODMR06ObjectTypeIsRequiredAndResolvedByTheClosedTable — правило вывода
// `objectType ← <module>_<resource>` СНЯТО (приёмка §2.4: оно не действует у 10
// записей из 27), поэтому ключ обязателен у каждого ресурса, а его значение
// резолвится закрытой таблицей.
func TestMODMR06ObjectTypeIsRequiredAndResolvedByTheClosedTable(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
		"  - name: gateway\n%s    parent: project\n    producer: derived\n    verbs: [get]\n"

	_, err := manifest.Load([]byte(strings.Replace(base, "%s", "", 1)))
	if err == nil {
		t.Fatalf("ресурс без objectType принят")
	}
	if !errors.Is(err, manifest.ErrObjectTypeRequired) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	if !strings.Contains(err.Error(), "resources[0].objectType") {
		t.Errorf("отказ не называет поле: %v", err)
	}
	// Текст НЕ предлагает вывод из имени: правило снято, и обещать его нельзя.
	for _, forbidden := range []string{"vpc_gateway ", "выводится", "derive"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Errorf("отказ предлагает снятое правило вывода (%q): %v", forbidden, err)
		}
	}

	if _, err := manifest.Load([]byte(strings.Replace(base, "%s", "    objectType: vpc_gateway\n", 1))); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}

	// Второй отрицательный: значение вне закрытой таблицы.
	_, err = manifest.Load([]byte(strings.Replace(base, "%s", "    objectType: vpc_gatewayz\n", 1)))
	if err == nil {
		t.Fatalf("тип вне закрытой таблицы принят")
	}
	if !errors.Is(err, manifest.ErrObjectTypeUnknown) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	if !strings.Contains(err.Error(), "vpc_gatewayz") {
		t.Errorf("отказ не называет полученное значение: %v", err)
	}
}

// ── MOD-MR-07 ───────────────────────────────────────────────────────────────

// TestMODMR07ParentOutsideTheClosedSetIsRefused — якорь области закрыт набором
// {project, account, cluster}.
func TestMODMR07ParentOutsideTheClosedSetIsRefused(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
		"  - name: network\n    objectType: vpc_network\n    parent: %s\n    producer: derived\n    verbs: [get]\n"

	_, err := manifest.Load([]byte(strings.Replace(base, "%s", "organization", 1)))
	if err == nil {
		t.Fatalf("якорь вне закрытого набора принят")
	}
	if !errors.Is(err, manifest.ErrParentUnknown) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{"resources[0].parent", "organization", "project", "account", "cluster"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	if _, err := manifest.Load([]byte(strings.Replace(base, "%s", "project", 1))); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// ── MOD-MR-08 ───────────────────────────────────────────────────────────────

// TestMODMR08DuplicateResourceNameNamesBothIndices — отказ называет ОБА индекса,
// а не первый: названная первая заставила бы чинить по одной, по прогону на
// каждую.
func TestMODMR08DuplicateResourceNameNamesBothIndices(t *testing.T) {
	doc := "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
		"  - name: network\n    objectType: vpc_network\n    parent: project\n    producer: derived\n    verbs: [get]\n" +
		"  - name: subnet\n    objectType: vpc_subnet\n    parent: project\n    producer: derived\n    verbs: [get]\n" +
		"  - name: network\n    objectType: vpc_network\n    parent: project\n    producer: derived\n    verbs: [get]\n"

	_, err := manifest.Load([]byte(doc))
	if err == nil {
		t.Fatalf("два ресурса с одним именем приняты")
	}
	if !errors.Is(err, manifest.ErrResourceNameDuplicated) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{"resources[0]", "resources[2]", "network"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "resources[1]") {
		t.Errorf("отказ называет непричастный ресурс: %v", err)
	}

	// Парный положительный: разные имена.
	ok := strings.Replace(doc, "  - name: network\n    objectType: vpc_network\n    parent: project\n    producer: derived\n    verbs: [get]\n"+
		"  - name: subnet", "  - name: gateway\n    objectType: vpc_gateway\n    parent: project\n    producer: derived\n    verbs: [get]\n"+
		"  - name: subnet", 1)
	if _, err := manifest.Load([]byte(ok)); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// ── MOD-MR-09 ───────────────────────────────────────────────────────────────

// TestMODMR09AuthoredRelationMayNotShadowAGeneratedVerb — объявленное отношение
// не вправе заместить порождённый глагол.
//
// Отношение `v_<глагол>` порождается из самого глагола; объявив его руками,
// автор получил бы ДВА объявления одного предмета, из которых верно одно.
func TestMODMR09AuthoredRelationMayNotShadowAGeneratedVerb(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
		"  - name: network\n    objectType: vpc_network\n    parent: project\n    producer: derived\n" +
		"    relations:\n      - {name: %s, definition: \"[user]\"}\n" +
		"    verbs: [get]\n"

	_, err := manifest.Load([]byte(strings.Replace(base, "%s", "v_get", 1)))
	if err == nil {
		t.Fatalf("отношение, замещающее порождённый глагол, принято")
	}
	if !errors.Is(err, manifest.ErrRelationShadowsVerb) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{"resources[0].relations[0].name", "v_get", "get"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	if _, err := manifest.Load([]byte(strings.Replace(base, "%s", "ssh", 1))); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// ── MOD-MR-27 ───────────────────────────────────────────────────────────────

// TestMODMR27ProducerIsRequiredAndItsSetIsClosed — ключ `producer` называет вид
// ОСТАЛЬНЫХ ключей записи, поэтому его отсутствие делает невыразимым сам вопрос
// «пережил ли авторский ключ перегенерацию».
func TestMODMR27ProducerIsRequiredAndItsSetIsClosed(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
		"  - name: network\n    objectType: vpc_network\n    parent: project\n%s    verbs: [get]\n"

	_, err := manifest.Load([]byte(strings.Replace(base, "%s", "", 1)))
	if err == nil {
		t.Fatalf("ресурс без producer принят")
	}
	if !errors.Is(err, manifest.ErrProducerRequired) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{"resources[0].producer", "derived", "authored"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	// Второй отрицательный: значение вне набора.
	_, err = manifest.Load([]byte(strings.Replace(base, "%s", "    producer: generated\n", 1)))
	if err == nil {
		t.Fatalf("producer вне закрытого набора принят")
	}
	if !errors.Is(err, manifest.ErrProducerUnknown) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	if !strings.Contains(err.Error(), "generated") {
		t.Errorf("отказ не называет полученное значение: %v", err)
	}

	// Парные положительные: оба законных значения.
	for _, producer := range []string{"derived", "authored"} {
		if _, err := manifest.Load([]byte(strings.Replace(base, "%s", "    producer: "+producer+"\n", 1))); err != nil {
			t.Fatalf("producer %q отвергнут: %v", producer, err)
		}
	}
}

// TestVerbLongFormRejectsAnUnknownKey — своя реализация разбора глагола НЕ
// вправе потерять свойство, которое держит `Decoder.KnownFields(true)`.
//
// Библиотека не проносит строгость внутрь собственного `UnmarshalYAML`:
// узел разбирается умолчательно, и `clazz` уехал бы молча. Свойство измерено
// при #1088 («line 7: field clazz not found in type verb») и обязано пережить
// заведение двух форм.
func TestVerbLongFormRejectsAnUnknownKey(t *testing.T) {
	doc := "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
		"  - name: network\n    objectType: vpc_network\n    parent: project\n    producer: derived\n" +
		"    verbs:\n      - {name: get, clazz: get}\n"
	_, err := manifest.Load([]byte(doc))
	if err == nil {
		t.Fatalf("неизвестный ключ внутри глагола принят молча")
	}
	if !strings.Contains(err.Error(), "clazz") {
		t.Errorf("отказ не называет неизвестный ключ: %v", err)
	}
}
