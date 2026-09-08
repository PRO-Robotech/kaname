// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// namedverbs_test.go — ПОИМЁННАЯ форма права роли, содержательная половина:
// MOD-RL-18/18a (полнота перечня по классу) и MOD-RL-19/19a (названное действие,
// чей гейт правилом роли непроизводим).
//
// Приёмка: services/iam/docs/engineering/acceptance/module-manifest-roles-and-seed-grants.md
// §3.6 п. 3–5, §3.7, сценарии MOD-RL-18, MOD-RL-18a, MOD-RL-19, MOD-RL-19a.
// Задача: kacho#1844, половина 2.
//
// # Вход НАСТОЯЩИЙ: раздел `resources` берётся у фикстуры, роль дописывается
//
// Раздел действий не сочиняется здесь: он читается из
// `../testdata/vpc.resources-fixture.yaml` — того же файла, которым судятся
// MOD-RL-05 и MOD-RL-22. Своя копия раздела была бы вторым манифестом об одном
// предмете и разошлась бы с первым молча ровно тогда, когда меняется каталог.
// Дописывается только роль под пробой: её в фикстуре нет и быть не должно —
// фикстура несёт ЗАКОННЫЕ роли, а предмет этих проб — отвергаемые.
//
// # Единицы РАЗНЫЕ у двух сценариев, и это не педантизм
//
//	MOD-RL-18  — единица «покрытое действие»: перечень полон по ПРИГОДНОМУ
//	             содержимому класса. Стадия — ЭКСПОРТ, после вердикта загрузчика.
//	MOD-RL-19  — единица «названное вхождение»: имя, чей гейт спрашивает пару вне
//	             `{v_*} ∪ {viewer, editor, admin}` НА ОБЪЕКТЕ ТИПА РЕСУРСА.
//	             Стадия — целостность, до экспорта.
//
// Сложение находок двух проверок дало бы величину, которую нечем перемерить,
// поэтому перепись каждой печатает свою.
package roleexport_test

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// withRole — фикстура соседнего пакета плюс ОДНА дописанная роль.
//
// Дописывается текстом, а не сборкой структуры: манифест обязан пройти тот же
// загрузчик, каким его читает продукт, — иначе проба судила бы вход, который
// продукт принять не может.
func withRole(t *testing.T, roleID, rules string) *manifest.Manifest {
	t.Helper()
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("чтение фикстуры соседнего пакета: %v", err)
	}
	doc := string(data)
	// Роль встаёт в конец раздела `roles`, ПЕРЕД следующим разделом верхнего
	// уровня: дописывание в самый конец файла положило бы её под `seed`.
	const anchor = "\ndeprecatedVerbs:"
	if !strings.Contains(doc, anchor) {
		t.Fatalf("якорь %q в фикстуре не найден: дописывать роль некуда", anchor)
	}
	role := fmt.Sprintf("\n  - id: %s\n    description: Роль под пробой поимённой формы права.\n"+
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n    rules:\n%s",
		roleID, rules)
	m, err := manifest.Load([]byte(strings.Replace(doc, anchor, role+anchor, 1)))
	if err != nil {
		t.Fatalf("фикстура с дописанной ролью %q отвергнута загрузчиком: %v", roleID, err)
	}
	return m
}

// roleFindings — находки о названной роли, отобранные по её идентификатору.
//
// Имя отличается от соседнего `findingsOf` (classfit_test.go) намеренно: там
// отбор идёт по ВИДУ находки, здесь — по роли, и одно имя на два предиката
// разошлось бы с собой при первой же правке любого из них.
func roleFindings(faults []error, roleID string) []roleexport.Finding {
	var out []roleexport.Finding
	for _, e := range faults {
		var f roleexport.Finding
		if errors.As(e, &f) && f.Role == roleID {
			out = append(out, f)
		}
	}
	return out
}

// ── MOD-RL-18 ───────────────────────────────────────────────────────────────

// TestMODRL18IncompleteNamedListIsRefused — отрицательный.
//
// Given роль с правом `{module: vpc, resources: [subnet], verbs: [addCidrBlocks]}`
// And класс `update` на `subnet` покрывает сверх него ещё `update` и
// `removeCidrBlocks` — и все три пригодны: гейт каждого спрашивает `v_update`
// When экспортёр производит политику
// Then экспорт отвергается: перечень не полон по классу `update` на `vpc.subnet`
// And отказ перечисляет НЕДОСТАЮЩИЕ имена поимённо
// And отказ называет обе годные починки
// And ни одного правила не производится.
func TestMODRL18IncompleteNamedListIsRefused(t *testing.T) {
	m := withRole(t, "vpc.named_incomplete",
		"      - {module: vpc, resources: [subnet], verbs: [addCidrBlocks]}\n")

	rules, faults, census := roleexport.ExportRoleRules(catalogfixture.Facts(), m, mustActions(t))
	t.Logf("перепись: %s", census.Summary())

	found := roleFindings(faults, "vpc.named_incomplete")
	if len(found) != 1 {
		t.Fatalf("находок о роли %d, ожидалась одна (перечень не полон по одному классу): %v",
			len(found), faults)
	}
	if !errors.Is(found[0].Kind, roleexport.ErrNamedVerbsIncompleteForClass) {
		t.Errorf("находка не отнесена к своей причине: %v", found[0].Kind)
	}
	detail := found[0].Detail
	// Недостающие имена — ПОИМЁННО: «перечень неполон» без имён не чинится.
	for _, want := range []string{"update", "removeCidrBlocks"} {
		if !strings.Contains(detail, want) {
			t.Errorf("отказ не называет недостающее действие %q: %s", want, detail)
		}
	}
	// Обе починки: дописать недостающие ЛИБО написать `classes:`.
	for _, want := range []string{"classes", "vpc.subnet", "update"} {
		if !strings.Contains(detail, want) {
			t.Errorf("отказ не называет %q: %s", want, detail)
		}
	}
	// «Ни одного правила не производится» — утверждается ИСХОДОМ, а не намерением:
	// частичный экспорт дал бы роль ýже объявленной, и заметили бы это вызовом.
	if _, ok := rules["vpc.named_incomplete"]; ok {
		t.Errorf("роль с неполным перечнем всё же произведена: частичный экспорт даёт " +
			"право ýже объявленного, и отличить его от работающего можно только вызовом")
	}
}

// TestMODRL18aCompleteNamedListExportsAsItsClass — ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ.
//
// Тот же перечень, дополненный `update` и `removeCidrBlocks`: экспорт проходит и
// даёт `verbs: ["update"]`. Без него отказ MOD-RL-18 зеленел бы на реализации,
// отвергающей ВСЯКИЙ поимённый перечень.
func TestMODRL18aCompleteNamedListExportsAsItsClass(t *testing.T) {
	m := withRole(t, "vpc.named_complete",
		"      - {module: vpc, resources: [subnet], verbs: [addCidrBlocks, update, removeCidrBlocks]}\n")

	rules, faults, census := roleexport.ExportRoleRules(catalogfixture.Facts(), m, mustActions(t))
	t.Logf("перепись: %s", census.Summary())

	if found := roleFindings(faults, "vpc.named_complete"); len(found) != 0 {
		t.Fatalf("полный перечень отвергнут: %v", found)
	}
	got, ok := rules["vpc.named_complete"]
	if !ok {
		t.Fatal("роль с полным перечнем не произведена вовсе")
	}
	if len(got) != 1 {
		t.Fatalf("правил произведено %d, документ несёт одно", len(got))
	}
	if len(got[0].Verbs) != 1 || got[0].Verbs[0] != "update" {
		t.Errorf("полный перечень сведён к %#v, а его класс — [update]", got[0].Verbs)
	}
}

// TestMODRL18ClassFormAndCompleteNamedFormGiveOneRule — §3.6 п. 5: обе формы
// дают РОВНО ОДИН И ТОТ ЖЕ `Rule`, и это утверждается СРАВНЕНИЕМ.
//
// Без сравнения «эквивалентны» осталось бы обещанием: две формы, чьи произведения
// расходятся, дают арендатору разные права при одинаковом на вид объявлении.
func TestMODRL18ClassFormAndCompleteNamedFormGiveOneRule(t *testing.T) {
	named := withRole(t, "vpc.two_forms",
		"      - {module: vpc, resources: [subnet], verbs: [addCidrBlocks, update, removeCidrBlocks]}\n")
	classed := withRole(t, "vpc.two_forms",
		"      - {module: vpc, resources: [subnet], classes: [update]}\n")

	facts, actions := catalogfixture.Facts(), mustActions(t)
	fromNamed, nf, _ := roleexport.ExportRoleRules(facts, named, actions)
	fromClass, cf, _ := roleexport.ExportRoleRules(facts, classed, actions)
	if len(roleFindings(nf, "vpc.two_forms")) != 0 || len(roleFindings(cf, "vpc.two_forms")) != 0 {
		t.Fatalf("одна из форм отвергнута: поимённая %v · классовая %v", nf, cf)
	}
	a, b := fromNamed["vpc.two_forms"], fromClass["vpc.two_forms"]
	if fmt.Sprintf("%#v", a) != fmt.Sprintf("%#v", b) {
		t.Errorf("формы дали РАЗНОЕ право:\n  поимённая %#v\n  классовая %#v", a, b)
	}
}

// ── MOD-RL-19 ───────────────────────────────────────────────────────────────

// namedRoleManifest — САМОДОСТАТОЧНЫЙ манифест: раздел `resources` с ровно теми
// действиями, которых требует ось, плюс одна роль с поимённым правом.
//
// # Почему не фикстура соседнего пакета, как у MOD-RL-05
//
// Оси Б и второй положительный MOD-RL-19a называют ВНУТРЕННИЕ действия
// (`internalGetNetwork`, `internalAttach`, `internalDetach`).
//
// ЗДЕСЬ СТОЯЛО «раздел `resources` НЕ ОБЪЯВЛЯЕТ их ни один манифест дерева», и
// это было верно в день записи: приёмка считала обе оси по ЧЕРНОВИКУ воркспейса,
// который внутренние действия объявляет, а поставляемый манифест — нет. Оговорка
// пережила свой предмет (#1997). Предикат, который её опровергает, тот же самый:
// `grep -c internalGetNetwork services/vpc/manifest.yaml` → 1 (было 0), и все три
// названных действия объявлены поставляемым `services/vpc/manifest.yaml`.
// РАСХОЖДЕНИЯ С ПРИЁМКОЙ БОЛЬШЕ НЕТ.
//
// Что вход этих осей есть в ДЕРЕВЕ, а не только здесь, утверждается отдельно и
// по дереву — `plane_agreement_has_a_subject_test.go`, раздел о трёх названных
// действиях. Без такого утверждения «оси не выдуманы» осталось бы словами.
//
// Манифест пробы при этом остаётся САМОДОСТАТОЧНЫМ, и теперь по другой причине,
// чем прежде. Прежняя — «в дереве входа нет» — снята. Действующая: ось называет
// РОЛЬ с поимённым правом, а поставляемый манифест vpc ролей такой формы не
// несёт, и вводить их туда ради пробы значило бы править поставку под
// инструмент. Проба объявляет РОВНО то, что ось называет; это не копия раздела,
// а его минимальный вход.
func namedRoleManifest(resources, rules string) string {
	return "apiVersion: iam/v1\nmodule: vpc\nresources:\n" + resources +
		"roles:\n  - id: vpc.named_probe\n" +
		"    description: Роль под пробой поимённой формы права.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n" + rules
}

// TestMODRL19NamedUnsuitableActionIsRefused — отрицательный, ТРИ оси.
//
// Given роль, чьё право НАЗЫВАЕТ ПОИМЁННО действие, чей гейт спрашивает пару
// «отношение + объект» вне `{v_*} ∪ {viewer, editor, admin}` на объекте типа
// ЭТОГО ресурса
// When валидатор целостности читает манифест
// Then отказ называет роль, действие и ПАРУ, которую требует гейт
// And отказ говорит, что приведением к `classes:` это право НЕ чинится.
//
// Оси взяты у ДЕРЕВА, а не выдуманы: их производитель — `required_relation` и
// `scope_extractor.object_type` записи каталога прав. Then утверждает про
// МНОЖЕСТВО производимого, а не про имя: перечень отношений вне множества
// открыт, и утверждение по имени устарело бы молча.
func TestMODRL19NamedUnsuitableActionIsRefused(t *testing.T) {
	axes := []struct {
		name      string
		resources string
		rules     string
		wantPair  string
	}{
		{
			name: "А — system_admin на cluster",
			resources: "  - name: addressPool\n    objectType: vpc_address_pool\n" +
				"    parents: [cluster]\n    producer: derived\n    verbs:\n      - get\n",
			rules:    "      - {module: vpc, resources: [addressPool], verbs: [get]}\n",
			wantPair: "system_admin@cluster",
		},
		{
			name: "Б — system_viewer на cluster",
			resources: "  - name: network\n    objectType: vpc_network\n" +
				"    parents: [project]\n    producer: derived\n    verbs:\n" +
				"      - {name: internalGetNetwork, class: get, internal: true}\n",
			rules:    "      - {module: vpc, resources: [network], verbs: [internalGetNetwork]}\n",
			wantPair: "system_viewer@cluster",
		},
		{
			name: "В — ярус ОБЛАСТИ на project",
			resources: "  - name: network\n    objectType: vpc_network\n" +
				"    parents: [project]\n    producer: derived\n    verbs:\n      - create\n",
			rules:    "      - {module: vpc, resources: [network], verbs: [create]}\n",
			wantPair: "editor@project",
		},
	}
	for _, ax := range axes {
		t.Run(ax.name, func(t *testing.T) {
			m := mustLoad(t, namedRoleManifest(ax.resources, ax.rules))
			faults, census := roleexport.CheckNamedVerbs(catalogfixture.Facts(), m, mustActions(t))
			t.Logf("перепись: %s", census.Summary())

			found := roleFindings(faults, "vpc.named_probe")
			if len(found) != 1 {
				t.Fatalf("находок %d, ожидалась одна: %v", len(found), faults)
			}
			if !errors.Is(found[0].Kind, roleexport.ErrNamedVerbNotProducibleByRoleRule) {
				t.Errorf("находка не отнесена к своей причине: %v", found[0].Kind)
			}
			detail := found[0].Detail
			if !strings.Contains(detail, ax.wantPair) {
				t.Errorf("отказ не называет ПАРУ %q: %s", ax.wantPair, detail)
			}
			if !strings.Contains(detail, "classes") {
				t.Errorf("отказ не говорит, что приведением к `classes:` это не чинится: %s", detail)
			}
		})
	}
}

// TestMODRL19aNamedSuitableActionsAreSilent — ПАРНЫЕ ПОЛОЖИТЕЛЬНЫЕ, их ДВА.
//
// Второй несёт ТО ЖЕ имя отношения, что ось В (`editor`), но на объекте типа
// ресурса. Без него проверка зеленела бы на реализации, отвергающей ярус ПО
// ИМЕНИ, — и мы вернули бы ту же ошибку с другой стороны: имя «наше», и по имени
// оно проходило бы.
func TestMODRL19aNamedSuitableActionsAreSilent(t *testing.T) {
	positives := []struct {
		name      string
		resources string
		rules     string
	}{
		{
			name: "глагольные отношения на объекте своего типа",
			resources: "  - name: subnet\n    objectType: vpc_subnet\n" +
				"    parents: [project]\n    producer: derived\n    verbs:\n" +
				"      - get\n      - update\n      - delete\n" +
				"      - {name: addCidrBlocks,     class: update}\n" +
				"      - {name: removeCidrBlocks,  class: update}\n" +
				"      - {name: listOperations,    class: list}\n" +
				"      - {name: listUsedAddresses, class: list}\n",
			rules: "      - {module: vpc, resources: [subnet], verbs: [get, update, delete, " +
				"addCidrBlocks, removeCidrBlocks, listOperations, listUsedAddresses]}\n",
		},
		{
			name: "ЯРУС с тем же именем, но на объекте типа ресурса",
			resources: "  - name: networkInterface\n    objectType: vpc_network_interface\n" +
				"    parents: [project]\n    producer: derived\n    verbs:\n" +
				"      - {name: internalAttach, class: update, internal: true}\n" +
				"      - {name: internalDetach, class: update, internal: true}\n",
			rules: "      - {module: vpc, resources: [networkInterface], " +
				"verbs: [internalAttach, internalDetach]}\n",
		},
	}
	for _, p := range positives {
		t.Run(p.name, func(t *testing.T) {
			m := mustLoad(t, namedRoleManifest(p.resources, p.rules))
			faults, census := roleexport.CheckNamedVerbs(catalogfixture.Facts(), m, mustActions(t))
			t.Logf("перепись: %s", census.Summary())
			if found := roleFindings(faults, "vpc.named_probe"); len(found) != 0 {
				t.Fatalf("пригодное названное действие отвергнуто: %v", found)
			}
			if census.Verbs == 0 {
				t.Error("названных вхождений осмотрено ноль: молчание проверки неотличимо " +
					"от того, что она не дошла до предмета")
			}
		})
	}
}

// TestNamedVerbCensusCountsWhatItRead — перепись обеих проверок печатает ОБЪЁМ
// ОСМОТРЕННОГО: «ноль находок» обязано быть отличимо от «ноль прочитанного».
//
// Проба предпосылки для обоих сценариев выше: на манифесте БЕЗ поимённых прав
// обе проверки молчат законно, и молчание это неотличимо от молчания сломанной
// проверки, если объём не назван.
func TestNamedVerbCensusCountsWhatItRead(t *testing.T) {
	m := mustFixture(t)
	_, census := roleexport.CheckNamedVerbs(catalogfixture.Facts(), m, mustActions(t))
	if census.Named != 0 {
		t.Errorf("фикстура несёт поимённые права (%d): её роли записаны классами", census.Named)
	}
	if census.Rules == 0 {
		t.Error("правил осмотрено ноль: молчание проверки неотличимо от её отсутствия")
	}

	withNamed := withRole(t, "vpc.named_suitable",
		"      - {module: vpc, resources: [subnet], verbs: [get]}\n")
	_, c2 := roleexport.CheckNamedVerbs(catalogfixture.Facts(), withNamed, mustActions(t))
	if c2.Named != 1 {
		t.Errorf("поимённых прав осмотрено %d, дописано одно: перепись не растёт вместе "+
			"с предметом, и её ноль ничего не доказывает", c2.Named)
	}
}
