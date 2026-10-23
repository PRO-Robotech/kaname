// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// nested_rule_test.go — судья формы вложенного правила роли (kaname#874, приёмка
// docs/engineering/acceptance/nested-rule-reaches-descendants-of-a-named-container.md,
// редакция 2, Р1, ND-04 (а)–(е)).
//
// Вход — НАСТОЯЩАЯ фикстура П1 (`registry.public-read-fixture.yaml`), в которой
// правится одно место роли `registry.reader` (roles[1], rules[0]). Законный
// близнец — та же фикстура без правки: загрузка успешна, роль несёт вложенное
// правило (ND-02). Разница каждой пары — один факт, её считает фикстура
// (`publicreadfixture.Delta`), а не автор.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// ndReaderBlock — блок роли `registry.reader` фикстуры П1 дословно.
const ndReaderBlock = `  - id: registry.reader
    description: >
      Пробная роль: чтение реестра и каждого его репозитория, включая
      созданные позже.
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: registry
        resources: [registries]
        classes: [get, list]
        children:
          - resources: [repositories]
            classes: [get, list]
`

// ndMutateReader — фикстура П1 с одной правкой внутри блока `registry.reader`.
func ndMutateReader(t *testing.T, old, new string) []byte {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	if err != nil {
		t.Fatalf("фикстура П1: %v", err)
	}
	if strings.Count(string(doc), ndReaderBlock) != 1 {
		t.Fatalf("блок registry.reader в фикстуре П1 не найден ровно один раз — проба судила бы не тот документ")
	}
	if strings.Count(ndReaderBlock, old) != 1 {
		t.Fatalf("правка %q стоит в блоке registry.reader не ровно один раз", old)
	}
	block := strings.Replace(ndReaderBlock, old, new, 1)
	twin := []byte(strings.Replace(string(doc), ndReaderBlock, block, 1))
	removed, added := publicreadfixture.Delta(doc, twin)
	if len(removed) == 0 && len(added) == 0 {
		t.Fatalf("правка %q → %q ничего не изменила", old, new)
	}
	return twin
}

func ndRequireFinding(t *testing.T, doc []byte, finding string) {
	t.Helper()
	_, err := manifest.Load(doc)
	if err == nil {
		t.Fatalf("загрузка приняла документ; ждали находку %q", finding)
	}
	if !strings.Contains(err.Error(), finding) {
		t.Fatalf("находка судьи формы\n ждали  %q\n получено %v", finding, err)
	}
}

// Близнец ND-04: немодифицированная фикстура грузится, и роль registry.reader
// несёт вложенное правило — то самое, что применяет ND-02.
func TestManifest_ND04_UnmodifiedFixtureLoadsWithTheNestedRule(t *testing.T) {
	doc, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	if err != nil {
		t.Fatalf("фикстура П1: %v", err)
	}
	m, err := manifest.Load(doc)
	if err != nil {
		t.Fatalf("фикстура П1 отвергнута загрузчиком: %v", err)
	}
	var found bool
	for _, r := range m.Roles {
		if r.ID != "registry.reader" {
			continue
		}
		found = true
		got := r.Rules[0].DomainRule()
		if len(got.Children) != 1 || len(got.Children[0].Resources) != 1 ||
			got.Children[0].Resources[0] != "repositories" || got.Children[0].Module != "" {
			t.Errorf("правило registry.reader в форме домена без вложенного над repositories: %+v", got)
		}
	}
	if !found {
		t.Fatalf("роли registry.reader в фикстуре нет")
	}
}

func TestManifest_ND04_a_NestedTypeMustLieUnderTheOwner(t *testing.T) {
	doc := ndMutateReader(t,
		"        resources: [registries]\n        classes: [get, list]\n        children:\n          - resources: [repositories]",
		"        resources: [repositories]\n        classes: [get, list]\n        children:\n          - resources: [registries]")
	ndRequireFinding(t, doc, `roles[1].rules[0].children[0].resources: тип "registry.registries" не лежит под "registry.repositories" ни по одному объявленному указателю parents; вложенное правило действует только на потомков типа правила-владельца`)
}

func TestManifest_ND04_b_OwnerNamesExactlyOneResource(t *testing.T) {
	doc := ndMutateReader(t, "        resources: [registries]\n", "        resources: [registries, repositories]\n")
	ndRequireFinding(t, doc, `roles[1].rules[0].resources: правило с children называет ровно один ресурс, получено 2`)
}

func TestManifest_ND04_c_OwnerNamesAResourceNotAWildcard(t *testing.T) {
	doc := ndMutateReader(t, "        resources: [registries]\n", "        resources: [\"*\"]\n")
	ndRequireFinding(t, doc, `roles[1].rules[0].resources: правило с children называет ресурс, а не «*»`)
}

func TestManifest_ND04_d_NestedRuleHasNoChildrenOfItsOwn(t *testing.T) {
	doc := ndMutateReader(t,
		"          - resources: [repositories]\n            classes: [get, list]\n",
		"          - resources: [repositories]\n            classes: [get, list]\n            children:\n              - resources: [repositories]\n                classes: [get]\n")
	ndRequireFinding(t, doc, `roles[1].rules[0].children[0].children: у вложенного правила своих children нет; более глубокий тип называется прямо под правилом-владельцем`)
}

func TestManifest_ND04_e_NestedRuleTakesTheOwnersModule(t *testing.T) {
	doc := ndMutateReader(t,
		"          - resources: [repositories]\n",
		"          - module: registry\n            resources: [repositories]\n")
	ndRequireFinding(t, doc, `roles[1].rules[0].children[0].module: вложенное правило берёт модуль правила-владельца`)
}

func TestManifest_ND04_f_EmptyChildrenIsRefused(t *testing.T) {
	doc := ndMutateReader(t,
		"        children:\n          - resources: [repositories]\n            classes: [get, list]\n",
		"        children: []\n")
	ndRequireFinding(t, doc, `roles[1].rules[0].children: пустой перечень; правило без вложенных пишется без ключа`)
}

// Р1 п. 2: под ярусом иерархии выбирает область выдачи. Ярусы объявлены
// манифестом службы — на нём и строится находка: правило над `project` с
// `children`.
func TestManifest_ND04_TierCannotOwnNestedRules(t *testing.T) {
	raw := string(servicemanifest.Raw())
	const anchor = "  - id: iam.project.edit\n"
	at := strings.Index(raw, anchor)
	if at < 0 {
		t.Fatalf("роли iam.project.edit в манифесте службы нет — проба судила бы не тот документ")
	}
	const rule = "      - module: iam\n        resources: [project]\n        classes: [get, list, update]\n"
	if !strings.HasPrefix(raw[at+len(anchor):], "    description: \"Edit Project\"\n    tier:\n      tierType: iam.cluster\n      tierId: cluster_root\n    rules:\n"+rule) {
		t.Fatalf("блок iam.project.edit манифеста службы изменился — правка пробы привязана к нему")
	}
	rolesAt := strings.Index(raw, "\nroles:\n")
	if rolesAt < 0 || rolesAt > at {
		t.Fatalf("раздел roles манифеста службы не найден перед iam.project.edit")
	}
	index := strings.Count(raw[rolesAt:at], "\n  - id: ")
	twin := strings.Replace(raw, anchor+"    description: \"Edit Project\"\n    tier:\n      tierType: iam.cluster\n      tierId: cluster_root\n    rules:\n"+rule,
		anchor+"    description: \"Edit Project\"\n    tier:\n      tierType: iam.cluster\n      tierId: cluster_root\n    rules:\n"+rule+
			"        children:\n          - resources: [accessBinding]\n            classes: [get]\n", 1)
	if _, err := servicemanifest.Load(); err != nil {
		t.Fatalf("близнец: манифест службы без правки не грузится: %v", err)
	}
	finding := `roles[` + itoa(index) + `].rules[0].resources: "project" — ярус иерархии; под ярусом выбирает область выдачи, children у него нет`
	_, err := manifest.Load([]byte(twin))
	if err == nil || !strings.Contains(err.Error(), finding) {
		t.Fatalf("находка яруса\n ждали  %q\n получено %v", finding, err)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// В5: схема объявляет ключ `children` и называет глубину прямо — «любая по
// цепи предков», потому что `publicReadToChildren` того же манифеста значит один
// шаг.
func TestManifest_ND04_SchemaDeclaresChildrenWithItsDepth(t *testing.T) {
	raw, err := os.ReadFile("../../schema/module-manifest.schema.json")
	if err != nil {
		t.Fatalf("схема: %v", err)
	}
	var s struct {
		Properties map[string]struct {
			Items struct {
				Properties map[string]struct {
					Items struct {
						Properties map[string]struct {
							Description string `json:"description"`
						} `json:"properties"`
					} `json:"items"`
				} `json:"properties"`
			} `json:"items"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("разбор схемы: %v", err)
	}
	rule := s.Properties["roles"].Items.Properties["rules"].Items.Properties
	if _, ok := rule["resources"]; !ok {
		t.Fatalf("путь roles.items.rules.items схемы не найден — проба судила бы пустоту")
	}
	ch, ok := rule["children"]
	if !ok {
		t.Fatalf("схема не объявляет ключ children у правила роли: манифест с вложенным правилом отвергался бы как неизвестный ключ")
	}
	if !strings.Contains(ch.Description, "любая по цепи предков") {
		t.Errorf("описание ключа children не называет глубину «любая по цепи предков»: %q", ch.Description)
	}
}

// П3: фикстура трёх уровней грузится — на ней утверждается глубина (ND-08).
func TestManifest_ND08_ThreeLevelFixtureLoads(t *testing.T) {
	doc, err := publicreadfixture.Read(publicreadfixture.ChildrenProbemodFile)
	if err != nil {
		t.Fatalf("фикстура П3: %v", err)
	}
	if _, err := manifest.Load(doc); err != nil {
		t.Fatalf("фикстура П3 отвергнута загрузчиком: %v", err)
	}
}
