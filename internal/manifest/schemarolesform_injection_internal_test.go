// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// schemarolesform_injection_internal_test.go — доказательство способности Г10
// упасть И смолчать (приёмка §7).
//
// Инъекция — НАСТОЯЩИЙ вход дерева: образец, возвращённый к тому значению,
// которое схема несла до этой работы. Не синтетика: именно это значение
// отвергало сорок пять живых имён из сорока восьми и не исполнялось никем.
package manifest

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// schemaRoleFormBefore — образец, стоявший в схеме ДО этой работы. Ровно два
// сегмента, второй допускает заглавные.
const schemaRoleFormBefore = `^[a-z][a-z0-9-]*\.[a-zA-Z][a-zA-Z0-9]*$`

// schemaTierEnumBefore — перечень ярусов, стоявший в схеме ДО этой работы.
var schemaTierEnumBefore = []string{"iam.account", "iam.project"}

// judgeSchemaValues — тот же предикат, которым судит Г10: равенство значения
// схемы единственному объявлению. Вынесен функцией, чтобы инъекция проверяла ТО
// ЖЕ, а не свою копию правила.
func judgeSchemaValues(pattern string, enum []string) (findings []string) {
	if pattern != RoleIDForm {
		findings = append(findings, "id.pattern: "+pattern+" ≠ "+RoleIDForm)
	}
	if strings.Join(enum, ",") != strings.Join(RoleTierTypes, ",") {
		findings = append(findings, "tierType.enum: "+strings.Join(enum, ",")+
			" ≠ "+strings.Join(RoleTierTypes, ","))
	}
	return findings
}

// TestSchemaFormGateRedsOnYesterdaysValues — инъекция настоящим входом.
func TestSchemaFormGateRedsOnYesterdaysValues(t *testing.T) {
	findings := judgeSchemaValues(schemaRoleFormBefore, schemaTierEnumBefore)
	if len(findings) != 2 {
		t.Fatalf("гейт не краснеет на значениях, которые схема несла вчера: находок %d\n"+
			"Гейт, молчащий на дефекте, из которого он выведен, не удерживает ничего", len(findings))
	}
	for _, want := range []string{"id.pattern", "tierType.enum"} {
		var seen bool
		for _, f := range findings {
			if strings.Contains(f, want) {
				seen = true
			}
		}
		if !seen {
			t.Errorf("находка не называет ключ схемы %q: %v", want, findings)
		}
	}

	// Вчерашний образец и правда отвергал флагманский вход — иначе инъекция
	// была бы про другое.
	if regexp.MustCompile(schemaRoleFormBefore).MatchString("vpc.network.admin") {
		t.Fatalf("инъекция беспредметна: вчерашний образец принимает vpc.network.admin, " +
			"значит покрасневший гейт краснел бы не на том, ради чего заведён")
	}
}

// TestSchemaFormGateStaysSilentOnTheAlignedSchema — законный близнец: схема,
// приведённая к объявлению.
func TestSchemaFormGateStaysSilentOnTheAlignedSchema(t *testing.T) {
	if f := judgeSchemaValues(RoleIDForm, RoleTierTypes); len(f) != 0 {
		t.Fatalf("приведённая схема объявлена находкой: %v", f)
	}
}

// TestSchemaFormGateJudgesTheKeyNotTheFileText — второй законный близнец:
// прежний образец, ЦИТИРУЕМЫЙ в описании ключа. Гейт судит ЗНАЧЕНИЕ ключа, а не
// текст файла, — иначе он краснел бы на собственном объяснении.
func TestSchemaFormGateJudgesTheKeyNotTheFileText(t *testing.T) {
	raw, err := os.ReadFile(publishedSchemaPath)
	if err != nil {
		t.Fatalf("опубликованная схема не читается: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("опубликованная схема не разбирается: %v", err)
	}
	id := doc["properties"].(map[string]any)["roles"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["id"].(map[string]any)
	// Описание цитирует прежний образец — ровно так, как это делает живой текст
	// схемы, объясняющий, что было раньше.
	id["description"] = "прежде здесь стояло " + schemaRoleFormBefore + ", и оно выражало три имени из сорока восьми"
	patched, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("сборка близнеца: %v", err)
	}
	if !strings.Contains(string(patched), "a-zA-Z") {
		t.Fatalf("близнец беспредметен: прежний образец в текст не попал")
	}
	var back map[string]any
	if err := json.Unmarshal(patched, &back); err != nil {
		t.Fatalf("близнец не разбирается: %v", err)
	}
	got := back["properties"].(map[string]any)["roles"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["id"].(map[string]any)["pattern"].(string)
	if f := judgeSchemaValues(got, RoleTierTypes); len(f) != 0 {
		t.Fatalf("гейт судит текст файла, а не значение ключа: цитата прежнего образца в "+
			"ОПИСАНИИ стала находкой — тогда он краснел бы на собственном объяснении: %v", f)
	}
}
