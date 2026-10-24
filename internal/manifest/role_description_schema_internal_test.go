// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_description_schema_internal_test.go — опубликованная схема манифеста
// объявляет предел назначения роли тем же числом и в тех же единицах, что домен
// (kaname#884, приёмка `role-description-ceiling-is-declared-by-the-schema.md`).
//
// # Почему предел читается из схемы, а не выписывается
//
// Загрузчик судит назначение доменным типом (kaname#867), и это держит
// `TestRoleDescriptionCeilingIsJudgedByTheLoaderInCharacters`. Здесь судится
// другое: что ГРАНИЦА, которую видит автор манифеста в своём редакторе, — та же.
// Поэтому граница в пробах ниже берётся из опубликованной схемы (RD-02…RD-04),
// а равенство её доменному пределу утверждается отдельно (RD-01): без этого
// схема, вовсе не объявившая предел, дала бы пробам «судить нечего» вместо
// красного.
//
// Тексты отказа сверяются ВХОЖДЕНИЕМ: полный текст ошибки начинается с
// обёртки загрузчика (`manifest: role description is longer than the domain
// bound: roles[0] (line 4): `), и равенство покраснело бы на верном загрузчике.
package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// roleDescriptionPath — путь поля в соглашении переписи требовательности.
const roleDescriptionPath = "roles[].description"

// cloneSchema — независимая копия разобранной схемы: инъекция правит копию,
// а опубликованный файл и его разбор остаются нетронутыми.
func cloneSchema(t *testing.T, schema map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("схема не сериализуется: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("копия схемы не разбирается: %v", err)
	}
	return out
}

// roleDescriptionNode — подсхема `roles[].description`; nil — пути в схеме нет.
func roleDescriptionNode(schema map[string]any) map[string]any {
	node := any(schema)
	for _, key := range []string{"properties", "roles", "items", "properties", "description"} {
		m, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		node = m[key]
	}
	m, _ := node.(map[string]any)
	return m
}

// schemaInt — целое ключевое слово подсхемы; ok=false, если его нет.
func schemaInt(node map[string]any, keyword string) (int, bool) {
	v, ok := node[keyword].(float64)
	if !ok {
		return 0, false
	}
	return int(v), true
}

// roleDescriptionSchemaFindings — расхождения объявления `roles[].description`
// в схеме с доменом (RD-01). Пустой результат — объявление согласно.
func roleDescriptionSchemaFindings(schema map[string]any) []string {
	node := roleDescriptionNode(schema)
	if node == nil {
		return []string{roleDescriptionPath + ": подсхемы в схеме нет — судить нечего, и это не согласие"}
	}
	var out []string
	switch maxLen, ok := schemaInt(node, "maxLength"); {
	case !ok:
		out = append(out, fmt.Sprintf("%s: maxLength не объявлен, а домен допускает не более %d знаков — "+
			"редактор автора молчит там, где загрузчик откажет", roleDescriptionPath, domain.DescriptionMax))
	case maxLen != domain.DescriptionMax:
		out = append(out, fmt.Sprintf("%s: maxLength схемы %d, а домена %d — автор и продукт видят разные границы",
			roleDescriptionPath, maxLen, domain.DescriptionMax))
	}
	if minLen, ok := schemaInt(node, "minLength"); !ok || minLen != 1 {
		out = append(out, fmt.Sprintf("%s: minLength %d (объявлен: %t), ожидается 1", roleDescriptionPath, minLen, ok))
	}
	text, _ := node["description"].(string)
	if !strings.Contains(text, itoaLocal(domain.DescriptionMax)) {
		out = append(out, fmt.Sprintf("%s: описание поля не называет верхний предел %d",
			roleDescriptionPath, domain.DescriptionMax))
	}
	if !strings.Contains(text, "кодов") {
		out = append(out, roleDescriptionPath+": описание поля не называет единицу счёта (кодовая точка Unicode)")
	}
	// Описание не утверждает, что верхнего предела нет: прежняя фраза «держит
	// побайтовая сверка с живой строкой, а не предел длины» с maxLength рядом
	// стала бы ложью о том же поле.
	if strings.Contains(text, "не предел длины") {
		out = append(out, roleDescriptionPath+": описание поля утверждает, что предела длины нет («…а не предел длины»)")
	}
	return out
}

// TestSchemaDeclaresTheDomainCeilingOfRoleDescription — RD-01.
func TestSchemaDeclaresTheDomainCeilingOfRoleDescription(t *testing.T) {
	if f := roleDescriptionSchemaFindings(readPublishedSchema(t)); len(f) > 0 {
		t.Fatalf("схема расходится с доменом у %s (%d):\n  %s", roleDescriptionPath, len(f), strings.Join(f, "\n  "))
	}
}

// TestRoleDescriptionSchemaInjection_CeilingBelowTheDomainIsFound — близнец RD-01:
// копия схемы отличается ОДНИМ числом (255 вместо предела домена), и находка
// называет путь и оба числа. Тем же путём копия проходит перепись
// требовательности: 256 знаков схема запрещает, загрузчик принимает.
func TestRoleDescriptionSchemaInjection_CeilingBelowTheDomainIsFound(t *testing.T) {
	published := readPublishedSchema(t)
	if f := roleDescriptionSchemaFindings(published); len(f) > 0 {
		t.Fatalf("контроль: опубликованная схема сама несёт находки — инъекция ничего не докажет:\n  %s",
			strings.Join(f, "\n  "))
	}
	low := cloneSchema(t, published)
	roleDescriptionNode(low)["maxLength"] = float64(domain.DescriptionMax - 1)

	findings := strings.Join(roleDescriptionSchemaFindings(low), "\n")
	for _, want := range []string{roleDescriptionPath, "255", "256"} {
		if !strings.Contains(findings, want) {
			t.Errorf("находка RD-01 не называет %q: %q", want, findings)
		}
	}

	c := judgeRequiredness(t, low)
	got := strings.Join(c.divergences, "\n")
	if !strings.Contains(got, roleDescriptionPath+" (maxLength 255): схема требует, загрузчик ПРИНИМАЕТ") {
		t.Errorf("перепись не назвала предел ниже домена расхождением; расхождения:\n%s", got)
	}
}

// TestRequirednessJudgesDeclaredCeiling_RaisedCeilingIsFound — RD-05: предел,
// объявленный схемой, судится, а не пропускается как аннотация.
func TestRequirednessJudgesDeclaredCeiling_RaisedCeilingIsFound(t *testing.T) {
	high := cloneSchema(t, readPublishedSchema(t))
	node := roleDescriptionNode(high)
	if node == nil {
		t.Fatalf("предпосылка: в схеме нет %s", roleDescriptionPath)
	}
	node["maxLength"] = float64(300)

	c := judgeRequiredness(t, high)
	got := strings.Join(c.divergences, "\n")
	if !strings.Contains(got, roleDescriptionPath+" (maxLength 300): схема допускает 300 знаков, загрузчик ОТВЕРГАЕТ") {
		t.Errorf("поднятый до 300 предел не назван расхождением; расхождений %d:\n%s", len(c.divergences), got)
	}
}

// TestRequirednessJudgesDeclaredCeiling_PublishedSchemaAgrees — законный
// близнец RD-05: нетронутая схема согласна, и судимых верхних пределов не
// меньше одного — обход, не осмотревший ни одного, зелёным не считается.
func TestRequirednessJudgesDeclaredCeiling_PublishedSchemaAgrees(t *testing.T) {
	c := judgeRequiredness(t, readPublishedSchema(t))
	if len(c.unknown) > 0 {
		t.Fatalf("распознаватель не знает %d форм:\n  %s", len(c.unknown), strings.Join(c.unknown, "\n  "))
	}
	t.Logf("судимых верхних пределов %d · расхождений %d", c.ceilings, len(c.divergences))
	if c.ceilings == 0 {
		t.Fatal("ни одного судимого maxLength: верхние пределы схемы не сверены с загрузчиком — " +
			"это «не выполнилось», а не согласие")
	}
	if len(c.divergences) > 0 {
		t.Fatalf("опубликованная схема расходится с загрузчиком:\n  %s", strings.Join(c.divergences, "\n  "))
	}
}

// roleManifest — П1: модуль iam, одна роль; назначение — строкой YAML как есть
// (вместе с кавычками или индикатором блока).
func roleManifest(descriptionYAML string) []byte {
	return []byte("apiVersion: iam/v1\nmodule: iam\nroles:\n" +
		"  - id: iam.role.edit\n    description: " + descriptionYAML + "\n" +
		"    tier: {tierType: iam.cluster, tierId: cluster_root}\n" +
		"    rules:\n      - {module: iam, resources: [role], classes: [get, list, update]}\n")
}

// TestRoleDescriptionBoundFromSchemaHoldsOnBothSides — RD-02, RD-03 (а, б),
// RD-04. Граница — из опубликованной схемы; исход — `Load`.
func TestRoleDescriptionBoundFromSchemaHoldsOnBothSides(t *testing.T) {
	node := roleDescriptionNode(readPublishedSchema(t))
	if node == nil {
		t.Fatalf("в схеме нет %s", roleDescriptionPath)
	}
	bound, ok := schemaInt(node, "maxLength")
	if !ok {
		t.Fatalf("%s: схема не объявляет maxLength — границу, которую видит автор, взять неоткуда",
			roleDescriptionPath)
	}
	refusal := fmt.Sprintf("roles[0].description: %d знаков, допускается не более %d — "+
		"применитель ролей отверг бы такое назначение на старте службы: "+
		"Illegal argument description: length must be <=%d", bound+1, bound, bound)

	const smile = "\U0001F600" // 4 байта UTF-8, 2 единицы UTF-16, ОДИН знак
	block := func(indicator string, n int) string {
		return indicator + "\n      " + strings.Repeat("a", n)
	}
	cases := []struct {
		name, yaml string
		refused    bool
	}{
		{"RD-02 в пределе, латиница", `"` + strings.Repeat("a", bound) + `"`, false},
		{"RD-02 на знак выше", `"` + strings.Repeat("a", bound+1) + `"`, true},
		{"RD-03а в пределе, знак вне BMP", `"` + strings.Repeat(smile, bound) + `"`, false},
		{"RD-03б на знак выше, знак вне BMP", `"` + strings.Repeat(smile, bound+1) + `"`, true},
		{"RD-04 блок > несёт перевод строки", block(">", bound), true},
		{"RD-04 блок >- перевод строки отсечён", block(">-", bound), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(roleManifest(tc.yaml))
			if !tc.refused {
				if err != nil {
					t.Fatalf("назначение в пределе %d отвергнуто: %v", bound, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("назначение сверх предела %d принято", bound)
			}
			if !errors.Is(err, ErrRoleDescriptionTooLong) {
				t.Errorf("отказ не отнесён к своей причине: %v", err)
			}
			if !strings.Contains(err.Error(), refusal) {
				t.Errorf("текст отказа не содержит ожидаемого:\n  ждём: %s\n  есть: %v", refusal, err)
			}
		})
	}
	// Единица счёта RD-03 — предпосылка, а не исход: знак вне BMP весит больше
	// одной единицы и в байтах, и в UTF-16, иначе (а) и (б) ничего не различают.
	if n := len(smile); n != 4 || utf8.RuneCountInString(smile) != 1 {
		t.Fatalf("предпосылка RD-03: знак %q — %d байт, %d знаков", smile, n, utf8.RuneCountInString(smile))
	}
}
