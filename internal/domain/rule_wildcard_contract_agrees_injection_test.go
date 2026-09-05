// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// rule_wildcard_contract_agrees_injection_test.go — доказательство того, что
// гейт СПОСОБЕН упасть и способен смолчать (задача продукта #1961).
//
// Вход синтетический: настоящее дерево не трогается, поэтому доказательство не
// истекает вместе с починкой предмета (`testing.md` §«Гейт на класс», п. 5 —
// фикстура, привязанная к живому дефекту, умирает вместе с ним).
//
// Каждый случай меняет РОВНО ОДИН факт против своего положительного близнеца:
// либо заявление в комментарии, либо вердикт производителя поведения. Дельта в
// два факта сразу не доказывала бы ничего — покраснеть мог сосед.
package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// synthProbe — производитель поведения, у которого ярус задан прямо.
// tenantRejects=true, platformRejects=false — политикозависимая подстановка.
func synthProbe(tenantRejects, platformRejects bool) wildcardProbe {
	return func(p domain.RulePolicy) error {
		reject := platformRejects
		if p == domain.TenantPolicy() {
			reject = tenantRejects
		}
		if reject {
			return errSynthRefusal
		}
		return nil
	}
}

// errSynthRefusal — отказ синтетического производителя. Текст не значим:
// гейт судит НАЛИЧИЕ отказа, а не его формулировку.
var errSynthRefusal = errors.New("синтетический отказ яруса")

func protoWith(fieldComment, field string) string {
	return "message Rule {\n" + fieldComment + "\n  repeated string " + field + " = 3;\n}\n"
}

func TestRuleWildcardContractGate_CanFailAndStaysSilent(t *testing.T) {
	const (
		claimEN = "  // Глаголы гранта. Literal `\"*\"` — SYSTEM-ONLY; только как единственный элемент."
		claimRU = "  // Глаголы гранта. Литерал `\"*\"` доступен только системной роли."
		noClaim = "  // Глаголы гранта. 1..16; lowercase; подстановка `\"*\"` только как единственный элемент."
		// Слово о системности БЕЗ литерала подстановки: проза о ярусах ролей
		// встречается сплошь и заявлением о подстановке не является.
		wordOnly = "  // Глаголы гранта. Роль бывает арендаторской и системной."
	)

	cases := []struct {
		name         string
		proto        string
		probes       map[string]wildcardProbe
		wantFindings int
		wantNamed    string
		wantFields   int
	}{
		{
			name:  "законный близнец: заявлено и домен ТАК И СУДИТ",
			proto: protoWith(claimEN, "verbs"),
			// арендатору нельзя, платформе можно — политикозависимая.
			probes:       map[string]wildcardProbe{"verbs": synthProbe(true, false)},
			wantFindings: 0, wantFields: 1,
		},
		{
			name:         "заявлено, а домен ПРИНИМАЕТ у арендатора — предмет #1961",
			proto:        protoWith(claimEN, "verbs"),
			probes:       map[string]wildcardProbe{"verbs": synthProbe(false, false)},
			wantFindings: 1, wantNamed: "verbs", wantFields: 1,
		},
		{
			name:  "F2-ru: то же заявление русской формой — распознаётся",
			proto: protoWith(claimRU, "verbs"),
			probes: map[string]wildcardProbe{
				"verbs": synthProbe(false, false),
			},
			wantFindings: 1, wantNamed: "verbs", wantFields: 1,
		},
		{
			name:         "домен ограничивает ярусом, а контракт МОЛЧИТ",
			proto:        protoWith(noClaim, "verbs"),
			probes:       map[string]wildcardProbe{"verbs": synthProbe(true, false)},
			wantFindings: 1, wantNamed: "verbs", wantFields: 1,
		},
		{
			name: "законный близнец: подстановка запрещена ОБОИМ ярусам, заявления нет",
			// это `resource_names` настоящего дерева: запрет, а не системная возможность.
			proto:        protoWith(noClaim, "resource_names"),
			probes:       map[string]wildcardProbe{"resource_names": synthProbe(true, true)},
			wantFindings: 0, wantFields: 1,
		},
		{
			name:         "заявление есть, производителя поведения НЕТ — проверить некому",
			proto:        protoWith(claimEN, "some_new_field"),
			probes:       map[string]wildcardProbe{},
			wantFindings: 1, wantNamed: "some_new_field", wantFields: 1,
		},
		{
			name:         "законный близнец: слово о системности БЕЗ литерала подстановки",
			proto:        protoWith(wordOnly, "verbs"),
			probes:       map[string]wildcardProbe{"verbs": synthProbe(false, false)},
			wantFindings: 0, wantFields: 1,
		},
		{
			name:         "пустое объявление — премиса гейта дерева обязана упасть",
			proto:        "message Rule {\n}\n",
			probes:       map[string]wildcardProbe{},
			wantFindings: 0, wantFields: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, census, err := auditRuleWildcardContract(tc.proto, tc.probes)
			if err != nil {
				t.Fatalf("разбор не отработал: %v", err)
			}
			t.Logf("находок %d · %s", len(findings), census)

			if census.Fields != tc.wantFields {
				t.Fatalf("полей прочитано %d, ожидалось %d", census.Fields, tc.wantFields)
			}
			if len(findings) != tc.wantFindings {
				t.Fatalf("находок %d, ожидалось %d: %v", len(findings), tc.wantFindings, findings)
			}
			if tc.wantNamed != "" && !strings.Contains(strings.Join(findings, "\n"), tc.wantNamed) {
				t.Fatalf("находка не назвала поле %q: %v", tc.wantNamed, findings)
			}
		})
	}
}

// TestRuleWildcardContractGate_UnclosedDeclarationIsNotAVerdict — незакрытое
// объявление есть «не выполнилось», а не «ноль находок».
func TestRuleWildcardContractGate_UnclosedDeclarationIsNotAVerdict(t *testing.T) {
	_, _, err := auditRuleWildcardContract("message Rule {\n  repeated string verbs = 3;\n", nil)
	if err == nil {
		t.Fatal("незакрытое объявление принято за годный разбор — вердикт был бы получен даром")
	}
	t.Logf("отказ разбора, как и должно: %v", err)
}
