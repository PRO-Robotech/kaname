// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// schemaconst_injection_internal_test.go — доказательство, что гейты `const`
// СПОСОБНЫ упасть, и падают ровно на своём предмете.
//
// # Почему доказательство едет вместе с гейтом, а не остаётся прогоном
//
// Способность упасть однажды показанная порчей дерева ничего не держит: она
// уходит вместе с сессией, а гейт остаётся — и остаётся на вид рабочим. Здесь
// инъекция подаётся ДАННЫМИ в ту же функцию сверки, которую зовёт гейт
// (`auditSchemaConsts`), поэтому переустройство гейта обязано пройти через это
// доказательство заново.
//
// # Инъекция роняет ТОЛЬКО проверяемое
//
// Каждый случай ниже отличается от законного близнеца РОВНО одним значением.
// Инъекция, нарушающая заодно соседнее свойство, доказательством не является:
// красное пришло бы от соседа, и вакуумность нового гейта осталась бы
// невидимой.
//
// # Законный близнец обязателен у каждого отрицания
//
// Без него «краснеет на порче» зеленело бы на сверке, объявляющей находкой
// всякое вхождение.
package manifest

import (
	"strings"
	"testing"
)

// injectedManifests — минимальная пара документов: один законный, второй
// отличается ровно одним значением.
func injectedManifests(account string) map[string]any {
	return map[string]any{
		"services/synthetic/manifest.yaml": map[string]any{
			"apiVersion": "iam/v1",
			"module":     "vpc",
			"seed": map[string]any{
				"serviceAccounts": []any{
					map[string]any{"name": "kacho-vpc", "account": account},
				},
			},
		},
	}
}

// constRequirement — одно требование схемы, поданное сверке напрямую.
func constRequirement(path, value string) []schemaConst {
	return []schemaConst{{path: path, value: value}}
}

// TestSchemaConstAuditRedensOnAContradictingValue — ОТРИЦАНИЕ: значение, схеме
// не отвечающее, есть находка, и находка называет файл и ключ.
func TestSchemaConstAuditRedensOnAContradictingValue(t *testing.T) {
	audit := auditSchemaConsts(
		constRequirement("seed.serviceAccounts[].account", "kacho-system"),
		injectedManifests("kacho-elsewhere"),
	)
	if len(audit.findings) != 1 {
		t.Fatalf("порча не дала ровно одной находки: находок %d, сверено %d — "+
			"сверка либо слепа, либо считает не то", len(audit.findings), audit.compared)
	}
	for _, must := range []string{
		"services/synthetic/manifest.yaml", // файл
		"seed.serviceAccounts[].account",   // ключ
		"kacho-elsewhere",                  // увиденное
		`const "kacho-system"`,             // объявленное
	} {
		if !strings.Contains(audit.findings[0], must) {
			t.Errorf("находка не называет %q — читатель не поймёт, что чинить: %s",
				must, audit.findings[0])
		}
	}
}

// TestSchemaConstAuditIsSilentOnALegalTwin — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к отрицанию
// выше: тот же путь, то же требование, отвечающее значение — молчание.
//
// Без него отрицание зеленело бы на сверке, объявляющей находкой всякое
// вхождение, и «гейт способен упасть» ничего бы не значило.
func TestSchemaConstAuditIsSilentOnALegalTwin(t *testing.T) {
	audit := auditSchemaConsts(
		constRequirement("seed.serviceAccounts[].account", "kacho-system"),
		injectedManifests("kacho-system"),
	)
	if len(audit.findings) != 0 {
		t.Fatalf("законный близнец объявлен находкой: %s", strings.Join(audit.findings, "; "))
	}
	if audit.agreeing != 1 || audit.compared != 1 {
		t.Fatalf("законный близнец не сосчитан: сверено %d, отвечает %d — "+
			"молчание могло быть молчанием пустого обхода", audit.compared, audit.agreeing)
	}
}

// TestSchemaConstAuditDoesNotJudgeADiscriminator — `const` под условием
// требованием НЕ является.
//
// Без этой ветви гейт потребовал бы от каждой выдачи `target: resources`, тогда
// как выдачи дерева законно пишут `allInScope`; находка была бы ложной, а
// прибор, у которого находки ложные, перестают читать.
func TestSchemaConstAuditDoesNotJudgeADiscriminator(t *testing.T) {
	audit := auditSchemaConsts(
		[]schemaConst{{path: "seed.serviceAccounts[].account", value: "system", conditional: true}},
		injectedManifests("kacho-system"),
	)
	if len(audit.findings) != 0 {
		t.Fatalf("дискриминатор условия судим как требование: %s", strings.Join(audit.findings, "; "))
	}
	if len(audit.discriminators) != 1 {
		t.Fatalf("дискриминатор не назван переписью: их %d — умолчание вместо «не судится»",
			len(audit.discriminators))
	}
	if audit.requirements != 0 {
		t.Fatalf("дискриминатор сосчитан требованием: требований %d", audit.requirements)
	}
}

// TestSchemaConstAuditNamesAnUnexercisedRequirement — требование, которого
// дерево не осуществляет, НЕ находка, но и не молчание.
//
// Ровно этот случай живёт в дереве (`seed.groups[].account`: групп не объявляет
// ни один манифест). Умолчать о нём значило бы выдать «ноль находок» за
// «подтверждено», а это разные утверждения.
func TestSchemaConstAuditNamesAnUnexercisedRequirement(t *testing.T) {
	audit := auditSchemaConsts(
		constRequirement("seed.groups[].account", "kacho-system"),
		injectedManifests("kacho-system"), // групп в документе нет вовсе
	)
	if len(audit.findings) != 0 {
		t.Fatalf("ненаписанный раздел объявлен находкой: %s", strings.Join(audit.findings, "; "))
	}
	if len(audit.unexercised) != 1 {
		t.Fatalf("неосуществлённое требование не названо: их %d", len(audit.unexercised))
	}
	if audit.compared != 0 {
		t.Fatalf("сверено %d вхождений там, где раздела нет — путь резолвится не туда", audit.compared)
	}
}

// TestSchemaConstAuditCountsEveryOccurrence — единица счёта есть ВХОЖДЕНИЕ, а не
// путь: список из двух элементов даёт две сверки и две находки.
//
// Без этого гейт мог бы судить первый элемент и молчать об остальных — беда
// тихая: перепись выглядела бы правдоподобно.
func TestSchemaConstAuditCountsEveryOccurrence(t *testing.T) {
	docs := map[string]any{
		"services/synthetic/manifest.yaml": map[string]any{
			"seed": map[string]any{
				"joins": []any{
					map[string]any{"serviceAccount": map[string]any{"account": "kacho-elsewhere"}},
					map[string]any{"serviceAccount": map[string]any{"account": "kacho-elsewhere"}},
				},
			},
		},
	}
	audit := auditSchemaConsts(
		constRequirement("seed.joins[].serviceAccount.account", "kacho-system"), docs)
	if audit.compared != 2 || len(audit.findings) != 2 {
		t.Fatalf("сверены не все вхождения списка: сверено %d, находок %d, ожидалось 2 и 2",
			audit.compared, len(audit.findings))
	}
}
