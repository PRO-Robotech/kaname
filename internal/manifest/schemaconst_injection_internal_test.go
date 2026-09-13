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
func constRequirement(path string, values ...string) []schemaConst {
	return []schemaConst{{path: path, values: values}}
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
		"services/synthetic/manifest.yaml",  // файл
		"seed.serviceAccounts[].account",    // ключ
		"kacho-elsewhere",                   // увиденное
		`допускает только ["kacho-system"]`, // объявленное
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
		[]schemaConst{{path: "seed.serviceAccounts[].account", values: []string{"system"}, conditional: true}},
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

// TestSchemaConstAuditAcceptsEitherSpellingOfAWindow — ОКНО: требование из двух
// значений принимает ОБА и не находит ни одного расхождения.
//
// Предмет — §2.4 приёмки `seed-identity-names-its-own-service.md`: манифесты
// пяти чужих продуктов переводятся своим порядком (П3), и до перевода в дереве
// законны оба написания одного аккаунта.
func TestSchemaConstAuditAcceptsEitherSpellingOfAWindow(t *testing.T) {
	for _, spelling := range []string{"kacho-system", "system"} {
		audit := auditSchemaConsts(
			constRequirement("seed.serviceAccounts[].account", "kacho-system", "system"),
			injectedManifests(spelling),
		)
		if len(audit.findings) != 0 {
			t.Fatalf("написание %q объявлено находкой при окне из двух: %s",
				spelling, strings.Join(audit.findings, "; "))
		}
		if audit.agreeing != 1 {
			t.Fatalf("написание %q не зачтено отвечающим: отвечает %d из %d сверенных",
				spelling, audit.agreeing, audit.compared)
		}
	}
}

// TestSchemaConstAuditRedensOnAValueOutsideTheWindow — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к
// окну: третье написание остаётся находкой.
//
// Без него проба выше зеленела бы на сверке, которая перестала судить вовсе,
// как только значений стало больше одного.
func TestSchemaConstAuditRedensOnAValueOutsideTheWindow(t *testing.T) {
	audit := auditSchemaConsts(
		constRequirement("seed.serviceAccounts[].account", "kacho-system", "system"),
		injectedManifests("sistem"),
	)
	if len(audit.findings) != 1 {
		t.Fatalf("значение вне окна не названо находкой: находок %d", len(audit.findings))
	}
	if !strings.Contains(audit.findings[0], "sistem") {
		t.Fatalf("находка не называет значения, которое противоречит: %q", audit.findings[0])
	}
}

// TestSchemaWalkReadsTheEnumForm — распознаватель ЗНАЕТ форму `enum`.
//
// Это самая тихая половина класса: пока обход её не знал, требование,
// записанное перечнем, не давало ни красного, ни зелёного — оно просто
// отсутствовало в наблюдении, и перепись при этом выглядела правдоподобной.
func TestSchemaWalkReadsTheEnumForm(t *testing.T) {
	schema := map[string]any{
		"properties": map[string]any{
			"account": map[string]any{"enum": []any{"kacho-system", "system"}},
		},
	}
	var consts []schemaConst
	var unknown []string
	walkSchemaConsts(schema, "", "$", false, &consts, &unknown)

	if len(unknown) != 0 {
		t.Fatalf("обход объявил форму непознанной: %s", strings.Join(unknown, "; "))
	}
	if len(consts) != 1 {
		t.Fatalf("перечень не прочитан требованием: требований %d", len(consts))
	}
	if got := consts[0].values; len(got) != 2 || got[0] != "kacho-system" || got[1] != "system" {
		t.Fatalf("перечень прочитан как %q", got)
	}
}

// TestSchemaWalkNamesAnEnumItCannotJudge — форма, которую обход судить не умеет,
// называется ВСЛУХ, а не пропускается.
//
// Три случая, и каждый — отдельный способ вывести требование из наблюдения:
// не список, пустой список, нестроковый элемент.
func TestSchemaWalkNamesAnEnumItCannotJudge(t *testing.T) {
	for name, enum := range map[string]any{
		"не список":           "kacho-system",
		"пустой список":       []any{},
		"нестроковый элемент": []any{"kacho-system", 17},
	} {
		var consts []schemaConst
		var unknown []string
		walkSchemaConsts(
			map[string]any{"properties": map[string]any{"account": map[string]any{"enum": enum}}},
			"", "$", false, &consts, &unknown)

		if len(unknown) != 1 {
			t.Errorf("%s: форма не названа непознанной (названо %d) — требование ушло бы "+
				"из наблюдения молча", name, len(unknown))
		}
		if len(consts) != 0 {
			t.Errorf("%s: непознанная форма сосчитана требованием", name)
		}
	}
}
