// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_copy_parity_reannotated_test.go — пятый вид записи ведомости: глагол
// есть у обеих копий, но служба СМЕНИЛА ВИД его аннотации (охраняемый глагол
// стал решаемым обработчиком), и запись разошлась не одним полем, а целиком:
// сменились значения нескольких полей и появилось поле, которого прежняя форма
// не несла вовсе (kaname#986). Четвёртый вид объясняет ровно одну подстановку и
// такого расхождения не покрывает by construction.
//
// Инъекция по каждой оси с законным близнецом; каждая меняет РОВНО ОДИН факт.
package check

import (
	"strings"
	"testing"
)

const testReannotatedFQN = "kaname.cloud.demo.v1.DemoService/Revoke"

// catalogEntryGuarded — охраняемая запись в форме генератора.
func catalogEntryGuarded(fqn, permission string) string {
	return "  {\n" +
		"    \"fqn\": \"" + fqn + "\",\n" +
		"    \"permission\": \"" + permission + "\",\n" +
		"    \"required_relation\": \"v_delete\",\n" +
		"    \"scope_extractor\": {\n" +
		"      \"object_type\": \"demo\",\n" +
		"      \"from_request_field\": \"demo_id\"\n" +
		"    },\n" +
		"    \"required_acr_min\": \"2\"\n" +
		"  }"
}

// catalogEntryHandlerDecides — та же запись, переаннотированная в «решает
// обработчик»: другие значения четырёх полей и новое поле `exempt_reason`.
func catalogEntryHandlerDecides(fqn, reason string) string {
	return "  {\n" +
		"    \"fqn\": \"" + fqn + "\",\n" +
		"    \"permission\": \"\\u003cexempt\\u003e\",\n" +
		"    \"required_relation\": \"\",\n" +
		"    \"scope_extractor\": {\n" +
		"      \"object_type\": \"\",\n" +
		"      \"from_request_field\": \"\"\n" +
		"    },\n" +
		"    \"required_acr_min\": \"2\",\n" +
		"    \"exempt_reason\": \"" + reason + "\"\n" +
		"  }"
}

// testReannotated — ведомость проб: одна запись того же вида, что действующая.
func testReannotated() []CatalogReannotatedEntry {
	return []CatalogReannotatedEntry{{
		FQN:      testReannotatedFQN,
		EdgeBody: catalogEntryGuarded(testReannotatedFQN, "demo.revoke"),
		OwnBody:  catalogEntryHandlerDecides(testReannotatedFQN, "HANDLER_DECIDES"),
		Why:      "синтетика пробы",
		Removal:  "край несёт новую запись",
		Refs:     "kaname#986",
	}}
}

// TestDeclaredReannotatedEntryExplainsARewrittenEntry — ось ВЕДОМОСТИ
// ПЕРЕАННОТИРОВАННЫХ: запись, разошедшаяся целиком, — находка, пока смена не
// объявлена; объявленная — молчит. Ровно один факт между близнецами: наличие
// записи ведомости.
func TestDeclaredReannotatedEntryExplainsARewrittenEntry(t *testing.T) {
	a := catalogEntry("kacho.cloud.a.v1.A/Get", "a.get")
	edge := catalogFile(a, catalogEntryGuarded(testReannotatedFQN, "demo.revoke"))
	own := catalogFile(a, catalogEntryHandlerDecides(testReannotatedFQN, "HANDLER_DECIDES"))

	t.Run("дефект: переаннотация не объявлена", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWithEveryLedger(nil, nil, nil, nil, nil, edge, own)
		requireFinding(t, findings, err, testReannotatedFQN, CatalogFindingCopies)
	})

	t.Run("близнец: та же переаннотация ОБЪЯВЛЕНА", func(t *testing.T) {
		findings, census, err := compareCatalogCopiesWithEveryLedger(nil, nil, nil, nil, testReannotated(), edge, own)
		requireSilent(t, findings, err)
		if census.ReannotatedApplied != 1 || census.ReannotatedDeclared != 1 {
			t.Fatalf("перепись не назвала применённую запись: %s", census)
		}
	})

	t.Run("контроль: прочие записи по-прежнему сверяются побайтово", func(t *testing.T) {
		own2 := catalogFile(catalogEntry("kacho.cloud.a.v1.A/Get", "a.GET"),
			catalogEntryHandlerDecides(testReannotatedFQN, "HANDLER_DECIDES"))
		findings, _, err := compareCatalogCopiesWithEveryLedger(nil, nil, nil, nil, testReannotated(), edge, own2)
		requireFinding(t, findings, err, "kacho.cloud.a.v1.A/Get", CatalogFindingCopies)
	})

	t.Run("контроль: наша запись не та, что объявлена", func(t *testing.T) {
		own3 := catalogFile(a, catalogEntryHandlerDecides(testReannotatedFQN, "PUBLIC_DIRECTORY"))
		findings, _, err := compareCatalogCopiesWithEveryLedger(nil, nil, nil, nil, testReannotated(), edge, own3)
		requireFinding(t, findings, err, testReannotatedFQN, CatalogFindingLedger)
	})

	t.Run("контроль: у края запись не та, что объявлена прежней", func(t *testing.T) {
		edge2 := catalogFile(a, catalogEntryGuarded(testReannotatedFQN, "demo.REVOKE"))
		findings, _, err := compareCatalogCopiesWithEveryLedger(nil, nil, nil, nil, testReannotated(), edge2, own)
		requireFinding(t, findings, err, testReannotatedFQN, CatalogFindingLedger)
	})
}

// TestDeclaredReannotatedEntryExpiresOnItsOwn — САМОИСТЕЧЕНИЕ: край несёт новую
// запись либо глагола у края нет — запись обязана уйти.
func TestDeclaredReannotatedEntryExpiresOnItsOwn(t *testing.T) {
	a := catalogEntry("kacho.cloud.a.v1.A/Get", "a.get")
	rewritten := catalogEntryHandlerDecides(testReannotatedFQN, "HANDLER_DECIDES")

	t.Run("дефект: край уже несёт новую запись, запись ведомости стоит", func(t *testing.T) {
		both := catalogFile(a, rewritten)
		findings, census, err := compareCatalogCopiesWithEveryLedger(nil, nil, nil, nil, testReannotated(), both, both)
		requireFinding(t, findings, err, testReannotatedFQN, CatalogFindingLedger)
		if census.ReannotatedApplied != 0 {
			t.Fatalf("запись, которой нечего объяснять, объявлена применённой: %s", census)
		}
	})

	t.Run("дефект: края нет вовсе", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWithEveryLedger(nil, nil, nil, nil, testReannotated(),
			catalogFile(a), catalogFile(a, rewritten))
		requireFinding(t, findings, err, testReannotatedFQN, CatalogFindingLedger)
	})

	t.Run("близнец: край ещё несёт прежнюю запись", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWithEveryLedger(nil, nil, nil, nil, testReannotated(),
			catalogFile(a, catalogEntryGuarded(testReannotatedFQN, "demo.revoke")), catalogFile(a, rewritten))
		requireSilent(t, findings, err)
	})
}

// TestDeclaredReannotatedEntryMustNameOurOwnVerb — запись о глаголе, которого в
// НАШЕЙ копии нет, утверждает о дереве неправду.
func TestDeclaredReannotatedEntryMustNameOurOwnVerb(t *testing.T) {
	a := catalogEntry("kacho.cloud.a.v1.A/Get", "a.get")
	edge := catalogFile(a, catalogEntryGuarded(testReannotatedFQN, "demo.revoke"))

	t.Run("дефект: нашей записи нет", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWithEveryLedger(nil, nil, nil, nil, testReannotated(), edge, catalogFile(a))
		requireFinding(t, findings, err, testReannotatedFQN, CatalogFindingLedger)
	})

	t.Run("близнец: наша запись на месте", func(t *testing.T) {
		findings, _, err := compareCatalogCopiesWithEveryLedger(nil, nil, nil, nil, testReannotated(), edge,
			catalogFile(a, catalogEntryHandlerDecides(testReannotatedFQN, "HANDLER_DECIDES")))
		requireSilent(t, findings, err)
	})
}

// TestDeclaredReannotatedEntriesCarryASubject — у каждой записи названы глагол,
// обе записи (разные, каждая разбирается и называет тот же глагол), причина,
// внешний предикат снятия и номер предмета. На пустой ведомости проходит с
// переписью.
func TestDeclaredReannotatedEntriesCarryASubject(t *testing.T) {
	reannotated := CatalogReannotatedEntries()
	t.Logf("перепись ведомости переаннотированных записей: записей %d", len(reannotated))
	for _, e := range reannotated {
		if e.FQN == "" {
			t.Errorf("запись ведомости без глагола: %+v", e)
			continue
		}
		if e.EdgeBody == e.OwnBody {
			t.Errorf("запись ведомости объявляет смену без смены: %s", e.FQN)
		}
		for side, body := range map[string]string{"края": e.EdgeBody, "наша": e.OwnBody} {
			fqn, err := catalogBlockFQN(body)
			if err != nil || fqn != e.FQN {
				t.Errorf("запись ведомости %s: запись %s не называет глагол записи (%q, %v)", e.FQN, side, fqn, err)
			}
		}
		if strings.TrimSpace(e.Why) == "" {
			t.Errorf("запись ведомости без причины: %s", e.FQN)
		}
		if strings.TrimSpace(e.Removal) == "" {
			t.Errorf("запись ведомости без предиката снятия: %s", e.FQN)
		}
		if !strings.Contains(e.Refs, "#") {
			t.Errorf("запись ведомости без номера предмета: %s (refs=%q)", e.FQN, e.Refs)
		}
	}
}
