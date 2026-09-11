// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verdict_subject_glue_injection_test.go — доказательство, что гейт способен
// упасть и способен смолчать.
//
// Гейт, который не проверен инъекцией, удостоверяет собственное молчание.
// Инъекция идёт в ОБЕ стороны и НАСТОЯЩИМ входом — тем самым текстом, который
// стоял в дереве до починки, и тремя местами, на которых гейт обязан молчать
// по границе своего предмета.
package check_test

import (
	"strings"
	"testing"
)

// injectedGlueSQL — форма, стоявшая в дереве до починки, дословно.
const injectedGlueSQL = "`\n" + `
SELECT ''::text AS cond_name
  FROM kaname.access_bindings b
  JOIN kaname.access_binding_subjects bs ON bs.binding_id = b.id
  JOIN speaker sp ON sp.subject = bs.subject_type || ':' || bs.subject_id
 WHERE b.status = 'ACTIVE'` + "\n`"

// twinProjectionSQL — ЗАКОННЫЙ БЛИЗНЕЦ: та же склейка в списке выборки.
// Обратный вопрос называет ею субъекта в ответе, а не отбирает по ней строки.
const twinProjectionSQL = "`\n" + `
SELECT bs.subject_type || ':' || bs.subject_id AS subject
  FROM kaname.access_binding_subjects bs
  JOIN scope sc ON sc.s_type = bs.resource_type AND sc.s_id = bs.resource_id` + "\n`"

// twinMemberGlueSQL — ВТОРОЙ ЗАКОННЫЙ БЛИЗНЕЦ: склейка ЧЛЕНА ГРУППЫ, вне
// границ этого гейта. Гейт обязан молчать даже в предикате — иначе он дал бы
// находку вне предмета.
const twinMemberGlueSQL = "`\n" + `
SELECT gm.group_id
  FROM kaname.group_members gm
  JOIN speaker sp ON sp.subject = gm.member_type || ':' || gm.member_id` + "\n`"

// twinCommentSQL — склейка, стоящая в КОММЕНТАРИИ, который объясняет запрет.
// Гейт читает исполняемую часть; иначе он краснел бы на собственном объяснении.
const twinCommentSQL = "`\n" + `
-- Прежде здесь стояло sp.subject = bs.subject_type || ':' || bs.subject_id.
SELECT 1 FROM kaname.access_binding_subjects bs
 WHERE bs.subject_type = $1 AND bs.subject_id = $2` + "\n`"

func auditInjected(t *testing.T, name, lit string) ([]glueFinding, glueCensus) {
	t.Helper()
	src := "package p\n\nconst q = " + lit + "\n"
	return auditFileForSubjectGlue(name, []byte(src))
}

// TestVerdictSubjectGlueGateRedsOnTheGlueThatWasThere — инъекция настоящим
// входом: гейт краснеет и НАЗЫВАЕТ КООРДИНАТУ.
func TestVerdictSubjectGlueGateRedsOnTheGlueThatWasThere(t *testing.T) {
	t.Parallel()
	found, c := auditInjected(t, "injected.go", injectedGlueSQL)
	if len(found) != 1 {
		t.Fatalf("на форме, стоявшей в дереве до починки, находок %d, ожидалась одна "+
			"(перепись: литералов %d, склеек %d, из них проекций %d). Гейт, не краснеющий "+
			"на собственном предмете, удостоверяет своё молчание",
			len(found), c.literals, c.occurrence, c.projection)
	}
	if found[0].line <= 0 || found[0].file == "" {
		t.Errorf("находка без координаты: %+v — по такому вердикту чинить нечего", found[0])
	}
	if !strings.Contains(found[0].text, "subject_type") {
		t.Errorf("находка не цитирует найденного: %+v", found[0])
	}
	t.Logf("инъекция: %s:%d (%s) — %s", found[0].file, found[0].line, found[0].clause, found[0].text)
}

// TestVerdictSubjectGlueGateSilentOnItsThreeLegalTwins — вторая сторона
// инъекции.
//
// Без неё гейт ловил бы ФОРМУ, а не существо, и первый же ложный срабат его
// отключил бы.
func TestVerdictSubjectGlueGateSilentOnItsThreeLegalTwins(t *testing.T) {
	t.Parallel()
	for _, tw := range []struct{ name, sql, why string }{
		{"проекция субъекта", twinProjectionSQL,
			"склейка в списке выборки называет ответ, а не отбирает строки"},
		{"склейка члена группы", twinMemberGlueSQL,
			"вне границ предмета: покраснев, гейт дал бы находку вне него"},
		{"склейка в комментарии", twinCommentSQL,
			"гейт читает исполняемую часть, иначе краснел бы на собственном объяснении"},
	} {
		found, c := auditInjected(t, "twin.go", tw.sql)
		if len(found) != 0 {
			t.Errorf("законный близнец «%s» дал %d находок (%+v): %s",
				tw.name, len(found), found, tw.why)
		}
		t.Logf("близнец «%s»: находок 0 (склеек встречено %d, проекций %d)",
			tw.name, c.occurrence, c.projection)
	}
}
