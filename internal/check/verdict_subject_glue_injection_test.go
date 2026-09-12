// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verdict_subject_glue_injection_test.go — доказательство падучести в ОБЕ
// стороны (порт одноимённой пробы репозитория платформы, снят там
// вынесением службы доступа — `kacho#2597`).
package check_test

import (
	"testing"
)

// TestSubjectGlue_RedInPredicate — ИНЪЕКЦИЯ: склейка стоит в WHERE — отбирает
// строки по вычисленному значению.
func TestSubjectGlue_RedInPredicate(t *testing.T) {
	t.Parallel()
	src := `package pg

const q = ` + "`" + `SELECT ab.id FROM access_bindings ab
   WHERE ab.subject_type || ':' || ab.subject_id = $1` + "`"
	findings, census := auditFileForSubjectGlue("q.go", []byte(src))
	if census.occurrence != 1 {
		t.Fatalf("склейка не распознана: %+v", census)
	}
	if len(findings) != 1 {
		t.Fatalf("склейка в предикате НЕ стала находкой: %d", len(findings))
	}
	if findings[0].clause != "predicate" {
		t.Errorf("клауза распознана неверно: %q", findings[0].clause)
	}
}

// TestSubjectGlue_RedInOnClause — та же ось, склейка в ON (условие соединения).
func TestSubjectGlue_RedInOnClause(t *testing.T) {
	t.Parallel()
	src := `package pg

const q = ` + "`" + `SELECT 1 FROM a
   JOIN b ON a.subject_type || ':' || a.subject_id = b.key` + "`"
	findings, _ := auditFileForSubjectGlue("q2.go", []byte(src))
	if len(findings) != 1 {
		t.Fatalf("склейка в ON НЕ стала находкой: %d", len(findings))
	}
}

// TestSubjectGlue_SilentInProjection — ЗАКОННЫЙ БЛИЗНЕЦ: та же склейка в
// списке выборки (называет ответ, не отбирает).
func TestSubjectGlue_SilentInProjection(t *testing.T) {
	t.Parallel()
	src := `package pg

const q = ` + "`" + `SELECT bs.subject_type || ':' || bs.subject_id
   FROM base_subjects bs` + "`"
	findings, census := auditFileForSubjectGlue("q3.go", []byte(src))
	if census.occurrence != 1 {
		t.Fatalf("склейка не распознана: %+v", census)
	}
	if len(findings) != 0 {
		t.Errorf("склейка в СПИСКЕ ВЫБОРКИ объявлена находкой: %+v", findings)
	}
	if census.projection != 1 {
		t.Errorf("законный близнец не засчитан переписью: %+v", census)
	}
}

// TestSubjectGlue_SilentOnItsOwnExplanation — комментарий, объясняющий сам
// запрет, не считается его нарушением.
func TestSubjectGlue_SilentOnItsOwnExplanation(t *testing.T) {
	t.Parallel()
	src := `package pg

const q = ` + "`" + `SELECT ab.id FROM access_bindings ab
   -- склейка subject_type || ':' || subject_id запрещена в предикате
   WHERE ab.subject_type = $1 AND ab.subject_id = $2` + "`"
	findings, census := auditFileForSubjectGlue("q4.go", []byte(src))
	if census.occurrence != 0 {
		t.Errorf("комментарий распознан как склейка: %+v", census)
	}
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на КОММЕНТАРИИ, объясняющем сам запрет: %+v", findings)
	}
}

// TestSubjectGlue_SilentOnPairedColumns — законный близнец: пара колонок без
// склейки, как решение и предписывает.
func TestSubjectGlue_SilentOnPairedColumns(t *testing.T) {
	t.Parallel()
	src := `package pg

const q = ` + "`" + `SELECT ab.id FROM access_bindings ab
   WHERE ab.subject_type = $1 AND ab.subject_id = $2` + "`"
	findings, census := auditFileForSubjectGlue("q5.go", []byte(src))
	if census.occurrence != 0 {
		t.Errorf("пара колонок распознана как склейка: %+v", census)
	}
	if len(findings) != 0 {
		t.Errorf("пара колонок объявлена находкой: %+v", findings)
	}
}
