// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// limit_export_procedure_injection_test.go — доказательство, что гейт процедуры
// выгрузки СПОСОБЕН упасть и способен смолчать.
//
// Инъекция идёт настоящим предикатом (`JudgeExportProcedure`) на синтетическом
// корпусе, а не подделкой рядом: подделка доказывала бы, что упасть способна она.
// У каждой находки в файле стоит ЗАКОННЫЙ БЛИЗНЕЦ — форма, отличающаяся одним
// фактом, на которой гейт обязан молчать. Отрицание без близнеца зеленело бы на
// гейте, отвергающем всё.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/dropguard"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const injectedGuide = "INSTALL.md"

// goodGuide — корпус, каким он обязан быть: образец для оператора плюс команда о
// конкретной таблице, дословно от производителя.
func goodGuide() map[string]string {
	return map[string]string{
		injectedGuide: "## 6. Обновление версии\n\nШаблон:\n\n" +
			"    " + dropguard.PreserveCommand("<таблица>") + "\n\nВеличины квот:\n\n" +
			"    " + dropguard.PreserveCommand("kaname.limits") + "\n",
	}
}

func requiredExportPairs() map[string]string {
	return map[string]string{"kaname.limits": injectedGuide}
}

// TestExportProcedureGate_ControlIsSilent — контроль. Стоит первым: утверждение,
// что гейт отвергает, ничего не стоит рядом с гейтом, отвергающим всё.
func TestExportProcedureGate_ControlIsSilent(t *testing.T) {
	t.Parallel()
	census, findings := check.JudgeExportProcedure(goodGuide(), requiredExportPairs())
	if len(findings) != 0 {
		t.Fatalf("годный корпус обязан молчать, получено: %v", findings)
	}
	if census.Guides != 1 || census.Procedures != 1 || census.Templates != 1 {
		t.Fatalf("перепись годного корпуса разошлась с ожидаемой: %s", census.String())
	}
}

// TestExportProcedureGate_MissingProcedureIsAFinding — процедуру вычеркнули.
func TestExportProcedureGate_MissingProcedureIsAFinding(t *testing.T) {
	t.Parallel()
	g := goodGuide()
	g[injectedGuide] = "## 6. Обновление версии\n\nНакатите миграции и запустите службу.\n"

	census, findings := check.JudgeExportProcedure(g, requiredExportPairs())
	requireExportFindingNames(t, findings, injectedGuide, "kaname.limits")
	if census.Guides != 1 {
		t.Fatalf("инструкция обязана быть прочитана даже когда процедуры в ней нет: %s", census.String())
	}
}

// TestExportProcedureGate_SecondSpellingIsAFinding — процедуру пересказали своими
// словами. Это и есть второе написание, ради которого гейт заведён: расходится
// всегда то, которое не исполняется.
func TestExportProcedureGate_SecondSpellingIsAFinding(t *testing.T) {
	t.Parallel()
	g := goodGuide()
	g[injectedGuide] = strings.Replace(g[injectedGuide],
		dropguard.PreserveCommand("kaname.limits"),
		`psql -c "\copy (SELECT * FROM kaname.limits) TO 'limits.csv'"`, 1)

	_, findings := check.JudgeExportProcedure(g, requiredExportPairs())
	requireExportFindingNames(t, findings, injectedGuide, "kaname.limits")
}

// TestExportProcedureGate_MissingGuideIsAFinding — инструкции нет вовсе.
func TestExportProcedureGate_MissingGuideIsAFinding(t *testing.T) {
	t.Parallel()
	_, findings := check.JudgeExportProcedure(map[string]string{}, requiredExportPairs())
	requireExportFindingNames(t, findings, injectedGuide, "kaname.limits")
}

// TestExportProcedureGate_TemplateAloneIsAFinding — остался ОДИН образец, а
// команды о таблице нет. Образец шагом не является: имя таблицы в нём обязан
// подставить оператор, а он подставляет его по отказу, которого ещё не видел.
func TestExportProcedureGate_TemplateAloneIsAFinding(t *testing.T) {
	t.Parallel()
	g := map[string]string{injectedGuide: "    " + dropguard.PreserveCommand("<таблица>") + "\n"}

	census, findings := check.JudgeExportProcedure(g, requiredExportPairs())
	requireExportFindingNames(t, findings, injectedGuide, "kaname.limits")
	if census.Templates != 1 || census.Procedures != 0 {
		t.Fatalf("образец обязан считаться отдельно от команды: %s", census.String())
	}
}

// TestExportProcedureGate_AnotherGuideIsNotJudgedIntoSilence — законный близнец:
// чужая инструкция с ГОДНОЙ процедурой о своей таблице молчит и не подменяет
// собой требуемую.
func TestExportProcedureGate_AnotherGuideIsNotJudgedIntoSilence(t *testing.T) {
	t.Parallel()
	g := goodGuide()
	g["docs/operator/INSTALL.md"] = "    " + dropguard.PreserveCommand("kaname.other_table") + "\n"

	census, findings := check.JudgeExportProcedure(g, requiredExportPairs())
	if len(findings) != 0 {
		t.Fatalf("годная процедура соседа обязана молчать, получено: %v", findings)
	}
	if census.Guides != 2 || census.Procedures != 2 {
		t.Fatalf("перепись не увидела соседа: %s", census.String())
	}
}

// TestExportProcedureGate_EmptyCorpusCountsZero — «находок ноль» обязано быть
// отличимо от «прочитано ноль». Гейт сам этого не различает и не обязан: пустой
// обход роняет прогон в `limit_export_procedure_test.go`, судящем живое дерево.
func TestExportProcedureGate_EmptyCorpusCountsZero(t *testing.T) {
	t.Parallel()
	census, _ := check.JudgeExportProcedure(map[string]string{}, map[string]string{})
	if census.Guides != 0 || census.Lines != 0 || census.Procedures != 0 {
		t.Fatalf("пустой корпус обязан давать нулевую перепись: %s", census.String())
	}
}

func requireExportFindingNames(t *testing.T, findings []string, want ...string) {
	t.Helper()
	if len(findings) == 0 {
		t.Fatalf("гейт смолчал там, где обязан назвать находку")
	}
	joined := strings.Join(findings, "\n")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("находка не называет координату %q — по ней нельзя починить:\n%s", w, joined)
		}
	}
}
