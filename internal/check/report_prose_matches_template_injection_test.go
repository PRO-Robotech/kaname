// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// report_prose_matches_template_injection_test.go — ДОКАЗАТЕЛЬСТВО
// ИНЪЕКЦИЕЙ для сверки прозы отчёта с литералом, который её печатает.
//
// Порт с монорепо: доказательство инъекцией семейства
// `reportprosematchestemplate`, снятого вынесением службы — `kacho#2597`.
// Координата монорепо здесь НЕ пишется целиком намеренно: путь вида
// `<имя>_injection` + `_test.go` читается гейтом обещаний как обещание
// доказательства В ЭТОМ дереве, и обещание не резолвилось бы. Дословно: все четыре оси.
// Изменилось только: пакет (`repohygiene` → `check_test`).
package check_test

import (
	"strings"
	"testing"
)

func TestProseGateSeesTheDriftAndKeepsQuietWithoutIt(t *testing.T) {
	t.Parallel()
	const (
		oldProse = "R7-3 — ПРИБОР ОБЪЁМА: ОДНА ОПЕРАЦИЯ ПРОТИВ НАЛИТОЙ МАТРИЦЫ"
		newProse = "R7-3 — ПРИБОР ОБЪЁМА: ОДНА ОПЕРАЦИЯ ПРОТИВ НАЛИТОЙ СЕТКИ"
	)
	tpl := []tmpl{{where: "probe_test.go:1", literal: newProse}}

	// ── (а) ДЕФЕКТ: шаблон правлен, отчёт не переснят.
	stale := map[string]string{"REPORT-x.txt": "шапка\n" + oldProse + "\nчисла"}
	got := proseMissingFromReports(tpl, stale)
	if len(got) != 1 {
		t.Fatalf("правленый без пересъёмки шаблон не назван: находок %d, ждали 1 (%v)", len(got), got)
	}
	if !strings.Contains(got[0], "probe_test.go:1") {
		t.Fatalf("находка без координаты: %q", got[0])
	}

	// ── (б) ЗАКОННЫЙ БЛИЗНЕЦ: сдвинулись вместе — молчание.
	fresh := map[string]string{"REPORT-x.txt": "шапка\n" + newProse + "\nчисла"}
	if got := proseMissingFromReports(tpl, fresh); len(got) != 0 {
		t.Fatalf("пересня́тый отчёт покрашен: %v", got)
	}

	// ── (в) ЗАКОННЫЙ БЛИЗНЕЦ: отчётов несколько, совпадение в НЕ ПЕРВОМ.
	many := map[string]string{
		"REPORT-a.txt": "чужая шапка",
		"REPORT-b.txt": newProse,
	}
	if got := proseMissingFromReports(tpl, many); len(got) != 0 {
		t.Fatalf("совпадение во втором отчёте не найдено: %v", got)
	}

	// ── (г) ДЕФЕКТ: корпус пуст — совпасть не с чем, и это находка, а не тишина.
	if got := proseMissingFromReports(tpl, map[string]string{}); len(got) != 1 {
		t.Fatalf("на пустом корпусе сверка молчит — значит она молчит всегда: %v", got)
	}
}
