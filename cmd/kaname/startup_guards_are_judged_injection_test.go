// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// startup_guards_are_judged_injection_test.go — доказательство того, что гейт
// соседнего файла СПОСОБЕН упасть, и падает ровно на своём предмете.
//
// Инъекция зовёт ТО ЖЕ ТЕЛО (`judgeStartupGuardCoverage`) и ТОТ ЖЕ
// распознаватель (`readStartupGuardCensus`), что исполняется на дереве: своя
// копия предиката разошлась бы с настоящим гейтом молча — и разошлась бы именно
// там, где расхождение не видно.
//
// У каждого отрицания стоит ЗАКОННЫЙ БЛИЗНЕЦ, отличающийся ОДНИМ фактом:
// без него красное доказывало бы лишь то, что гейт умеет краснеть, а не то, что
// он краснеет на своём предмете.
package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupGuardCoverage_JudgedGuardIsSilent(t *testing.T) {
	// КОНТРОЛЬ: всё цело — гейт молчит. Без него всякое красное ниже
	// доказывало бы только то, что гейт краснеет всегда.
	_, judged, findings := judgeStartupGuardCoverage(
		startupGuardCensus{
			Guards:    []string{"requireAlpha", "requireBeta"},
			Judged:    []string{"requireAlpha", "requireBeta"},
			FilesRead: 2,
		}, map[string]string{})
	if len(findings) != 0 {
		t.Fatalf("гейт покраснел на целом дереве: %v", findings)
	}
	if judged != 2 {
		t.Fatalf("судимых насчитано %d, ожидалось 2", judged)
	}
}

func TestStartupGuardCoverage_UnjudgedGuardIsAFinding(t *testing.T) {
	// ИНЪЕКЦИЯ, ОДИН ФАКТ против контроля выше: `requireBeta` пробой не зовётся.
	_, judged, findings := judgeStartupGuardCoverage(
		startupGuardCensus{
			Guards:    []string{"requireAlpha", "requireBeta"},
			Judged:    []string{"requireAlpha"},
			FilesRead: 2,
		}, map[string]string{})
	if len(findings) != 1 {
		t.Fatalf("несудимый страж не найден: находок %d (%v)", len(findings), findings)
	}
	if !strings.Contains(findings[0], "requireBeta") {
		t.Fatalf("находка не называет виновника: %q", findings[0])
	}
	if judged != 1 {
		t.Fatalf("судимых насчитано %d, ожидалось 1", judged)
	}
}

func TestStartupGuardCoverage_ExcusedGuardIsSilent(t *testing.T) {
	// ЗАКОННЫЙ БЛИЗНЕЦ инъекции выше: тот же несудимый страж, но НАЗВАН в
	// ведомости с причиной. Ровно один факт отличия — запись ведомости.
	_, _, findings := judgeStartupGuardCoverage(
		startupGuardCensus{
			Guards:    []string{"requireAlpha", "requireBeta"},
			Judged:    []string{"requireAlpha"},
			FilesRead: 2,
		}, map[string]string{"requireBeta": "профилем не выразимо: читает смонтированный файл"})
	if len(findings) != 0 {
		t.Fatalf("названный в ведомости страж дал находку: %v", findings)
	}
}

func TestStartupGuardCoverage_StaleExcuseIsAFinding(t *testing.T) {
	// САМОИСТЕЧЕНИЕ: запись, которой больше некого прощать, — находка. Иначе
	// снятый страж оставил бы за собой прощение, под которое уедет следующий.
	_, _, findings := judgeStartupGuardCoverage(
		startupGuardCensus{
			Guards:    []string{"requireAlpha"},
			Judged:    []string{"requireAlpha"},
			FilesRead: 1,
		}, map[string]string{"requireGone": "причина, у которой не осталось предмета"})
	if len(findings) != 1 {
		t.Fatalf("протухшая запись ведомости не найдена: находок %d (%v)", len(findings), findings)
	}
	if !strings.Contains(findings[0], "requireGone") {
		t.Fatalf("находка не называет запись: %q", findings[0])
	}
}

// TestStartupGuardCoverage_RecognizerSeparatesGuardsFromTheirLegalTwins —
// распознаватель судит УЗЕЛ РАЗБОРА, а не подстроку.
//
// Три законных близнеца в одном синтетическом пакете, и ни один не обязан быть
// сосчитан стражем либо судимым:
//
//	requireSomethingElse   имя то же, результат НЕ error — это помощник;
//	requireInAComment      имя названо ТОЛЬКО комментарием пробы — не вызов;
//	requireInAMessage      имя названо ТОЛЬКО в тексте отказа — не вызов.
func TestStartupGuardCoverage_RecognizerSeparatesGuardsFromTheirLegalTwins(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("синтетический файл не записан: %v", err)
		}
	}
	write("guards.go", `package main

import "fmt"

func requireReal(x bool) error {
	if x {
		return nil
	}
	return fmt.Errorf("отказ")
}

// requireSomethingElse — ЗАКОННЫЙ БЛИЗНЕЦ: имя то же, результат не error.
func requireSomethingElse(x bool) bool { return x }
`)
	write("probe_test.go", `package main

import "testing"

// В комментарии названы requireInAComment и requireSomethingElse — вызовом это
// не является.
func `+profileProbeName+`(t *testing.T) {
	if err := requireReal(true); err != nil {
		t.Fatal("requireInAMessage: " + err.Error())
	}
}
`)
	census := readStartupGuardCensus(t, dir)

	if census.FilesRead != 2 {
		t.Fatalf("прочитано файлов %d, ожидалось 2", census.FilesRead)
	}
	if len(census.Guards) != 1 || census.Guards[0] != "requireReal" {
		t.Fatalf("стражи распознаны неверно: %v (близнец без error попал в перечень?)", census.Guards)
	}
	for _, name := range census.Judged {
		if name == "requireInAComment" || name == "requireInAMessage" || name == "requireSomethingElse" {
			t.Fatalf("имя из комментария либо из текста отказа сосчитано вызовом: %v", census.Judged)
		}
	}
	if !contains(census.Judged, "requireReal") {
		t.Fatalf("настоящий вызов не распознан: %v", census.Judged)
	}
}

// TestStartupGuardCoverage_EmptyWalkIsReachable — у ветви «обход пуст» есть
// достижимый вход, то есть она не украшение.
func TestStartupGuardCoverage_EmptyWalkIsReachable(t *testing.T) {
	census := readStartupGuardCensus(t, t.TempDir())
	if census.FilesRead != 0 || len(census.Guards) != 0 {
		t.Fatalf("пустой каталог дал непустую перепись: %+v", census)
	}
}

// TestStartupGuardCoverage_ParserReadsTheRealPackage — распознаватель разбирает
// НАСТОЯЩИЙ пакет, а не только синтетику: без этого зелёное синтетики ничего не
// говорит о дереве.
func TestStartupGuardCoverage_ParserReadsTheRealPackage(t *testing.T) {
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "revocationauthority.go", nil, parser.SkipObjectResolution); err != nil {
		t.Fatalf("файл стража не разбирается: %v", err)
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
