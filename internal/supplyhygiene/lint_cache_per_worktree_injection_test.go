// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lint_cache_per_worktree_injection_test.go — способность меры упасть и смолчать
// доказывается ИНЪЕКЦИЕЙ, а не прочтением.
//
// Каждая инъекция меняет против контроля РОВНО ОДИН факт. Иначе неизвестно,
// какой из двух дал красное, и вердикт недействителен, хотя выглядит как
// обычный зелёный.
//
// Прогонов шесть: контроль · четыре одно-фактных дефекта по числу осей · и
// законный близнец — ЗАКОММЕНТИРОВАННОЕ мягкое присваивание, на котором мера
// обязана молчать: гейт, краснеющий на собственном объяснении, есть тот самый
// класс, который корпус ловит.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lintCacheFixture — синтетический рецепт. Каждый параметр — ОДИН факт, чтобы
// инъекция меняла ровно его.
type lintCacheFixture struct {
	op     string // форма присваивания
	val    string // значение
	export bool   // вывозится ли переменная
	print  bool   // печатает ли цель `lint` кэш
	extra  string // дополнительная строка перед присваиванием
}

// writeLintCacheRecipe — собирает рецепт и кладёт его в свежий корень.
func writeLintCacheRecipe(t *testing.T, f lintCacheFixture) string {
	t.Helper()
	root := t.TempDir()

	var b strings.Builder
	b.WriteString("# Кэш линтера — СВОЙ у каждой рабочей копии; переменная GOLANGCI_LINT_CACHE\n")
	b.WriteString("# объявлена ниже. Эта строка — комментарий, и предметом не является.\n")
	if f.extra != "" {
		b.WriteString(f.extra + "\n")
	}
	b.WriteString("GOLANGCI_LINT_CACHE " + f.op + " " + f.val + "\n")
	if f.export {
		b.WriteString("export GOLANGCI_LINT_CACHE\n")
	}
	b.WriteString("\nlint:\n")
	if f.print {
		b.WriteString("\t@echo \"кэш линтера: $(GOLANGCI_LINT_CACHE)\"\n")
	}
	b.WriteString("\tgolangci-lint run --config=.github/golangci.yml ./...\n")

	if err := os.WriteFile(filepath.Join(root, lintCacheRecipe), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("фикстура не собрана: %v", err)
	}
	return root
}

// sound — контроль: все пять осей выполнены.
func sound() lintCacheFixture {
	return lintCacheFixture{op: ":=", val: "$(CURDIR)/.cache/golangci-lint", export: true, print: true}
}

func TestInjection_SoundRecipeIsSilent(t *testing.T) {
	census, findings := scanLintCache(writeLintCacheRecipe(t, sound()))
	if census.Assignments != 1 || census.LintRecipeLines == 0 {
		t.Fatalf("распознаватель не увидел предмет: присваиваний %d, строк цели %d — "+
			"инъекции ниже были бы вакуумными", census.Assignments, census.LintRecipeLines)
	}
	if census.CachePrints != 1 {
		t.Fatalf("печать кэша не распознана: %d — ось переписи не проверялась бы", census.CachePrints)
	}
	if len(findings) != 0 {
		t.Fatalf("исправный рецепт объявлен находкой: %v — мера ловит форму, а не существо", findings)
	}
}

// TestInjection_SoftAssignmentIsAFinding — ось 2, ЖЁСТКОСТЬ.
func TestInjection_SoftAssignmentIsAFinding(t *testing.T) {
	f := sound()
	f.op = "?=" // единственный изменённый факт
	_, findings := scanLintCache(writeLintCacheRecipe(t, f))
	if !anyContains(findings, "?=") {
		t.Fatalf("мягкое присваивание не найдено: %v — унаследованная переменная вернула бы общий кэш", findings)
	}
}

// TestInjection_UnanchoredValueIsAFinding — ось 3, ЯКОРЬ.
func TestInjection_UnanchoredValueIsAFinding(t *testing.T) {
	f := sound()
	f.val = "/home/dk/.cache/golangci-lint" // единственный изменённый факт
	_, findings := scanLintCache(writeLintCacheRecipe(t, f))
	if !anyContains(findings, "$(CURDIR)") {
		t.Fatalf("неякоренное значение не найдено: %v — у двух копий кэш снова один", findings)
	}
}

// TestInjection_MissingExportIsAFinding — ось 4, ВЫВОЗ.
func TestInjection_MissingExportIsAFinding(t *testing.T) {
	f := sound()
	f.export = false // единственный изменённый факт
	_, findings := scanLintCache(writeLintCacheRecipe(t, f))
	if !anyContains(findings, "не экспортирован") {
		t.Fatalf("потерянный `export` не найден: %v — до дочернего процесса значение не доедет", findings)
	}
}

// TestInjection_SilentLintTargetIsAFinding — ось 5, ПЕРЕПИСЬ.
func TestInjection_SilentLintTargetIsAFinding(t *testing.T) {
	f := sound()
	f.print = false // единственный изменённый факт
	_, findings := scanLintCache(writeLintCacheRecipe(t, f))
	if !anyContains(findings, "не печатает кэш") {
		t.Fatalf("молчащая цель не найдена: %v — «чисто» неотличимо от «судил не то дерево»", findings)
	}
}

// TestInjection_CommentedOutSoftAssignmentIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ.
//
// Против контроля отличается ровно одним фактом: добавлена ЗАКОММЕНТИРОВАННАЯ
// мягкая форма. Исполняемая часть не изменилась, значит мера обязана молчать —
// иначе она судит текст, а не то, что рецепт делает.
func TestInjection_CommentedOutSoftAssignmentIsSilent(t *testing.T) {
	f := sound()
	f.extra = "# GOLANGCI_LINT_CACHE ?= /tmp/shared-cache" // единственный изменённый факт
	census, findings := scanLintCache(writeLintCacheRecipe(t, f))
	if census.Assignments != 1 {
		t.Fatalf("комментарий засчитан присваиванием: %d — мера читает текст, а не рецепт", census.Assignments)
	}
	if len(findings) != 0 {
		t.Fatalf("гейт покраснел на собственном объяснении: %v", findings)
	}
}

// TestInjection_AbsentRecipeIsAFinding — пустой обход есть поломка, а не чистота.
func TestInjection_AbsentRecipeIsAFinding(t *testing.T) {
	census, findings := scanLintCache(t.TempDir())
	if census.LinesRead != 0 {
		t.Fatalf("рецепта нет, а строки прочитаны: %d", census.LinesRead)
	}
	if len(findings) == 0 {
		t.Fatal("отсутствие рецепта прошло молча — «ноль находок» стало неотличимо от «ноль прочитанного»")
	}
}

// anyContains — есть ли среди находок та, что несёт подстроку.
func anyContains(findings []string, sub string) bool {
	for _, f := range findings {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}
