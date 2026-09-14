// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recipe_call_coordinate_test.go — TestRecipeCallNamesADirectoryOfThisTree:
// гейт класса «утверждение, пережившее свой предмет», применённый к строке
// ВЫЗОВА в комментарии рецепта сборки.
//
// Предмет, разбор по позициям аргументов и границы — в шапке
// `recipe_call_coordinate.go`. Способность гейта упасть и смолчать доказана
// инъекцией — `recipe_call_coordinate_injection_test.go`.
package check_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

func TestRecipeCallNamesADirectoryOfThisTree(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = corpusRoot + "/" + modulePrefix
	}

	body, err := os.ReadFile(filepath.Join(ownDir, "Makefile")) // #nosec G304 -- корень своего дерева
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рецепт сборки не прочитан: %v", err)
	}
	tracked, err := check.TrackedPathsOfTree(ownDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: отслеживаемые пути не прочитаны: %v", err)
	}
	ownHome, err := check.OwnHomeOfTree(ownDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: дом этого дерева не назван: %v", err)
	}

	calls, lines, comments := check.RecipeCallsOf(string(body), ownHome)
	c := check.JudgeRecipeCalls(calls, check.TrackedDirsOf(tracked))
	c.Lines, c.Comments = lines, comments

	// ПЕРЕПИСЬ ПЕЧАТАЕТ ВСЕ ВЕЛИЧИНЫ. Одно число скрывало бы ровно тот случай,
	// ради которого гейт заведён: рецепт, в котором судить оказалось нечего.
	t.Logf("осмотрено: строк рецепта %d · из них комментариев %d · строк вызова %d · "+
		"из них называют каталог %d · освобождено упоминанием чужого репозитория %d · "+
		"резолвится %d · находок %d · дом этого дерева %s",
		c.Lines, c.Comments, c.Calls, c.Dirs, c.Exempt, c.Resolved, len(c.Findings), ownHome)

	// ГРАНИЦА — ОТДЕЛЬНОЙ СТРОКОЙ, а не умолчанием. Слепая зона, которую видно,
	// есть остаток; слепая зона, о которой молчат, есть дыра.
	t.Log("вне суждения: путь, названный ПРОЗОЙ, и ЦЕЛЬ вызова. Первое — свой предмет " +
		"со своим замером, второе принадлежит гейту провязки (`judge_target_wiring.go`); " +
		"их числа здесь НЕ печатаются намеренно — напечатанный ноль читался бы как " +
		"«искали и не нашли»")

	// Пустой обход — ОТКАЗ, а не пустой успех.
	if c.Comments == 0 {
		t.Fatal("в рецепте не прочитано НИ ОДНОЙ строки-комментария: «ноль находок» здесь " +
			"означало бы «ноль прочитанного»")
	}
	if c.Calls == 0 {
		t.Fatal("в комментариях рецепта не найдено НИ ОДНОЙ строки вызова: разбор перестал " +
			"узнавать форму, которую судит, и молчал бы при любом каталоге")
	}
	// ЦЕЛЬ ЭТОГО ГЕЙТА — НОЛЬ вызовов с `-C`, и на ней он ПРОХОДИТ.
	//
	// Отказ на нулевом числе вызовов-с-каталогом сделал бы идеал поломкой и
	// подталкивал бы держать такой вызов ради зелёного (`testing.md`
	// §«Проба не имеет права падать на ДОСТИЖЕНИИ СВОЕЙ ЦЕЛИ»). Что РАЗБОР жив,
	// доказывают премисы выше: они судят, узнаёт ли он комментарий и форму
	// вызова, — а это свойство разбора, тогда как число каталогов есть свойство
	// дерева.
	if c.Dirs == 0 {
		t.Log("вызовов с ключом `-C` в рецепте НЕТ — это цель гейта, а не пустой обход: " +
			"каталога, который мог бы не резолвиться, здесь просто не называют")
	}

	for _, f := range c.Findings {
		t.Error(f)
	}
}
