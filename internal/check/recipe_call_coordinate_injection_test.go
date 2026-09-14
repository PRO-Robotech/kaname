// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recipe_call_coordinate_injection_test.go — доказательство падучести гейта
// TestRecipeCallNamesADirectoryOfThisTree.
//
// Гейт, чью способность падать никто не проверял, неотличим от мёртвого: он
// молчит одинаково и на исправном рецепте, и на сломанном. Поэтому по каждой оси
// здесь стоит ПАРА — внесённый дефект и ЗАКОННЫЙ БЛИЗНЕЦ той же формы, на
// котором гейт обязан смолчать.
//
// Инъекция гоняет ТЕ ЖЕ функции, что держатель по дереву: живой рецепт ради
// доказательства не правится — правка сделала бы вердикт функцией рабочего
// каталога и трогала бы копию, в которой работают соседние полосы.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// injRecipeHome — дом синтетического дерева инъекции.
const injRecipeHome = "PRO-Robotech/kaname"

// injRecipeDirs — каталоги, которые синтетическое дерево отслеживает.
func injRecipeDirs() map[string]bool {
	return check.TrackedDirsOf([]string{"tools/auditlistfilter/main.go", "deploy/values.yaml"})
}

// injRecipeJudge — весь путь суждения на синтетическом рецепте. ТЕ ЖЕ функции,
// что зовёт держатель по дереву.
func injRecipeJudge(t *testing.T, body string) check.RecipeCallCensus {
	t.Helper()
	calls, lines, comments := check.RecipeCallsOf(body, injRecipeHome)
	c := check.JudgeRecipeCalls(calls, injRecipeDirs())
	c.Lines, c.Comments = lines, comments
	t.Logf("осмотрено: строк %d · комментариев %d · вызовов %d · называют каталог %d · "+
		"освобождено %d · резолвится %d · находок %d",
		c.Lines, c.Comments, c.Calls, c.Dirs, c.Exempt, c.Resolved, len(c.Findings))
	return c
}

func injRecipeOnly(t *testing.T, c check.RecipeCallCensus, want string) {
	t.Helper()
	if len(c.Findings) == 0 {
		t.Fatalf("находок ноль, а ожидалась хотя бы одна про %q — гейт не умеет краснеть", want)
	}
	for _, f := range c.Findings {
		if strings.Contains(f, want) {
			return
		}
	}
	t.Fatalf("ни одна находка не называет %q:\n%s", want, strings.Join(c.Findings, "\n"))
}

func injRecipeSilent(t *testing.T, c check.RecipeCallCensus) {
	t.Helper()
	if len(c.Findings) > 0 {
		t.Fatalf("законный рецепт дал находки — гейт краснеет на верной работе:\n%s",
			strings.Join(c.Findings, "\n"))
	}
}

// TestInjection_RecipeCallToAMissingDirectoryIsFound — ОСЬ A: каталог, которого
// в дереве нет, есть находка, и она называет КООРДИНАТУ строки.
func TestInjection_RecipeCallToAMissingDirectoryIsFound(t *testing.T) {
	t.Parallel()
	c := injRecipeJudge(t, "# Вызов: `make -C services/iam cla-check`\n")
	injRecipeOnly(t, c, "services/iam")
	if !strings.Contains(strings.Join(c.Findings, "\n"), "Makefile:1") {
		t.Fatalf("находка не назвала номера строки — читателю негде искать:\n%s",
			strings.Join(c.Findings, "\n"))
	}
}

// TestInjection_RecipeCallToALiveDirectoryIsSilent — ОСЬ A, ЗАКОННЫЙ БЛИЗНЕЦ:
// та же форма вызова с каталогом, который в дереве ЕСТЬ, молчит.
//
// Без этой оси ось A доказывала бы только то, что гейт умеет краснеть, — а
// краснеть на всём умеет и сломанный.
func TestInjection_RecipeCallToALiveDirectoryIsSilent(t *testing.T) {
	t.Parallel()
	c := injRecipeJudge(t, "# Вызов: `make -C deploy fga-model-embed`\n")
	injRecipeSilent(t, c)
	if c.Resolved != 1 {
		t.Fatalf("законный вызов не засчитан резолвящимся: резолвится %d", c.Resolved)
	}
}

// TestInjection_RecipeGluedChdirFormIsParsed — ОСЬ B: приклеенная форма ключа
// (`-C<кат>`) разбирается наравне с раздельной.
//
// Форма, о которой разбор не знает, даёт не красное и не зелёное, а МОЛЧАНИЕ:
// всё записанное в ней уходит из-под наблюдения, не дав ни одной находки.
func TestInjection_RecipeGluedChdirFormIsParsed(t *testing.T) {
	t.Parallel()
	c := injRecipeJudge(t, "# Вызов: `make -Cservices/iam cla-check`\n")
	injRecipeOnly(t, c, "services/iam")
}

// TestInjection_RecipeProseMentionIsNotACall — ОСЬ C: та же координата ПРОЗОЙ
// находкой не является.
//
// Ось несущая: подстрока `services/iam` законно стоит в объяснениях прошлых
// дефектов, и гейт по подстроке краснел бы на собственном объяснении.
func TestInjection_RecipeProseMentionIsNotACall(t *testing.T) {
	t.Parallel()
	c := injRecipeJudge(t,
		"# Прежде ведомость объявляла свою область координатой монорепо (`services/iam`),\n"+
			"# и подъём ради пути `./services/iam/...` отказывал.\n"+
			"# Вызов: `make cla-check`\n")
	injRecipeSilent(t, c)
	if c.Calls != 1 {
		t.Fatalf("строк вызова распознано %d, а в мире она одна: проза принята за вызов "+
			"либо вызов потерян", c.Calls)
	}
}

// TestInjection_RecipeForeignRepoLineIsExempt — ОСЬ D: строка, назвавшая ЧУЖОЙ
// репозиторий, освобождается, и освобождение ВИДНО в переписи.
//
// Требовать координат чужого дерева отсюда значило бы завести находку на
// правдивой записи; умолчать освобождение — завести слепую зону ровно того
// размера, которого никто не видит.
func TestInjection_RecipeForeignRepoLineIsExempt(t *testing.T) {
	t.Parallel()
	c := injRecipeJudge(t,
		"# Вызов в дереве PRO-Robotech/kacho: `make -C services/vpc newman`\n")
	injRecipeSilent(t, c)
	if c.Exempt != 1 {
		t.Fatalf("освобождение не названо числом: освобождено %d из %d названных каталогов — "+
			"невидимое исключение есть слепая зона", c.Exempt, c.Dirs)
	}
}

// TestInjection_RecipeOwnRepoMentionIsNotForeign — ОСЬ D, ЗАКОННЫЙ БЛИЗНЕЦ:
// упоминание СВОЕГО дома освобождения не даёт.
//
// Без этой оси освобождение снимало бы проверку со всякой строки, где вообще
// назван репозиторий организации, — то есть работало бы маской.
func TestInjection_RecipeOwnRepoMentionIsNotForeign(t *testing.T) {
	t.Parallel()
	c := injRecipeJudge(t,
		"# Дом этого дерева — PRO-Robotech/kaname; вызов: `make -C services/iam cla-check`\n")
	injRecipeOnly(t, c, "services/iam")
	if c.Exempt != 0 {
		t.Fatalf("своё упоминание дома дало освобождение (%d) — исключение стало маской", c.Exempt)
	}
}

// TestInjection_RecipeCallWithoutAChdirIsNotJudged — ОСЬ E: вызов без ключа
// каталога предметом не является.
//
// Иначе гейт требовал бы каталога от `make build` и краснел бы на всяком
// обычном вызове.
func TestInjection_RecipeCallWithoutAChdirIsNotJudged(t *testing.T) {
	t.Parallel()
	c := injRecipeJudge(t, "# Вызов: `make cla-check` и `go test ./internal/check/`\n")
	injRecipeSilent(t, c)
	if c.Calls != 2 {
		t.Fatalf("строк вызова распознано %d, а в мире их две", c.Calls)
	}
	if c.Dirs != 0 {
		t.Fatalf("вызов без ключа `-C` засчитан называющим каталог: %d", c.Dirs)
	}
}

// TestInjection_RecipeNonCommentLineIsNotJudged — ОСЬ F: ИСПОЛНЯЕМАЯ строка
// рецепта комментарием не является.
//
// Предмет гейта — обещание, данное ЧИТАТЕЛЮ комментарием. Рецепт, реально
// зовущий соседа по дереву, судится прогоном, а не этим разбором.
func TestInjection_RecipeNonCommentLineIsNotJudged(t *testing.T) {
	t.Parallel()
	c := injRecipeJudge(t, "target:\n\tmake -C services/iam cla-check\n")
	injRecipeSilent(t, c)
	if c.Calls != 0 {
		t.Fatalf("исполняемая строка принята за комментарий: вызовов %d", c.Calls)
	}
}

// TestInjection_RecipeEmptyWalkIsVisibleInTheCensus — ОСЬ G: пустой обход виден
// ЧИСЛАМИ, а не выдаёт себя за «находок нет».
func TestInjection_RecipeEmptyWalkIsVisibleInTheCensus(t *testing.T) {
	t.Parallel()
	c := injRecipeJudge(t, "target:\n\techo без единого комментария\n")
	if c.Comments != 0 || c.Calls != 0 {
		t.Fatalf("рецепт без комментариев дал комментариев %d и вызовов %d", c.Comments, c.Calls)
	}
	if len(c.Findings) != 0 {
		t.Fatalf("пустой обход дал находки: %s", strings.Join(c.Findings, "\n"))
	}
	// Держатель по дереву на таком входе ОТКАЗЫВАЕТ (премиса `c.Comments == 0`);
	// здесь доказано, что величина, на которой стоит его премиса, действительно
	// обнуляется, — иначе премиса не исполнилась бы НИ РАЗУ.
}
