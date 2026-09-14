// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lint_cache_per_worktree_test.go — линтер судит СВОЁ дерево, а не соседнее.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Кэш golangci-lint по умолчанию один на машину (`~/.cache/golangci-lint`), а
// запись в нём ключуется СОДЕРЖИМЫМ пакета, не деревом. Рабочих копий этого
// модуля на машине разработки десятки, и у одинакового содержимого ключ один:
// прогон в одной копии возвращает разбор, снятый в ДРУГОЙ, — с чужими путями.
//
// Чужой путь мимо якорных исключений конфигурации (`^internal/…`) не матчит
// ничего, поэтому исключения перестают применяться МОЛЧА, и «0 issues» и
// «64 находки» становятся одинаково недостоверными. Заметить подмену по выводу
// нечем: координаты выглядят своими.
//
// Цена измерена одним фактом различия, а не предположена. Два синтетических
// дерева с ОДИНАКОВЫМ содержимым и одинаковым путём модуля; прогон в первом
// заселяет кэш, прогон во втором его читает; различие между инъекцией и
// контролем — ТОЛЬКО каталог кэша:
//
//	общий кэш → ../aaa/probe.go:3:6: type base is unused (unused)
//	свой кэш  →     probe.go:3:6: type base is unused (unused)
//
// Вердикт назвал файл ЧУЖОГО дерева. Та же форма наблюдалась на живом дереве
// (`../w2-domain-base/internal/apps/kaname/api/user/user_test.go`, kacho#2642).
//
// ─────────────────────────────────────────────────────────────────────────────
// МЕХАНИЗМ ЕСТЬ С 2026-08-05, И ДО СИХ ПОР ЕГО НЕ ДЕРЖАЛО НИЧТО
//
// Рецепт прибивает кэш к каталогу рабочей копии (`77e00ab8`). Это верно и
// работает — но снять эту строку, ослабить `:=` до `?=` или потерять `export`
// можно БЕЗ КРАСНОГО: защита исчезает, а прогон продолжает выглядеть исправным,
// потому что вердикт остаётся правдоподобным. Правило без механизма есть
// пожелание; здесь механизм был, а держателя у него не было.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ — пять осей, каждая закрывает свой отказ
//
//  1. ОБЪЯВЛЕНИЕ. Рецепт называет `GOLANGCI_LINT_CACHE` значением. Нет строки —
//     инструмент уходит на умолчание, то есть на общий кэш машины.
//  2. ЖЁСТКОСТЬ. Присваивание `:=`, а не `?=`/`=`-по-умолчанию: с мягкой формой
//     унаследованная из окружения переменная молча вернула бы общий кэш, и
//     защита осталась бы НА ВИД на месте — худший из отказов, потому что он
//     неотличим от исправного.
//  3. ЯКОРЬ. Значение производится от каталога рабочей копии (`$(CURDIR)`).
//     Фиксированный путь сделал бы кэш общим снова — уже своим именем.
//  4. ВЫВОЗ. Переменная экспортируется: неэкспортированная до дочернего
//     процесса не доедет, и объявление осталось бы украшением.
//  5. ПЕРЕПИСЬ. Цель `lint` ПЕЧАТАЕТ кэш, которым судила. Без этого «чисто»
//     неотличимо от «судил не то дерево»: оба исхода печатают одно и то же.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГЕЙТ СУДИТ ИСПОЛНЯЕМУЮ ЧАСТЬ, А НЕ ТЕКСТ
//
// Присваивание Make стоит в НАЧАЛЕ строки, строка рецепта — с табуляции, а
// строка, чей первый значащий знак `#`, — комментарий. Имя переменной законно
// встречается в прозе этого файла и в шапке рецепта; гейт, краснеющий на
// собственном объяснении, — тот самый класс, который корпус ловит.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
//   - Она судит ОБЪЯВЛЕНИЕ рецепта, а не процесс. Что каталог существует и
//     изолирован, доказывает прогон, а не разбор текста.
//   - Она не связывает того, кто зовёт `golangci-lint` РУКАМИ, в обход рецепта.
//     Именно так и возник kacho#2642: команда воспроизведения в теле задачи
//     зовёт инструмент напрямую. Рецепт защищён, прямой вызов — нет, и это
//     остаток, а не обещание: закрыть его нечем, пока кэш выбирает вызывающий.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// lintCacheRecipe — рецепт сборки относительно корня службы.
const lintCacheRecipe = "Makefile"

// lintCacheVar — переменная, чьё объявление и есть предмет.
const lintCacheVar = "GOLANGCI_LINT_CACHE"

// reLintCacheAssign — присваивание Make: имя стоит в НАЧАЛЕ строки. Строка
// рецепта начинается с табуляции и присваиванием Make не является.
var reLintCacheAssign = regexp.MustCompile(`^` + lintCacheVar + `[ \t]*(\?=|::=|:=|\+=|=)[ \t]*(.*)$`)

// reLintCacheExport — вывоз переменной дочернему процессу.
var reLintCacheExport = regexp.MustCompile(`^export[ \t]+` + lintCacheVar + `\b`)

// lintCacheCensus — объём осмотренного: «ноль находок» обязано быть отличимо от
// «ноль прочитанного».
type lintCacheCensus struct {
	LinesRead       int
	Assignments     int
	Exports         int
	LintRecipeLines int
	CachePrints     int
}

// makeCommentLine — строка, чей первый значащий знак `#`.
func makeCommentLine(s string) bool {
	t := strings.TrimLeft(s, " \t")
	return strings.HasPrefix(t, "#")
}

// scanLintCache — разбор над ПРОИЗВОЛЬНЫМ корнем. Вынесено из пробы затем, чтобы
// способность гейта упасть доказывалась подачей входа, а не чтением.
func scanLintCache(root string) (lintCacheCensus, []string) {
	var census lintCacheCensus
	var findings []string

	raw, err := os.ReadFile(filepath.Join(root, lintCacheRecipe))
	if err != nil {
		return census, append(findings, lintCacheRecipe+": не прочитан: "+err.Error()+
			" — о том, каким кэшем судит линтер, не сказано ничего, и зелёное здесь означало бы «не читали»")
	}

	lines := strings.Split(string(raw), "\n")
	census.LinesRead = len(lines)

	var assignOp, assignVal string
	inLintRecipe := false
	for _, ln := range lines {
		if makeCommentLine(ln) {
			continue
		}
		if m := reLintCacheAssign.FindStringSubmatch(ln); m != nil {
			census.Assignments++
			assignOp, assignVal = m[1], strings.TrimSpace(m[2])
			if i := strings.Index(assignVal, "#"); i >= 0 {
				assignVal = strings.TrimSpace(assignVal[:i])
			}
		}
		if reLintCacheExport.MatchString(ln) {
			census.Exports++
		}

		// Блок цели `lint`: начинается объявлением в начале строки и кончается
		// первой непустой строкой, которая рецептом не является.
		if strings.HasPrefix(ln, "lint:") {
			inLintRecipe = true
			continue
		}
		if inLintRecipe {
			if strings.TrimSpace(ln) == "" {
				continue
			}
			if !strings.HasPrefix(ln, "\t") {
				inLintRecipe = false
				continue
			}
			census.LintRecipeLines++
			if strings.Contains(ln, "echo") &&
				(strings.Contains(ln, "$("+lintCacheVar+")") || strings.Contains(ln, "${"+lintCacheVar+"}")) {
				census.CachePrints++
			}
		}
	}

	// 1. ОБЪЯВЛЕНИЕ.
	if census.Assignments == 0 {
		findings = append(findings, lintCacheRecipe+": `"+lintCacheVar+"` рецептом не объявлен — "+
			"инструмент уходит на умолчание `~/.cache/golangci-lint`, общее на машину, и возвращает "+
			"разбор соседней рабочей копии того же модуля с ЧУЖИМИ путями (kacho#2642)")
	} else {
		// 2. ЖЁСТКОСТЬ.
		if assignOp != ":=" && assignOp != "::=" {
			findings = append(findings, lintCacheRecipe+": `"+lintCacheVar+"` присвоен через `"+assignOp+
				"` — мягкая форма отдаёт значение унаследованной из окружения переменной, то есть "+
				"молча возвращает общий кэш, оставляя защиту НА ВИД на месте. Нужно `:=`")
		}
		// 3. ЯКОРЬ.
		if !strings.Contains(assignVal, "$(CURDIR)") && !strings.Contains(assignVal, "${CURDIR}") {
			findings = append(findings, lintCacheRecipe+": `"+lintCacheVar+"` = `"+assignVal+
				"` — значение не производится от каталога рабочей копии (`$(CURDIR)`), значит у двух "+
				"копий модуля кэш снова ОДИН, и вердикт снова принадлежит тому дереву, что заселило запись")
		}
	}

	// 4. ВЫВОЗ.
	if census.Assignments > 0 && census.Exports == 0 {
		findings = append(findings, lintCacheRecipe+": `"+lintCacheVar+"` объявлен, но не экспортирован — "+
			"переменная Make без `export` до дочернего процесса не доезжает, и объявление остаётся украшением")
	}

	// 5. ПЕРЕПИСЬ.
	if census.LintRecipeLines > 0 && census.CachePrints == 0 {
		findings = append(findings, lintCacheRecipe+": цель `lint` не печатает кэш, которым судила — "+
			"«чисто» становится неотличимо от «судил не то дерево», потому что оба исхода печатают одно и то же")
	}

	return census, findings
}

func TestLintCacheIsOwnedByThisWorktree(t *testing.T) {
	t.Parallel()

	census, findings := scanLintCache(serviceRoot)

	t.Logf("перепись: строк рецепта прочитано %d · присваиваний `%s` %d · вывозов %d · "+
		"строк рецепта цели `lint` %d · из них печатающих кэш %d · находок %d",
		census.LinesRead, lintCacheVar, census.Assignments, census.Exports,
		census.LintRecipeLines, census.CachePrints, len(findings))

	// Пустой обход — поломка гейта, а не чистота дерева.
	if census.LinesRead == 0 {
		t.Fatal("рецепт не прочитан ни одной строкой — вердикт беспредметен")
	}
	if census.LintRecipeLines == 0 {
		t.Fatal("цель `lint` в рецепте не найдена — ось переписи вакуумна, " +
			"и её молчание означало бы «не искали», а не «печатает»")
	}

	for _, f := range findings {
		t.Error(f)
	}
}
