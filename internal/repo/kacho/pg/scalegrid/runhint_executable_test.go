// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// runhint_executable_test.go — КОМАНДА ПЕРЕСЪЁМА, КОТОРУЮ ПЕЧАТАЕТ ГЕЙТ,
// ОБЯЗАНА ИСПОЛНЯТЬСЯ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Гейты свежести отказывают словами «переснять вот так» и печатают команду.
// Команда — часть свойства гейта, а не украшение: находка, посылающая читателя
// исполнять то, что не исполнится, стоит ему захода и снимается следующим как
// непонятная (`testing.md` §«Гейт на класс», п. 8).
//
// После выноса службы в собственный модуль (`github.com/PRO-Robotech/kacho-iam`)
// образец пакета `./services/iam/internal/...` из корня дерева НЕ РЕЗОЛВИТСЯ
// вовсе: корневой модуль этих пакетов больше не содержит. Две подсказки из
// четырёх переехали на форму `-C services/iam ./internal/...`, две остались на
// прежней — и никто этого не решал. Это ровно класс «параллельные полосы одного
// механизма обязаны сверяться между собой» (`architecture.md`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ РАЗБОР, А НЕ ПОИСК ПО ОБРАЗЦУ
//
// Построчный поиск этого класса НЕ ИЗМЕРЯЕТ, и это проверено: обе негодные
// подсказки записаны СКЛЕЙКОЙ, где слова `go test ` и образец пакета стоят на
// РАЗНЫХ строках, —
//
//	const matrixRunCommand = "KACHO_MATRIX_VOLUME=1 go test " +
//		"./services/iam/internal/repo/kacho/pg/relverdict/ -run …"
//
// поэтому `grep 'go test .*\./'` находил пять годных подсказок и НИ ОДНОЙ
// негодной. Распознаватель, не знающий склейки, молчит именно там, где предмет
// и живёт (`testing.md` §«Гейт на класс», п. 7).
//
// Разбор вдобавок отличает литерал от КОММЕНТАРИЯ: в соседнем файле пакета
// строка `go test ./...` стоит в объяснении, а не в команде, и поиск по тексту
// подал бы её находкой.
package scalegrid_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// hintDirs — каталоги, чьи пробы печатают команды пересъёма.
//
// Оба, а не один: гейт свежести сетки живёт в `scalegrid`, гейт свежести объёма
// матрицы — в `relverdict`, и негодная подсказка нашлась в КАЖДОМ.
var hintDirs = []string{
	"services/iam/internal/repo/kacho/pg/relverdict",
	"services/iam/internal/repo/kacho/pg/scalegrid",
}

// resnapshotCommand — одна найденная команда: где записана и что просит запустить.
type resnapshotCommand struct {
	// File — путь относительно корня дерева.
	File string
	// Line — строка объявления, чтобы находка называла ВИНОВНИКА.
	Line int
	// Text — склеенный текст команды целиком.
	Text string
	// Dir — значение ключа -C, если он есть; иначе пусто (корень дерева).
	Dir string
	// Patterns — образцы пакетов (аргументы, начинающиеся с "./").
	Patterns []string
}

// collectCensus — объём осмотренного. Печатается всегда, чтобы «ноль находок»
// было отличимо от «ноль прочитанного».
type collectCensus struct {
	Files    int
	Literals int
	Commands int
}

// foldString — склейка строковых литералов в одно значение.
//
// Возвращает ok=false, как только в склейке встречается не-литерал: додумывать
// значение выражения гейт не вправе — он либо прочитал команду целиком, либо не
// прочитал её вовсе.
func foldString(expr ast.Expr) (string, bool) {
	switch node := expr.(type) {
	case *ast.BasicLit:
		if node.Kind != token.STRING {
			return "", false
		}
		value, err := strconv.Unquote(node.Value)
		if err != nil {
			return "", false
		}
		return value, true
	case *ast.BinaryExpr:
		if node.Op != token.ADD {
			return "", false
		}
		left, ok := foldString(node.X)
		if !ok {
			return "", false
		}
		right, ok := foldString(node.Y)
		if !ok {
			return "", false
		}
		return left + right, true
	case *ast.ParenExpr:
		return foldString(node.X)
	}
	return "", false
}

// parseCommand — разбор склеенного текста на каталог (-C) и образцы пакетов.
func parseCommand(text string) (dir string, patterns []string) {
	fields := strings.Fields(text)
	for i := 0; i < len(fields); i++ {
		switch {
		case fields[i] == "-C" && i+1 < len(fields):
			dir = fields[i+1]
			i++
		case strings.HasPrefix(fields[i], "./"):
			patterns = append(patterns, fields[i])
		}
	}
	return dir, patterns
}

// collectResnapshotCommands — обход каталога: все `_test.go`, разобранные как Go.
//
// Каталог берётся АБСОЛЮТНЫМ, чтобы проба способности упасть могла навести этот
// же обход на синтетику, а не на дерево.
func collectResnapshotCommands(absDir, relDir string) ([]resnapshotCommand, collectCensus, error) {
	var census collectCensus
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return nil, census, fmt.Errorf("состав %s: %w", absDir, err)
	}

	var found []resnapshotCommand
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, rerr := os.ReadFile(filepath.Join(absDir, name)) // #nosec G304 -- обход СОБСТВЕННОГО каталога проб, путь не из запроса
		if rerr != nil {
			return nil, census, fmt.Errorf("чтение %s: %w", name, rerr)
		}
		// Комментарии НЕ разбираются намеренно: предмет — исполняемая часть.
		file, perr := parser.ParseFile(fset, name, body, parser.SkipObjectResolution)
		if perr != nil {
			// Неразобранный файл — ОТКАЗ, а не молчание: пропустить его значило
			// бы вынести из-под гейта то, что мы не прочитали.
			return nil, census, fmt.Errorf("не разбирается как Go %s: %w", name, perr)
		}
		census.Files++

		ast.Inspect(file, func(node ast.Node) bool {
			expr, ok := node.(ast.Expr)
			if !ok {
				return true
			}
			switch expr.(type) {
			case *ast.BasicLit, *ast.BinaryExpr, *ast.ParenExpr:
			default:
				return true
			}
			text, ok := foldString(expr)
			if !ok {
				return true
			}
			census.Literals++
			if strings.Contains(text, "go test ") {
				dir, patterns := parseCommand(text)
				if len(patterns) > 0 {
					census.Commands++
					found = append(found, resnapshotCommand{
						File:     relDir + "/" + name,
						Line:     fset.Position(expr.Pos()).Line,
						Text:     text,
						Dir:      dir,
						Patterns: patterns,
					})
				}
			}
			// Склейка прочитана целиком — внутрь не спускаемся, иначе её части
			// сосчитались бы второй раз.
			return false
		})
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].File != found[j].File {
			return found[i].File < found[j].File
		}
		return found[i].Line < found[j].Line
	})
	return found, census, nil
}

// resolves — РЕЗОЛВИТСЯ ли образец пакета на самом деле.
//
// Исход, а не объявление: вместо запрета на подстроку спрашивается тот же
// инструмент, которым читатель будет исполнять команду.
func resolves(root string, cmd resnapshotCommand, pattern string) error {
	args := []string{"list"}
	if cmd.Dir != "" {
		args = append(args, "-C", cmd.Dir)
	}
	args = append(args, pattern)
	run := exec.Command("go", args...) // #nosec G204 -- аргументы взяты из СОБСТВЕННЫХ проб дерева, не из запроса
	run.Dir = root
	out, err := run.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// TestEveryResnapshotHintNamesAResolvablePackage — гейт.
func TestEveryResnapshotHintNamesAResolvablePackage(t *testing.T) {
	root := repoRoot(t)

	var all []resnapshotCommand
	var total collectCensus
	for _, relDir := range hintDirs {
		found, census, err := collectResnapshotCommands(filepath.Join(root, relDir), relDir)
		if err != nil {
			t.Fatalf("обход %s: %v", relDir, err)
		}
		all = append(all, found...)
		total.Files += census.Files
		total.Literals += census.Literals
		total.Commands += census.Commands
	}

	// Предпосылка: предмет существует. Пустой обход — отказ, а не тишина:
	// молчание гейта тогда означало бы «ноль прочитанного», а не «ноль находок».
	if total.Files == 0 {
		t.Fatalf("прочитано НОЛЬ файлов проб в %v — у гейта исчез предмет, и его "+
			"молчание не означало бы исполнимости команд", hintDirs)
	}
	if len(all) == 0 {
		t.Fatalf("команд пересъёма НЕ НАЙДЕНО ни одной при %d прочитанных файлах: "+
			"либо подсказки сняты, либо распознаватель перестал знать форму их записи",
			total.Files)
	}

	var findings []string
	checked := 0
	for _, cmd := range all {
		for _, pattern := range cmd.Patterns {
			checked++
			if err := resolves(root, cmd, pattern); err != nil {
				where := "из корня дерева"
				if cmd.Dir != "" {
					where = "с -C " + cmd.Dir
				}
				findings = append(findings, fmt.Sprintf(
					"%s:%d — образец %q %s НЕ РЕЗОЛВИТСЯ: %v\n      команда: %s",
					cmd.File, cmd.Line, pattern, where, err, cmd.Text))
			}
		}
	}

	t.Logf("перепись: файлов проб прочитано %d, склеенных литералов %d, "+
		"команд с образцом пакета %d, образцов проверено %d",
		total.Files, total.Literals, total.Commands, checked)

	if len(findings) > 0 {
		t.Fatalf("команд пересъёма, которые НЕ ИСПОЛНЯТСЯ: %d из %d\n  %s\n\n"+
			"Гейт печатает эту команду читателю как «переснять вот так». "+
			"После выноса службы в собственный модуль образец ./services/iam/... "+
			"из корня не резолвится — форма стала `-C services/iam ./internal/...`.",
			len(findings), checked, strings.Join(findings, "\n  "))
	}
}

// TestResnapshotHintCheckerCanFail — способность гейта упасть и смолчать,
// доказанная НАСТОЯЩИМ входом в обе стороны.
//
// Обе подсказки резолвятся тем же `go list` против ТОГО ЖЕ дерева, что и в
// гейте выше: подделки здесь нет, различие между случаями — РОВНО ОДНО
// (переехал ли образец на форму `-C services/iam`).
func TestResnapshotHintCheckerCanFail(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()

	// СИНТЕТИКА СОБИРАЕТСЯ, А НЕ ПИШЕТСЯ ЦЕЛИКОМ — и это не стиль.
	//
	// Первая редакция держала её ЦЕЛЫМИ литералами, и гейт выше нашёл САМ СЕБЯ:
	// он обходит и этот файл тоже, склеил фикстуру и подал её находкой наравне
	// с настоящими подсказками. Ровно тот класс, который корпус ловит, — гейт,
	// сработавший на собственном объяснении.
	//
	// Сборка через ПЕРЕМЕННУЮ делает фикстуру невидимой распознавателю by
	// construction: склейка с не-литералом не сворачивается, поэтому ни один
	// литерал этого файла не несёт «go test » и образец пакета ОДНОВРЕМЕННО.
	//
	// Отсюда названная ГРАНИЦА гейта: подсказку, собранную из переменных, он не
	// увидит. Сегодня таких нет — все 10 найденных записаны литералами, — а
	// перепись в выводе покажет, если их число поедет.
	stalePattern := "./services/iam/internal/repo/kacho/pg/relverdict/"
	movedPattern := "./internal/repo/kacho/pg/relverdict/"
	prosePattern := "./services/iam/nowhere/"

	stale := "package p\n\nconst staleHint = \"KACHO_X=1 go test \" +\n\t\"" +
		stalePattern + " -run TestX -count=1\"\n"
	moved := "package p\n\nconst movedHint = \"KACHO_X=1 go test -C services/iam \" +\n\t\"" +
		movedPattern + " -run TestX -count=1\"\n"
	// Команда в КОММЕНТАРИИ — не команда: законный близнец распознавателя.
	inProse := "package p\n\n// Прогон поднимает контейнеры, поэтому go test " +
		prosePattern + " его не зовёт.\nconst unrelated = 1\n"

	for name, src := range map[string]string{
		"stale_test.go": stale, "moved_test.go": moved, "prose_test.go": inProse,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatalf("синтетика %s: %v", name, err)
		}
	}

	found, census, err := collectResnapshotCommands(dir, "синтетика")
	if err != nil {
		t.Fatalf("обход синтетики: %v", err)
	}
	if census.Files != 3 {
		t.Fatalf("прочитано %d файлов синтетики, ожидалось 3", census.Files)
	}
	// Проза командой не считается — иначе гейт краснел бы на собственном объяснении.
	if len(found) != 2 {
		t.Fatalf("распознано %d команд, ожидалось 2 (проза не команда): %+v", len(found), found)
	}

	var sawStale, sawMoved bool
	for _, cmd := range found {
		for _, pattern := range cmd.Patterns {
			err := resolves(root, cmd, pattern)
			switch {
			case strings.HasPrefix(cmd.File, "синтетика") && cmd.Dir == "":
				sawStale = true
				if err == nil {
					t.Errorf("образец %q без -C РЕЗОЛВИЛСЯ из корня — гейт потерял "+
						"способность падать: негодную подсказку он объявит годной", pattern)
				}
			default:
				sawMoved = true
				if err != nil {
					t.Errorf("образец %q с -C %s НЕ резолвится (%v) — гейт краснеет "+
						"на ЗАКОННОЙ форме и будет снят первым же срабатыванием",
						pattern, cmd.Dir, err)
				}
			}
		}
	}
	if !sawStale || !sawMoved {
		t.Fatalf("обе стороны обязаны быть предъявлены: негодная=%v, законная=%v",
			sawStale, sawMoved)
	}
}
