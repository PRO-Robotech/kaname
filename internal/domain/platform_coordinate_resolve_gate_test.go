// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_coordinate_resolve_gate_test.go — координату от корня платформы
// резолвит ДЕТЕКТОР ПОСАДКИ, а не собственный подъём по дереву (задача #2160).
//
// # Предмет
//
// Пробы этого пакета судят контракт роли и страницу арендатора. Контракт лежит
// НАД модулем (`proto/…` корня платформы) и в поставку модуля не входит; страница
// лежит ВНУТРИ него. Значит у прогона две посадки, и в одной из них предмет части
// проб отсутствует BY CONSTRUCTION — это «условие не создано», третий исход, и он
// не вычитается из вердикта и не зачитывается в успех.
//
// Назначить этот исход можно двумя способами, и они РАЗНЫЕ:
//
//	детектор посадки  — `internal/treeposture` спрашивает, лежит ли модуль в
//	                    каталоге модулей ЭТОГО дерева, и только потом приводит
//	                    координату. Чужое дерево над клоном ему не годится;
//	свой подъём       — цикл, ищущий файл по координате у каждого предка. Он
//	                    судит по НАЛИЧИЮ ФАЙЛА, поэтому в клоне, стоящем под
//	                    чужим деревом с той же координатой, находит ЧУЖОЙ файл и
//	                    выносит вердикт о нём.
//
// # Цена измерена, а не предположена
//
// Клон модуля положен под дерево, несущее `proto/kaname/cloud/iam/v1/role.proto`
// с другим содержимым. Проба, резолвящая ту же координату через `platformtree`
// (`internal/apps/kaname/api/role`), назвала «УСЛОВИЕ НЕ СОЗДАНО» и вышла кодом 0.
// Пробы этого пакета, резолвившие своим подъёмом, прочитали ЧУЖОЙ контракт,
// напечатали НАХОДКУ о нём и вышли кодом 1. Один и тот же исход, два ответа, и
// машинный неверен — ровно класс задачи #2160.
//
// # Что гейт судит и чего не судит
//
// Судит УПОТРЕБЛЕНИЕ: несёт ли файл координату от корня платформы и чем он её
// резолвит. Не судит, ПРАВИЛЬНАЯ ли координата — это предмет самой пробы.
//
// Читается ИСПОЛНЯЕМАЯ ЧАСТЬ (разбор в синтаксическое дерево), а не текст:
// координата встречается и в объяснениях, и в фикстурах соседних гейтов, и
// проверка по подстроке краснела бы на собственном комментарии.
//
// Способность падать и молчать доказывает не этот прогон, а инъекция
// (`platform_coordinate_resolve_gate_injection_test.go`).
package domain_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// domainPackageDir — координата ЭТОГО пакета от корня платформы.
//
// Записана так же, как всё, что гейт судит, и резолвится тем же детектором:
// гейт, требующий свойства от других, обязан быть его первым носителем. Пакет
// лежит ВНУТРИ модуля, поэтому координата резолвится в ОБЕИХ посадках и пропуска
// здесь не бывает.
const domainPackageDir = "services/iam/internal/domain"

// platformRootSegments — первые сегменты координат, записанных ОТ КОРНЯ ПЛАТФОРМЫ.
//
// Перечень закрытый и короткий намеренно: он называет каталоги, которые в дереве
// платформы лежат РЯДОМ с каталогом модулей, — то есть ровно те, чьё присутствие
// у арендатора не гарантировано.
var platformRootSegments = map[string]bool{
	"proto":    true,
	"services": true,
	"deploy":   true,
	".github":  true,
}

// resolveCensus — объём осмотренного. Печатается всегда: «ноль находок» обязано
// быть отличимо от «ноль прочитанного».
type resolveCensus struct {
	Files    int
	Coords   int
	Resolves int
	Ascents  int
}

func (c resolveCensus) String() string {
	return fmt.Sprintf(
		"файлов Go прочитано %d · координат от корня платформы %d · "+
			"резолвов через platformtree %d · собственных подъёмов по дереву %d",
		c.Files, c.Coords, c.Resolves, c.Ascents)
}

// isPlatformCoordinate — строка записана координатой ОТ КОРНЯ ПЛАТФОРМЫ.
//
// Требуется разделитель: голое `deploy` — имя каталога, а не координата, и
// засчитывать его значило бы краснеть на слове.
func isPlatformCoordinate(s string) bool {
	head, _, ok := strings.Cut(s, "/")
	return ok && platformRootSegments[head]
}

// auditPlatformCoordinateResolve — разбор ИСХОДНИКОВ на две находки.
//
// Вход — карта «имя файла → его текст», а не каталог: тогда тот же разбор
// прогоняется инъекцией на синтетике, и способность падать доказывается без
// правки настоящего дерева.
func auditPlatformCoordinateResolve(sources map[string]string) ([]string, resolveCensus, error) {
	var (
		findings []string
		census   resolveCensus
	)

	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, sources[name], parser.SkipObjectResolution)
		if err != nil {
			// Неразбираемый исходник — НЕ вердикт: гейт не вправе называть
			// находкой то, чего он не прочитал.
			return nil, census, fmt.Errorf("разбор %s не отработал: %w", name, err)
		}
		census.Files++

		coords, resolves, ascents := auditOneSource(file)
		census.Coords += coords
		census.Resolves += resolves
		census.Ascents += ascents

		// Без координаты предмета нет: подъём сам по себе законен и о посадке
		// ничего не утверждает.
		if coords == 0 {
			continue
		}
		if resolves == 0 {
			findings = append(findings, fmt.Sprintf(
				"%s: координат от корня платформы %d, резолвов через platformtree 0 — "+
					"предпосылку назначает не детектор посадки, и в клоне под чужим "+
					"деревом вердикт будет о чужом дереве", name, coords))
		}
		if ascents > 0 {
			findings = append(findings, fmt.Sprintf(
				"%s: собственных подъёмов по дереву %d рядом с координатой от корня "+
					"платформы — исход назначает НАЛИЧИЕ ФАЙЛА, а не посадка модуля",
				name, ascents))
		}
	}

	return findings, census, nil
}

// auditOneSource — три величины одного файла.
func auditOneSource(file *ast.File) (coords, resolves, ascents int) {
	loops := loopBodies(file)
	inLoop := func(p token.Pos) bool {
		for _, l := range loops {
			if p >= l.from && p < l.to {
				return true
			}
		}
		return false
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.BasicLit:
			if e.Kind != token.STRING {
				return true
			}
			if v, uerr := strconv.Unquote(e.Value); uerr == nil && isPlatformCoordinate(v) {
				coords++
			}
		case *ast.CallExpr:
			sel, ok := e.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch {
			case pkg.Name == "platformtree" && strings.HasPrefix(sel.Sel.Name, "Require"):
				resolves++
			case pkg.Name == "filepath" && sel.Sel.Name == "Join":
				// ВТОРАЯ ЗАКОННАЯ ФОРМА записи координаты, и знать её обязательно:
				// именно ею она была записана здесь до этой правки. Распознаватель,
				// знающий одну форму, оставил бы вторую вне наблюдения молча.
				if len(e.Args) == 0 {
					return true
				}
				lit, ok := e.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if v, uerr := strconv.Unquote(lit.Value); uerr == nil && platformRootSegments[v] {
					coords++
				}
			case pkg.Name == "filepath" && sel.Sel.Name == "Dir" && inLoop(e.Pos()):
				// ПОДЪЁМ — это ЦИКЛ. Одиночное взятие каталога у пути,
				// полученного от детектора, подъёмом не является, и требовать
				// по нему вердикта значило бы краснеть на верном коде.
				ascents++
			}
		}
		return true
	})
	return coords, resolves, ascents
}

// loopSpan — границы тела цикла.
type loopSpan struct{ from, to token.Pos }

func loopBodies(file *ast.File) []loopSpan {
	var out []loopSpan
	ast.Inspect(file, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.ForStmt:
			out = append(out, loopSpan{s.Body.Pos(), s.Body.End()})
		case *ast.RangeStmt:
			out = append(out, loopSpan{s.Body.Pos(), s.Body.End()})
		}
		return true
	})
	return out
}

// readGoSources — исходники Go названного каталога (без подкаталогов).
func readGoSources(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог пакета не прочитан (%s): %v", dir, err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: исходник не прочитан (%s): %v", e.Name(), rerr)
		}
		out[e.Name()] = string(b)
	}
	return out
}

// TestPlatformCoordinatesInThisPackageResolveThroughTheDetector — вердикт о
// НАСТОЯЩЕМ пакете.
func TestPlatformCoordinatesInThisPackageResolveThroughTheDetector(t *testing.T) {
	sources := readGoSources(t, platformtree.RequirePath(t, domainPackageDir))

	findings, census, err := auditPlatformCoordinateResolve(sources)
	if err != nil {
		t.Fatalf("разбор не отработал: %v", err)
	}
	t.Logf("объём осмотренного: %s", census)

	// Премиса: «ноль находок» обязано быть отличимо от «ноль прочитанного».
	// Числа координат здесь НЕ требуется: ноль координат — законная цель (пробы
	// пакета могут перестать судить дерево), а не поломка. Способность
	// распознавателя ИХ ВИДЕТЬ доказывает инъекция, а не это число.
	if census.Files == 0 {
		t.Fatal("обход пуст: ни одного файла Go не прочитано — вердикт беспредметен")
	}

	for _, f := range findings {
		t.Errorf("НАХОДКА: %s", f)
	}
}
