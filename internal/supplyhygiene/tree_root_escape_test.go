// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// tree_root_escape_test.go — код модуля не поднимается ВЫШЕ своего корня
// литеральной цепочкой `../`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Модуль живёт в двух посадках: внутри монорепо (`services/iam`) и
// самостоятельным клоном у арендатора. Цепочка `"../../../.."`, выписанная в
// пробе, есть координата РАСКЛАДКИ монорепо, а не свойство модуля: в первой
// посадке она приводит к корню дерева платформы, во второй — к каталогу, в
// который клон распаковали, то есть к ЧУЖОМУ дереву либо к домашнему каталогу
// того, кто клонировал.
//
// Существенно не то, что проба при этом падает. Существенно, что она ПРОХОДИТ
// там, где по вычисленному пути лежит нечто разбираемое: вердикт выносится о
// чужом дереве и от настоящего неотличим. Наблюдалось прямо (kacho#2254): обход
// манифестов ушёл в исходники тулчейна Go, лежащие в домашнем каталоге, и 38
// секунд разбирал заведомо негодные файлы из его собственного набора проб.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО СУДИТСЯ
//
// Литерал-цепочка `..` (`".."`, `"../.."`, `"../../../.."`) сопоставляется с
// ГЛУБИНОЙ каталога, в котором он написан, отсчитанной от корня модуля:
//
//	звеньев ≤ глубины  → путь остаётся в модуле. Законно, молчим;
//	звеньев >  глубины → путь выходит за модуль. НАХОДКА.
//
// Граница именно такая: цепочка, приводящая РОВНО в корень модуля
// (`"../.."` из `internal/errors`), верна в обеих посадках, потому что корень
// модуля есть в обеих. Цепочка на звено длиннее верна ровно в одной.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ДЕЛАТЬ С НАХОДКОЙ
//
// Дерево платформы спрашивается у объявленного владельца —
// `internal/testsupport/platformtree`: в монорепо он возвращает корень, в клоне
// назначает ПРОПУСК с названной предпосылкой (третий исход, а не красное).
// Владелец из обхода исключён и назван ниже: судить его собственные фикстуры
// этой мерой значило бы требовать от резолва не пользоваться тем, что он
// резолвит.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ РАЗБОР, А НЕ ПОИСК ПО ОБРАЗЦУ
//
// Строка `../../../..` встречается в этом дереве не только выражением пути: она
// стоит в комментариях, объясняющих ЭТОТ ЖЕ класс, и в прозе документов. Поиск
// по подстроке краснел бы на собственном объяснении — тот самый класс, который
// корпус ловит (`testing.md` §«Гейт на класс», п. 4). Здесь судится узел
// строкового литерала, полученный разбором.
package supplyhygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// treeRootEscapeExemptDirs — каталоги модуля, чьи литералы этой мерой не
// судятся, и причина по каждому.
//
// Перечень закрыт и мал НАМЕРЕННО: каждая запись — место, куда класс вносят
// незамеченным. Запись, которой больше нечего исключать, обязана быть снята —
// проба это проверяет отдельным утверждением ниже.
var treeRootEscapeExemptDirs = map[string]string{
	"internal/testsupport/platformtree": "объявленный владелец резолва: его собственные " +
		"фикстуры строят синтетические деревья и обязаны выражать подъём напрямую",
}

// dotDotChain — цепочка ли это звеньев `..`, и сколько их.
//
// Принимаются только чистые цепочки: `..`, `../..`, `../../..`. Строка, где
// между звеньями стоит имя (`../pkg/..`), путём-подъёмом не является — её
// корень известен по имени, и посадку она не переживает по другой причине.
func dotDotChain(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	parts := strings.Split(s, "/")
	for _, p := range parts {
		if p != ".." {
			return 0, false
		}
	}
	return len(parts), true
}

// treeRootEscape — одно попадание.
type treeRootEscape struct {
	file  string
	line  int
	lit   string
	links int
	depth int
}

// treeRootEscapeCensus — объём осмотренного. Печатается всегда: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
type treeRootEscapeCensus struct {
	FilesRead  int
	LitsSeen   int
	ChainsSeen int
	InModule   int
	Unparsed   []string
	ExemptHit  map[string]int
}

// judgeTreeRootEscapes — СУЖДЕНИЕ, отделённое от дерева прогона.
//
// Отделено намеренно: гейт, чью способность падать нельзя предъявить иначе как
// поломкой настоящего дерева, доказательства не имеет. Здесь тот же обход
// зовётся на синтетическом корне, и инъекция подаёт ему один изменённый факт.
func judgeTreeRootEscapes(root string) ([]treeRootEscape, treeRootEscapeCensus, error) {
	census := treeRootEscapeCensus{ExemptHit: map[string]int{}}
	var findings []treeRootEscape

	fset := token.NewFileSet()
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if d.IsDir() {
			if _, skip := skippedDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			if _, ok := treeRootEscapeExemptDirs[filepath.ToSlash(rel)]; ok {
				census.ExemptHit[filepath.ToSlash(rel)]++
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		census.FilesRead++

		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			// Негодный по синтаксису файл — не находка этой меры: о нём судит
			// сборка. Но и молчать нельзя: пропуск обязан быть виден.
			census.Unparsed = append(census.Unparsed, filepath.ToSlash(rel))
			return nil
		}

		// Глубина каталога файла от корня: `internal/errors/x_test.go` лежит на
		// глубине 2, поэтому `../..` приводит РОВНО в корень.
		dir := filepath.ToSlash(filepath.Dir(rel))
		depth := 0
		if dir != "." {
			depth = len(strings.Split(dir, "/"))
		}

		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			census.LitsSeen++
			val, uqErr := strconv.Unquote(lit.Value)
			if uqErr != nil {
				return true
			}
			links, isChain := dotDotChain(val)
			if !isChain {
				return true
			}
			census.ChainsSeen++
			if links <= depth {
				census.InModule++
				return true
			}
			findings = append(findings, treeRootEscape{
				file:  filepath.ToSlash(rel),
				line:  fset.Position(lit.Pos()).Line,
				lit:   val,
				links: links,
				depth: depth,
			})
			return true
		})
		return nil
	})
	if walkErr != nil {
		return nil, census, walkErr
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		return findings[i].line < findings[j].line
	})
	return findings, census, nil
}

// TestModuleCodeNeverClimbsAboveItsOwnRoot — литерал-подъём не выходит за корень
// модуля НИ В ОДНОМ файле модуля.
func TestModuleCodeNeverClimbsAboveItsOwnRoot(t *testing.T) {
	root, err := filepath.Abs(serviceRoot)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен: %v", err)
	}

	findings, census, err := judgeTreeRootEscapes(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход модуля сорвался: %v", err)
	}

	if census.FilesRead == 0 {
		t.Fatalf("обход пуст: файлов Go прочитано 0 (корень %s) — «находок ноль» здесь "+
			"неотличимо от «ноль прочитанного», и вердикт беспредметен", root)
	}
	if census.ChainsSeen == 0 {
		t.Fatalf("цепочек подъёма не найдено ни одной при %d прочитанных файлах: "+
			"распознаватель перестал их видеть, и молчание меры ничего не означает",
			census.FilesRead)
	}
	for _, u := range census.Unparsed {
		t.Logf("НЕ РАЗОБРАН (вердикт по нему не выносится): %s", u)
	}

	for dir := range treeRootEscapeExemptDirs {
		if census.ExemptHit[dir] == 0 {
			t.Errorf("послаблению нечего исключать: каталог %s обходом не встречен — "+
				"запись пережила свой предмет и обязана быть снята", dir)
		}
	}

	for _, f := range findings {
		t.Errorf("%s:%d: подъём %q выходит ЗА КОРЕНЬ МОДУЛЯ: звеньев %d при глубине "+
			"каталога %d. В монорепо это корень дерева платформы, в самостоятельном "+
			"клоне — каталог, в который клон распаковали: вердикт выносится о ЧУЖОМ "+
			"дереве и от настоящего неотличим. Дерево платформы спрашивается у "+
			"`internal/testsupport/platformtree` (Require/RequirePath): в монорепо оно "+
			"есть, в клоне назначается ПРОПУСК с названной предпосылкой",
			f.file, f.line, f.lit, f.links, f.depth)
	}

	t.Logf("перепись: файлов Go прочитано %d · строковых литералов осмотрено %d · "+
		"цепочек подъёма %d, из них внутри модуля %d · выходящих за модуль %d · "+
		"не разобрано %d · каталогов-послаблений %d",
		census.FilesRead, census.LitsSeen, census.ChainsSeen, census.InModule,
		len(findings), len(census.Unparsed), len(treeRootEscapeExemptDirs))
}
