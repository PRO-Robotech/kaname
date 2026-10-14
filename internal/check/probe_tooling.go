// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// probe_tooling.go — ОСНАСТКА ПРОБ: не-тестовые файлы Go под
// `internal/testsupport/`, которые импортируют только пробы (задача
// PRO-Robotech/kaname#816).
//
// # ПРЕДМЕТ
//
// Гейты прод-кода не судят файлы проб: пробе законно назвать таблицу секрета
// и поставить отметку, которую продукт ставит лишь миграцией, — фикстура
// заводит то, что заводит продукт. Файлом пробы до сих пор считался только
// `*_test.go`. Но `*_test.go` из другого пакета не импортируется, и общая
// фикстура многих пакетов обязана лежать в обычном файле — в оснастке проб.
// Без второй формы такой файл судился бы как прод-код, а у фикстуры, вынесенной
// из двадцати четырёх копий в одну, гейты прод-кода находили бы «третьего
// писателя», которого прод-сборка не содержит.
//
// # ПРЕДПОСЫЛКА — ПРОВЕРЯЕТСЯ, А НЕ ОБЪЯВЛЯЕТСЯ
//
// Снять оснастку с суда честно ровно тогда, когда прод-сборка её не видит.
// `ProbeToolingImports` судит это по разбору импортов каждого не-тестового
// файла вне оснастки: импорт пакета оснастки любой формы (обычный, псевдоним,
// с точкой, пустое имя, под любым тегом сборки) — находка с координатой. Иначе
// оснастка стала бы местом, куда прод-код прячет то, что гейт обязан видеть.
//
// Оснастки в обходе нет — тоже находка: исключение, которому нечего
// исключать, истекает само.
//
// # ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
//  1. Судится импорт ИЗ ЭТОГО МОДУЛЯ: другой модуль `internal/` этого модуля
//     импортировать не может — это держит компилятор.
//  2. Связь в обход импорта (`go:linkname`, отражение) не судится: в дереве
//     такой формы нет.
package check

import (
	"fmt"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

// ProbeToolingDir — каталог оснастки проб относительно корня модуля.
const ProbeToolingDir = "internal/testsupport/"

// ProbeToolingGoFile — не-тестовый файл Go оснастки проб.
func ProbeToolingGoFile(rel string) bool {
	return ProductionGoFile(rel) && strings.HasPrefix(rel, ProbeToolingDir)
}

// ShippedGoFile — не-тестовый файл Go прод-сборки: вне оснастки проб. Отбор
// гейтов прод-кода, которым оснастка проб не предмет; предпосылку держит
// `ProbeToolingImports`.
func ShippedGoFile(rel string) bool {
	return ProductionGoFile(rel) && !strings.HasPrefix(rel, ProbeToolingDir)
}

// ProbeToolingCensus — перепись проверки и её находки.
type ProbeToolingCensus struct {
	// FilesParsed — разобрано не-тестовых файлов Go.
	FilesParsed int
	// ProbeToolingFiles — из них оснастки проб; ShippedFiles — прод-сборки.
	ProbeToolingFiles, ShippedFiles int
	// Findings — импорт оснастки из прод-сборки с координатой; отсутствие
	// оснастки в обходе.
	Findings []string
}

// ProbeToolingImports судит корпус не-тестовых файлов Go модуля с путём module:
// ни один файл прод-сборки не импортирует пакет оснастки проб.
func ProbeToolingImports(corpus TreeCorpus, module string) (ProbeToolingCensus, error) {
	var c ProbeToolingCensus
	if len(corpus) == 0 {
		return c, ErrEmptyTraversal
	}
	tooling := module + "/" + strings.TrimSuffix(ProbeToolingDir, "/")
	fset := token.NewFileSet()
	for _, rel := range corpus.Rels() {
		f, err := parser.ParseFile(fset, rel, corpus[rel], parser.ImportsOnly|parser.ParseComments)
		if err != nil {
			return c, fmt.Errorf("разбор %s: %w", rel, err)
		}
		c.FilesParsed++
		if strings.HasPrefix(rel, ProbeToolingDir) {
			c.ProbeToolingFiles++
			continue
		}
		c.ShippedFiles++
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return c, fmt.Errorf("путь импорта %s: %w", fset.Position(imp.Pos()), err)
			}
			if p == tooling || strings.HasPrefix(p, tooling+"/") {
				pos := fset.Position(imp.Pos())
				c.Findings = append(c.Findings, fmt.Sprintf(
					"%s:%d: файл прод-сборки импортирует оснастку проб %s — гейты прод-кода оснастку не судят, "+
						"и импорт делает её прод-кодом, который никто не судит",
					rel, pos.Line, p))
			}
		}
	}
	if c.ProbeToolingFiles == 0 {
		c.Findings = append(c.Findings, "оснастки проб в обходе нет ("+ProbeToolingDir+
			"): исключение гейтов прод-кода снимать вместе с отбором ShippedGoFile")
	}
	sort.Strings(c.Findings)
	return c, nil
}
