// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// census_fixture_producer.go — проба, которая пересчитывает ВСЕ строки
// таблицы, не вправе наполнять её сама в обход производителя.
//
// Порт с монорепо (`internal/repohygiene/censusfixtureproducer_test.go`,
// снят вынесением службы — `kacho#2597`). Гейт уже цитируется ШЕСТЬЮ местами
// в дереве службы (прод-код `internal/repo/kaname/pg/scalegrid/{census,seed}.go`
// и пробы `relverdict`/`parentedge`) как «гейт дерева
// `TestCensusFixturesSeedThroughTheProducer`» — предмет жив, и цитаты уже
// ждут держателя. Осталось дословно: имя функции гейта, разбор и текст
// находки. Изменилось: пакет-производитель узнаётся ОДНОЙ величиной (каталог
// = хвост импорта: у самостоятельного модуля службы расхождения, из-за
// которого монорепо держало ДВЕ константы, больше нет), обход — от корня
// СВОЕГО модуля, без сегмента `services/iam`.
//
// # Предмет
//
// Утверждение вида «у каждой строки зеркала есть цепь предков» — квантор по
// всему множеству. Если множество наполнила сама проба прямой записью в
// таблицу, утверждается свойство ФИКСТУРЫ: она положила ровно то, что потом
// пересчитала. Такая проба остаётся зелёной, даже если производитель
// перестал писать цепь ЦЕЛИКОМ.
//
// # Единица суждения — ПАКЕТ, а не файл
//
// В Go все `_test.go` каталога с одним именем пакета собираются в один
// бинарь и делят помощников. Проба, сеющая через помощника из соседнего
// файла, сеет через производителя ровно так же.
//
// # Разбор идёт по СТРОКОВЫМ ЛИТЕРАЛАМ, а не по тексту файла
//
// Текстовый поиск нашёл бы обе примеет и в комментарии, объясняющем эту же
// дисциплину (в том числе в шапке самой пробы полноты).
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

const (
	// CensusMirrorTable / CensusEdgeTable — таблицы, чья совместная
	// упомянутость в ОДНОМ SQL-литерале и есть перепись покрытия: она
	// спрашивает про рёбра у строк зеркала, то есть квантифицирует по
	// множеству.
	CensusMirrorTable = "kaname.resource_mirror"
	CensusEdgeTable   = "kaname.resource_parent_edge"
	// RawEdgeWriteMarker — прямая запись рёбер в обход производителя.
	RawEdgeWriteMarker = "INSERT INTO kaname.resource_parent_edge"
	// EdgeProducerCall — имя экспортированной функции-производителя.
	EdgeProducerCall = "UpsertTx"
	// EdgeProducerDir — каталог пакета-производителя, ОТ КОРНЯ своего модуля
	// (было `services/iam/internal/repo/kaname/pg/resource_mirror`).
	EdgeProducerDir = "internal/repo/kaname/pg/resource_mirror"
	// EdgeProducerImport — хвост пути импорта. В самостоятельном модуле
	// службы совпадает с каталогом (расхождение, из-за которого монорепо
	// нёс ДВЕ константы, было следствием сегмента `services/iam`, которого
	// у своего модуля нет).
	EdgeProducerImport = EdgeProducerDir
)

// CensusFileFacts — то, что гейт узнаёт об одном файле.
type CensusFileFacts struct {
	Rel      string
	Census   bool
	RawWrite bool
	Producer bool
}

// CensusFactsOf разбирает один файл. Разбор, а не текст: комментарий,
// объясняющий эту же дисциплину, производителем не является.
func CensusFactsOf(rel string, body []byte, producerPkg string) (CensusFileFacts, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, body, parser.SkipObjectResolution)
	if err != nil {
		return CensusFileFacts{}, err
	}
	facts := CensusFileFacts{Rel: rel}

	producerNames := map[string]bool{}
	for _, im := range file.Imports {
		p, uerr := strconv.Unquote(im.Path.Value)
		if uerr != nil || !strings.HasSuffix(p, EdgeProducerImport) {
			continue
		}
		name := producerPkg
		if im.Name != nil {
			name = im.Name.Name
		}
		producerNames[name] = true
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BasicLit:
			if node.Kind != token.STRING {
				return true
			}
			v, uerr := strconv.Unquote(node.Value)
			if uerr != nil {
				return true
			}
			if strings.Contains(v, CensusMirrorTable) && strings.Contains(v, CensusEdgeTable) {
				facts.Census = true
			}
			if strings.Contains(v, RawEdgeWriteMarker) {
				facts.RawWrite = true
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != EdgeProducerCall {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if ok && producerNames[id.Name] {
				facts.Producer = true
			}
		}
		return true
	})
	return facts, nil
}

// JudgeCensusFixtures выносит вердикт по КАТАЛОГАМ: ключ — каталог тестового
// пакета, значение — факты его файлов.
func JudgeCensusFixtures(byDir map[string][]CensusFileFacts) []string {
	var findings []string
	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	for _, d := range dirs {
		files := byDir[d]
		producerInPackage := false
		for _, f := range files {
			if f.Producer {
				producerInPackage = true
				break
			}
		}
		for _, f := range files {
			if !f.Census {
				continue
			}
			if f.RawWrite {
				findings = append(findings, f.Rel+
					" — проба пересчитывает все строки зеркала и САМА кладёт рёбра прямой "+
					"записью: она утверждает свойство своей фикстуры и останется зелёной, "+
					"даже если производитель перестанет писать цепь целиком")
				continue
			}
			if !producerInPackage {
				findings = append(findings, f.Rel+
					" — проба пересчитывает все строки зеркала, но НИ ОДИН файл её тестового "+
					"пакета не зовёт производителя ("+EdgeProducerDir+"."+EdgeProducerCall+
					"): непонятно, чьё свойство она утверждает")
			}
		}
	}
	sort.Strings(findings)
	return findings
}
