// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package accesssnapshot

// consumer_is_named_test.go — у инструмента НАЗВАН потребитель, и запись о нём
// истекает в ОБЕ стороны (kacho#2640).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Пакет с нулём внешних импортёров читается как мёртвый код — так его и назвала
// перепись, из которой заведена задача. Мёртвым он не является: его потребитель
// есть, и это интеграционная проба этого же пакета, утверждающая сценарий
// приёмки против настоящей двери решения.
//
// Такое состояние законно и НЕУСТОЙЧИВО сразу в две стороны, поэтому прозой оно
// не держится:
//
//	потребителей стало БОЛЬШЕ — динамическая половина утверждения закрепляется
//	                            снаружи, и шапка пакета, объявляющая единственным
//	                            потребителем свою пробу, пережила предмет;
//	потребителей стало НОЛЬ   — инструмент мёртв целиком и снимается ВМЕСТЕ с
//	                            пробами (LEAN, ban #11), а не остаётся «про запас».
//
// Обе стороны — находки. Гейт, знающий одну, оставил бы вторую невидимой: и
// «класс закрыт» и «класс вырос» выглядят из прозы одинаково.
//
// ─────────────────────────────────────────────────────────────────────────────
// СЧЁТ ИДЁТ ПО УЗЛАМ, А НЕ ПО ПОДСТРОКЕ
//
// Путь пакета стоит в прозе соседних шапок и в тексте самой задачи; предикат по
// тексту краснел бы на собственном объяснении проверяемого. Поэтому импорт
// опознаётся узлом `ast.ImportSpec` разобранного дерева, а вызовы инструмента —
// узлами-идентификаторами.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// toolImportPath — путь, по которому инструмент импортируют снаружи.
const toolImportPath = "github.com/PRO-Robotech/kaname/internal/testsupport/accesssnapshot"

// toolAPI — то, чем инструментом пользуются. Оба имени, а не одно: снимок без
// сравнения ничего не утверждает, сравнение без снимка нечего сравнивать.
var toolAPI = []string{"Take", "Compare"}

// consumerCensus — объём осмотренного; печатается ВСЕГДА.
type consumerCensus struct {
	Files       int
	Parsed      int
	OwnFiles    int // файлов самого пакета в обходе
	Importers   int // файлов модуля, импортирующих инструмент
	OwnCalls    int // обращений к API инструмента внутри пакета
	OutsideRoot string
}

func (c consumerCensus) Summary() string {
	return fmt.Sprintf(
		"файлов модуля %d · разобрано %d · из них файлов пакета %d · внешних импортёров %d · "+
			"обращений к API внутри пакета %d (корень %s)",
		c.Files, c.Parsed, c.OwnFiles, c.Importers, c.OwnCalls, c.OutsideRoot)
}

// scanToolConsumers обходит перечень файлов и считает обе величины.
//
// Состав приходит ПАРАМЕТРОМ: в живом дереве его даёт обход модуля, а инъекция
// подаёт синтетический — доказательство, требующее испортить рабочую копию, в
// конвейере не исполняется никогда.
func scanToolConsumers(files []string, ownDir string) (importers []string, c consumerCensus, err error) {
	api := map[string]bool{}
	for _, name := range toolAPI {
		api[name] = true
	}
	fset := token.NewFileSet()
	for _, path := range files {
		if !strings.HasSuffix(path, ".go") {
			continue
		}
		c.Files++
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, c, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		c.Parsed++
		own := filepath.Dir(path) == ownDir
		if own {
			c.OwnFiles++
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && api[id.Name] {
					c.OwnCalls++
				}
				return true
			})
			continue
		}
		for _, imp := range file.Imports {
			quoted, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			if quoted == toolImportPath {
				c.Importers++
				importers = append(importers, path)
			}
		}
	}
	return importers, c, nil
}

// TestIAM2640_ToolConsumersAreNamed — гейт задачи #2640, предмет А.
func TestIAM2640_ToolConsumersAreNamed(t *testing.T) {
	root := moduleRootFromTool(t)
	files, err := treecorpus.UnderWithSuffix(root, ".go")
	if err != nil {
		t.Fatalf("обход модуля: %v", err)
	}
	ownDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("абсолютный путь пакета: %v", err)
	}
	importers, census, err := scanToolConsumers(files, ownDir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	census.OutsideRoot = root
	defer func() { t.Logf("%s", census.Summary()) }()

	if census.Parsed == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО файла модуля (корень %s) — вердикт "+
			"беспредметен: «ноль импортёров» неотличимо от «ноль прочитанного»", root)
	}
	if census.OwnFiles == 0 {
		t.Fatalf("обход не нашёл НИ ОДНОГО файла самого пакета (каталог %s) — "+
			"распознаватель своих файлов мёртв, и тогда обе половины он делит вслепую",
			ownDir)
	}

	if census.OwnCalls == 0 {
		t.Errorf("инструмент не зовёт НИ ОДНА проба этого пакета: у него не осталось " +
			"потребителей вовсе. Снимок доступа существует ради утверждения перехода " +
			"IAM-ID-1; инструмент без утверждения — код, который тихо ничего не делает, " +
			"оставаясь на вид работающим. Снимайте ВМЕСТЕ с пробами (LEAN), а не " +
			"оставляйте «про запас».")
	}
	if census.Importers > 0 {
		t.Errorf("у инструмента появились ВНЕШНИЕ потребители (%d): %v. Шапка пакета "+
			"объявляет единственным потребителем собственную интеграционную пробу и "+
			"называет динамическую половину утверждения (IAM-ID-1-29/30) незакреплённой — "+
			"запись пережила предмет. Перечитайте шапку: если равенство множеств ДО и "+
			"ПОСЛЕ теперь утверждается снаружи, так и напишите.",
			census.Importers, importers)
	}
}

// moduleRootFromTool поднимается от каталога пакета до go.mod.
func moduleRootFromTool(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("абсолютный путь пакета: %v", err)
	}
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod не найден вверх от каталога инструмента")
		}
		dir = parent
	}
}
