// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// catalog_snapshot_wiring_test.go — гейт «снимок каталога, ПОСТРОЕННЫЙ
// композиционным корнем, им же и ЗАПУЩЕН» (kacho#1945).
//
// # Предмет
//
// `catalog.Snapshot` — то, чем путь запроса отвечает на «жив ли модуль» после
// #1927. Он наполняется однажды строками, которые на старте прочитал страж
// паритета, и живым его делает ТОЛЬКО периодическая петля `Run`. Не запущенная
// петля превращает снимок в кеш без гашения: снятие модуля перестаёт доезжать до
// пути запроса до перезапуска службы, и состояние не сходится само.
//
// # Почему это НЕ ловится ничем другим
//
// Отказ ТИХИЙ во всех наблюдаемых местах сразу. Служба поднимается, становится
// Ready и отвечает — на строках, прочитанных на старте. Проба самой петли
// зелёная: петля исправна, её просто никто не зовёт. Проба use-case'а зелёная:
// внутри процесса снимок и живые строки равны, пока строку не сняли. Страж
// старта доволен: он сверяет ПАРИТЕТ канона со строками, а не то, перечитывают
// ли строки потом.
//
// Замер на день заведения: прод-вызовов `Snapshot.Run` — НОЛЬ; звали её только
// юнит-проба и интеграционная проба обновления.
//
// # Гейт судит ПЕРЕМЕННУЮ, а не имя ручки и не форму запуска
//
// Ищется идентификатор, СВЯЗАННЫЙ вызовом `catalog.NewSnapshot`, и требуется,
// чтобы он был получателем вызова `Run` где-то в прод-коде того же
// композиционного корня. Тогда гейт переживает и переименование переменной, и
// смену формы запуска: здесь петли поднимаются списком задач
// (`tasks = append(tasks, func() error { … })`), а не голым `go`, и гейт,
// знающий одну форму, молчал бы на другой.
//
// # Границы, названные вслух
//
// Судится СВЯЗЫВАНИЕ и ВЫЗОВ в пределах одного пакета. Снимок, переданный чужому
// пакету, который запустил бы петлю у себя, этим гейтом не виден; такой формы в
// дереве нет, а появившись, она обязана быть учтена своим изменением. Период,
// с которым петля запущена, гейт не судит вовсе — «никогда» ручкой невыразимо
// by construction (`envDurationMS` возвращает умолчание на любом непозитивном
// значении), поэтому предмета у такой проверки нет.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// catalogPkgPath — пакет, чей снимок обязан быть запущен.
const catalogPkgPath = "github.com/PRO-Robotech/kacho-iam/internal/catalog"

// catalogSnapshotCtor — конструктор снимка.
const catalogSnapshotCtor = "NewSnapshot"

// snapshotRunMethod — метод, поднимающий петлю обновления.
const snapshotRunMethod = "Run"

// snapshotBinding — идентификатор, связанный конструктором снимка.
type snapshotBinding struct {
	Name string
	File string
	Line int
}

// wiringCensus — объём осмотренного; печатается всегда.
type wiringCensus struct {
	Files    int
	Parsed   int
	Built    int
	RunRecvs int
}

func (c wiringCensus) Summary() string {
	return fmt.Sprintf("прод-файлов корня %d · разобрано %d · снимков построено %d · "+
		"получателей вызова Run увидено %d", c.Files, c.Parsed, c.Built, c.RunRecvs)
}

// snapshotWiring разбирает ПЕРЕЧЕНЬ файлов композиционного корня и возвращает
// связанные конструктором идентификаторы и множество тех, у кого позван `Run`.
//
// Состав приходит ПАРАМЕТРОМ: в живом дереве его даёт индекс git, а инъекция
// подаёт синтетический — доказательство, требующее испортить рабочую копию, в
// конвейере не исполняется никогда.
func snapshotWiring(root string, files []string) (built []snapshotBinding, started map[string]bool, c wiringCensus, err error) {
	started = make(map[string]bool)
	fset := token.NewFileSet()
	for _, path := range files {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		c.Files++
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, nil, c, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		c.Parsed++
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		local := localNameOfCatalogImport(file)

		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				// Связывание: `snap, err := catalog.NewSnapshot(…)`.
				if local == "" || len(x.Rhs) != 1 || len(x.Lhs) == 0 {
					return true
				}
				call, ok := x.Rhs[0].(*ast.CallExpr)
				if !ok || !isSelector(call.Fun, local, catalogSnapshotCtor) {
					return true
				}
				id, ok := x.Lhs[0].(*ast.Ident)
				if !ok || id.Name == "_" {
					return true
				}
				c.Built++
				built = append(built, snapshotBinding{
					Name: id.Name, File: rel, Line: fset.Position(id.Pos()).Line,
				})
			case *ast.CallExpr:
				// Запуск: `<идентификатор>.Run(…)`, в любой обёртке.
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != snapshotRunMethod {
					return true
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				c.RunRecvs++
				started[recv.Name] = true
			}
			return true
		})
	}
	sort.Slice(built, func(i, j int) bool {
		if built[i].File != built[j].File {
			return built[i].File < built[j].File
		}
		return built[i].Line < built[j].Line
	})
	return built, started, c, nil
}

// isSelector — выражение есть `<local>.<name>`.
func isSelector(e ast.Expr, local, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == local
}

// localNameOfCatalogImport — ЛОКАЛЬНОЕ имя пакета каталога в этом файле;
// псевдоним учитывается, иначе форма `cat "…/catalog"` осталась бы вне
// наблюдения.
func localNameOfCatalogImport(file *ast.File) string {
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != catalogPkgPath {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				return ""
			}
			return imp.Name.Name
		}
		return "catalog"
	}
	return ""
}

// TestIAM1945_CatalogSnapshotBuiltByTheRootIsAlsoStartedByIt — гейт задачи #1945.
func TestIAM1945_CatalogSnapshotBuiltByTheRootIsAlsoStartedByIt(t *testing.T) {
	root := iamServiceRoot(t)

	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, "cmd"), ".go")
	if err != nil {
		t.Fatalf("перечень файлов композиционного корня: %v", err)
	}
	built, started, census, err := snapshotWiring(root, files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("%s", census.Summary())

	if census.Parsed == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла композиционного корня — "+
			"вердикт беспредметен: «ноль находок» неотличимо от «ноль прочитанного» (корень %s)", root)
	}
	if census.Built == 0 {
		t.Fatalf("композиционный корень не строит снимка каталога вовсе (разобрано %d файлов) — "+
			"это отказ РАЗБОРА либо снятие предмета; во втором случае гейт снимается "+
			"ВМЕСТЕ с ним, а не остаётся молчать", census.Parsed)
	}

	for _, b := range built {
		if started[b.Name] {
			continue
		}
		t.Errorf("%s:%d — снимок каталога `%s` построен и НЕ запущен: без петли "+
			"`%s.%s(ctx, период)` он наполняется однажды на старте и больше не "+
			"перечитывается, поэтому снятие модуля не доезжает до пути запроса до "+
			"перезапуска службы (kacho#1945)",
			b.File, b.Line, b.Name, b.Name, snapshotRunMethod)
	}
}
