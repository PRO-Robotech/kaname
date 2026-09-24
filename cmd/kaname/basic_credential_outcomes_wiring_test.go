// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// basic_credential_outcomes_wiring_test.go — перепись исходов полосы базового
// секрета ЧИТАЕТСЯ корнем, а не только собирается обработчиком (задача
// kaname#379).
//
// # Почему это отдельная проба
//
// Перепись без читателя — тот же класс, что закрыт у токен-эндпоинта (#2501):
// разбивка отказов живёт только в памяти процесса, и отсечка отзыва-всех,
// сработавшая тысячу раз, неотличима от не сработавшей ни разу. Обработчик
// внутреннего слушателя собирается в корне одной цепочкой, и первая же
// правка, снявшая регистрацию коллектора, прошла бы обзор незамеченной.
//
// # Что здесь считается провязкой
//
// Тот же идентификатор, которому присвоена цепочка `internaliamapp.NewHandler(…)…`,
// упомянут ВНУТРИ вызова `NewBasicCredentialOutcomeCollector`. Не «слово
// встречается в файле»: имя обработчика стоит и в комментариях рядом.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// basicCensusWiring — что обход нашёл в файлах корня.
type basicCensusWiring struct {
	files    int
	bound    []string        // идентификаторы, которым присвоен обработчик
	readers  int             // вызовов читателя переписи
	observed map[string]bool // идентификаторы, названные внутри вызовов читателя
}

// mute — обработчики, чья перепись не читается.
func (w basicCensusWiring) mute() []string {
	var out []string
	for _, name := range w.bound {
		if !w.observed[name] {
			out = append(out, name)
		}
	}
	return out
}

// buildsInternalIAMHandler — корень цепочки присваивания есть
// `internaliamapp.NewHandler(…)`.
func buildsInternalIAMHandler(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	for ok {
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return false
		}
		if pkg, isIdent := sel.X.(*ast.Ident); isIdent {
			return pkg.Name == "internaliamapp" && sel.Sel.Name == "NewHandler"
		}
		call, ok = sel.X.(*ast.CallExpr)
	}
	return false
}

// scanBasicCensusWiring обходит разобранные файлы.
func scanBasicCensusWiring(files []*ast.File) basicCensusWiring {
	w := basicCensusWiring{files: len(files), observed: map[string]bool{}}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if len(x.Rhs) != 1 || len(x.Lhs) != 1 || !buildsInternalIAMHandler(x.Rhs[0]) {
					return true
				}
				if id, ok := x.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
					w.bound = append(w.bound, id.Name)
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "NewBasicCredentialOutcomeCollector" {
					return true
				}
				w.readers++
				for _, arg := range x.Args {
					ast.Inspect(arg, func(inner ast.Node) bool {
						if id, ok := inner.(*ast.Ident); ok {
							w.observed[id.Name] = true
						}
						return true
					})
				}
			}
			return true
		})
	}
	return w
}

func parseSources(t *testing.T, sources map[string]string) []*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []*ast.File
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, sources[name], 0)
		if err != nil {
			t.Fatalf("разбор %s: %v", name, err)
		}
		out = append(out, f)
	}
	return out
}

// TestTheBasicCredentialCensusHasAReaderInTheRoot — обход файлов корня.
func TestTheBasicCredentialCensusHasAReaderInTheRoot(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("чтение каталога корня: %v", err)
	}
	sources := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(filepath.Clean(name))
		if rerr != nil {
			t.Fatalf("чтение %s: %v", name, rerr)
		}
		sources[name] = string(src)
	}
	w := scanBasicCensusWiring(parseSources(t, sources))
	t.Logf("перепись: не-тестовых файлов корня разобрано %d · построений обработчика %v · "+
		"вызовов читателя %d · названных им идентификаторов %d", w.files, w.bound, w.readers, len(w.observed))

	if w.files == 0 {
		t.Fatalf("разобрано ноль файлов корня — обход беспредметен")
	}
	if len(w.bound) == 0 {
		t.Fatalf("построений обработчика внутреннего слушателя в корне НОЛЬ — гейт беспредметен: " +
			"он молчал бы и тогда, когда обработчик собирают иначе")
	}
	if mute := w.mute(); len(mute) > 0 {
		t.Fatalf("обработчик(и) %v построены, а перепись исходов полосы базового секрета НЕ ЧИТАЕТСЯ "+
			"(вызовов читателя %d). Отказ по отсечке отзыва-всех, «строки нет» и «секрет не тот» "+
			"остаются в памяти процесса, и контроль, не сработавший ни разу, неотличим от "+
			"сработавшего.\nСнятие: `metricsReg.NewBasicCredentialOutcomeCollector("+
			"basicCredentialCells(), basicCredentialOutcomeReader(%s))` рядом с построением.",
			mute, w.readers, mute[0])
	}
}

// TestBasicCensusWiringGate_FindsAMuteHandlerAndStaysSilentOnTheWiredTwin —
// инъекция в обе стороны на синтетике: обработчик без читателя находится,
// обработчик с читателем молчит, читатель, назвавший ДРУГОЙ идентификатор, не
// засчитывается.
func TestBasicCensusWiringGate_FindsAMuteHandlerAndStaysSilentOnTheWiredTwin(t *testing.T) {
	const build = `package main
func f() {
	h := internaliamapp.NewHandler(l, a).WithLogger(x)
	_ = h
`
	for _, c := range []struct {
		name     string
		body     string
		wantMute bool
	}{
		{"читателя нет", build + "}\n", true},
		{"читатель назвал обработчик", build +
			"\tmetricsReg.NewBasicCredentialOutcomeCollector(basicCredentialCells(), basicCredentialOutcomeReader(h))\n}\n", false},
		{"читатель назвал другой идентификатор", build +
			"\tmetricsReg.NewBasicCredentialOutcomeCollector(basicCredentialCells(), basicCredentialOutcomeReader(other))\n}\n", true},
	} {
		w := scanBasicCensusWiring(parseSources(t, map[string]string{"wiring.go": c.body}))
		if len(w.bound) != 1 {
			t.Fatalf("%s: построение обработчика не распознано (найдено %v) — инъекция беспредметна", c.name, w.bound)
		}
		if got := len(w.mute()) > 0; got != c.wantMute {
			t.Fatalf("%s: немой обработчик найден=%v, ожидалось %v (читателей %d)", c.name, got, c.wantMute, w.readers)
		}
	}
}
