// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// harness_model_parity_test.go — ГЕЙТ: харнесс ставит модель ТЕМИ ЖЕ шагами, что
// композиционный корень.
//
// # Предмет
//
// Проба последней мили (kacho#1969) утверждает вердикт над моделью процесса, которую
// ставит `installHarnessComposedModel`. Утверждение это осмысленно ровно постольку,
// поскольку харнесс приводит процесс к тому состоянию, в котором его поднимает
// корень (`cmd/kaname/model_compose.go`, `installComposedModel`). Разойдись
// они — и проба доказывала бы работу цепи, которой продукт не исполняет: харнесс,
// пропустивший допуск, поставил бы модель, которую старт отверг бы, то есть
// фикстура стала бы СНИСХОДИТЕЛЬНЕЕ ПРОДУКТА.
//
// Расхождение это МОЛЧАЛИВОЕ by construction: обе стороны собираются, обе зелены
// по своим пробам, и вопрос, который задаёт одна, — не тот, на который отвечает
// другая. Ни одна проба половины покраснеть не может.
//
// # Что судится, а что нет
//
// Судится ПОСЛЕДОВАТЕЛЬНОСТЬ шагов модели — упорядоченный перечень вызовов
// `modelcompose.*` и `authzmodel.*` внутри обеих функций. НЕ судятся: сообщения
// отказов, форма журналирования, обработка отчётов — они принадлежат своим
// сторонам, и требовать их совпадения значило бы запретить корню печатать
// перепись через `slog`, а харнессу — через поток ошибок.
//
// Обход идёт по УЗЛУ вызова, а не по слову: имена шагов встречаются в этом файле,
// в шапках обеих функций и в текстах отказов, и предикат по подстроке краснел бы
// на собственном объяснении.
//
// # Самоистечение
//
// Гейт истекает от появления предмета, а не от чьей-то памяти: заведёт корень
// четвёртый шаг — перечни разойдутся, гейт покраснеет и назовёт ОБЕ координаты,
// и тот, кто шаг заводил, узнает о харнессе в тот же заход.

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

// modelStepPackages — чьи вызовы суть ШАГИ модели процесса.
//
// Перечень закрыт намеренно: открытый («всякий вызов пакета») притащил бы в
// сравнение `slog`, `fmt` и `os`, то есть форму журналирования, — и гейт краснел
// бы на различии, о котором он не должен судить вовсе.
var modelStepPackages = map[string]bool{"modelcompose": true, "authzmodel": true}

// orderedModelStepsIn — упорядоченный перечень шагов модели внутри названной
// функции, и объём осмотренного вместе с ним.
//
// Объём возвращается ВСЕГДА: перечень из нуля шагов у функции, которую обход не
// нашёл, и у функции, которая шагов не делает, выглядит одинаково, а означает
// разное.
func orderedModelStepsIn(t *testing.T, path, funcName string) (steps []string, callsSeen int) {
	t.Helper()
	entry, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := treecorpus.UnderWithSuffix(filepath.Dir(entry), ".go")
	if err != nil {
		t.Fatalf("индекс helper пакета: %v", err)
	}
	sources, err := collectModelSources(entry, paths, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	steps, callsSeen, err = expandModelSources(sources, funcName)
	if err != nil {
		t.Fatalf("%s.%s: %v", entry, funcName, err)
	}

	return steps, callsSeen
}

// TestHarnessComposesTheModelTheCompositionRootWouldInstall — перечни шагов
// совпадают.
func TestHarnessComposesTheModelTheCompositionRootWouldInstall(t *testing.T) {
	const (
		rootPath    = "../../../../cmd/kaname/model_compose.go"
		rootFunc    = "installComposedModel"
		harnessPath = "harness_composed_model_test.go"
		harnessFunc = "installHarnessComposedModel"
	)

	rootSteps, rootCalls := orderedModelStepsIn(t, rootPath, rootFunc)
	harnessSteps, harnessCalls := orderedModelStepsIn(t, harnessPath, harnessFunc)

	// Перепись печатается ВСЕГДА: «ноль расхождений» обязано быть отличимо от
	// «ноль прочитанного».
	t.Logf("осмотрено вызовов: корень %d, харнесс %d; шагов модели: корень %v, харнесс %v",
		rootCalls, harnessCalls, rootSteps, harnessSteps)

	if len(rootSteps) == 0 {
		t.Fatalf("%s.%s не делает НИ ОДНОГО шага модели — вердикт беспредметен: "+
			"либо корень перестал собирать модель, либо перечень %v перестал её опознавать",
			rootPath, rootFunc, modelStepPackages)
	}

	if len(harnessSteps) != len(rootSteps) {
		t.Fatalf("ХАРНЕСС РАСХОДИТСЯ С КОРНЕМ по числу шагов: корень %d %v (%s.%s), "+
			"харнесс %d %v (%s.%s). Проба последней мили утверждает вердикт над моделью, "+
			"которую ставит харнесс; шагом меньше — и она доказывает работу цепи, которой "+
			"продукт не исполняет",
			len(rootSteps), rootSteps, rootPath, rootFunc,
			len(harnessSteps), harnessSteps, harnessPath, harnessFunc)
	}
	for i := range rootSteps {
		if rootSteps[i] != harnessSteps[i] {
			t.Fatalf("ХАРНЕСС РАСХОДИТСЯ С КОРНЕМ на шаге %d: корень %q (%s.%s), "+
				"харнесс %q (%s.%s). Порядок здесь несущий: установка после первого чтения "+
				"запрещена, а допуск судит то, что композиция собрала",
				i+1, rootSteps[i], rootPath, rootFunc,
				harnessSteps[i], harnessPath, harnessFunc)
		}
	}
}

// modelSource сохраняет файл-владелец import bindings каждой функции.
type modelSource struct {
	path string
	file *ast.File
}

// collectModelSources принимает только непосредственный каталог entry; одинаковое
// имя package в дочернем каталоге не даёт права подменять локальные helpers.
func collectModelSources(entry string, paths []string, read func(string) ([]byte, error)) ([]modelSource, error) {
	entry, err := filepath.Abs(entry)
	if err != nil {
		return nil, err
	}
	entry = filepath.Clean(entry)
	body, err := read(entry)
	if err != nil {
		return nil, err
	}
	file, err := parser.ParseFile(token.NewFileSet(), entry, body, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	out := []modelSource{{entry, file}}
	seen := map[string]bool{entry: true}
	for _, p := range paths {
		p, err = filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		p = filepath.Clean(p)
		if seen[p] || filepath.Dir(p) != filepath.Dir(entry) {
			continue
		}
		seen[p] = true
		if !strings.HasSuffix(entry, "_test.go") && strings.HasSuffix(p, "_test.go") {
			continue
		}
		body, err := read(p)
		if err != nil {
			return nil, err
		}
		other, err := parser.ParseFile(token.NewFileSet(), p, body, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		if other.Name.Name == file.Name.Name {
			out = append(out, modelSource{p, other})
		}
	}
	return out, nil
}

func expandedModelSteps(file *ast.File, entry string) ([]string, int, error) {
	return expandModelSources([]modelSource{{"fixture.go", file}}, entry)
}

// expandModelSources — ограниченный source predicate, без утверждения о CFG.
// Невызванные literals, defer/go и неоднозначный local binding не дают шагов.
func expandModelSources(sources []modelSource, entry string) ([]string, int, error) {
	type ownedFunction struct {
		fn    *ast.FuncDecl
		owner *ast.File
	}
	functions := map[string]ownedFunction{}
	for _, source := range sources {
		for _, decl := range source.file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
				if _, duplicate := functions[fn.Name.Name]; duplicate {
					return nil, 0, fmt.Errorf("неоднозначная функция %s @%s", fn.Name.Name, source.path)
				}
				functions[fn.Name.Name] = ownedFunction{fn, source.file}
			}
		}
	}
	var steps []string
	calls := 0
	active := map[string]bool{}
	var expand func(string) error
	expand = func(name string) error {
		owned, ok := functions[name]
		if !ok || owned.fn.Body == nil {
			return fmt.Errorf("функция %s не разобрана", name)
		}
		if active[name] {
			return fmt.Errorf("цикл helper %s", name)
		}
		active[name] = true
		defer delete(active, name)
		locals := modelLocalBindings(owned.fn)
		imports := map[string]string{}
		for _, im := range owned.owner.Imports {
			p, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				return err
			}
			alias := filepath.Base(p)
			if im.Name != nil {
				alias = im.Name.Name
			}
			if p == "github.com/PRO-Robotech/kaname/internal/modelcompose" {
				imports[alias] = "modelcompose"
			}
			if p == "github.com/PRO-Robotech/kaname/internal/authzmodel" {
				imports[alias] = "authzmodel"
			}
		}
		var walk func(ast.Node) error
		walk = func(node ast.Node) error {
			if node == nil {
				return nil
			}
			var failure error
			ast.Inspect(node, func(n ast.Node) bool {
				if failure != nil {
					return false
				}
				switch n.(type) {
				case *ast.FuncLit, *ast.DeferStmt, *ast.GoStmt:
					failure = fmt.Errorf("неподдержанная отложенная/косвенная форма в %s", name)
					return false
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if err := walk(call.Fun); err != nil {
					failure = err
					return false
				}
				for _, arg := range call.Args {
					if err := walk(arg); err != nil {
						failure = err
						return false
					}
				}
				calls++
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					if locals[fun.Name] {
						failure = fmt.Errorf("затенённый helper %s", fun.Name)
					} else if _, ok := functions[fun.Name]; ok {
						failure = expand(fun.Name)
					} else if !modelLanguageBuiltin(fun.Name) {
						failure = fmt.Errorf("неразрешённый helper %s", fun.Name)
					}
				case *ast.SelectorExpr:
					pkg, ok := fun.X.(*ast.Ident)
					if !ok {
						failure = fmt.Errorf("неподдержанный вычисляемый callee в %s", name)
						break
					}
					if canonical, ok := imports[pkg.Name]; ok {
						if locals[pkg.Name] {
							failure = fmt.Errorf("затенённый model import %s", pkg.Name)
						} else {
							steps = append(steps, canonical+"."+fun.Sel.Name)
						}
					} else if modelStepPackages[pkg.Name] {
						failure = fmt.Errorf("model name %s не связан с импортом", pkg.Name)
					}
				default:
					failure = fmt.Errorf("неподдержанный callee в %s", name)
				}
				return false
			})
			return failure
		}
		return walk(owned.fn.Body)
	}
	if err := expand(entry); err != nil {
		return nil, calls, err
	}
	if len(steps) == 0 {
		return nil, calls, fmt.Errorf("нет шагов модели")
	}
	return steps, calls, nil
}

func modelLocalBindings(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Field:
			for _, id := range node.Names {
				out[id.Name] = true
			}
		case *ast.ValueSpec:
			for _, id := range node.Names {
				out[id.Name] = true
			}
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					out[id.Name] = true
				}
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{node.Key, node.Value} {
				if id, ok := e.(*ast.Ident); ok {
					out[id.Name] = true
				}
			}
		}
		return true
	})
	return out
}

func modelLanguageBuiltin(name string) bool {
	switch name {
	case "append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len", "make", "max", "min", "new", "panic", "print", "println", "real", "recover", "bool", "byte", "complex64", "complex128", "error", "float32", "float64", "int", "int8", "int16", "int32", "int64", "rune", "string", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr":
		return true
	}
	return false
}
