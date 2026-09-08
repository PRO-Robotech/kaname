// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// harness_model_parity_test.go — ГЕЙТ: харнесс ставит модель ТЕМИ ЖЕ шагами, что
// композиционный корень.
//
// # Предмет
//
// Проба последней мили (#1969) утверждает вердикт над моделью процесса, которую
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
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
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
	src, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- путь собран из констант гейта
	if err != nil {
		t.Fatalf("%s не прочитан: %v — непрочитанное есть НАХОДКА, а не «ноль шагов»", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("%s не разобран: %v", path, err)
	}

	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == funcName && fn.Body != nil {
			body = fn.Body
			break
		}
	}
	if body == nil {
		t.Fatalf("%s не объявляет %s — предпосылка гейта исчезла, и сравнивать нечего "+
			"(функция переименована либо снята: тогда снимите гейт ТЕМ ЖЕ изменением)",
			path, funcName)
	}

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callsSeen++
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || !modelStepPackages[pkg.Name] {
			return true
		}
		steps = append(steps, pkg.Name+"."+sel.Sel.Name)
		return true
	})
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
