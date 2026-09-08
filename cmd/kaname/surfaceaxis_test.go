// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// surfaceaxis_test.go — выключенная поверхность НАЗЫВАЕТ, что не обслуживается.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Пустой адрес означает «поверхность не поднята». Само по себе это законно, и
// именно поэтому опасно: неподнятая поверхность выглядит РОВНО ТАК ЖЕ, как
// исправно работающая, — процесс стартовал, ошибок нет, журнал чист.
//
// Отличает их только объяснение. Поэтому `addrAxis` требует причину ДОВОДОМ, а
// не берёт из общего шаблона: у поверхностей цена выключения РАЗНАЯ, и «адрес
// не задан» без неё не говорит оператору ничего.
//
// Гейт судит РАЗОБРАННОЕ дерево, а не текст: слово «addrAxis» стоит в этом
// файле и в объяснениях рядом, и предикат по подстроке краснел бы на
// собственном объяснении проверяемого.
//
// Способность упасть доказана инъекцией — surfaceaxis_injection_test.go.

// axisExplanations возвращает по каждому вызову addrAxis координату и признак
// «причина выключения названа непустым текстом».
//
// Каталог принимается доводом: тем же вызовом инъекция подаёт синтетический
// вход, меняя ровно один факт.
func axisExplanations(dir string) (calls []string, explained []bool, err error) {
	const axisFunc = "addrAxis"
	const becauseArgIndex = 1
	fset := token.NewFileSet()
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, nil, err
	}
	for _, path := range names {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil, nil, perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, isIdent := call.Fun.(*ast.Ident)
			if !isIdent || ident.Name != axisFunc {
				return true
			}
			pos := fset.Position(call.Pos())
			calls = append(calls, filepath.Base(pos.Filename)+":"+strconv.Itoa(pos.Line))
			explained = append(explained, hasNonEmptyText(call, becauseArgIndex))
			return true
		})
	}
	return calls, explained, nil
}

// hasNonEmptyText — довод под индексом есть непустой текст (литерал либо их
// склейка). Выражение иной формы за объяснение НЕ засчитывается: причина обязана
// читаться в месте объявления, а не собираться где-то ещё.
func hasNonEmptyText(call *ast.CallExpr, idx int) bool {
	if len(call.Args) <= idx {
		return false
	}
	return textLen(call.Args[idx]) > 0
}

func textLen(e ast.Expr) int {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return 0
		}
		// Кавычки в длину не входят: "" обязано читаться как пустое.
		return len(v.Value) - 2
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return 0
		}
		return textLen(v.X) + textLen(v.Y)
	default:
		return 0
	}
}

func TestEveryDisabledSurfaceSaysWhatItDoesNotServe(t *testing.T) {
	calls, explained, err := axisExplanations(".")
	if err != nil {
		t.Fatalf("обход каталога не состоялся: %v", err)
	}

	var silent []string
	for i, ok := range explained {
		if !ok {
			silent = append(silent, calls[i])
		}
	}

	t.Logf("осмотрено: осей адреса объявлено %d, из них называют причину выключения %d, "+
		"молчат %d", len(calls), len(calls)-len(silent), len(silent))

	if len(calls) == 0 {
		t.Fatal("осей адреса не найдено ни одной — обход пуст, вердикт беспредметен: " +
			"«все объясняют» верно тривиально, когда объяснять некому")
	}
	if len(silent) > 0 {
		t.Errorf("поверхности выключаются МОЛЧА: %s.\n"+
			"Неподнятая поверхность выглядит ровно так же, как исправно работающая — "+
			"процесс стартовал, ошибок нет. Отличает их только причина, и она обязана "+
			"называть, ЧТО именно не обслуживается", strings.Join(silent, ", "))
	}
}

// TestBothRESTFrontsDeclareTheirAxis — оба фронта объявлены осью, а не подняты
// молча.
//
// Утверждение о ДЕРЕВЕ, а не о процессе: поднять его в пробе значило бы поднять
// базу, слушатели и удостоверения — то есть проверять посадку, а не объявление.
func TestBothRESTFrontsDeclareTheirAxis(t *testing.T) {
	src, err := parser.ParseFile(token.NewFileSet(), "serve.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("serve.go не разбирается: %v", err)
	}
	want := map[string]bool{
		"KANAME_API_SERVER__REST_ENDPOINT":          false,
		"KANAME_API_SERVER__INTERNAL_REST_ENDPOINT": false,
	}
	ast.Inspect(src, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, isIdent := call.Fun.(*ast.Ident)
		if !isIdent || ident.Name != "addrAxis" || len(call.Args) < 2 {
			return true
		}
		lit := literalText(call.Args[1])
		for knob := range want {
			if strings.Contains(lit, knob) {
				want[knob] = true
			}
		}
		return true
	})
	for knob, found := range want {
		if !found {
			t.Errorf("ручка %s не названа ни одной осью адреса: состояние этого фронта "+
				"при старте не сообщается, и «не поднят» неотличимо от «работает»", knob)
		}
	}
	t.Logf("осмотрено: ручек фронтов ожидалось %d, названо осями %d", len(want), countTrue(want))
}

func countTrue(m map[string]bool) int {
	n := 0
	for _, v := range m {
		if v {
			n++
		}
	}
	return n
}

func literalText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return ""
		}
		return strings.Trim(v.Value, "\"`")
	case *ast.BinaryExpr:
		return literalText(v.X) + literalText(v.Y)
	default:
		return ""
	}
}
