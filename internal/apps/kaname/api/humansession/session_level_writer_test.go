// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// session_level_writer_test.go — ГЕЙТ ПАКЕТА: у записи уровня сессии внутри
// неё ОДИН вызывающий (задача PRO-Robotech/kaname#343, предикат снятия п. 1).
//
// Оператор `Writer.PresentInSession` пишет уровень с условием на прежнее
// значение, но условие держит только то, что кандидата приносит ОДНО место
// (`presentInSession`, `session_level.go`). Второй вызывающий оператора —
// второй вывод кандидата, и он разошёлся бы с первым молча: оба компилируются,
// оба типизированы. Поэтому вызов оператора в не-тестовом коде пакета — ровно
// один, и судится он УЗЛОМ разбора (вызов метода с этим именем на любом
// получателе), а не словом: комментарий и строка вызовом не являются.
//
// Перепись печатает объём осмотренного и выведенный из дерева перечень
// вызывающих правила `assurance.LevelOf` — иначе шестой вызывающий появился бы
// молча. Пустой обход — отказ, а не «ноль находок».
//
// Способность упасть и смолчать — TestSessionLevelWriterJudge_Injection ниже.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// levelWriterHome — единственное законное место вызова оператора.
const levelWriterHome = "session_level.go:presentInSession"

// levelWriterCensus — объём осмотренного и находки.
type levelWriterCensus struct {
	files       int
	calls       []string // "файл:функция" каждого вызова оператора
	ruleCallers []string // "файл:функция" каждого вызова assurance.LevelOf
}

// judgeLevelWriters — разбор набора файлов (имя → исходник).
func judgeLevelWriters(files map[string]string) (levelWriterCensus, error) {
	var c levelWriterCensus
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	fset := token.NewFileSet()
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, files[name], parser.SkipObjectResolution)
		if err != nil {
			return c, fmt.Errorf("%s: %w", name, err)
		}
		c.files++
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			where := filepath.Base(name) + ":" + fd.Name.Name
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "PresentInSession":
					c.calls = append(c.calls, where)
				case "LevelOf":
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "assurance" {
						c.ruleCallers = append(c.ruleCallers, where)
					}
				}
				return true
			})
		}
	}
	return c, nil
}

// levelWriterFindings — вызовы оператора вне дома и отсутствие дома.
func levelWriterFindings(c levelWriterCensus) []string {
	var out []string
	home := 0
	for _, w := range c.calls {
		if w == levelWriterHome {
			home++
			continue
		}
		out = append(out, "вызов Writer.PresentInSession вне "+levelWriterHome+": "+w+
			" — второй вывод кандидата уровня, условие на прежнее значение держит только один вызывающий (kaname#343)")
	}
	if home != 1 {
		out = append(out, fmt.Sprintf("в %s вызовов оператора %d, ожидался 1 — дом единственного писателя переехал", levelWriterHome, home))
	}
	return out
}

func TestSessionLevelHasOneWriterCallSite(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог пакета не прочитан: %v", err)
	}
	files := map[string]string{}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s: %v", n, err)
		}
		files[n] = string(b)
	}
	if len(files) == 0 {
		t.Fatal("проверка НЕ ИСПОЛНЯЛАСЬ: не-тестовых файлов пакета 0 — судить нечего, «ноль находок» был бы «ноль прочитанного»")
	}
	c, err := judgeLevelWriters(files)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: файлов %d · вызовов оператора записи уровня %d %v · вызывающих правила LevelOf %d %v",
		c.files, len(c.calls), c.calls, len(c.ruleCallers), c.ruleCallers)
	if len(c.calls) == 0 {
		t.Fatal("проверка НЕ ИСПОЛНЯЛАСЬ: вызовов оператора записи уровня 0 — разбор слеп либо оператор переименован")
	}
	if f := levelWriterFindings(c); len(f) > 0 {
		t.Fatalf("находок %d:\n  %s", len(f), strings.Join(f, "\n  "))
	}
}

// TestSessionLevelWriterJudge_Injection — инъекция в обе стороны на синтетике:
// второй вызов оператора краснеет с координатой; законный близнец — вызов
// ЕДИНСТВЕННОГО писателя из глагола — молчит; слово в комментарии и строке —
// не вызов.
func TestSessionLevelWriterJudge_Injection(t *testing.T) {
	t.Parallel()
	home := `package humansession
func presentInSession(w Writer) { _, _ = w.PresentInSession(nil, "", nil, "", "", zero) }`
	twin := `package humansession
// w.PresentInSession(...) — упоминание в комментарии
func (uc *StepUpUseCase) Execute(w Writer) { _ = "w.PresentInSession"; presentInSession(w) }`
	defect := `package humansession
func (uc *StepUpUseCase) Execute(w Writer) { _, _ = w.PresentInSession(nil, "", nil, "2", "", zero) }`

	c, err := judgeLevelWriters(map[string]string{"session_level.go": home, "step_up.go": twin})
	if err != nil {
		t.Fatal(err)
	}
	if f := levelWriterFindings(c); len(f) != 0 {
		t.Fatalf("законный близнец обязан молчать: %v", f)
	}
	c, err = judgeLevelWriters(map[string]string{"session_level.go": home, "step_up.go": defect})
	if err != nil {
		t.Fatal(err)
	}
	f := levelWriterFindings(c)
	if len(f) != 1 || !strings.Contains(f[0], "step_up.go:Execute") {
		t.Fatalf("второй вызывающий обязан краснеть с координатой step_up.go:Execute: %v", f)
	}
	c, err = judgeLevelWriters(map[string]string{"step_up.go": twin})
	if err != nil {
		t.Fatal(err)
	}
	if f := levelWriterFindings(c); len(f) != 1 || !strings.Contains(f[0], "переехал") {
		t.Fatalf("снятый дом обязан краснеть: %v", f)
	}
}
