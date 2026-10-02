// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// force_logout_teardown_wiring_test.go — ПРИНУДИТЕЛЬНЫЙ ВЫХОД СНИМАЕТ НАШУ
// СЕССИЮ ВХОДА, И КОРЕНЬ ПРОВЯЗЫВАЕТ ЭТО БЕЗУСЛОВНО (задачи kaname#313, #363).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Прежде исполнителя снятия выбирала посадка: под своей — наша запись сессии,
// под внешней — сессия у поставщика. Поставщика больше нет, и сессия входа
// человека — всегда наша строка. Опасность снятия развилки — ПОТЕРЯННАЯ
// провязка: глагол без исполнителя снятия отказывает `Unavailable` до всякой
// записи (это судит `internal/apps/kaname/api/internal_iam`), и распорядитель
// не может вывести никого, а старт проходит.
//
// Здесь судится ВЫБОР корня: `WithOwnSessions` зовётся в сборке ровно один раз
// и получает построенное хранилище, а не пустое значение. Разбор судит узел
// вызова, а не текст: имя в комментарии провязкой не считается.
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

// forceLogoutWiringFile — файл, в котором корень собирает обработчик глагола.
const forceLogoutWiringFile = "wiring.go"

// ownSessionsReading — что разбор увидел в одном файле.
type ownSessionsReading struct {
	// Calls — вызовов прочитано, перепись.
	Calls int
	// Wired — строки вызовов `WithOwnSessions(<построение>)`.
	Wired []int
	// Nil — строки вызовов `WithOwnSessions(nil)`.
	Nil []int
}

// readOwnSessionsWiring — предикат. Вынесен функцией: доказательство
// способности упасть зовёт ТОТ ЖЕ разбор.
func readOwnSessionsWiring(path string, src []byte) (ownSessionsReading, error) {
	var out ownSessionsReading
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return out, err
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		out.Calls++
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WithOwnSessions" || len(call.Args) != 1 {
			return true
		}
		line := fset.Position(call.Pos()).Line
		if id, isIdent := call.Args[0].(*ast.Ident); isIdent && id.Name == "nil" {
			out.Nil = append(out.Nil, line)
			return true
		}
		out.Wired = append(out.Wired, line)
		return true
	})
	return out, nil
}

func TestCompositionRoot_ForceLogoutTearsDownOurOwnSessionOnEveryStart(t *testing.T) {
	src, err := os.ReadFile(forceLogoutWiringFile)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан: %v", forceLogoutWiringFile, err)
	}
	r, err := readOwnSessionsWiring(forceLogoutWiringFile, src)
	if err != nil {
		t.Fatalf("разбор %s: %v", forceLogoutWiringFile, err)
	}
	t.Logf("перепись: %s — вызовов прочитано %d · провязок снятия %v · пустых провязок %v",
		forceLogoutWiringFile, r.Calls, r.Wired, r.Nil)
	if r.Calls == 0 {
		t.Fatalf("в %s не прочитано ни одного вызова — разбор не видит файла, и его молчание "+
			"сказано ни о чём", forceLogoutWiringFile)
	}
	if len(r.Nil) > 0 {
		t.Fatalf("корень подаёт глаголу пустого исполнителя снятия (строки %v): глагол отказывает "+
			"на каждом вызове, и распорядитель не выводит никого", r.Nil)
	}
	if len(r.Wired) != 1 {
		t.Fatalf("исполнитель снятия сессии входа провязан %d раз (строки %v), ожидался ровно один: "+
			"без провязки глагол отказывает на каждом вызове, две провязки — две сборки одного "+
			"обработчика", len(r.Wired), r.Wired)
	}
}

// Способность упасть и промолчать — на синтетике: потерянная провязка и
// пустое значение — находки; провязка построением и имя в комментарии —
// молчание.
func TestForceLogoutTeardownJudgeFindsALostWiringAndSparesTheLawfulForm(t *testing.T) {
	for _, c := range []struct {
		name       string
		src        string
		wired, nil int
	}{
		{"провязка построением", "package main\n\nfunc f() { h.WithOwnSessions(kanamepg.NewHumanSessionRepo(pool)) }\n", 1, 0},
		{"провязка потеряна", "package main\n\nfunc f() { h.WithLogger(logger) }\n", 0, 0},
		{"пустое значение", "package main\n\nfunc f() { h.WithOwnSessions(nil) }\n", 0, 1},
		{"имя в комментарии", "package main\n\n// WithOwnSessions(repo) звали здесь.\nfunc f() { h.WithLogger(logger) }\n", 0, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, err := readOwnSessionsWiring("wiring.go", []byte(c.src))
			if err != nil {
				t.Fatalf("разбор синтетики: %v", err)
			}
			if r.Calls == 0 {
				t.Fatalf("перепись синтетики пуста: %+v", r)
			}
			if len(r.Wired) != c.wired || len(r.Nil) != c.nil {
				t.Fatalf("прочитано провязок %d и пустых %d, ожидалось %d и %d: %+v",
					len(r.Wired), len(r.Nil), c.wired, c.nil, r)
			}
		})
	}
}
