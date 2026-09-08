// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// schema_guard_wiring_test.go — гейт «страж прежней схемы ПОЗВАН, и позван ДО
// первого писателя пути старта».
//
// ─────────────────────────────────────────────────────────────────────────────
// # Предмет
//
// Страж, написанный и не позванный, отличается от отсутствующего ровно одним:
// он покрыт пробами и потому выглядит работающим. Это класс мёртвого стража
// (`00-kacho-core` ban #16): вопрос не «есть ли функция», а «меняет ли она исход
// старта».
//
// Здесь он особенно тихий: снятый вызов не роняет ни сборку, ни пробы состава,
// ни пробы на живой базе — те зовут стража НАПРЯМУЮ. Молчание было бы полным.
//
// ─────────────────────────────────────────────────────────────────────────────
// # Судятся ДВА факта, и второй из первого не следует
//
//	A. ВЫЗОВ. `assertNoRetiredSchema` вызван в композиционном корне.
//
//	B. ПОРЯДОК. Вызов стоит ДО первого писателя пути старта — фоновой уборки
//	   таблицы операций. Порядок здесь несущий, а не вкус: предмет стража —
//	   отказ РАНЬШЕ первой записи. Страж, отработавший после того, как процесс
//	   начал писать, отвечает на вопрос, который уже решён.
//
// ─────────────────────────────────────────────────────────────────────────────
// # Судится РАЗОБРАННЫЙ исходник, а не его текст
//
// Имя стража стоит и в прозе — в шапке этого файла, в шапке самого стража, в
// комментарии у места вызова. Проверка по подстроке зеленела бы на собственном
// объяснении и осталась бы зелёной над закомментированным вызовом. Поэтому
// судятся узлы вызова.
//
// # Граница названа вслух
//
// Гейт судит `serve.go` — файл, который поднимает пул и на котором стоят оба
// загрузочных стража базы. Вызов, уехавший в чужой пакет, ему не виден; такой
// формы в дереве нет, а появившись, она обязана быть учтена своим изменением.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

const (
	// schemaGuardCall — страж, чей вызов судится.
	schemaGuardCall = "assertNoRetiredSchema"

	// firstBootWriterCall — первое, что путь старта ПИШЕТ в базу: фоновая
	// уборка терминальных строк таблицы операций снимает строки.
	firstBootWriterCall = "operations.StartRetentionSweep"
)

// callOffsets отдаёт смещение ПЕРВОГО вызова каждого названного глагола.
// Отсутствующий глагол получает -1: «не позван» и «позван первым» обязаны быть
// различимы, а не сливаться в ноль.
func callOffsets(t *testing.T, src, filename string, want ...string) (map[string]int, int) {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("разбор %s: %v", filename, err)
	}

	found := make(map[string]int, len(want))
	for _, name := range want {
		found[name] = -1
	}

	seen := 0
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		seen++
		name := renderCallee(call.Fun)
		if at, tracked := found[name]; tracked && at == -1 {
			found[name] = fset.Position(call.Lparen).Offset
		}
		return true
	})
	return found, seen
}

// renderCallee сводит вызываемое к `имя` либо `пакет.Имя`. Прочие формы (вызов
// результата, метод на выражении) именем не представимы и в счёт не идут.
func renderCallee(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if pkg, ok := f.X.(*ast.Ident); ok {
			return pkg.Name + "." + f.Sel.Name
		}
	}
	return ""
}

func TestSchemaGuard_IsCalledOnTheBootPathBeforeTheFirstWriter(t *testing.T) {
	src, err := os.ReadFile("serve.go")
	if err != nil {
		t.Fatalf("serve.go не прочитан: %v", err)
	}

	at, calls := callOffsets(t, string(src), "serve.go", schemaGuardCall, firstBootWriterCall)

	// Предпосылка гейта: обход что-то видел. Ноль вызовов означал бы, что судить
	// было нечего, — и «нарушений нет» стало бы неотличимо от «не прочитано».
	if calls == 0 {
		t.Fatal("в serve.go не найдено ни одного вызова — обход пуст, вердикт беспредметен")
	}

	// (A) Вызов есть.
	if at[schemaGuardCall] < 0 {
		t.Fatalf("serve.go не зовёт %s: страж написан и не позван — служба поднимется "+
			"поверх базы прежней установки, а страж будет выглядеть работающим, "+
			"потому что его пробы зовут его напрямую", schemaGuardCall)
	}

	// (B) Порядок. Отсутствие писателя — тоже находка: значит гейт судит
	// порядок относительно того, чего в файле нет, и молчит по этой причине.
	if at[firstBootWriterCall] < 0 {
		t.Fatalf("serve.go не зовёт %s — гейт порядка потерял точку отсчёта и молчал бы "+
			"не потому, что порядок верен", firstBootWriterCall)
	}
	if at[schemaGuardCall] > at[firstBootWriterCall] {
		t.Errorf("%s стоит ПОСЛЕ %s: путь старта успел записать в базу до того, как страж "+
			"сказал, что база не та — отказ обязан наступать раньше первой записи",
			schemaGuardCall, firstBootWriterCall)
	}

	t.Logf("перепись serve.go: вызовов осмотрено %d · %s на смещении %d · %s на смещении %d",
		calls, schemaGuardCall, at[schemaGuardCall], firstBootWriterCall, at[firstBootWriterCall])
}

// Предпосылка ГЕЙТА, а не дерева: разбор обязан отличать вызов от упоминания.
// Без этого утверждения гейт мог бы зеленеть на закомментированном вызове, и
// заметить это можно было бы только сняв провязку.
func TestSchemaGuard_WiringGateReadsCallsNotProse(t *testing.T) {
	const guardOnlyMentioned = `package main

// assertNoRetiredSchema сюда ещё не провязан.
func serve() error {
	_ = "assertNoRetiredSchema"
	operations.StartRetentionSweep(ctx)
	return nil
}
`
	at, calls := callOffsets(t, guardOnlyMentioned, "synthetic.go", schemaGuardCall, firstBootWriterCall)
	if calls == 0 {
		t.Fatal("синтетика не дала ни одного вызова — доказательство беспредметно")
	}
	if at[schemaGuardCall] >= 0 {
		t.Error("разбор засчитал за вызов комментарий или строковый литерал: гейт зеленел бы " +
			"на закомментированной провязке")
	}
	// Законный близнец в той же синтетике: настоящий вызов рядом УЗНАЁТСЯ.
	// Без него «не засчитал» было бы неотличимо от «не считает ничего».
	if at[firstBootWriterCall] < 0 {
		t.Error("разбор не узнал настоящий вызов через селектор — он не считает ничего")
	}
	if strings.Count(guardOnlyMentioned, schemaGuardCall) < 2 {
		t.Fatal("синтетика перестала нести имя стража прозой — предмет доказательства исчез")
	}
}
