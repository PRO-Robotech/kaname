// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// cutoff_write_paths_census_test.go — каждый путь записи строки отсечки
// отзыва-всех подан пробе выдачи по отсечке (задача kaname#379).
//
// # Почему перепись, а не выписанный перечень
//
// Проба выдачи по отсечке (`client_token_revoke_all_integration_test.go`)
// подаёт отсечку каждым путём записи отдельно: читатель, понимающий форму
// строки одного пути, был бы зелен на пробе, подающей только его. Перечень
// путей, выписанный в пробе рукой, этого не держит — путь, заведённый позже и
// в перечень не внесённый, остаётся без пробы молча, а длина выписанного
// перечня совпадает сама с собой при любом дереве.
//
// Поэтому пути выводятся из дерева: путь записи — функция этого пакета, в теле
// которой исполняется операция записи отсечки (`upsertRevokeAllSQL`). Опознаётся
// УЗЛОМ разбора (идентификатор в теле функции), а не словом: имя операции в
// комментарии или строке путём записи не является.
//
// # Перепись печатает обе величины
//
// «Путей записи по дереву N · подано пробой M». Ноль путей по дереву — не
// «покрыто всё», а «не выполнилось»: обход, не нашедший ни одного пути,
// падает с названной причиной.
package pg_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// cutoffWriteOperation — имя операции записи строки отсечки: ОДНА на дерево.
const cutoffWriteOperation = "upsertRevokeAllSQL"

// cutoffWritePathsInTree — пути записи строки отсечки в этом пакете: функции,
// в теле которых исполняется операция записи. Возвращает пути и число
// разобранных файлов.
func cutoffWritePathsInTree(t *testing.T) ([]string, int) {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err, "чтение каталога пакета")
	fset := token.NewFileSet()
	found := map[string]struct{}{}
	parsed := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		require.NoErrorf(t, perr, "разбор %s", name)
		parsed++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			executes := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && id.Name == cutoffWriteOperation {
					executes = true
					return false
				}
				return !executes
			})
			if executes {
				found[funcPathName(fn)] = struct{}{}
			}
		}
	}
	paths := make([]string, 0, len(found))
	for p := range found {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, parsed
}

// funcPathName — «Получатель.Метод» либо имя функции без получателя.
func funcPathName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	typ := fn.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// fedCutoffWritePaths — пути записи, которые подаёт проба выдачи по отсечке.
func fedCutoffWritePaths() []string {
	seen := map[string]struct{}{}
	for _, w := range revokeAllWritersUnderTest() {
		seen[w.path] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// TestRevokeAllProbeFeedsEveryWritePathOfTheCutoffRow — перепись путей записи
// по дереву против путей, которые подаёт проба. Расхождение в любую сторону —
// находка: путь без пробы молчит о своей форме строки, а запись пробы о пути,
// которого нет, — исключение, пережившее свой предмет.
func TestRevokeAllProbeFeedsEveryWritePathOfTheCutoffRow(t *testing.T) {
	inTree, parsed := cutoffWritePathsInTree(t)
	require.NotZerof(t, parsed, "не разобран ни один файл пакета — перепись не выполнилась")
	require.NotEmptyf(t, inTree,
		"по дереву не найдено ни одного пути записи строки отсечки (операция %s) среди %d файлов — "+
			"перепись не выполнилась, это не «покрыто всё»", cutoffWriteOperation, parsed)

	fed := fedCutoffWritePaths()
	fedSet := map[string]struct{}{}
	for _, p := range fed {
		fedSet[p] = struct{}{}
	}
	treeSet := map[string]struct{}{}
	for _, p := range inTree {
		treeSet[p] = struct{}{}
	}
	var unfed, stale []string
	for _, p := range inTree {
		if _, ok := fedSet[p]; !ok {
			unfed = append(unfed, p)
		}
	}
	for _, p := range fed {
		if _, ok := treeSet[p]; !ok {
			stale = append(stale, p)
		}
	}
	t.Logf("перепись: файлов разобрано %d · путей записи строки отсечки по дереву %d · подано пробой %d",
		parsed, len(inTree), len(fed))
	if len(unfed) > 0 {
		t.Errorf("пути записи строки отсечки без пробы выдачи по отсечке: %v", unfed)
	}
	if len(stale) > 0 {
		t.Errorf("проба подаёт пути записи, которых в дереве нет: %v", stale)
	}
}
