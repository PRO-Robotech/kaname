// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// outbox_scan_observer_wiring_test.go — задача #2062, половина «одинаково для
// ВСЕХ очередей сервиса».
//
// Решение об исходе скана объявлено одним производителем
// (`metrics.OutboxScanObserver`). Держится это не тем, что так написано в его
// шапке, а тем, что КАЖДЫЙ сканер сервиса через него провязан: очередь, чей
// сайт забыли поправить, молчала бы на отказе — и её молчание было бы
// неотличимо от исправной работы, то есть ровно тот класс, ради которого
// счётчики исходов и заведены.
//
// Гейт судит РАЗОБРАННЫЙ исходник, а не текст: имя производителя встречается и
// в комментариях (в том числе в этом файле), и проверка по подстроке краснела
// бы на собственном объяснении.

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

// callName возвращает `pkg.Func` для вызова вида `pkg.Func(...)`.
func callName(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return pkg.Name + "." + sel.Sel.Name
}

func TestEveryOutboxScannerIsWiredThroughTheSingleObserver(t *testing.T) {
	t.Parallel()

	entries, err := filepath.Glob("*.go")
	require.NoError(t, err)
	require.NotEmpty(t, entries, "исходников композиционного корня не найдено — обход пуст")

	fset := token.NewFileSet()
	scanned := 0
	var collectors, observers []string

	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		raw, rerr := os.ReadFile(path)
		require.NoError(t, rerr)
		file, perr := parser.ParseFile(fset, path, raw, parser.SkipObjectResolution)
		require.NoError(t, perr, "исходник не разобран: %s", path)
		scanned++

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch callName(call) {
			case "outboxmetrics.NewCollector":
				collectors = append(collectors, fset.Position(call.Pos()).String())
			case "metrics.OutboxScanObserver":
				observers = append(observers, fset.Position(call.Pos()).String())
			}
			return true
		})
	}
	sort.Strings(collectors)
	sort.Strings(observers)

	t.Logf("перепись: исходников корня разобрано %d, сканеров заведено %d, наблюдателей исхода %d",
		scanned, len(collectors), len(observers))

	require.NotZero(t, scanned, "разобрано ноль исходников — вердикт беспредметен")
	require.NotEmpty(t, collectors,
		"перепись не нашла НИ ОДНОГО сканера очереди — она смотрит не туда, и её вердикт ничего не значит")
	require.Equal(t, len(collectors), len(observers),
		"сканеров %d, а наблюдателей исхода %d — у какой-то очереди отказ скана остаётся невидимым.\nсканеры:\n%s\nнаблюдатели:\n%s",
		len(collectors), len(observers),
		strings.Join(collectors, "\n"), strings.Join(observers, "\n"))
}
