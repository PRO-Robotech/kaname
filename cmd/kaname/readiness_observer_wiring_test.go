// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// readiness_observer_wiring_test.go — носитель готовности, который собирает
// корень, ЗЕРКАЛИТ свой исход в величину (задача продукта #2494).
//
// # Почему это отдельная проба, а не строка в шапке
//
// Общий носитель готовности несёт объявленную опцию зеркала (`WithResultObserver`)
// и вызывается ею у трёх соседних служб. Kaname — единственная, кто поставляется
// отдельно, к ЧУЖОМУ дежурному, — её не читала: имена трёх зависимостей выходили
// наружу только в теле пробы, и узнать их можно было лишь пробросом порта.
//
// # Что здесь считается провязкой
//
// Опция стоит ДОВОДОМ ТОГО ЖЕ вызова `health.New`, которым построен носитель. Не
// «слово встречается в файле»: имя опции стоит и в комментарии соседнего пакета,
// и гейт по подстроке зеленел бы на собственном объяснении.
//
// # Что эта проба НЕ закрывает — сказано прямо
//
// Она судит ПРОВЯЗКУ, а не поведение приёмника: что ряды заведены нулём при
// регистрации и двигаются на событии, держит проба пакета величин
// (`internal/observability/metrics/readiness_recorder_test.go`). Предметы разные,
// и слив их в одну пробу дал бы зелёное на половине свойства.

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

// healthCarrierPath — путь объявленного носителя готовности.
const healthCarrierPath = "github.com/PRO-Robotech/corelib/observability/health"

func TestTheReadinessCarrierMirrorsItsResultIntoAValue(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("чтение каталога корня: %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)

	var (
		parsed    int
		built     []string // файлы, строящие носитель
		mirrored  []string // из них — с зеркалом в том же вызове
		optionAll int      // вхождений опции вообще, включая не-довод
	)
	fset := token.NewFileSet()
	for _, name := range files {
		src, rerr := os.ReadFile(filepath.Clean(name))
		if rerr != nil {
			t.Fatalf("чтение %s: %v", name, rerr)
		}
		file, perr := parser.ParseFile(fset, name, src, 0)
		if perr != nil {
			t.Fatalf("разбор %s: %v", name, perr)
		}
		parsed++
		local := localName(file, healthCarrierPath)
		if local == "" {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != local {
				return true
			}
			if sel.Sel.Name == "WithResultObserver" {
				optionAll++
				return true
			}
			if sel.Sel.Name != "New" {
				return true
			}
			built = append(built, name)
			for _, arg := range call.Args {
				withObserver := false
				ast.Inspect(arg, func(inner ast.Node) bool {
					isel, ok := inner.(*ast.SelectorExpr)
					if ok && isel.Sel.Name == "WithResultObserver" {
						withObserver = true
					}
					return true
				})
				if withObserver {
					mirrored = append(mirrored, name)
					break
				}
			}
			return true
		})
	}

	t.Logf("перепись: не-тестовых файлов корня разобрано %d, построений носителя %v, "+
		"из них с зеркалом %v, вхождений опции всего %d", parsed, built, mirrored, optionAll)

	if parsed == 0 {
		t.Fatalf("разобрано ноль файлов корня — обход беспредметен, и его молчание сказано ни о чём")
	}
	if len(built) == 0 {
		t.Fatalf("построений носителя готовности в корне НОЛЬ — гейт беспредметен: он молчал бы " +
			"и тогда, когда готовности не стало вовсе")
	}
	if len(mirrored) != len(built) {
		t.Fatalf("носитель готовности строится в %v, а зеркало исхода провязано только в %v.\n\n"+
			"Без зеркала наружу выходит ОДИН БИТ — «под не готов». Имя отказавшей зависимости "+
			"остаётся в теле пробы, поднятой по TLS на внутреннем порту: дежурный в три часа "+
			"ночи не отличит «база недоступна» (сломан продукт) от «образ не той версии, что "+
			"схема» (условие не создано).\n"+
			"Снятие: `health.New(checkers, health.WithResultObserver(metricsReg.ReadinessRecorder(...).Observe))`.",
			built, mirrored)
	}
}
