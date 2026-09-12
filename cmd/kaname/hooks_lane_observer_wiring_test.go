// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// hooks_lane_observer_wiring_test.go — полоса хуков поставщика личности,
// собранная корнем, НЕСЁТ приёмник исходов (задача продукта #2495).
//
// # Почему это отдельная проба
//
// Приёмник, объявленный и не провязанный, отличается от отсутствующего ровно
// одним: он покрыт пробой своего пакета и потому выглядит работающим. Наружу это
// видно как «рядов нет» — то же, что видно при исправной полосе, к которой
// никто не приходил. То есть неотличимость ровно та, ради устранения которой
// величина и заводится.
//
// # Что здесь считается провязкой
//
// Поле `LaneObserver` в составном литерале `Handlers`, которым собран
// мультиплексор полосы. Не «слово встречается в файле»: имя поля стоит и в
// комментарии объявляющего пакета.

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

// hooksHandlerPath — путь пакета, объявляющего полосу хуков.
const hooksHandlerPath = "github.com/PRO-Robotech/kaname/internal/handler/iamhooks"

func TestTheHookLaneCarriesItsOutcomeObserver(t *testing.T) {
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
		parsed   int
		bundles  []string // файлы, собирающие пакет обработчиков полосы
		observed []string // из них — с провязанным приёмником
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
		local := localName(file, hooksHandlerPath)
		if local == "" {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Handlers" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != local {
				return true
			}
			bundles = append(bundles, name)
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "LaneObserver" {
					observed = append(observed, name)
					break
				}
			}
			return true
		})
	}

	t.Logf("перепись: не-тестовых файлов корня разобрано %d, сборок полосы %v, "+
		"из них с приёмником исходов %v", parsed, bundles, observed)

	if parsed == 0 {
		t.Fatalf("разобрано ноль файлов корня — обход беспредметен")
	}
	if len(bundles) == 0 {
		t.Fatalf("сборок полосы хуков в корне НОЛЬ — гейт беспредметен: он молчал бы и тогда, " +
			"когда полосы не стало вовсе")
	}
	if len(observed) != len(bundles) {
		t.Fatalf("полоса хуков собирается в %v, а приёмник исходов провязан только в %v.\n\n"+
			"Это ЖИВОЙ путь входа человека. Без величины «полоса отказывает» и «поставщик не "+
			"настроен звать хук» дают одинаково ненаблюдаемые картины: в первом случае растут "+
			"строки журнала, во втором их нет вовсе, и отсутствие строк тревогой не бывает.\n"+
			"Снятие: поле `LaneObserver: metricsReg.AuthnHooksRecorder(...)` в составном литерале `Handlers`.",
			bundles, observed)
	}
}
