// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// hook_lane_reconciler_test.go — ПОЛОСА ПЕРВОГО ВХОДА НЕ СТРОИТ СВОЕГО
// РЕКОНСАЙЛЕРА, А ПРИНИМАЕТ ЕГО (задача kaname#116).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Реконсайлер пути запроса собирается в `wiring.go` вместе с приёмником размера
// материализации привязки. Полоса первого входа — живой путь регистрации
// человека — собирала СВОЙ экземпляр, и приёмника на нём не было: материализации
// этой полосы в гистограмму не попадали, а она читалась как полная.
//
// Различить это по числам нельзя. Гистограмма, не видящая полосы, выглядит
// РОВНО ТАК ЖЕ, как гистограмма полосы, по которой нет трафика, — поэтому
// «ноль наблюдений» тут не улика, и заметить дефект можно только по проводке.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ — И ПОЧЕМУ НЕ «ЭКЗЕМПЛЯР ОДИН НА ПРОЦЕСС»
//
// Утверждается ровно одно: сборщик хуков реконсайлера НЕ СТРОИТ и ПРИНИМАЕТ его
// параметром. Требование «экземпляр один на весь процесс» было бы шире
// измеренного и неверно: фоновый воркер обхода (`serve.go`) строит свой
// осознанно — у него своё имя в журнале и свой жизненный цикл. Попадают ли ЕГО
// материализации в ту же гистограмму — вопрос продуктовый, он не решался, и он
// заведён задачей #157, а не закрыт молча этим гейтом.
//
// ─────────────────────────────────────────────────────────────────────────────
// РАЗБОР СУДИТ УЗЕЛ, А НЕ ТЕКСТ
//
// Построение опознаётся узлом `ast.CallExpr` с селектором `<псевдоним>.New`, где
// псевдоним прочитан из объявления импорта ТОГО ЖЕ файла. Переименование
// псевдонима распознаватель не обманет, а упоминание имени в комментарии
// построением не считается — иначе гейт краснел бы на собственном объяснении
// (`testing.md` §«Гейт на класс», п. 4).
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	// hookLaneFile — файл сборщика полосы хуков.
	hookLaneFile = "hooks_mux.go"
	// hookLaneBuilder — сам сборщик.
	hookLaneBuilder = "buildHooksMux"
	// reconcilePkgPath — путь импорта реконсайлера привязки.
	reconcilePkgPath = "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	// reconcileTypeName — тип, который сборщик обязан принимать.
	reconcileTypeName = "Reconciler"
)

// hookLaneReading — что разбор увидел в одном файле.
type hookLaneReading struct {
	// Alias — псевдоним импорта реконсайлера; пусто, если он не импортирован.
	Alias string
	// Builds — координаты построений `<псевдоним>.New(...)`.
	Builds []int
	// AcceptsReconciler — принимает ли сборщик параметр типа `*<псевдоним>.Reconciler`.
	AcceptsReconciler bool
	// Calls — вызовов прочитано, перепись.
	Calls int
	// Params — параметров сборщика прочитано, перепись.
	Params int
}

// readHookLane — предикат. Вынесен функцией: инъекция зовёт ТОТ ЖЕ разбор,
// иначе она доказывает способность упасть у своей копии.
func readHookLane(path string, src []byte, builderName string) (hookLaneReading, error) {
	var out hookLaneReading
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return out, err
	}
	for _, spec := range f.Imports {
		p, uerr := strconv.Unquote(spec.Path.Value)
		if uerr != nil || p != reconcilePkgPath {
			continue
		}
		if spec.Name != nil {
			out.Alias = spec.Name.Name
		} else {
			out.Alias = "reconcile"
		}
	}
	if out.Alias == "" {
		return out, nil
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			out.Calls++
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "New" {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == out.Alias {
					out.Builds = append(out.Builds, fset.Position(call.Pos()).Line)
				}
			}
		}
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != builderName || fd.Type.Params == nil {
			return true
		}
		for _, p := range fd.Type.Params.List {
			out.Params++
			star, ok := p.Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			sel, ok := star.X.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != reconcileTypeName {
				continue
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == out.Alias {
				out.AcceptsReconciler = true
			}
		}
		return true
	})
	return out, nil
}

// TestHookLaneTakesTheSharedReconciler — сам гейт.
func TestHookLaneTakesTheSharedReconciler(t *testing.T) {
	src, err := os.ReadFile(filepath.Clean(hookLaneFile)) // #nosec G304 -- файл пакета, не ввод снаружи
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан: %v", hookLaneFile, err)
	}
	r, err := readHookLane(hookLaneFile, src, hookLaneBuilder)
	if err != nil {
		t.Fatalf("разбор %s: %v", hookLaneFile, err)
	}

	t.Logf("перепись: %s — псевдоним реконсайлера %q, вызовов прочитано %d, параметров "+
		"%s прочитано %d, построений %v, принимает экземпляр: %t",
		hookLaneFile, r.Alias, r.Calls, hookLaneBuilder, r.Params, r.Builds, r.AcceptsReconciler)

	if r.Alias == "" {
		t.Fatalf("%s не импортирует реконсайлер вовсе: либо полоса перестала материализовать "+
			"доступ, либо файл переименован — и тогда гейт стережёт координату, которой нет",
			hookLaneFile)
	}
	if r.Params == 0 {
		t.Fatalf("у %s не прочитано ни одного параметра — разбор не нашёл сборщика, и его "+
			"молчание сказано ни о чём", hookLaneBuilder)
	}
	if len(r.Builds) > 0 {
		var where []string
		for _, l := range r.Builds {
			where = append(where, hookLaneFile+":"+strconv.Itoa(l))
		}
		t.Fatalf("полоса первого входа строит СВОЙ реконсайлер — %s\n\n"+
			"Экземпляр пути запроса собирается в wiring.go вместе с приёмником размера "+
			"материализации привязки; собранный здесь его не несёт, и материализации живой "+
			"полосы регистрации человека в гистограмму не попадают. Гистограмма, не видящая "+
			"полосы, выглядит РОВНО ТАК ЖЕ, как гистограмма полосы без трафика, поэтому по "+
			"числам дефект не различим.\n"+
			"Снятие: принять экземпляр параметром (`services.bindingReconciler`), а не "+
			"собирать второй.", strings.Join(where, " · "))
	}
	if !r.AcceptsReconciler {
		t.Fatalf("%s не принимает *%s.%s параметром, и своего не строит — значит полоса "+
			"первого входа материализацию не ведёт вовсе. Либо провязка потеряна, либо "+
			"предмет гейта исчез; молча это выглядит одинаково",
			hookLaneBuilder, r.Alias, reconcileTypeName)
	}
}
