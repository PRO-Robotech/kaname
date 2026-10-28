// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// binding_reconcilers_test.go — КАЖДЫЙ реконсайлер привязки в композиционном
// корне собирается со своей полосой наблюдения размера (задача kaname#157).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Реконсайлер привязки строится в корне дважды, и оба экземпляра законны:
// путь запроса (`wiring.go`) и фоновый обход (`serve.go`: воркер очереди
// реконсайла, подмётка, истечение срока, догон и проверка на старте) — у
// второго своё имя в журнале и свой жизненный цикл. Приёмник размера
// материализации нёс только первый; материализации обхода в гистограмму не
// попадали, а гистограмма читалась как полная. Полоса вне наблюдения выглядит
// ровно как полоса без трафика, поэтому по числам дефект не различим —
// заметить его можно только по проводке.
//
// Решение (kaname#157): обход ВХОДИТ в гистограмму, полосы разведены меткой
// `lane` (`request` · `sweep`). Смешивать их без метки нельзя — размеры
// обхода и размеры пути запроса отвечают на разные вопросы.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ ПОЛОВИНЫ
//
//	ПОВЕДЕНИЕ — экземпляр, собранный сборщиком полосы, проходит настоящий
//	            проход привязки, и сдвигается ряд ЕГО полосы, а соседний — нет.
//	ДЕРЕВО    — в корне нет построения реконсайлера МИМО сборщиков полос, и у
//	            каждого сборщика есть вызывающий. Третье построение без полосы —
//	            тот самый класс, которым был воркер обхода; сборщик без
//	            вызывающего — полоса, объявленная наблюдаемой и не провязанная.
//
// Построение опознаётся узлом `ast.CallExpr` `<псевдоним>.New`, псевдоним
// читается из объявления импорта ТОГО ЖЕ файла: воркер обхода и был пропущен
// поиском по имени, потому что записан под другим псевдонимом.
package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// errPassStopped обрывает проход ПОСЛЕ замера размера: дальше прохода проба
// не судит, а исход вызова доказывает, что замер был пройден.
var errPassStopped = errors.New("проход оборван пробой после замера размера")

// thinBindingStore — хранилище одного прохода: выдача действующая, селекторов
// у роли нет. Остальные методы порта не реализованы: обращение к ним — паника,
// и значит проход ушёл туда, куда проба его не вела.
type thinBindingStore struct {
	reconcileapp.ReconcileStore
}

func (thinBindingStore) AcquireBindingLock(context.Context, domain.AccessBindingID) error {
	return nil
}

func (thinBindingStore) LoadBinding(_ context.Context, id domain.AccessBindingID) (reconcileapp.BindingScope, bool, error) {
	return reconcileapp.BindingScope{BindingID: id, Active: true}, true, nil
}

func (thinBindingStore) CurrentMembers(context.Context, domain.AccessBindingID) ([]domain.TargetMember, error) {
	return nil, errPassStopped
}

type thinBindingTx struct{}

func (thinBindingTx) WithTx(ctx context.Context, fn func(context.Context, reconcileapp.ReconcileStore) error) error {
	return fn(ctx, thinBindingStore{})
}

// materializationPasses — число наблюдений полосы по величине объектов и есть
// ли ряд полосы на проводе вовсе. Отсутствие ряда — не отказ пробы, а ответ:
// реконсайлер без приёмника не регистрирует семейства, и это ровно дефект.
func materializationPasses(t *testing.T, reg *metrics.Registry, lane string) (count uint64, present bool) {
	t.Helper()
	g, ok := reg.Registerer().(prometheus.Gatherer)
	if !ok {
		t.Fatalf("реестр величин не отдаёт собранное — проба не видит провода")
	}
	families, err := g.Gather()
	if err != nil {
		t.Fatalf("сбор реестра: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != metrics.BindingMaterializationObjectsMetric {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "lane" && lp.GetValue() == lane {
					return m.GetHistogram().GetSampleCount(), true
				}
			}
		}
	}
	return 0, false
}

// bindingReconcilerLanes — сборщики полос и полоса каждого. Перечень закрыт:
// третья полоса без решения о ней — находка дерева ниже.
var bindingReconcilerLanes = map[string]string{
	"newRequestBindingReconciler": metrics.BindingMaterializationLaneRequest,
	"newSweepBindingReconciler":   metrics.BindingMaterializationLaneSweep,
}

// TestBindingReconcilerPassMovesItsOwnLane — ПОВЕДЕНИЕ.
func TestBindingReconcilerPassMovesItsOwnLane(t *testing.T) {
	builders := map[string]func(reconcileapp.TxRunner, *metrics.Registry) *reconcileapp.Reconciler{
		"newRequestBindingReconciler": func(tx reconcileapp.TxRunner, reg *metrics.Registry) *reconcileapp.Reconciler {
			return newRequestBindingReconciler(tx, nil, catalogfixture.Source(), reg)
		},
		"newSweepBindingReconciler": func(tx reconcileapp.TxRunner, reg *metrics.Registry) *reconcileapp.Reconciler {
			return newSweepBindingReconciler(tx, nil, catalogfixture.Source(), reg)
		},
	}
	if len(builders) != len(bindingReconcilerLanes) {
		t.Fatalf("проба зовёт %d сборщиков, а полос объявлено %d", len(builders), len(bindingReconcilerLanes))
	}
	for name, build := range builders {
		lane, ok := bindingReconcilerLanes[name]
		if !ok {
			t.Fatalf("сборщик %s не назван в перечне полос", name)
		}
		t.Run(name, func(t *testing.T) {
			reg := metrics.NewRegistry()
			rec := build(thinBindingTx{}, reg)

			err := rec.ReconcileBinding(context.Background(), domain.AccessBindingID("ab-157"))
			if !errors.Is(err, errPassStopped) {
				t.Fatalf("проход не дошёл до точки, где проба его обрывает: %v — замер размера "+
					"тогда не пройден, и молчание ряда сказано ни о чём", err)
			}
			for _, other := range metrics.BindingMaterializationLanes {
				got, present := materializationPasses(t, reg, other)
				switch {
				case other == lane && (!present || got != 1):
					t.Errorf("проход реконсайлера %s НЕ сдвинул ряд своей полосы %q (ряд на проводе: %t, "+
						"наблюдений %d) — материализации этой полосы вне гистограммы, и она читается "+
						"как полоса без трафика", name, lane, present, got)
				case other != lane && got != 0:
					t.Errorf("проход реконсайлера %s сдвинул ряд ЧУЖОЙ полосы %q (наблюдений %d) — "+
						"полосы снова читаются слитно", name, other, got)
				}
			}
		})
	}
}

// reconcilerBuildSite — построение реконсайлера в исходнике.
type reconcilerBuildSite struct {
	File string
	Line int
	// Enclosing — функция, внутри которой построение лежит; пусто — уровень пакета.
	Enclosing string
}

// reconcilerTreeReading — что разбор увидел в одном файле.
type reconcilerTreeReading struct {
	Builds []reconcilerBuildSite
	// BuilderCalls — вызовы сборщиков полос по имени.
	BuilderCalls map[string]int
	// Calls — вызовов прочитано, перепись.
	Calls int
}

// readReconcilerTree — предикат дерева над одним файлом. Вынесен функцией:
// инъекция зовёт ТОТ ЖЕ разбор.
func readReconcilerTree(path string, src []byte) (reconcilerTreeReading, error) {
	out := reconcilerTreeReading{BuilderCalls: map[string]int{}}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return out, err
	}
	alias := ""
	for _, spec := range f.Imports {
		p, uerr := strconv.Unquote(spec.Path.Value)
		if uerr != nil || p != reconcilePkgPath {
			continue
		}
		if spec.Name != nil {
			alias = spec.Name.Name
		} else {
			alias = "reconcile"
		}
	}
	for _, decl := range f.Decls {
		enclosing := ""
		if fd, ok := decl.(*ast.FuncDecl); ok {
			enclosing = fd.Name.Name
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			out.Calls++
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				if _, lane := bindingReconcilerLanes[fn.Name]; lane {
					out.BuilderCalls[fn.Name]++
				}
			case *ast.SelectorExpr:
				if pkg, ok := fn.X.(*ast.Ident); ok && alias != "" && pkg.Name == alias && fn.Sel.Name == "New" {
					out.Builds = append(out.Builds, reconcilerBuildSite{
						File: filepath.Base(path), Line: fset.Position(call.Pos()).Line, Enclosing: enclosing,
					})
				}
			}
			return true
		})
	}
	return out, nil
}

// reconcilerTreeVerdict — находки по сумме прочтений пакета. Пустой срез —
// дерево держит свойство.
func reconcilerTreeVerdict(readings []reconcilerTreeReading) []string {
	var findings []string
	builtIn := map[string]int{}
	called := map[string]int{}
	for _, r := range readings {
		for _, b := range r.Builds {
			if _, lane := bindingReconcilerLanes[b.Enclosing]; lane {
				builtIn[b.Enclosing]++
				continue
			}
			where := b.Enclosing
			if where == "" {
				where = "уровень пакета"
			}
			findings = append(findings, "реконсайлер привязки построен МИМО сборщика полосы — "+
				b.File+":"+strconv.Itoa(b.Line)+" ("+where+"): его материализации не попадут ни в "+
				"одну полосу гистограммы размера, и полоса будет читаться как полоса без трафика")
		}
		for name, n := range r.BuilderCalls {
			called[name] += n
		}
	}
	names := make([]string, 0, len(bindingReconcilerLanes))
	for name := range bindingReconcilerLanes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if builtIn[name] != 1 {
			findings = append(findings, "сборщик "+name+" строит реконсайлер "+strconv.Itoa(builtIn[name])+
				" раз вместо одного — либо сборщика нет, и гейт стережёт координату, которой нет, "+
				"либо в нём два экземпляра с одной полосой")
		}
		if called[name] == 0 {
			findings = append(findings, "у сборщика "+name+" нет вызывающего — полоса "+
				strconv.Quote(bindingReconcilerLanes[name])+" объявлена наблюдаемой и не провязана; "+
				"её материализации идут через другой сборщик и пишутся в чужую полосу")
		}
	}
	return findings
}

// TestEveryBindingReconcilerIsBuiltWithALane — ДЕРЕВО.
func TestEveryBindingReconcilerIsBuiltWithALane(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("обход пакета: %v", err)
	}
	var readings []reconcilerTreeReading
	files, calls, builds := 0, 0, 0
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(filepath.Clean(p)) // #nosec G304 -- файл пакета, не ввод снаружи
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан: %v", p, rerr)
		}
		r, perr := readReconcilerTree(p, src)
		if perr != nil {
			t.Fatalf("разбор %s: %v", p, perr)
		}
		files++
		calls += r.Calls
		builds += len(r.Builds)
		readings = append(readings, r)
	}
	t.Logf("перепись: файлов пакета прочитано %d, вызовов %d, построений реконсайлера %d",
		files, calls, builds)
	if files == 0 || calls == 0 {
		t.Fatalf("перепись пуста (файлов %d, вызовов %d) — молчание гейта сказано ни о чём", files, calls)
	}
	if findings := reconcilerTreeVerdict(readings); len(findings) > 0 {
		t.Fatalf("находок %d:\n%s", len(findings), strings.Join(findings, "\n"))
	}
}
