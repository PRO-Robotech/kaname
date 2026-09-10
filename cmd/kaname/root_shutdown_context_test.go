// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// root_shutdown_context_test.go — гейт «НЕОТМЕНЯЕМОГО КОНТЕКСТА в композиционном
// корне не бывает» (kacho#2465).
//
// # Предмет
//
// `runServe` оканчивается на `group.Wait()`, а группа возвращает управление лишь
// когда вернулись ВСЕ задачи. Долгоживущая задача возвращается по `ctx.Done()`
// своего контекста; на `context.Background()` этого не случается никогда. Одна
// такая задача из двух десятков — и процесс не выходит по сигналу вовсе: его
// снимает среда по истечении окна мягкого гашения, посреди исходящего разговора,
// оставляя строки очереди заклеймёнными и не применёнными.
//
// # Почему гейт судит КОНТЕКСТ, а не «задачу, отданную в errgroup»
//
// Соблазнительная форма — обойти литералы задач в `serve.go` и потребовать от
// каждой отменяемого контекста. Она СЛЕПА ровно к тому дефекту, ради которого
// заводится: обе находки дня заведения жили не в литерале задачи, а за вызовом
// собранного в другом файле замыкания (`inviteMailDrainerTask()`,
// `compensationDrainerTask()`), и в теле задачи не было ни одного упоминания
// контекста. Распознаватель, знающий одну форму записи предмета, молчит на
// остальных — и молчит неотличимо от чистого дерева.
//
// Поэтому предмет здесь — ИСТОЧНИК неотменяемого контекста, где бы в корне он ни
// стоял. Он один на все формы запуска: список задач, голый `go`, замыкание,
// собранное соседним файлом, метод, спрятанный за интерфейсом.
//
// # Что считается ЗАКОННЫМ
//
// Неотменяемый контекст обязан быть РОДИТЕЛЕМ производного, а не аргументом
// работы: `signal.NotifyContext(context.Background(), …)`,
// `context.WithCancel/WithTimeout/WithDeadline(context.Background(), …)`. Такое
// вхождение и есть то место, где у процесса появляется отменяемый корень.
//
// Всё остальное — находка, если не перечислено в ведомости ниже с причиной. У
// ведомости есть СРОК ГОДНОСТИ: запись, которой больше нечего прощать, — тоже
// находка, иначе следующая слепая зона унаследует чужое послабление.
//
// # Границы, названные вслух
//
// Судится КОРЕНЬ (`cmd/`), а не всё дерево службы. Отвязанный контекст внутри
// use-case — другой предмет с другим доводом (там он покупает переживание
// запроса, а не мешает выходу процесса), и у него свои пробы. Форма
// `context.WithoutCancel` в корне сегодня не встречается ни разу; появившись,
// она обязана прийти своим решением — гейт назовёт её находкой, потому что
// производной от отменяемого корня она не является.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// nonCancellableCtors — конструкторы контекста, который не отменяется НИКОГДА.
var nonCancellableCtors = map[string]bool{
	"Background": true,
	"TODO":       true,
}

// contextDerivations — вызовы, для которых неотменяемый контекст есть РОДИТЕЛЬ,
// а не рабочий аргумент. Ключ — `<локальное имя пакета>.<функция>`; пакет
// сверяется по пути импорта, поэтому псевдоним не выводит форму из наблюдения.
var contextDerivations = []struct {
	Path        string
	DefaultName string
	Funcs       []string
}{
	{"context", "context", []string{"WithCancel", "WithTimeout", "WithDeadline", "WithValue"}},
	{"os/signal", "signal", []string{"NotifyContext"}},
}

// bgExemption — прощённое вхождение: сколько раз и почему.
type bgExemption struct {
	Count  int
	Reason string
}

// nonCancellableExempt — ведомость мест корня, где неотменяемый контекст ЗАКОНЕН.
//
// Ключ — `<путь от корня службы>#<имя вызываемого>`; счёт входит в ключ по
// значению, чтобы ВТОРОЕ вхождение того же вида в том же файле не проехало
// молча под уже выданным прощением.
//
// Запись, которой нечего прощать, — НАХОДКА: послабление обязано истекать само,
// иначе оно переживает свой предмет и достаётся следующему дефекту даром.
var nonCancellableExempt = map[string]bgExemption{
	"cmd/iamctl/main.go#Run": {
		Count: 1,
		Reason: "корень процесса ОДНОРАЗОВОГО инструмента оператора: он не служит, " +
			"не держит долгоживущих задач и завершается кодом возврата своей работы. " +
			"Отменять здесь нечего — сигнал прекращает сам процесс.",
	},
	"cmd/kaname/audit_shipper_wiring.go#Preflight": {
		Count: 1,
		Reason: "предпосылка приёмника журнала: синхронная проверка уровня потока " +
			"в памяти (`slog.Handler.Enabled`). Ни внешнего вызова, ни горутины, ни " +
			"ожидания — отменять нечего, и предела времени такой проверке не нужно.",
	},
}

// bgSite — вхождение неотменяемого контекста, не являющееся производным.
type bgSite struct {
	File   string // путь от корня службы
	Line   int
	Callee string // имя вызываемого, которому контекст отдан; "" — связывание переменной
	Ctor   string // Background | TODO
}

func (s bgSite) key() string { return s.File + "#" + s.Callee }

// rootCtxCensus — объём осмотренного; печатается ВСЕГДА.
type rootCtxCensus struct {
	Files     int
	Parsed    int
	Occur     int // вхождений context.Background()/TODO()
	Derived   int // из них — родитель производного контекста
	Exempted  int // из них — прощённых ведомостью
	Findings  int
	StaleExpt int // записей ведомости, которым нечего прощать
}

func (c rootCtxCensus) Summary() string {
	return fmt.Sprintf(
		"прод-файлов корня %d · разобрано %d · вхождений неотменяемого контекста %d · "+
			"из них производных %d · прощённых %d · находок %d · записей ведомости без предмета %d",
		c.Files, c.Parsed, c.Occur, c.Derived, c.Exempted, c.Findings, c.StaleExpt)
}

// scanNonCancellableContexts разбирает ПЕРЕЧЕНЬ файлов и возвращает вхождения
// неотменяемого контекста, не являющиеся производными, вместе с переписью.
//
// Состав приходит ПАРАМЕТРОМ: в живом дереве его даёт индекс git, а инъекция
// подаёт синтетический — доказательство, требующее испортить рабочую копию, в
// конвейере не исполняется никогда.
func scanNonCancellableContexts(root string, files []string) (sites []bgSite, c rootCtxCensus, err error) {
	fset := token.NewFileSet()
	for _, path := range files {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		c.Files++
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, c, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		c.Parsed++
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		ctxLocal := localNameOfImport(file, "context", "context")
		derivations := derivationSelectors(file)

		// Первый проход: все вхождения `context.Background()` / `context.TODO()`.
		occur := map[token.Pos]string{}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !nonCancellableCtors[sel.Sel.Name] {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || ctxLocal == "" || id.Name != ctxLocal {
				return true
			}
			occur[call.Pos()] = sel.Sel.Name
			return true
		})
		c.Occur += len(occur)

		// Второй проход: кому вхождение отдано аргументом.
		consumed := map[token.Pos]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee, isDerivation := classifyCallee(call, derivations)
			for _, arg := range call.Args {
				inner, ok := arg.(*ast.CallExpr)
				if !ok {
					continue
				}
				ctor, isOccur := occur[inner.Pos()]
				if !isOccur || consumed[inner.Pos()] {
					continue
				}
				consumed[inner.Pos()] = true
				if isDerivation {
					c.Derived++
					continue
				}
				sites = append(sites, bgSite{
					File: rel, Line: fset.Position(inner.Pos()).Line,
					Callee: callee, Ctor: ctor,
				})
			}
			return true
		})
		// Вхождение, никому не отданное аргументом (`ctx := context.Background()`),
		// производным не является: отменяемым его не делает ничто.
		for pos, ctor := range occur {
			if consumed[pos] {
				continue
			}
			sites = append(sites, bgSite{
				File: rel, Line: fset.Position(pos).Line, Callee: "", Ctor: ctor,
			})
		}
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
	return sites, c, nil
}

// classifyCallee возвращает имя вызываемого и то, является ли вызов ПРОИЗВОДНЫМ
// контекста.
func classifyCallee(call *ast.CallExpr, derivations map[string]bool) (name string, derivation bool) {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		name = fn.Sel.Name
		if id, ok := fn.X.(*ast.Ident); ok {
			if derivations[id.Name+"."+fn.Sel.Name] {
				return name, true
			}
		}
	case *ast.Ident:
		name = fn.Name
	}
	return name, false
}

// derivationSelectors — множество `<локальное имя>.<функция>`, законно
// принимающих неотменяемый контекст РОДИТЕЛЕМ. Собирается по путям импорта,
// поэтому псевдоним пакета формы из наблюдения не выводит.
func derivationSelectors(file *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, d := range contextDerivations {
		local := localNameOfImport(file, d.Path, d.DefaultName)
		if local == "" {
			continue
		}
		for _, fn := range d.Funcs {
			out[local+"."+fn] = true
		}
	}
	return out
}

// adjudicate разводит вхождения на прощённые и находки и досчитывает записи
// ведомости, которым нечего прощать.
func adjudicate(sites []bgSite, ledger map[string]bgExemption, c *rootCtxCensus) (findings []bgSite, stale []string) {
	seen := map[string]int{}
	for _, s := range sites {
		seen[s.key()]++
	}
	for _, s := range sites {
		ex, ok := ledger[s.key()]
		if ok && seen[s.key()] == ex.Count {
			c.Exempted++
			continue
		}
		findings = append(findings, s)
	}
	for key, ex := range ledger {
		if seen[key] != ex.Count {
			stale = append(stale, fmt.Sprintf("%s (объявлено %d, найдено %d)", key, ex.Count, seen[key]))
		}
	}
	sort.Strings(stale)
	c.Findings = len(findings)
	c.StaleExpt = len(stale)
	return findings, stale
}

// TestIAM2465_NoRootTaskRunsOnANonCancellableContext — гейт задачи #2465.
func TestIAM2465_NoRootTaskRunsOnANonCancellableContext(t *testing.T) {
	root := iamServiceRoot(t)

	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, "cmd"), ".go")
	if err != nil {
		t.Fatalf("перечень файлов композиционного корня: %v", err)
	}
	sites, census, err := scanNonCancellableContexts(root, files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	findings, stale := adjudicate(sites, nonCancellableExempt, &census)
	t.Logf("%s", census.Summary())

	if census.Parsed == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла композиционного корня — "+
			"вердикт беспредметен: «ноль находок» неотличимо от «ноль прочитанного» (корень %s)", root)
	}
	if census.Occur == 0 {
		t.Fatalf("в корне не найдено НИ ОДНОГО вхождения `context.Background()`/`TODO()` "+
			"(разобрано %d файлов) — а отменяемый корень процесса производится именно из "+
			"него: это отказ РАЗБОРА, а не чистое дерево", census.Parsed)
	}
	if census.Derived == 0 {
		t.Fatalf("ни одно вхождение не опознано как РОДИТЕЛЬ производного контекста "+
			"(вхождений %d) — распознаватель производных мёртв, и тогда «прощено/находка» "+
			"он делит вслепую", census.Occur)
	}

	for _, s := range findings {
		t.Errorf("%s:%d — работа получает `context.%s()`, который не отменяется НИКОГДА "+
			"(вызываемый %q). Долгоживущая задача на таком контексте не возвращается, "+
			"`group.Wait()` в `runServe` не возвращается вслед за ней, и процесс не выходит "+
			"по сигналу — его снимает среда по истечении окна. Возьми контекст, который "+
			"отменяет гашение процесса, либо, если отменять действительно нечего, впиши "+
			"место в `nonCancellableExempt` с причиной.",
			s.File, s.Line, s.Ctor, s.Callee)
	}
	for _, key := range stale {
		t.Errorf("ведомость `nonCancellableExempt`: записи %s больше нечего прощать — "+
			"послабление пережило свой предмет и досталось бы следующему дефекту даром. "+
			"Снимите запись ВМЕСТЕ с предметом.", key)
	}
}
