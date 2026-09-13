// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// root_shutdown_cause_test.go — гейт «КОНТЕКСТ ФОНОВЫХ ЗАДАЧ КОРНЯ ОТМЕНЯЕТСЯ
// ОБЕИМИ ПРИЧИНАМИ ГАШЕНИЯ» (kacho#2506, предикат 3).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — ПРИЧИНА, А НЕ НАЛИЧИЕ ОТМЕНЫ
//
// Причин гашения ДВЕ: сигнал среды и КРАХ. Сигнальный контекст знает одну.
// Задача, взявшая его, по краху не возвращается, а `runServe` оканчивается на
// `group.Wait()`, который ждёт ВСЕ задачи, — процесс не выходит вовсе.
//
// Гейт kacho#2465 этого не видит by construction: он стережёт контекст, который
// не отменяется НИКОГДА, и производный от сигнального корня считает законным.
// Он законен — он недостаточен. Поэтому предмет заведён соседним гейтом, а не
// дописан к тому: его зелёное здесь не доказывает ничего.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПЕРЕПИСЬ В ТРИ ЧИСЛА, И ОДНОГО НЕ ХВАТАЕТ
//
//	задач N               — сколько замыканий-задач корня вообще есть;
//	на корневом контексте M — сколько берут контекст, отменяемый ОБЕИМИ причинами;
//	на сигнальном K       — сколько взяли контекст, знающий ОДНУ причину.
//
// Одно число скрыло бы ровно этот случай: «задач 16» ничего не говорит о
// причине, а «на корневом 12» без знаменателя читается как полнота. Находка —
// K > 0; разница N − M − K законна (есть задачи, не берущие контекста вовсе:
// слушатель возвращается по своему останову).
//
// ─────────────────────────────────────────────────────────────────────────────
// ФОРМ ЗАПИСИ ЗАДАЧИ ДВЕ, И ВТОРАЯ БЫЛА БЫ СЛЕПОЙ ЗОНОЙ
//
// `func() error { … }` и `func() (err error) { … }` — обе законны и обе живут в
// корне. Поиск по подстроке знает первую; разбор судит УЗЕЛ типа и потому знает
// обе. Проверено переписью: предикат по тексту `func() error {` даёт 14 там, где
// разбор находит 16.
//
// Судится РАЗОБРАННОЕ дерево, а не текст: имя сигнального контекста встречается
// в корне и в прозе, объясняющей это самое требование, и предикат по подстроке
// краснел бы на собственном объяснении проверяемого.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// rootTaskSite — замыкание-задача композиционного корня.
type rootTaskSite struct {
	File string
	Line int
	// Ctx — какой контекст оно берёт: "root" | "signal" | "".
	Ctx string
}

// shutdownCauseCensus — объём осмотренного; печатается ВСЕГДА.
type shutdownCauseCensus struct {
	Files       int
	Parsed      int
	Tasks       int
	OnRoot      int
	OnSignal    int
	SignalCtx   string
	RootCtx     string
	RootDerived bool
}

func (c shutdownCauseCensus) Summary() string {
	return fmt.Sprintf(
		"прод-файлов корня %d · разобрано %d · замыканий-задач %d · "+
			"на корневом контексте %d · на сигнальном %d · сигнальный контекст %q · "+
			"корневой %q · производный от сигнального %t",
		c.Files, c.Parsed, c.Tasks, c.OnRoot, c.OnSignal,
		c.SignalCtx, c.RootCtx, c.RootDerived)
}

// scanShutdownCauses разбирает перечень файлов корня и отвечает, каким
// контекстом пользуется каждое замыкание-задача.
//
// Состав приходит ПАРАМЕТРОМ: в живом дереве его даёт обход корня, а инъекция
// подаёт синтетический.
func scanShutdownCauses(root string, files []string) (sites []rootTaskSite, c shutdownCauseCensus, err error) {
	fset := token.NewFileSet()
	parsed := make([]*ast.File, 0, len(files))
	rels := make([]string, 0, len(files))
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
		parsed = append(parsed, file)
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rels = append(rels, filepath.ToSlash(rel))
	}

	// ШАГ 1 — имя СИГНАЛЬНОГО контекста: первый результат `signal.NotifyContext`.
	for _, file := range parsed {
		if name := signalContextName(file); name != "" {
			c.SignalCtx = name
			break
		}
	}
	// ШАГ 2 — ИМЕНА корня гашения и то, производен ли он от сигнального.
	//
	// ПРОИЗВОДНЫЙ ПРЕДПОЧИТАЕТСЯ ПЕРВОМУ ПОПАВШЕМУСЯ, и это не мелочь: в корне
	// есть отменяемые контексты, к гашению процесса отношения не имеющие
	// (отмена поверхностей, отмена счётчика допуска). Взяв первый по порядку
	// файла, распознаватель называл бы корневым тот, что не производен от
	// сигнального, — и объявлял бы находкой исправное дерево.
	for _, file := range parsed {
		name, derived := rootContextName(file, c.SignalCtx)
		if name == "" {
			continue
		}
		if c.RootCtx == "" || (derived && !c.RootDerived) {
			c.RootCtx, c.RootDerived = name, derived
		}
	}
	// ИМЁН У КОРНЯ ДВА, И ВТОРОЕ БЫЛО БЫ СЛЕПОЙ ЗОНОЙ. Объект гашения отдаёт
	// контекст отдельным связыванием (`taskCtx := rootShutdown.Context()`), и
	// задачи берут ВТОРОЕ имя. Распознаватель, знающий одно, насчитал бы «на
	// корневом 1» при одиннадцати задачах на нём — то есть объявил бы находкой
	// исправное дерево.
	rootNames := map[string]bool{}
	if c.RootCtx != "" {
		rootNames[c.RootCtx] = true
		for _, file := range parsed {
			for _, alias := range contextAliasesOf(file, c.RootCtx) {
				rootNames[alias] = true
			}
		}
	}
	// ШАГ 3 — замыкания-задачи и контекст каждого.
	for i, file := range parsed {
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.FuncLit)
			if !ok || !isTaskSignature(lit.Type) {
				return true
			}
			c.Tasks++
			site := rootTaskSite{File: rels[i], Line: fset.Position(lit.Pos()).Line}
			switch {
			case mentionsAnyOf(lit.Body, rootNames):
				site.Ctx = "root"
				c.OnRoot++
			case c.SignalCtx != "" && bodyMentions(lit.Body, c.SignalCtx):
				site.Ctx = "signal"
				c.OnSignal++
				sites = append(sites, site)
			}
			return true
		})
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].Line < sites[j].Line })
	return sites, c, nil
}

// isTaskSignature — форма замыкания-задачи: ноль доводов, один результат
// `error`. Знает ОБЕ законные записи результата — безымянную и именованную.
func isTaskSignature(t *ast.FuncType) bool {
	if t.Params != nil && len(t.Params.List) != 0 {
		return false
	}
	if t.Results == nil || len(t.Results.List) != 1 {
		return false
	}
	id, ok := t.Results.List[0].Type.(*ast.Ident)
	return ok && id.Name == "error"
}

// signalContextName — первый результат `signal.NotifyContext(…)`.
func signalContextName(file *ast.File) string {
	name := ""
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "NotifyContext" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "signal" {
			return true
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok && name == "" {
			name = id.Name
		}
		return true
	})
	return name
}

// rootContextName — имя контекста ФОНОВЫХ ЗАДАЧ и то, производен ли он от
// сигнального.
//
// Форм заведения ДВЕ, и обе законны: собственный тип корня гашения
// (`newRootShutdown(<сигнальный>, …)` + `.Context()`) и голый
// `context.WithCancel(<сигнальный>)`. Знать надо обе — иначе распознаватель
// молчит на той, которой пользуются, и молчит неотличимо от чистого дерева.
func rootContextName(file *ast.File, signalName string) (name string, derived bool) {
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		parentIsSignal := false
		if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == signalName && signalName != "" {
			parentIsSignal = true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name != "newRootShutdown" {
				return true
			}
		case *ast.SelectorExpr:
			id, ok := fn.X.(*ast.Ident)
			if !ok || id.Name != "context" || fn.Sel.Name != "WithCancel" {
				return true
			}
		default:
			return true
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		if name == "" || (parentIsSignal && !derived) {
			name, derived = id.Name, parentIsSignal
		}
		return true
	})
	return name, derived
}

// contextAliasesOf — имена, связанные с контекстом корня гашения через
// `<корень>.Context()`. Форма законна и в корне ею пользуются: отдельное имя
// для контекста задач читается однозначно, тогда как затенение `ctx` дало бы
// одно имя на два контекста — и следующий взял бы сигнальный, думая, что берёт
// корневой.
func contextAliasesOf(file *ast.File, rootName string) []string {
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) != 1 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Context" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != rootName {
			return true
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok {
			out = append(out, id.Name)
		}
		return true
	})
	return out
}

// mentionsAnyOf — упоминается ли в теле хоть одно из имён.
func mentionsAnyOf(body *ast.BlockStmt, names map[string]bool) bool {
	for name := range names {
		if bodyMentions(body, name) {
			return true
		}
	}
	return false
}

// bodyMentions — упоминается ли идентификатор в теле замыкания.
func bodyMentions(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// TestIAM2506_NoRootTaskWaitsOnTheSignalContextAlone — гейт задачи #2506.
func TestIAM2506_NoRootTaskWaitsOnTheSignalContextAlone(t *testing.T) {
	root := iamServiceRoot(t)
	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, "cmd"), ".go")
	if err != nil {
		t.Fatalf("перечень файлов композиционного корня: %v", err)
	}
	sites, census, err := scanShutdownCauses(root, files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("%s", census.Summary())

	if census.Parsed == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла корня — вердикт беспредметен: "+
			"«ноль находок» неотличимо от «ноль прочитанного» (корень %s)", root)
	}
	if census.Tasks == 0 {
		t.Fatalf("в корне не найдено НИ ОДНОГО замыкания-задачи (разобрано %d файлов) — "+
			"это отказ РАЗБОРА, а не корень без фоновых работ", census.Parsed)
	}
	if census.SignalCtx == "" {
		t.Fatalf("в корне не найдено `signal.NotifyContext` — распознаватель сигнального " +
			"контекста мёртв, и тогда «на сигнальном 0» он печатает by construction")
	}
	if census.RootCtx == "" {
		t.Fatalf("у корня НЕТ отменяемого контекста фоновых задач: гашение по краху " +
			"слушателя не доедет до задачи-ожидателя, `group.Wait()` не вернётся, и " +
			"процесс не выйдет вовсе — его снимет среда по истечении окна")
	}
	if !census.RootDerived {
		t.Errorf("корневой контекст %q не производен от сигнального %q — тогда СИГНАЛ "+
			"перестаёт гасить фоновые задачи, и починка одной причины сломала вторую",
			census.RootCtx, census.SignalCtx)
	}
	if census.OnRoot == 0 {
		t.Errorf("корневой контекст %q заведён и НЕ ВЗЯТ ни одной задачей (задач %d) — "+
			"ручка есть, гашение по краху всё равно никуда не доезжает",
			census.RootCtx, census.Tasks)
	}
	for _, s := range sites {
		t.Errorf("%s:%d — замыкание-задача берёт СИГНАЛЬНЫЙ контекст %q. Он знает одну "+
			"причину гашения из двух: гашение, начатое КРАХОМ слушателя или отказом "+
			"дренажа, до задачи не доезжает, а `group.Wait()` в `runServe` ждёт ВСЕ "+
			"задачи. Процесс тогда не выходит вовсе: погашенные серверы, живая задача, "+
			"код возврата краха не отдан никогда. Возьми корневой контекст %q.",
			s.File, s.Line, census.SignalCtx, census.RootCtx)
	}
}
