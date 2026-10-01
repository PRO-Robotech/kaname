// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// supergate_exempt_sites.go — перепись мест надзора администратора облака против
// ведомости классов (NTF1-F12, гейт; §1.11 приёмки NTF-1; замысел З19).
//
// # Предмет
//
// Надзор администратора облака — второе слагаемое исхода двери kaname: на отказе
// модели (или там, где вопроса к модели нет) он даёт «да» субъекту, который
// держит `system_admin` на синглтоне кластера. На типах ленты уведомлений он не
// применяется (Р5). Перечень этих типов объявлен ОДНИМ местом, а предикат
// перечня обязан стоять в каждом месте класса «обобщённая дверь» — там, где тип
// объекта приходит параметром и надзор решает исход.
//
// # Как находится место — идентичностью объекта, а не именем
//
// Пакеты главного модуля разбираются и проверяются типами (`go/types`; данные
// экспорта зависимостей — того же `go list -deps -export`). Употребление члена
// семейства — идентификатор, который проверка типов связала с объектом,
// названным в ведомости. Одноимённая локальная функция, комментарий и строка в
// тексте ошибки употреблением не являются.
//
// Место — пара «объемлющее объявление верхнего уровня · член семейства», с
// числом употреблений. Объемлющее — функция или метод (литерал функции
// засчитывается объявлению, внутри которого написан), либо инициализатор
// пакетной переменной.
//
// # Что такое «под предикатом»
//
// Употребление в месте класса `door` стоит под предикатом, если по пути от
// объявления к нему найдено одно из:
//
//   - объемлющее `if !SuperGateExempt(t) { …надзор… }` — употребление в теле;
//   - объемлющее `if SuperGateExempt(t) { … } else { …надзор… }` — в `else`;
//   - в объемлющем блоке, РАНЬШЕ оператора, несущего употребление, стоит
//     `if SuperGateExempt(t) { …выход }` без `else`, тело которого кончается
//     оператором выхода (`return`, `continue`, `break`, `goto`, `panic`).
//
// Условие обязано быть РОВНО вызовом предиката либо его отрицанием: вызов внутри
// `&&` или `||` охраной не засчитывается — такая охрана пропускает надзор на
// второй половине условия.
//
// Предикат опознаётся тоже идентичностью. Чего гейт НЕ судит — названо: о каком
// объекте спрашивает предикат (аргумент вызова), он не проверяет; это держат
// пробы F12 (а)–(ж) исходом двери.
//
// # Вторая декларация перечня
//
// Перечень читается из его объявления (ключи составного литерала пакетной
// переменной, названной ведомостью), а не выписывается здесь. Запись множества
// где угодно ещё, членом которого константой названа строка из перечня, — вторая
// декларация, и это находка. Формы множества: ключ литерала словаря, элемент
// литерала среза или массива (тип литерала — по подлежащему типу, так что
// именованный тип и вложенный литерал с опущенным типом судятся так же), ветка
// `switch`. Значение поля структуры и значение словаря — употребление слова
// модели, а не член множества (кортеж посева `moduleseed.ServiceTuple`), и
// находкой не являются.
//
// # Ограничение, названное честно
//
// Код за ограничениями сборки, не выбранными `go list` хоста, ассемблер и cgo
// гейту не видны (§1.8 приёмки: в дереве их нет). Пакет с cgo — отказ гейта, а
// не молчание.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SuperGateClassDoor — класс «обобщённая дверь»: тип объекта приходит
// параметром, и предикат перечня обязан стоять над употреблением.
const SuperGateClassDoor = "door"

// superGateClasses — закрытый словарь классов ведомости (§1.11). Класса
// «комментарий» здесь нет: гейт читает код, и комментарий употреблением не
// бывает.
var superGateClasses = map[string]struct{}{
	SuperGateClassDoor: {}, // обобщённая дверь
	"fixed":            {}, // место с закреплённым предметом
	"definition":       {}, // определение или обёртка
	"plan":             {}, // план и группировка: несёт метку «вопроса нет»
}

// SuperGateLedger — разобранная ведомость классов.
type SuperGateLedger struct {
	Predicate string // полное имя функции предиката
	Set       string // «<путь пакета>.<имя>» пакетной переменной перечня
	Family    []string
	Rows      []SuperGateLedgerRow
}

// SuperGateLedgerRow — одна строка ведомости: место и его класс.
type SuperGateLedgerRow struct {
	Line      int
	Class     string
	Enclosing string
	Member    string
	Count     int
	Label     string
}

// ParseSuperGateLedger разбирает ведомость. Строка неизвестного вида, класс вне
// словаря, повтор места — ошибка разбора, а не молчание.
func ParseSuperGateLedger(r io.Reader) (*SuperGateLedger, error) {
	led := &SuperGateLedger{}
	seen := map[string]int{}
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		switch f[0] {
		case "predicate", "set", "family":
			if len(f) != 2 {
				return nil, fmt.Errorf("ведомость, строка %d: %q ждёт одно поле", n, f[0])
			}
			switch f[0] {
			case "predicate":
				led.Predicate = f[1]
			case "set":
				led.Set = f[1]
			default:
				led.Family = append(led.Family, f[1])
			}
		case "site":
			if len(f) < 5 || len(f) > 6 {
				return nil, fmt.Errorf("ведомость, строка %d: site <класс> <объемлющее> <член> <число> [метка]", n)
			}
			if _, ok := superGateClasses[f[1]]; !ok {
				return nil, fmt.Errorf("ведомость, строка %d: класс %q вне словаря", n, f[1])
			}
			cnt, err := strconv.Atoi(f[4])
			if err != nil || cnt <= 0 {
				return nil, fmt.Errorf("ведомость, строка %d: число употреблений %q", n, f[4])
			}
			row := SuperGateLedgerRow{Line: n, Class: f[1], Enclosing: f[2], Member: f[3], Count: cnt}
			if len(f) == 6 {
				row.Label = f[5]
			}
			key := row.Enclosing + " " + row.Member
			if prev, dup := seen[key]; dup {
				return nil, fmt.Errorf("ведомость, строки %d и %d: место %s названо дважды", prev, n, key)
			}
			seen[key] = n
			led.Rows = append(led.Rows, row)
		default:
			return nil, fmt.Errorf("ведомость, строка %d: неизвестный вид строки %q", n, f[0])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ведомость: %w", err)
	}
	if led.Predicate == "" || led.Set == "" || len(led.Family) == 0 {
		return nil, errors.New("ведомость: не названы predicate, set либо ни одного family")
	}
	return led, nil
}

// SuperGateUse — одно употребление члена семейства.
type SuperGateUse struct {
	Pos       string // файл:строка относительно корня модуля
	Enclosing string
	Member    string
	Guarded   bool
}

// SuperGateFinding — находка с координатой.
type SuperGateFinding struct {
	Pos    string
	Reason string
}

func (f SuperGateFinding) String() string { return f.Pos + " — " + f.Reason }

// SuperGateReport — что осмотрено и что найдено. Печатается всегда.
type SuperGateReport struct {
	Packages    int
	Files       int
	SetTypes    []string
	Uses        []SuperGateUse
	PlacesBy    map[string]int // класс → число мест (сумма употреблений по строкам ведомости)
	Findings    []SuperGateFinding
	DeclaredSet string // координата объявления перечня
}

// superGatePkg — пакет главного модуля, разобранный исходником.
type superGatePkg struct {
	path  string
	rel   string
	files []*ast.File
	info  *types.Info
	types *types.Package
}

// superGateTree — перечень главного модуля и данные экспорта зависимостей.
type superGateTree struct {
	root       string
	modulePath string
	goVersion  string
	listed     []*surfaceListed
	byPath     map[string]*surfaceListed
	fset       *token.FileSet
	gc         types.Importer

	mu   sync.Mutex
	base map[string]*superGatePkg
}

var (
	superGateTreesMu sync.Mutex
	superGateTrees   = map[string]*superGateTree{}
)

// superGateListTimeout — срок `go list` по всему модулю. Тот же довод, что у
// surfaceListTimeout: зависший `go list` не съедает бюджет прогона молча.
const superGateListTimeout = 5 * time.Minute

func superGateTreeFor(ctx context.Context, root string) (*superGateTree, error) {
	superGateTreesMu.Lock()
	defer superGateTreesMu.Unlock()
	if t, ok := superGateTrees[root]; ok {
		return t, nil
	}
	t, err := loadSuperGateTree(ctx, root)
	if err != nil {
		return nil, err
	}
	superGateTrees[root] = t
	return t, nil
}

func loadSuperGateTree(ctx context.Context, root string) (*superGateTree, error) {
	args := []string{"list", "-deps", "-export",
		"-json=ImportPath,Name,Dir,GoFiles,CgoFiles,Export,Standard,DepOnly,Imports,Module,Error"}
	if surfaceListRace {
		args = append(args, "-race")
	}
	args = append(args, "./...")
	ctx, cancel := context.WithTimeout(ctx, superGateListTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...) // #nosec G204 -- аргументы постоянны, корень — дерево пробы
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("перепись надзора: go list ./... в %s не завершился: %w", root, ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("перепись надзора: go list ./... в %s: %w\n%s", root, err, strings.TrimSpace(stderr.String()))
	}
	t := &superGateTree{root: root, byPath: map[string]*surfaceListed{}, fset: token.NewFileSet(), base: map[string]*superGatePkg{}}
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p surfaceListed
		if derr := dec.Decode(&p); errors.Is(derr, io.EOF) {
			break
		} else if derr != nil {
			return nil, fmt.Errorf("перепись надзора: разбор вывода go list: %w", derr)
		}
		if p.Error != nil {
			return nil, fmt.Errorf("перепись надзора: пакет %s: %s", p.ImportPath, p.Error.Err)
		}
		pp := p
		t.listed = append(t.listed, &pp)
		t.byPath[p.ImportPath] = &pp
		if pp.Module != nil && pp.Module.Main && !pp.DepOnly {
			if !sameDir(pp.Module.Dir, root) {
				return nil, fmt.Errorf("перепись надзора: главный модуль %s лежит в %s, а судится %s", pp.Module.Path, pp.Module.Dir, root)
			}
			t.modulePath = pp.Module.Path
			t.goVersion = pp.Module.GoVersion
		}
	}
	if t.modulePath == "" {
		return nil, fmt.Errorf("перепись надзора: go list не назвал ни одного пакета главного модуля в %s", root)
	}
	t.gc = importer.ForCompiler(t.fset, "gc", func(path string) (io.ReadCloser, error) {
		p, ok := t.byPath[path]
		if !ok || p.Export == "" {
			return nil, fmt.Errorf("данных экспорта для %s нет", path)
		}
		return os.Open(p.Export) // #nosec G304 -- путь назвал go list этого прогона
	})
	return t, nil
}

func (t *superGateTree) mainPackages() []*surfaceListed {
	var out []*surfaceListed
	for _, p := range t.listed {
		if p.Module != nil && p.Module.Main && !p.DepOnly {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ImportPath < out[j].ImportPath })
	return out
}

func (t *superGateTree) relOf(importPath string) string {
	if importPath == t.modulePath {
		return "."
	}
	return strings.TrimPrefix(importPath, t.modulePath+"/")
}

// SuperGateOverlay — правка пакета для инъекции: имя файла → новое содержимое
// (заменяет одноимённый файл либо добавляет новый).
type SuperGateOverlay map[string]map[string]string

// check — пакет, разобранный и проверенный типами; наложение заменяет файлы.
func (t *superGateTree) check(p *surfaceListed, files map[string]string) (*superGatePkg, error) {
	if len(files) == 0 {
		t.mu.Lock()
		cached := t.base[p.ImportPath]
		t.mu.Unlock()
		if cached != nil {
			return cached, nil
		}
	}
	if len(p.CgoFiles) > 0 {
		return nil, fmt.Errorf("перепись надзора: пакет %s собирается с cgo — исходником его не прочесть", p.ImportPath)
	}
	rel := t.relOf(p.ImportPath)
	names := append([]string(nil), p.GoFiles...)
	for name := range files {
		found := false
		for _, n := range names {
			if n == name {
				found = true
				break
			}
		}
		if !found {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	sp := &superGatePkg{path: p.ImportPath, rel: rel}
	for _, name := range names {
		var src []byte
		if body, ok := files[name]; ok {
			src = []byte(body)
		} else {
			b, err := os.ReadFile(filepath.Join(p.Dir, name)) // #nosec G304 -- каталог и имя назвал go list
			if err != nil {
				return nil, fmt.Errorf("перепись надзора: %s/%s: %w", rel, name, err)
			}
			src = b
		}
		f, err := parser.ParseFile(t.fset, rel+"/"+name, src, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("перепись надзора: разбор %w", err)
		}
		sp.files = append(sp.files, f)
	}
	sp.info = &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	var typeErrs []string
	conf := types.Config{
		Importer: t.gc,
		Error: func(err error) {
			if len(typeErrs) < 5 {
				typeErrs = append(typeErrs, err.Error())
			}
		},
	}
	if t.goVersion != "" {
		conf.GoVersion = "go" + t.goVersion
	}
	t.mu.Lock()
	tp, _ := conf.Check(p.ImportPath, t.fset, sp.files, sp.info)
	t.mu.Unlock()
	if len(typeErrs) > 0 {
		return nil, fmt.Errorf("перепись надзора: проверка типов %s:\n  %s", rel, strings.Join(typeErrs, "\n  "))
	}
	sp.types = tp
	if len(files) == 0 {
		t.mu.Lock()
		t.base[p.ImportPath] = sp
		t.mu.Unlock()
	}
	return sp, nil
}

// superGateObjectKey — имя объекта так, как его называет ведомость: функция и
// метод — полным именем `go/types`; поле — «<путь пакета>.<тип>.<поле>».
func superGateObjectKey(obj types.Object, owner string) string {
	switch o := obj.(type) {
	case *types.Func:
		return o.Origin().FullName()
	case *types.Var:
		if o.IsField() && o.Pkg() != nil && owner != "" {
			return o.Pkg().Path() + "." + owner + "." + o.Name()
		}
		if o.Pkg() != nil && o.Parent() == o.Pkg().Scope() {
			return o.Pkg().Path() + "." + o.Name()
		}
	}
	return ""
}

// fieldOwners — у каждого поля структуры, объявленной в пакете, — имя его типа.
func fieldOwners(pkg *types.Package) map[*types.Var]string {
	out := map[*types.Var]string{}
	if pkg == nil {
		return out
	}
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := tn.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			out[st.Field(i)] = name
		}
	}
	return out
}

// memberName — короткое имя члена семейства по его полному.
func memberName(full string) string {
	if i := strings.LastIndex(full, "."); i >= 0 {
		return full[i+1:]
	}
	return full
}

// enclosingName — объемлющее объявление верхнего уровня так, как его пишет
// ведомость.
func enclosingName(rel string, decl ast.Decl, spec *ast.ValueSpec) string {
	if fd, ok := decl.(*ast.FuncDecl); ok {
		if fd.Recv != nil && len(fd.Recv.List) == 1 {
			return rel + ".(" + recvTypeName(fd.Recv.List[0].Type) + ")." + fd.Name.Name
		}
		return rel + "." + fd.Name.Name
	}
	if spec != nil && len(spec.Names) > 0 {
		return rel + ".var:" + spec.Names[0].Name
	}
	return rel + ".decl"
}

func recvTypeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return "*" + recvTypeName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return recvTypeName(x.X)
	case *ast.IndexListExpr:
		return recvTypeName(x.X)
	}
	return "?"
}

// predicateCall — условие есть РОВНО вызов предиката либо его отрицание.
//
// Вызов внутри конъюнкции или дизъюнкции не засчитывается: `if ok &&
// SuperGateExempt(t) { return }` пропускает надзор при `!ok`, и гейт, принявший
// такую форму, судил бы слово, а не охрану.
func predicateCall(e ast.Expr, info *types.Info, predicate string) (found, negated bool) {
	switch x := ast.Unparen(e).(type) {
	case *ast.UnaryExpr:
		if x.Op == token.NOT {
			if call, ok := ast.Unparen(x.X).(*ast.CallExpr); ok && isPredicateCall(call, info, predicate) {
				return true, true
			}
		}
	case *ast.CallExpr:
		if isPredicateCall(x, info, predicate) {
			return true, false
		}
	}
	return false, false
}

func isPredicateCall(call *ast.CallExpr, info *types.Info, predicate string) bool {
	var id *ast.Ident
	switch fn := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = fn
	case *ast.SelectorExpr:
		id = fn.Sel
	default:
		return false
	}
	obj, ok := info.Uses[id].(*types.Func)
	return ok && obj.Origin().FullName() == predicate
}

// terminates — оператор выхода последним в теле.
func terminates(body *ast.BlockStmt, info *types.Info) bool {
	if body == nil || len(body.List) == 0 {
		return false
	}
	switch s := body.List[len(body.List)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return s.Tok == token.CONTINUE || s.Tok == token.BREAK || s.Tok == token.GOTO
	case *ast.ExprStmt:
		if call, ok := s.X.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok {
				if b, ok := info.Uses[id].(*types.Builtin); ok && b.Name() == "panic" {
					return true
				}
			}
		}
	}
	return false
}

// guardedBy — стоит ли узел (по пути от объявления) под предикатом.
func guardedBy(path []ast.Node, info *types.Info, predicate string) bool {
	for i := len(path) - 2; i >= 0; i-- {
		child := path[i+1]
		switch parent := path[i].(type) {
		case *ast.IfStmt:
			found, negated := predicateCall(parent.Cond, info, predicate)
			if !found {
				continue
			}
			if child == parent.Body && negated {
				return true
			}
			if parent.Else != nil && child == parent.Else && !negated {
				return true
			}
		case *ast.BlockStmt:
			for _, st := range parent.List {
				if st == child {
					break
				}
				ifs, ok := st.(*ast.IfStmt)
				if !ok || ifs.Else != nil || ifs.Init != nil {
					continue
				}
				if found, negated := predicateCall(ifs.Cond, info, predicate); found && !negated && terminates(ifs.Body, info) {
					return true
				}
			}
		case *ast.CaseClause:
			for _, st := range parent.Body {
				if st == child {
					break
				}
				ifs, ok := st.(*ast.IfStmt)
				if !ok || ifs.Else != nil || ifs.Init != nil {
					continue
				}
				if found, negated := predicateCall(ifs.Cond, info, predicate); found && !negated && terminates(ifs.Body, info) {
					return true
				}
			}
		}
	}
	return false
}

// ScanSuperGateSites — перепись по дереву модуля root против ведомости.
// overlay — правка пакетов для инъекции (ключ — путь импорта); nil — дерево как есть.
func ScanSuperGateSites(ctx context.Context, root string, led *SuperGateLedger, overlay SuperGateOverlay) (*SuperGateReport, error) {
	t, err := superGateTreeFor(ctx, root)
	if err != nil {
		return nil, err
	}
	family := map[string]struct{}{}
	for _, f := range led.Family {
		family[f] = struct{}{}
	}
	rep := &SuperGateReport{PlacesBy: map[string]int{}}

	var pkgs []*superGatePkg
	listedPaths := map[string]bool{}
	for _, p := range t.mainPackages() {
		listedPaths[p.ImportPath] = true
		sp, cerr := t.check(p, overlay[p.ImportPath])
		if cerr != nil {
			return nil, cerr
		}
		pkgs = append(pkgs, sp)
	}
	for path := range overlay {
		if !listedPaths[path] {
			return nil, fmt.Errorf("перепись надзора: наложение на пакет %s, которого нет в модуле", path)
		}
	}

	// Объявления: члены семейства, предикат и перечень должны существовать.
	declared := map[string]bool{}
	var setLit *ast.CompositeLit
	var setPkg *superGatePkg
	for _, sp := range pkgs {
		owners := fieldOwners(sp.types)
		for id, obj := range sp.info.Defs {
			if obj == nil {
				continue
			}
			owner := ""
			if v, ok := obj.(*types.Var); ok && v.IsField() {
				owner = owners[v]
			}
			key := superGateObjectKey(obj, owner)
			if key == "" {
				continue
			}
			declared[key] = true
			if key == led.Set {
				setPkg = sp
				setLit = valueLiteralOf(sp, id)
			}
		}
	}
	for _, f := range led.Family {
		if !declared[f] {
			rep.Findings = append(rep.Findings, SuperGateFinding{Pos: "ведомость", Reason: "член семейства " + f + " в дереве не объявлен"})
		}
	}
	if !declared[led.Predicate] {
		rep.Findings = append(rep.Findings, SuperGateFinding{Pos: "ведомость", Reason: "предикат " + led.Predicate + " в дереве не объявлен"})
	}
	setValues := map[string]struct{}{}
	if setLit == nil {
		rep.Findings = append(rep.Findings, SuperGateFinding{Pos: "ведомость", Reason: "перечень " + led.Set + " не объявлен составным литералом"})
	} else {
		rep.DeclaredSet = t.fset.Position(setLit.Pos()).String()
		for _, el := range setLit.Elts {
			k := el
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				k = kv.Key
			}
			if s, ok := stringConst(setPkg.info, k); ok {
				setValues[s] = struct{}{}
				rep.SetTypes = append(rep.SetTypes, s)
			}
		}
		sort.Strings(rep.SetTypes)
		if len(setValues) == 0 {
			rep.Findings = append(rep.Findings, SuperGateFinding{Pos: rep.DeclaredSet, Reason: "перечень пуст — предикату нечего исключать"})
		}
	}

	// Употребления.
	type placeAgg struct {
		count int
		first string
		uses  []SuperGateUse
	}
	places := map[string]*placeAgg{}
	for _, sp := range pkgs {
		rep.Packages++
		owners := fieldOwners(sp.types)
		for _, f := range sp.files {
			rep.Files++
			for _, decl := range f.Decls {
				walkDecl(decl, func(spec *ast.ValueSpec, path []ast.Node) {
					n := path[len(path)-1]
					// Вторая декларация перечня.
					if setLit != nil {
						reportSecondDecl(rep, t.fset, sp, n, setLit, setValues)
					}
					id, ok := n.(*ast.Ident)
					if !ok {
						return
					}
					obj := sp.info.Uses[id]
					if obj == nil {
						return
					}
					owner := ""
					if v, ok := obj.(*types.Var); ok && v.IsField() {
						owner = owners[v]
						if owner == "" {
							owner = fieldOwnerFromSelection(sp.info, path)
						}
					}
					key := superGateObjectKey(obj, owner)
					if _, ok := family[key]; !ok {
						return
					}
					use := SuperGateUse{
						Pos:       t.fset.Position(id.Pos()).String(),
						Enclosing: enclosingName(sp.rel, decl, spec),
						Member:    memberName(key),
						Guarded:   guardedBy(path, sp.info, led.Predicate),
					}
					rep.Uses = append(rep.Uses, use)
					pk := use.Enclosing + " " + use.Member
					a := places[pk]
					if a == nil {
						a = &placeAgg{first: use.Pos}
						places[pk] = a
					}
					a.count++
					a.uses = append(a.uses, use)
				})
			}
		}
	}

	// Сверка с ведомостью.
	rowByKey := map[string]SuperGateLedgerRow{}
	for _, row := range led.Rows {
		rowByKey[row.Enclosing+" "+row.Member] = row
	}
	keys := make([]string, 0, len(places))
	for k := range places {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := places[k]
		row, ok := rowByKey[k]
		if !ok {
			rep.Findings = append(rep.Findings, SuperGateFinding{Pos: a.first,
				Reason: fmt.Sprintf("место %s (употреблений %d) вне ведомости классов — классифицируйте его в §1.11 и в ведомости", k, a.count)})
			continue
		}
		if row.Count != a.count {
			rep.Findings = append(rep.Findings, SuperGateFinding{Pos: a.first,
				Reason: fmt.Sprintf("место %s: употреблений %d, ведомость (строка %d) называет %d", k, a.count, row.Line, row.Count)})
		}
		rep.PlacesBy[row.Class] += a.count
		if row.Class != SuperGateClassDoor {
			continue
		}
		for _, u := range a.uses {
			if !u.Guarded {
				rep.Findings = append(rep.Findings, SuperGateFinding{Pos: u.Pos,
					Reason: fmt.Sprintf("место класса «обобщённая дверь» %s (%s) не стоит под предикатом перечня %s", k, row.Label, led.Predicate)})
			}
		}
	}
	for _, row := range led.Rows {
		if _, ok := places[row.Enclosing+" "+row.Member]; !ok {
			rep.Findings = append(rep.Findings, SuperGateFinding{Pos: fmt.Sprintf("ведомость, строка %d", row.Line),
				Reason: fmt.Sprintf("строка ведомости %s %s без места в дереве", row.Enclosing, row.Member)})
		}
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool { return rep.Findings[i].Pos < rep.Findings[j].Pos })
	return rep, nil
}

// walkDecl обходит объявление, отдавая путь от него к каждому узлу и ближайшую
// объемлющую спецификацию пакетной переменной (nil вне неё).
func walkDecl(decl ast.Decl, visit func(spec *ast.ValueSpec, path []ast.Node)) {
	gd, isVar := decl.(*ast.GenDecl)
	isVar = isVar && gd.Tok == token.VAR
	var path []ast.Node
	ast.Inspect(decl, func(n ast.Node) bool {
		if n == nil {
			path = path[:len(path)-1]
			return true
		}
		path = append(path, n)
		var spec *ast.ValueSpec
		if isVar {
			for _, a := range path {
				if vs, ok := a.(*ast.ValueSpec); ok {
					spec = vs
					break
				}
			}
		}
		visit(spec, path)
		return true
	})
}

// fieldOwnerFromSelection — владелец поля, объявленного вне пакета употребления.
func fieldOwnerFromSelection(info *types.Info, path []ast.Node) string {
	if len(path) < 2 {
		return ""
	}
	sel, ok := path[len(path)-2].(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	s := info.Selections[sel]
	if s == nil {
		return ""
	}
	t := s.Recv()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		return n.Obj().Name()
	}
	return ""
}

// valueLiteralOf — составной литерал, которым инициализирована пакетная переменная.
func valueLiteralOf(sp *superGatePkg, id *ast.Ident) *ast.CompositeLit {
	for _, f := range sp.files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, s := range gd.Specs {
				vs, ok := s.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if name != id || i >= len(vs.Values) {
						continue
					}
					if cl, ok := ast.Unparen(vs.Values[i]).(*ast.CompositeLit); ok {
						return cl
					}
				}
			}
		}
	}
	return nil
}

func stringConst(info *types.Info, e ast.Expr) (string, bool) {
	tv, ok := info.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}

// reportSecondDecl — запись МНОЖЕСТВА, членом которого назван тип перечня вне
// его объявления: ключ или значение литерала словаря, элемент литерала среза
// или массива, ветка switch. Из суждения выведено ровно одно — значение поля
// литерала структуры: это употребление слова модели (кортеж посева
// `moduleseed.ServiceTuple{objectType: …}`), а запрет З19 — на вторую
// декларацию набора. Словарь, решающий по значениям, — та же вторая
// декларация, поэтому его значения судятся наравне с ключами. Тип литерала берётся у проверки типов, поэтому
// именованный тип и вложенный литерал с опущенным типом судятся по
// подлежащему типу.
func reportSecondDecl(rep *SuperGateReport, fset *token.FileSet, sp *superGatePkg, n ast.Node,
	setLit *ast.CompositeLit, set map[string]struct{}) {
	var exprs []ast.Expr
	switch x := n.(type) {
	case *ast.CompositeLit:
		if x == setLit {
			return
		}
		tv, ok := sp.info.Types[x]
		if !ok || tv.Type == nil {
			return
		}
		switch tv.Type.Underlying().(type) {
		case *types.Map:
			for _, el := range x.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					exprs = append(exprs, kv.Key, kv.Value)
				}
			}
		case *types.Slice, *types.Array:
			for _, el := range x.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					exprs = append(exprs, kv.Value)
					continue
				}
				exprs = append(exprs, el)
			}
		default:
			return
		}
	case *ast.CaseClause:
		exprs = x.List
	default:
		return
	}
	for _, e := range exprs {
		s, ok := stringConst(sp.info, e)
		if !ok {
			continue
		}
		if _, in := set[s]; in {
			rep.Findings = append(rep.Findings, SuperGateFinding{Pos: fset.Position(e.Pos()).String(),
				Reason: fmt.Sprintf("вторая декларация перечня типов без надзора: %q названо вне объявления перечня", s)})
		}
	}
}
