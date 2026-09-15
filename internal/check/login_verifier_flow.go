// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_verifier_flow.go — РАЗБОР ПОТОКА предмета внутри файлов, которым он
// разрешён: материала способа входа — внутри разрешённых файлов, имени таблицы
// секрета — внутри файла-владельца. Предметов два, разбор один: вынос у них
// записывается одними и теми же формами, и вторая копия разбора разошлась бы с
// первой молча — ровно на той форме, которую знает одна из копий.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ «ВЫНОС» — ВСЕ СТОКИ ГРАММАТИКИ GO
//
// Значение несёт предмет, если оно им является (источник), либо собрано из
// несущего: склейка `+`, приведение к строке, срезу байтов либо строковому типу
// корпуса, взятие адреса, разыменование, индекс, срез, утверждение типа,
// составной литерал с несущим элементом (у карты — и с несущим ключом),
// встроенные `append`/`min`/`max`, замыкание, возвращающее несущее, и его
// вызов на месте. Хранилище, куда несущее положено, несёт его дальше; обход
// `range` по несущему делает несущими ключ и значение.
//
// Вынос — любое место, откуда предмет уходит из файла мимо гейта:
//
//	возврат функции              значение возврата несёт предмет
//	именованный результат        присваивание ему — в том числе составное и
//	                             из отложенного замыкания: оно уходит вызывающему
//	переменная пакета            присваивание ей, её полю, её элементу; предмет
//	                             ключом её карты; переменная ДРУГОГО пакета
//	память параметра, получателя присваивание через них: поле, элемент,
//	                             разыменование, `copy` в них
//	канал                        отправка
//	вызов функции корпуса        аргумент либо получатель функции или метода,
//	                             объявленных в файле, которому предмет не
//	                             разрешён (соседний файл того же пакета, другой
//	                             пакет корпуса)
//	непрозрачный вызов           вызов, внутрь которого гейт не видит
//	                             (библиотека, метод значения, чей тип синтаксис
//	                             не называет, функция-значение), — находка, если
//	                             он не объявлен ПОТРЕБИТЕЛЕМ с причиной
//	встроенный вывод             `panic`, `print`, `println`
//	память без владельца         присваивание в поле результата вызова
//
// Вызов функции СВОЕГО разрешённого файла выносом не является: предмет
// остаётся в файле, и разбор продолжается в её теле с отмеченными параметрами —
// до неподвижной точки.
//
// ПОТРЕБИТЕЛЬ — вызов, которому предмет отдан по существу: оператор базы, куда
// материал ложится аргументом. Объявляется в `LoginVerifierSpec.OpaqueConsumers`
// ключом «функция → вызов» с причиной; объявление без вызова — находка
// (послабление обязано истекать само). Результат потребителя предмета не несёт
// — это и есть то, что объявление утверждает, и почему у него есть причина.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
//  1. ПСЕВДОНИМ: запись через указатель, взятый на локальную (`p := &out;
//     p.m = x; return out`), не прослеживается до `out`.
//  2. ИСТОЧНИК ПОТОКА МАТЕРИАЛА — ВЫХОД `Reveal`. Материал, прочитанный
//     владельцем из базы до обёртки в тип, — строка, и её путь внутри файла
//     гейт не видит; держит ревью единственного разрешённого файла.
//  3. ОТРАЖЕНИЕ и `unsafe` синтаксического следа не оставляют.
package check

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"
)

// lvSubject — предмет потока.
type lvSubject struct {
	// noun — чем предмет назван в находке; suffix — окончание краткого
	// причастия («присвоен» у материала, «присвоено» у имени): текст находки
	// несёт на его месте `{о}`.
	noun, suffix string
	// isSource — значение само является предметом.
	isSource func(f *lvFile, e ast.Expr) bool
	// keep — файлы, где предмет вправе быть: вызов их функций — не вынос.
	keep map[string]bool
}

// LoginVerifierFlowCensus — перепись разбора потока одного предмета.
type LoginVerifierFlowCensus struct {
	Functions int // тел функций разобрано (с уровнем пакета)
	Holders   int // хранилищ, несущих предмет
	// Calls — вызовы, получившие предмет, по исходу: в свой файл, в чужие файлы
	// корпуса, объявленным потребителям, необъявленным непрозрачным.
	InFile, ToCorpus, ToConsumer, Undeclared int
}

func (c LoginVerifierFlowCensus) String() string {
	return fmt.Sprintf("тел разобрано %d, хранилищ с предметом %d, вызовов с предметом: в свой файл %d, "+
		"в чужие файлы корпуса %d, объявленным потребителям %d, необъявленным %d",
		c.Functions, c.Holders, c.InFile, c.ToCorpus, c.ToConsumer, c.Undeclared)
}

type lvRole int

const (
	lvRoleNone   lvRole = iota // не хранилище: функция, тип, константа
	lvRoleBlank                // `_`
	lvRoleLocal                // локальная переменная
	lvRoleParam                // параметр либо получатель
	lvRoleResult               // именованный результат
	lvRolePkgVar               // переменная уровня пакета
)

type lvFieldRole struct {
	role  lvRole
	owner ast.Node // *ast.FuncDecl либо *ast.FuncLit
}

// lvCtx — где идёт разбор: объявление функции и внутреннее замыкание.
type lvCtx struct {
	decl *ast.FuncDecl
	lit  *ast.FuncLit
}

// lvFlow — разбор потока одного предмета по его файлам.
type lvFlow struct {
	ix        *lvIndex
	subj      lvSubject
	consumers map[string]string
	used      map[string]int

	f          *lvFile
	roles      map[*ast.Field]lvFieldRole
	tainted    map[lvVar]bool
	litReturns map[*ast.FuncLit]bool
	seeds      map[*ast.FuncDecl]map[int]bool
	changed    bool

	final    bool
	findings map[string]bool
	census   LoginVerifierFlowCensus
}

// lvRunFlow — разбор предмета subj по файлам files; находки, перепись,
// использования объявленных потребителей.
func lvRunFlow(ix *lvIndex, files []*lvFile, subj lvSubject, consumers map[string]string) ([]string, LoginVerifierFlowCensus, map[string]int) {
	fl := &lvFlow{
		ix: ix, subj: subj, consumers: consumers, used: map[string]int{},
		roles: map[*ast.Field]lvFieldRole{}, tainted: map[lvVar]bool{},
		litReturns: map[*ast.FuncLit]bool{}, seeds: map[*ast.FuncDecl]map[int]bool{},
		findings: map[string]bool{},
	}
	var own []*lvFile
	for _, f := range files {
		if subj.keep[f.rel] {
			own = append(own, f)
			fl.indexRoles(f)
		}
	}
	// Сведения только прибывают (хранилище начинает нести предмет, параметр —
	// отмечается, замыкание — возвращает), поэтому точка достигается; предел —
	// страж от разбора, который Go не собрал бы.
	for pass := 0; ; pass++ {
		if pass > 1000 {
			break
		}
		fl.changed = false
		fl.pass(own)
		if !fl.changed {
			break
		}
	}
	fl.final = true
	fl.pass(own)
	fl.census.Holders = len(fl.tainted)
	out := make([]string, 0, len(fl.findings))
	for m := range fl.findings {
		out = append(out, m)
	}
	sort.Strings(out)
	return out, fl.census, fl.used
}

func (fl *lvFlow) pass(files []*lvFile) {
	for _, f := range files {
		fl.f = f
		for _, decl := range f.file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				if fl.final {
					fl.census.Functions++
				}
				for i := range fl.seeds[d] {
					fl.taint(lvParam(d.Type, i))
				}
				fl.walk(d.Body, lvCtx{decl: d})
			case *ast.GenDecl:
				// Значения уровня пакета: вызовы в инициализаторах и замыкания.
				if d.Tok != token.VAR {
					continue
				}
				if fl.final {
					fl.census.Functions++
				}
				for _, s := range d.Specs {
					for _, v := range s.(*ast.ValueSpec).Values {
						fl.walk(v, lvCtx{})
					}
				}
			}
		}
	}
}

// indexRoles — роли полей сигнатур: параметр, получатель, именованный результат.
func (fl *lvFlow) indexRoles(f *lvFile) {
	mark := func(ft *ast.FuncType, recv *ast.FieldList, owner ast.Node) {
		for _, l := range []*ast.FieldList{recv, ft.Params} {
			if l != nil {
				for _, fld := range l.List {
					fl.roles[fld] = lvFieldRole{role: lvRoleParam, owner: owner}
				}
			}
		}
		if ft.Results != nil {
			for _, fld := range ft.Results.List {
				fl.roles[fld] = lvFieldRole{role: lvRoleResult, owner: owner}
			}
		}
	}
	ast.Inspect(f.file, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.FuncDecl:
			mark(d.Type, d.Recv, d)
		case *ast.FuncLit:
			mark(d.Type, nil, d)
		}
		return true
	})
}

// lvVar — хранилище: объявление имени и само имя. Объект разбора здесь не
// называется — его тип объявлен устаревшим; пара «объявление, имя» различает
// хранилища так же: у двух имён одного объявления (`a, b := …`) имена разные.
type lvVar struct {
	decl any
	name string
}

func lvVarOf(id *ast.Ident) (lvVar, bool) {
	if id == nil || id.Obj == nil {
		return lvVar{}, false
	}
	return lvVar{decl: id.Obj.Decl, name: id.Obj.Name}, true
}

func (fl *lvFlow) isTainted(id *ast.Ident) bool {
	v, ok := lvVarOf(id)
	return ok && fl.tainted[v]
}

func (fl *lvFlow) taint(id *ast.Ident) {
	if v, ok := lvVarOf(id); ok && !fl.tainted[v] {
		fl.tainted[v] = true
		fl.changed = true
	}
}

func (fl *lvFlow) seed(fn *ast.FuncDecl, i int) {
	if fl.seeds[fn] == nil {
		fl.seeds[fn] = map[int]bool{}
	}
	if !fl.seeds[fn][i] {
		fl.seeds[fn][i] = true
		fl.changed = true
	}
}

// find — находка в последнем проходе.
func (fl *lvFlow) find(pos token.Pos, ctx lvCtx, what string) {
	if !fl.final {
		return
	}
	where := "уровень пакета"
	if ctx.decl != nil {
		where = declLabel(ctx.decl)
	}
	fl.findings[fmt.Sprintf("%s:%d: %s %s (%s)", fl.f.rel, fl.f.fset.Position(pos).Line,
		fl.subj.noun, strings.ReplaceAll(what, "{о}", fl.subj.suffix), where)] = true
}

func (fl *lvFlow) walk(root ast.Node, ctx lvCtx) {
	ast.Inspect(root, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.FuncLit:
			fl.walk(s.Body, lvCtx{decl: ctx.decl, lit: s})
			return false
		case *ast.AssignStmt:
			fl.assign(s, ctx)
		case *ast.ValueSpec:
			for i, name := range s.Names {
				if i < len(s.Values) && fl.carries(s.Values[i]) {
					fl.store(name, ctx, s.Pos(), false)
				}
			}
		case *ast.RangeStmt:
			if fl.carries(s.X) {
				for _, e := range []ast.Expr{s.Key, s.Value} {
					if e != nil {
						fl.store(e, ctx, s.Pos(), false)
					}
				}
			}
		case *ast.SendStmt:
			if fl.carries(s.Value) {
				fl.find(s.Pos(), ctx, "отправлен{о} в канал — получатель берёт его мимо разрешённого файла")
			}
		case *ast.ReturnStmt:
			fl.ret(s, ctx)
		case *ast.CallExpr:
			fl.call(s, ctx)
		}
		return true
	})
}

func (fl *lvFlow) assign(s *ast.AssignStmt, ctx lvCtx) {
	if len(s.Lhs) == len(s.Rhs) {
		for i, lhs := range s.Lhs {
			if fl.carries(s.Rhs[i]) {
				fl.store(lhs, ctx, s.Pos(), false)
				continue
			}
			// Предмет ключом: `m[предмет] = x` кладёт его в хранилище m.
			if ix, ok := lvUnparen(lhs).(*ast.IndexExpr); ok && fl.carries(ix.Index) {
				fl.store(lhs, ctx, s.Pos(), false)
			}
		}
		return
	}
	if len(s.Rhs) == 1 && fl.carries(s.Rhs[0]) {
		for _, lhs := range s.Lhs {
			fl.store(lhs, ctx, s.Pos(), false)
		}
	}
}

// store — предмет положен в lhs. through — запись идёт В ПАМЯТЬ значения
// (`copy` в срез), даже если lhs — голое имя.
func (fl *lvFlow) store(lhs ast.Expr, ctx lvCtx, pos token.Pos, through bool) {
	lhs = lvUnparen(lhs)
	if sel, ok := lhs.(*ast.SelectorExpr); ok {
		if b := fl.ix.resolveSelector(fl.f, sel); b != nil {
			fl.find(pos, ctx, fmt.Sprintf("присвоен{о} переменной другого пакета `%s.%s` — её читатели получают его мимо разрешённого файла",
				fl.ix.pkgNames[b.file.dir], b.name))
			return
		}
	}
	id, direct := lvRootIdent(lhs)
	direct = direct && !through
	if id == nil {
		fl.find(pos, ctx, "записан{о} в память, чьего владельца синтаксис не называет (результат вызова), — её видит тот, кто её отдал")
		return
	}
	role, owner := fl.role(id)
	switch role {
	case lvRoleBlank:
	case lvRoleLocal:
		fl.taint(id)
	case lvRoleParam:
		if direct {
			fl.taint(id)
			return
		}
		fl.find(pos, ctx, fmt.Sprintf("записан{о} в память параметра либо получателя `%s` — её видит вызывающий", id.Name))
	case lvRoleResult:
		if _, isDecl := owner.(*ast.FuncDecl); isDecl {
			fl.find(pos, ctx, fmt.Sprintf("присвоен{о} именованному результату `%s` — он уходит вызывающему", id.Name))
			return
		}
		// Результат замыкания: судится по тому, куда уходит само замыкание.
		fl.taint(id)
	case lvRolePkgVar:
		fl.find(pos, ctx, fmt.Sprintf("присвоен{о} переменной пакета `%s` — её читатели получают его мимо разрешённого файла", id.Name))
	default:
		fl.find(pos, ctx, fmt.Sprintf("присвоен{о} `%s`, чьё хранилище гейт не видит", id.Name))
	}
}

// role — чем является имя в месте записи.
func (fl *lvFlow) role(id *ast.Ident) (lvRole, ast.Node) {
	if id.Name == "_" {
		return lvRoleBlank, nil
	}
	if b := fl.ix.resolve(fl.f, id); b != nil {
		return lvRolePkgVar, nil
	}
	if id.Obj == nil || id.Obj.Kind != ast.Var {
		return lvRoleNone, nil
	}
	if fld, ok := id.Obj.Decl.(*ast.Field); ok {
		r := fl.roles[fld]
		return r.role, r.owner
	}
	return lvRoleLocal, nil
}

func (fl *lvFlow) ret(s *ast.ReturnStmt, ctx lvCtx) {
	carried := false
	for _, r := range s.Results {
		carried = carried || fl.carries(r)
	}
	if ctx.lit != nil {
		if len(s.Results) == 0 && ctx.lit.Type.Results != nil {
			for _, fld := range ctx.lit.Type.Results.List {
				for _, n := range fld.Names {
					carried = carried || fl.isTainted(n)
				}
			}
		}
		if carried && !fl.litReturns[ctx.lit] {
			fl.litReturns[ctx.lit] = true
			fl.changed = true
		}
		return
	}
	if carried {
		fl.find(s.Pos(), ctx, "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта")
	}
}

// lvBuiltins — встроенные функции Go.
var lvBuiltins = map[string]bool{
	"append": true, "cap": true, "clear": true, "close": true, "complex": true, "copy": true,
	"delete": true, "imag": true, "len": true, "make": true, "max": true, "min": true, "new": true,
	"panic": true, "print": true, "println": true, "real": true, "recover": true,
}

// isBuiltin — имя встроенной функции, не перекрытое объявлением пакета.
func (fl *lvFlow) isBuiltin(id *ast.Ident) bool {
	if id.Obj != nil || !lvBuiltins[id.Name] {
		return false
	}
	_, fn := fl.ix.funcs[fl.f.dir][id.Name]
	return !fn && fl.ix.bindings[fl.f.dir][id.Name] == nil && !fl.ix.types[fl.f.dir][id.Name]
}

func (fl *lvFlow) call(c *ast.CallExpr, ctx lvCtx) {
	fun := lvCallee(c.Fun)
	var carried []int
	for i, a := range c.Args {
		if fl.carries(a) {
			carried = append(carried, i)
		}
	}
	recv := false
	if sel, ok := fun.(*ast.SelectorExpr); ok && fl.ix.importDir(fl.f, sel.X) == "" && fl.carries(sel.X) {
		recv = true
	}
	if len(carried) == 0 && !recv {
		return
	}
	if fl.ix.isConversion(fl.f, fun) {
		return // поток идёт в результат и судится у его стока
	}
	if id, ok := fun.(*ast.Ident); ok && fl.isBuiltin(id) {
		switch id.Name {
		case "copy":
			if len(c.Args) == 2 && fl.carries(c.Args[1]) {
				fl.store(c.Args[0], ctx, c.Pos(), true)
			}
		case "panic", "print", "println":
			fl.find(c.Pos(), ctx, fmt.Sprintf("отдан{о} встроенной функции `%s` — она выводит значение за пределы процесса", id.Name))
		}
		return
	}
	if lit, ok := fun.(*ast.FuncLit); ok {
		for _, i := range carried {
			fl.taint(lvParam(lit.Type, i))
		}
		return
	}
	if target, ok := fl.resolveCall(fun, ctx); ok {
		if fl.subj.keep[target.file.rel] {
			if fl.final {
				fl.census.InFile++
			}
			for _, i := range carried {
				fl.seed(target.decl, i)
			}
			return
		}
		if fl.final {
			fl.census.ToCorpus++
		}
		fl.find(c.Pos(), ctx, fmt.Sprintf("передан{о} `%s`, объявленной в %s, — дальше путь идёт вне разрешённого файла",
			lvRender(fun), target.file.rel))
		return
	}
	key := lvFuncLabel(ctx.decl) + " → " + lvRender(fun)
	if _, ok := fl.consumers[key]; ok {
		if fl.final {
			fl.census.ToConsumer++
			fl.used[key]++
		}
		return
	}
	if fl.final {
		fl.census.Undeclared++
	}
	fl.find(c.Pos(), ctx, fmt.Sprintf("передан{о} вызову `%s`, внутрь которого гейт не видит, и вызов не объявлен "+
		"потребителем: ключ «%s» в LoginVerifierSpec.OpaqueConsumers с причиной — либо вызов снимается", lvRender(fun), key))
}

// resolveCall — функция корпуса, которую зовёт fun, если синтаксис её называет.
func (fl *lvFlow) resolveCall(fun ast.Expr, ctx lvCtx) (lvFunc, bool) {
	switch t := fun.(type) {
	case *ast.Ident:
		if t.Obj != nil {
			if fd, ok := t.Obj.Decl.(*ast.FuncDecl); ok && t.Obj.Kind == ast.Fun {
				return lvFunc{decl: fd, file: fl.f}, true
			}
			return lvFunc{}, false
		}
		if fn, ok := fl.ix.funcs[fl.f.dir][t.Name]; ok {
			return fn, true
		}
		for _, d := range fl.ix.dotDirs(fl.f) {
			if fn, ok := fl.ix.funcs[d][t.Name]; ok {
				return fn, true
			}
		}
	case *ast.SelectorExpr:
		if dir := fl.ix.importDir(fl.f, t.X); dir != "" {
			fn, ok := fl.ix.funcs[dir][t.Sel.Name]
			return fn, ok
		}
		x, ok := t.X.(*ast.Ident)
		if !ok || x.Obj == nil || ctx.decl == nil || ctx.decl.Recv == nil || len(ctx.decl.Recv.List) == 0 {
			return lvFunc{}, false
		}
		if fld, ok := x.Obj.Decl.(*ast.Field); ok && fld == ctx.decl.Recv.List[0] {
			recvType, _ := receiverTypeName(ctx.decl)
			fn, ok := fl.ix.methods[fl.f.dir][recvType][t.Sel.Name]
			return fn, ok
		}
	}
	return lvFunc{}, false
}

// carries — значение несёт предмет.
func (fl *lvFlow) carries(e ast.Expr) bool {
	if e == nil {
		return false
	}
	if fl.subj.isSource(fl.f, e) {
		return true
	}
	switch n := e.(type) {
	case *ast.Ident:
		return fl.isTainted(n)
	case *ast.ParenExpr:
		return fl.carries(n.X)
	case *ast.SelectorExpr:
		return fl.ix.importDir(fl.f, n.X) == "" && fl.carries(n.X)
	case *ast.StarExpr:
		return fl.carries(n.X)
	case *ast.UnaryExpr:
		return n.Op == token.AND && fl.carries(n.X)
	case *ast.BinaryExpr:
		return n.Op == token.ADD && (fl.carries(n.X) || fl.carries(n.Y))
	case *ast.IndexExpr:
		return fl.carries(n.X)
	case *ast.SliceExpr:
		return fl.carries(n.X)
	case *ast.TypeAssertExpr:
		return fl.carries(n.X)
	case *ast.CompositeLit:
		_, isMap := n.Type.(*ast.MapType)
		for _, el := range n.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				if fl.carries(el) {
					return true
				}
				continue
			}
			// Ключ-имя у структуры — имя поля, а не значение: судится ключ карты.
			if fl.carries(kv.Value) || (isMap && fl.carries(kv.Key)) {
				return true
			}
		}
	case *ast.FuncLit:
		return fl.litReturns[n]
	case *ast.CallExpr:
		fun := lvCallee(n.Fun)
		if lit, ok := fun.(*ast.FuncLit); ok {
			return fl.litReturns[lit]
		}
		if len(n.Args) == 1 && fl.ix.isConversion(fl.f, fun) {
			return fl.carries(n.Args[0])
		}
		if id, ok := fun.(*ast.Ident); ok && fl.isBuiltin(id) && (id.Name == "append" || id.Name == "min" || id.Name == "max") {
			for _, a := range n.Args {
				if fl.carries(a) {
					return true
				}
			}
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// синтаксические помощники

func lvUnparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// lvCallee — вызываемое без скобок и без подстановки типов обобщения.
func lvCallee(e ast.Expr) ast.Expr {
	for {
		switch n := e.(type) {
		case *ast.ParenExpr:
			e = n.X
		case *ast.IndexExpr:
			e = n.X
		case *ast.IndexListExpr:
			e = n.X
		default:
			return e
		}
	}
}

// lvRootIdent — имя, чья память меняется записью в e; direct — e и есть имя.
func lvRootIdent(e ast.Expr) (*ast.Ident, bool) {
	direct := true
	for {
		switch n := e.(type) {
		case *ast.Ident:
			return n, direct
		case *ast.ParenExpr:
			e = n.X
		case *ast.SelectorExpr:
			e, direct = n.X, false
		case *ast.IndexExpr:
			e, direct = n.X, false
		case *ast.IndexListExpr:
			e, direct = n.X, false
		case *ast.StarExpr:
			e, direct = n.X, false
		default:
			return nil, false
		}
	}
}

// lvParam — имя i-го параметра (у вариадического — последнее); nil у
// безымянного.
func lvParam(ft *ast.FuncType, i int) *ast.Ident {
	if ft.Params == nil {
		return nil
	}
	var names []*ast.Ident
	for _, fld := range ft.Params.List {
		if len(fld.Names) == 0 {
			names = append(names, nil)
			continue
		}
		names = append(names, fld.Names...)
	}
	if len(names) == 0 {
		return nil
	}
	if i >= len(names) {
		i = len(names) - 1
	}
	return names[i]
}

// lvRender — вызываемое текстом ключа потребителя.
func lvRender(e ast.Expr) string {
	switch n := e.(type) {
	case *ast.Ident:
		return n.Name
	case *ast.SelectorExpr:
		return lvRender(n.X) + "." + n.Sel.Name
	case *ast.CallExpr:
		return lvRender(n.Fun) + "(…)"
	case *ast.IndexExpr:
		return lvRender(n.X) + "[…]"
	case *ast.ParenExpr:
		return "(" + lvRender(n.X) + ")"
	case *ast.StarExpr:
		return "*" + lvRender(n.X)
	case *ast.FuncLit:
		return "func(…)"
	}
	return "…"
}

// lvFuncLabel — функция ключа потребителя: `Тип.Метод`, `функция` либо
// «уровень пакета».
func lvFuncLabel(decl *ast.FuncDecl) string {
	if decl == nil {
		return "уровень пакета"
	}
	if decl.Recv != nil {
		t, _ := receiverTypeName(decl)
		return t + "." + decl.Name.Name
	}
	return decl.Name.Name
}
