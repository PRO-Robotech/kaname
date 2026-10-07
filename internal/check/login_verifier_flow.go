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
// несущего: склейка `+`, приведение к предобъявленному типу (строке, числу —
// приведение к числу не очищает: `uint8(часть[0])` — байт материала), срезу
// байтов либо типу корпуса, взятие адреса, разыменование, индекс, срез,
// утверждение типа, составной литерал с несущим элементом (у карты — и с
// несущим ключом), встроенные `append`/`min`/`max`, замыкание, возвращающее
// несущее, и его вызов на месте, РЕЗУЛЬТАТ ПРЕОБРАЗУЮЩЕГО ПОТРЕБИТЕЛЯ (ниже) и
// результат функции своего файла, чей возврат нёс предмет. Хранилище, куда
// несущее положено, несёт его дальше; обход `range` по несущему делает
// несущими ключ и значение. Многозначный вызов судится по ПОЗИЦИЯМ во всех
// пяти местах, где грамматика Go его допускает: присваивание (`a, b, ok :=
// f()`), объявление (`var a, b = f()`), возврат функции и возврат замыкания
// (`return f()`), единственный аргумент (`g(f())` — позиция i результата f есть
// аргумент i функции g). Где число позиций синтаксис не называет (оба вызова —
// непрозрачные), вызов несёт предмет, если несёт ЛЮБАЯ его позиция, — строже.
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
// до неподвижной точки. Обратная половина — ВОЗВРАТ СВОЕМУ ФАЙЛУ: возврат
// предмета из функции, которую зовёт ТОЛЬКО её файл (без получателя,
// неэкспортируемая, упомянута лишь вызовом и лишь в своём файле — `lvInternal`),
// выносом не является, и результат её вызова у вызывающего несёт предмет по
// позициям. Возврат из любой другой функции — вынос.
//
// Отдать материал КОНСТРУКТОРУ ЕГО ТИПА (функция файла объявления выхода без
// получателя, чей результат называет тип) — не вынос, а возврат под защиту
// типа; перепись считает такие вызовы отдельно. Любая другая функция того же
// файла судится как функция корпуса.
//
// ПОТРЕБИТЕЛЬ — непрозрачный вызов, которому предмет отдан по существу.
// Объявляется в `LoginVerifierSpec.OpaqueConsumers` ключом «функция → вызов» с
// ВИДОМ и причиной (kaname#139); объявление без вызова — находка (послабление
// обязано истекать само), объявление без вида — отказ прогона. Видов два:
//
//	поглощающий     оператор базы, сравнение, односторонняя функция: результат
//	                — признак исхода либо величина, из которой предмет не
//	                восстановить; ни одна позиция результата предмета не несёт
//	преобразующий   строковая операция, декодирование, разборщик, снятие
//	                обёртки: результат собран ИЗ предмета и несёт его в каждой
//	                позиции, кроме объявленных чистыми с причиной (признак
//	                «найдено», ошибка, не несущая входа). Результат ведётся
//	                дальше, как выход `Reveal`: часть, возвращённая из файла, —
//	                находка, часть, отданная необъявленному вызову, — находка.
//
// Перепись называет порознь объявленных потребителей и прослеженные
// результаты: «потребителей N» не говорит, сколько результатов разбор вёл.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
//  1. ПСЕВДОНИМ ЗНАЧЕНИЕМ: указатель, взятый адресом (`p := &out; p.m = x`), и
//     его копии прослеживаются до цели; срез либо карта, скопированные
//     присваиванием (`ys := xs; ys[0] = x; return xs`), — нет: без типов
//     синтаксис не отличает такую копию от копии значения.
//  2. ИСТОЧНИК ПОТОКА МАТЕРИАЛА — ВЫХОД `Reveal`. Материал, прочитанный
//     владельцем из базы до обёртки в тип, — строка, и её путь внутри файла
//     гейт не видит; держит ревью единственного разрешённого файла.
//  3. ОТРАЖЕНИЕ и `unsafe` синтаксического следа не оставляют.
//  4. ВИД ПОТРЕБИТЕЛЯ ГЕЙТ НЕ ПРОВЕРЯЕТ: внутрь вызова библиотеки он не видит,
//     и «поглощающий», объявленный вызову, чей результат на деле несёт
//     предмет, замолчит о его выносе. Вид держится причиной в ведомости,
//     сверенной с кодом вызова, и ревью ведомости. Оператор базы, ЧИТАЮЩИЙ
//     материал, объявлен поглощающим по границе 2: строка, прочитанная
//     владельцем, до обёртки в тип не ведётся.
//  5. СТРОЖЕ, ЧЕМ НУЖНО, — названо, чтобы не чинилось ослаблением: сводка
//     возврата функции своего файла одна на все места вызова (контекст не
//     различается); структура, в поле которой лёг предмет, несёт его вся —
//     число в соседнем поле тоже; признак `ok` у `v, ok := m[k]` и подобных
//     некомпонентных форм несёт предмет вместе со значением; многозначный
//     вызов, чьё число позиций синтаксис не называет (непрозрачный вызов
//     аргументом непрозрачного либо вариадического), несёт предмет, если несёт
//     любая позиция, и отдаёт его всем параметрам получателя.
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
	// intoType — функция корпуса, которой предмет отдан ОБРАТНО В СВОЙ ТИП
	// (конструктор типа материала): не вынос, а возврат под защиту типа. nil —
	// у предмета такого стока нет.
	intoType func(lvFunc) bool
}

// LoginVerifierFlowCensus — перепись разбора потока одного предмета.
type LoginVerifierFlowCensus struct {
	Functions int // тел функций разобрано (с уровнем пакета)
	Holders   int // хранилищ, несущих предмет
	// Calls — вызовы, получившие предмет, по исходу: в свой файл, в чужие файлы
	// корпуса, объявленным потребителям, необъявленным непрозрачным.
	InFile, ToCorpus, ToConsumer, Undeclared int
	// Absorbed, Transformed — из ToConsumer: вызовы поглощающих и
	// преобразующих; результат вторых прослежен дальше (kaname#139).
	// «Потребителей N» и «результатов прослежено M» — разные утверждения.
	Absorbed, Transformed int
	// ReturnsInFile — возвратов предмета из помощника, которого зовёт только
	// свой файл: результат прослежен у вызывающего, а не объявлен выносом.
	ReturnsInFile int
	// IntoType — вызовов конструктора типа материала с предметом (возврат в тип).
	IntoType int
}

func (c LoginVerifierFlowCensus) String() string {
	return fmt.Sprintf("тел разобрано %d, хранилищ с предметом %d, вызовов с предметом: в свой файл %d, "+
		"в чужие файлы корпуса %d, объявленным потребителям %d (поглощающим %d; преобразующим %d — "+
		"их результат прослежен дальше), необъявленным %d, конструктору своего типа %d; возвратов "+
		"своему файлу прослежено %d",
		c.Functions, c.Holders, c.InFile, c.ToCorpus, c.ToConsumer, c.Absorbed, c.Transformed,
		c.Undeclared, c.IntoType, c.ReturnsInFile)
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
	consumers map[string]LoginVerifierConsumer
	used      map[string]int
	// arity — потребитель → число позиций результата там, где синтаксис его
	// называет: чистая позиция за ним разрешает то, чего нет, и истекает.
	arity map[string]int
	// cur — где идёт разбор сейчас: ключ потребителя называет функцию, а
	// значение вызова судится и вне оператора, где он стоит.
	cur lvCtx
	// retCarry — функция разрешённого файла → позиции её результата, несущие
	// предмет; internal — функция, которую зовёт ТОЛЬКО её файл (см. lvInternal).
	retCarry map[*ast.FuncDecl]map[int]bool
	internal map[*ast.FuncDecl]bool

	f       *lvFile
	roles   map[*ast.Field]lvFieldRole
	tainted map[lvVar]bool
	// aliases — указатель, взятый адресом: имя-указатель → имена, чья память
	// за ним. Запись через указатель — запись в память цели.
	aliases    map[lvVar][]*ast.Ident
	litReturns map[*ast.FuncLit]bool
	seeds      map[*ast.FuncDecl]map[int]bool
	changed    bool

	final    bool
	findings map[string]bool
	census   LoginVerifierFlowCensus
}

// lvRunFlow — разбор предмета subj по файлам files; находки, перепись,
// использования объявленных потребителей и число позиций их результата там,
// где синтаксис его называет.
func lvRunFlow(ix *lvIndex, files []*lvFile, subj lvSubject, consumers map[string]LoginVerifierConsumer) ([]string, LoginVerifierFlowCensus, map[string]int, map[string]int) {
	fl := &lvFlow{
		ix: ix, subj: subj, consumers: consumers, used: map[string]int{}, arity: map[string]int{},
		roles: map[*ast.Field]lvFieldRole{}, tainted: map[lvVar]bool{}, aliases: map[lvVar][]*ast.Ident{},
		litReturns: map[*ast.FuncLit]bool{}, seeds: map[*ast.FuncDecl]map[int]bool{},
		retCarry: map[*ast.FuncDecl]map[int]bool{}, internal: map[*ast.FuncDecl]bool{},
		findings: map[string]bool{},
	}
	var own []*lvFile
	for _, f := range files {
		if subj.keep[f.rel] {
			own = append(own, f)
			fl.indexRoles(f)
			for d := range lvInternal(f, files) {
				fl.internal[d] = true
			}
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
	return out, fl.census, fl.used, fl.arity
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
	prev := fl.cur
	fl.cur = ctx
	defer func() { fl.cur = prev }()
	ast.Inspect(root, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.FuncLit:
			fl.walk(s.Body, lvCtx{decl: ctx.decl, lit: s})
			return false
		case *ast.AssignStmt:
			fl.assign(s, ctx)
		case *ast.ValueSpec:
			if len(s.Values) == 1 && len(s.Names) > 1 {
				// `var a, b = f()` — кортеж: позиция судится по позиции.
				fl.noteArity(s.Values[0], len(s.Names))
				for i, name := range s.Names {
					if fl.tupleCarries(s.Values[0], i) {
						fl.store(name, ctx, s.Pos(), false)
					}
				}
				break
			}
			for i, name := range s.Names {
				if i < len(s.Values) {
					fl.alias(name, s.Values[i])
				}
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
			fl.alias(lhs, s.Rhs[i])
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
	if len(s.Rhs) == 1 {
		fl.noteArity(s.Rhs[0], len(s.Lhs))
		for i, lhs := range s.Lhs {
			if fl.tupleCarries(s.Rhs[0], i) {
				fl.store(lhs, ctx, s.Pos(), false)
			}
		}
	}
}

// tupleCarries — позиция i многозначного выражения e несёт предмет. У вызова
// позиция судится по позиции: преобразующий потребитель и функция своего файла
// знают, какие позиции несут. Прочие многозначные формы (`v, ok := m[k]`,
// утверждение типа, приём из канала, замыкание на месте) судятся целиком, как
// прежде: признак `ok` предмета не несёт, но разбор не различает его — строже,
// а не слабее.
func (fl *lvFlow) tupleCarries(e ast.Expr, i int) bool {
	if c, ok := lvUnparen(e).(*ast.CallExpr); ok {
		if _, lit := lvCallee(c.Fun).(*ast.FuncLit); !lit && !fl.subj.isSource(fl.f, c) {
			return fl.resultCarries(c, i)
		}
	}
	return fl.carries(e)
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
		if !direct {
			// Запись через указатель, взятый адресом, — запись в память цели:
			// `p := &out; p.m = x` кладёт x в out.
			if v, ok := lvVarOf(id); ok {
				for _, target := range fl.aliases[v] {
					fl.store(target, ctx, pos, false)
				}
			}
		}
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

// alias — lhs становится указателем на память имён, которые называет rhs:
// `&x`, `&x.f`, `&x[i]` либо копия указателя, уже взятого адресом. Сведения
// только прибывают, как и у хранилищ с предметом.
func (fl *lvFlow) alias(lhs, rhs ast.Expr) {
	id, ok := lvUnparen(lhs).(*ast.Ident)
	if !ok {
		return
	}
	v, ok := lvVarOf(id)
	if !ok {
		return
	}
	var targets []*ast.Ident
	switch r := lvUnparen(rhs).(type) {
	case *ast.UnaryExpr:
		if r.Op == token.AND {
			if root, _ := lvRootIdent(r.X); root != nil {
				targets = []*ast.Ident{root}
			}
		}
	case *ast.Ident:
		if src, ok := lvVarOf(r); ok {
			targets = fl.aliases[src]
		}
	}
	for _, t := range targets {
		tv, ok := lvVarOf(t)
		if !ok && fl.ix.resolve(fl.f, t) == nil {
			continue
		}
		seen := false
		for _, have := range fl.aliases[v] {
			if hv, _ := lvVarOf(have); have == t || (ok && hv == tv) {
				seen = true
				break
			}
		}
		if !seen {
			fl.aliases[v] = append(fl.aliases[v], t)
			fl.changed = true
		}
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
	var positions []int
	if n := lvResultCount(ctx); len(s.Results) == 1 && n > 1 {
		// `return f()` многозначного f — у функции и у замыкания: позиция
		// результата — позиция f.
		fl.noteArity(s.Results[0], n)
		for i := 0; i < n; i++ {
			if fl.tupleCarries(s.Results[0], i) {
				carried = true
				positions = append(positions, i)
			}
		}
	} else {
		for i, r := range s.Results {
			if fl.carries(r) {
				carried = true
				positions = append(positions, i)
			}
		}
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
	if !carried {
		return
	}
	for _, i := range positions {
		if fl.retCarry[ctx.decl] == nil {
			fl.retCarry[ctx.decl] = map[int]bool{}
		}
		if !fl.retCarry[ctx.decl][i] {
			fl.retCarry[ctx.decl][i] = true
			fl.changed = true
		}
	}
	if fl.internal[ctx.decl] {
		// Вызывающие — только в этом файле, и у каждого результат вызова несёт
		// предмет (resultCarries): вынос судится там, куда он уйдёт дальше.
		if fl.final {
			fl.census.ReturnsInFile++
		}
		return
	}
	fl.find(s.Pos(), ctx, "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта")
}

// lvResultCount — число позиций результата функции разбора: замыкания, если
// разбор внутри него, иначе объявления.
func lvResultCount(ctx lvCtx) int {
	switch {
	case ctx.lit != nil:
		return lvFieldCount(ctx.lit.Type.Results)
	case ctx.decl != nil:
		return lvFieldCount(ctx.decl.Type.Results)
	}
	return 0
}

// lvFieldCount — число позиций перечня полей (параметров либо результатов).
func lvFieldCount(l *ast.FieldList) int {
	if l == nil {
		return 0
	}
	n := 0
	for _, fld := range l.List {
		if len(fld.Names) == 0 {
			n++
			continue
		}
		n += len(fld.Names)
	}
	return n
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
	carried := fl.argCarried(c)
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
		if fl.subj.intoType != nil && fl.subj.intoType(target) {
			if fl.final {
				fl.census.IntoType++
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
	if cons, ok := fl.consumers[key]; ok {
		if fl.final {
			fl.census.ToConsumer++
			fl.used[key]++
			if cons.Kind == ConsumerTransforming {
				fl.census.Transformed++
			} else {
				fl.census.Absorbed++
			}
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
			return false
		}
		// Вызов в позиции одного значения однозначен: Go не собрал бы иное.
		fl.noteArity(n, 1)
		return fl.resultCarries(n, 0)
	}
	return false
}

// resultCarries — позиция pos результата вызова c несёт предмет. Несут:
//
//   - результат функции разрешённого файла, чей возврат в этой позиции нёс
//     предмет (сводка по всем местам вызова — без различения контекста, строже);
//   - результат ПРЕОБРАЗУЮЩЕГО потребителя, получившего предмет аргументом либо
//     получателем, — в каждой позиции, кроме объявленных чистыми.
//
// Поглощающий потребитель, необъявленный непрозрачный вызов (он сам находка) и
// функция чужого файла (передача ей — находка) результатом предмет не несут.
func (fl *lvFlow) resultCarries(c *ast.CallExpr, pos int) bool {
	fun := lvCallee(c.Fun)
	if fl.ix.isConversion(fl.f, fun) {
		return len(c.Args) == 1 && fl.carries(c.Args[0])
	}
	if target, ok := fl.resolveCall(fun, fl.cur); ok {
		return fl.subj.keep[target.file.rel] && fl.retCarry[target.decl][pos]
	}
	if id, ok := fun.(*ast.Ident); ok && fl.isBuiltin(id) {
		return false
	}
	cons, ok := fl.consumers[lvFuncLabel(fl.cur.decl)+" → "+lvRender(fun)]
	if !ok || cons.Kind != ConsumerTransforming || !fl.receives(c) {
		return false
	}
	_, clean := cons.Clean[pos]
	return !clean
}

// receives — вызов получает предмет аргументом либо получателем.
func (fl *lvFlow) receives(c *ast.CallExpr) bool {
	if len(fl.argCarried(c)) > 0 {
		return true
	}
	sel, ok := lvCallee(c.Fun).(*ast.SelectorExpr)
	return ok && fl.ix.importDir(fl.f, sel.X) == "" && fl.carries(sel.X)
}

// argCarried — номера аргументов вызова c, получающих предмет. Многозначный
// вызов единственным аргументом (`g(f())`) раскладывается по позициям: позиция
// i результата f — аргумент i функции g. Число позиций берётся у того, чью
// сигнатуру синтаксис называет: у f (функция корпуса), иначе у g (функция
// корпуса либо замыкание без вариадического хвоста). Не называет ни одна — f
// несёт предмет, если несёт любая позиция, и получают его все параметры g
// (у непрозрачной g — аргумент 0): строже, а не слабее.
func (fl *lvFlow) argCarried(c *ast.CallExpr) []int {
	if len(c.Args) == 1 && c.Ellipsis == token.NoPos {
		if n, ok := fl.litArity(c.Args[0]); ok {
			// Замыкание на месте (`g(func() (A, B) {…}())`) судится целиком,
			// как в присваивании кортежем: несёт — получают все n позиций.
			if !fl.carries(c.Args[0]) {
				return nil
			}
			out := make([]int, n)
			for i := range out {
				out[i] = i
			}
			return out
		}
		if inner, ok := fl.multiValued(c.Args[0]); ok {
			params, variadic, known := fl.signature(lvCallee(c.Fun))
			n, sized := fl.resultArity(inner)
			if !sized && known && !variadic {
				n, sized = params, true
			}
			if sized {
				fl.noteArity(inner, n)
				var out []int
				for i := 0; i < n; i++ {
					if fl.resultCarries(inner, i) {
						out = append(out, i)
					}
				}
				return out
			}
			if !fl.resultCarriesAny(inner) {
				return nil
			}
			if !known || params == 0 {
				return []int{0}
			}
			out := make([]int, params)
			for i := range out {
				out[i] = i
			}
			return out
		}
	}
	var out []int
	for i, a := range c.Args {
		if fl.carries(a) {
			out = append(out, i)
		}
	}
	return out
}

// litArity — e есть вызов замыкания на месте с n > 1 позициями результата;
// число позиций называет само замыкание.
func (fl *lvFlow) litArity(e ast.Expr) (int, bool) {
	c, ok := lvUnparen(e).(*ast.CallExpr)
	if !ok {
		return 0, false
	}
	lit, ok := lvCallee(c.Fun).(*ast.FuncLit)
	if !ok {
		return 0, false
	}
	n := lvFieldCount(lit.Type.Results)
	return n, n > 1
}

// multiValued — e есть вызов, который МОЖЕТ быть многозначным: не замыкание на
// месте (оно судится целиком), не источник, не приведение и не встроенная
// функция (они однозначны).
func (fl *lvFlow) multiValued(e ast.Expr) (*ast.CallExpr, bool) {
	c, ok := lvUnparen(e).(*ast.CallExpr)
	if !ok || fl.subj.isSource(fl.f, c) {
		return nil, false
	}
	fun := lvCallee(c.Fun)
	if _, lit := fun.(*ast.FuncLit); lit || fl.ix.isConversion(fl.f, fun) {
		return nil, false
	}
	if id, ok := fun.(*ast.Ident); ok && fl.isBuiltin(id) {
		return nil, false
	}
	return c, true
}

// signature — число параметров вызываемого и вариадичность, если синтаксис
// называет его сигнатуру: замыкание либо функция корпуса.
func (fl *lvFlow) signature(fun ast.Expr) (params int, variadic, known bool) {
	var ft *ast.FuncType
	if lit, ok := fun.(*ast.FuncLit); ok {
		ft = lit.Type
	} else if target, ok := fl.resolveCall(fun, fl.cur); ok {
		ft = target.decl.Type
	}
	if ft == nil {
		return 0, false, false
	}
	if l := ft.Params; l != nil && len(l.List) > 0 {
		_, variadic = l.List[len(l.List)-1].Type.(*ast.Ellipsis)
	}
	return lvFieldCount(ft.Params), variadic, true
}

// resultArity — число позиций результата вызова c, если вызывается функция
// корпуса.
func (fl *lvFlow) resultArity(c *ast.CallExpr) (int, bool) {
	if target, ok := fl.resolveCall(lvCallee(c.Fun), fl.cur); ok {
		return lvFieldCount(target.decl.Type.Results), true
	}
	return 0, false
}

// resultCarriesAny — хоть одна позиция результата вызова c несёт предмет, когда
// их число синтаксис не называет. У преобразующего потребителя, получившего
// предмет, позиция за последней объявленной чистой не объявлена чистой — несёт.
func (fl *lvFlow) resultCarriesAny(c *ast.CallExpr) bool {
	fun := lvCallee(c.Fun)
	if target, ok := fl.resolveCall(fun, fl.cur); ok {
		if !fl.subj.keep[target.file.rel] {
			return false
		}
		for _, carried := range fl.retCarry[target.decl] {
			if carried {
				return true
			}
		}
		return false
	}
	cons, ok := fl.consumers[lvFuncLabel(fl.cur.decl)+" → "+lvRender(fun)]
	return ok && cons.Kind == ConsumerTransforming && fl.receives(c)
}

// noteArity — e, если это вызов объявленного потребителя, стоит там, где его
// результат занимает n позиций.
func (fl *lvFlow) noteArity(e ast.Expr, n int) {
	c, ok := lvUnparen(e).(*ast.CallExpr)
	if !ok {
		return
	}
	key := lvFuncLabel(fl.cur.decl) + " → " + lvRender(lvCallee(c.Fun))
	if _, declared := fl.consumers[key]; declared && n > fl.arity[key] {
		fl.arity[key] = n
	}
}

// lvInternal — функции файла f, которые зовёт ТОЛЬКО он сам: без получателя
// (метод достижим через интерфейс откуда угодно), неэкспортируемые, не `init`,
// упомянутые в своём файле хоть раз и только как вызываемое, а в соседних
// файлах того же пакета — ни разу. Возврат предмета из такой функции уходит
// вызывающему внутри файла, и разбор ведёт его там; у любой другой функции
// возврат предмета — вынос, как прежде.
//
// Упоминание в соседнем файле узнаётся по имени без разрешения (`Obj == nil`):
// одноимённое поле литерала структуры либо метод с тем же именем делают
// функцию «не только своей» — строже, а не слабее.
func lvInternal(f *lvFile, files []*lvFile) map[*ast.FuncDecl]bool {
	cands := map[string]*ast.FuncDecl{}
	for _, decl := range f.file.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if !ok || d.Recv != nil || d.Body == nil || ast.IsExported(d.Name.Name) || d.Name.Name == "init" || d.Name.Name == "_" {
			continue
		}
		cands[d.Name.Name] = d
	}
	callees := map[*ast.Ident]bool{}
	ast.Inspect(f.file, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if id, ok := lvCallee(c.Fun).(*ast.Ident); ok {
				callees[id] = true
			}
		}
		return true
	})
	calls := map[*ast.FuncDecl]int{}
	escaped := map[*ast.FuncDecl]bool{}
	ast.Inspect(f.file, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || id.Obj == nil {
			return true
		}
		d, ok := id.Obj.Decl.(*ast.FuncDecl)
		if !ok || cands[id.Name] != d || id == d.Name {
			return true
		}
		if callees[id] {
			calls[d]++
		} else {
			escaped[d] = true // значение функции уходит туда, куда разбор не смотрит
		}
		return true
	})
	for _, g := range files {
		if g == f || g.dir != f.dir {
			continue
		}
		ast.Inspect(g.file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				ast.Inspect(sel.X, func(m ast.Node) bool {
					if id, ok := m.(*ast.Ident); ok && id.Obj == nil {
						if d := cands[id.Name]; d != nil {
							escaped[d] = true
						}
					}
					return true
				})
				return false
			}
			if id, ok := n.(*ast.Ident); ok && id.Obj == nil {
				if d := cands[id.Name]; d != nil {
					escaped[d] = true
				}
			}
			return true
		})
	}
	out := map[*ast.FuncDecl]bool{}
	for _, d := range cands {
		if calls[d] > 0 && !escaped[d] {
			out[d] = true
		}
	}
	return out
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
