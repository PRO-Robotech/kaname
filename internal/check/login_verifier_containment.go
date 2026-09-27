// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_verifier_containment.go — ЯДРО гейта: проверочный материал способа входа
// выходит из своего типа ТОЛЬКО в названном файле и не уходит из него мимо
// объявленного потребителя, а таблицу секрета называет ТОЛЬКО её адаптер (фаза
// Ф2, `kacho#1268`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Материал пароля живёт в типе `domain.LoginVerifier`, который не печатается, не
// пишется в журнал и не сериализуется: каждый общий путь вывода отдаёт
// заглушку либо отказ (`internal/domain/login_method_test.go`). Выход у
// материала ОДИН — метод `Reveal`, — и он нужен ровно тем, кто кладёт материал в
// базу и сверяет с ним предъявленное.
//
// Правил три:
//
//  1. ВЫХОД вне разрешённого ФАЙЛА — находка: материал достан строкой и дальше
//     ничем не защищён.
//  2. ВТОРОЙ ЧИТАТЕЛЬ КОЛОНКИ — выражение вне файла-владельца, называющее
//     таблицу секрета, — находка: он читает материал строкой, минуя тип.
//  3. ВЫНОС — материал из разрешённого файла, имя таблицы из файла-владельца
//     уходят туда, куда гейт дальше не смотрит, — находка. Разбор потока —
//     `login_verifier_flow.go`, один на оба предмета.
//
// Разрешение даётся ФАЙЛУ, а не пакету: пакет адаптера — 70 не-тестовых файлов,
// и разрешение каталогу пропускало выход в любом из них.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПЕРЕПИСЬ НАПИСАНИЙ — ЧТО РАСПОЗНАВАТЕЛЬ ЗНАЕТ, ВЫВЕДЕНО ИЗ ГРАММАТИКИ
//
// Судится РАЗБОРОМ, а не текстом: комментарий Go, объясняющий выход, и строка с
// его именем законны и обязаны остаться — гейт, краснеющий на собственном
// объяснении, снимают первым.
//
// Правило 1 — выход записывается ОДНОЙ формой, селектором с его именем: вызов,
// значение метода, выражение метода, метод через интерфейс и через встроенное
// поле.
//
// Правило 2 — имя таблицы. Строковое значение Go (литерал в двойных и в обратных
// кавычках, с экранированием Go внутри) судится ГРАММАТИКОЙ SQL — `sql_relation_name.go`:
// имя без кавычек в любом регистре, в кавычках побайтово, `U&"…"` с UESCAPE,
// со схемой и без, внутри строки SQL (`'…'::regclass`, `EXECUTE '…'`,
// E-, U&-, N-, долларовая строка, продолжение, склейка `||`). Каким выражением
// Go это значение записано:
//
//	литерал                  "…" и `…`
//	склейка                  `+` литералов, констант, приведений `string(…)`
//	                         и к строковому типу корпуса; судится свёрнутое
//	                         значение и отдельно каждое звено
//	связанное имя            константа либо переменная уровня пакета, чьё
//	                         значение называет таблицу, — в том числе
//	                         повторённая неявно в группе `const (…)`; сама
//	                         константа владельца — такое имя
//	локальная константа      `const` внутри функции участвует в склейке
//	селектор другого пакета  `пакет.Имя` — с именем пакета, псевдонимом импорта и
//	                         через импорт с точкой
//
// Правило 3 — вынос: возврат, именованный результат, переменная пакета (своего
// и чужого, её поле, элемент, ключ карты), память параметра и получателя,
// канал, аргумент функции чужого файла, непрозрачный вызов без объявления
// потребителя, встроенный вывод. Полный перечень и то, что несёт предмет, —
// шапка `login_verifier_flow.go`. Переменная пакета в разрешённом файле, чьё
// значение обращается к выходу, — вынос материала сама по себе.
//
// Объявление предмета (имя выхода, файл и тип, где он объявлен, имя таблицы,
// разрешённые файлы, потребители) приходит ПАРАМЕТРОМ из файла пробы: литерал
// имени таблицы в этом файле сделал бы гейт своей же первой находкой, а файл
// пробы в корпус не входит by construction.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕМИСЫ — ОТКАЗ, А НЕ МОЛЧАНИЕ
//
//   - выход объявлен РОВНО ОДИН раз, в названном файле, на названном типе.
//     Иначе селектор с тем же именем означает не этот выход, и перепись мерит
//     чужой метод;
//   - файл-владелец таблицы называет её хоть раз: иначе второе правило ослепло;
//   - каждый разрешённый файл выход ИСПОЛЬЗУЕТ, каждый объявленный потребитель
//     получает предмет: разрешение без предмета — место, куда вызов вносят
//     незамеченным (послабление обязано истекать само).
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
//  1. ФАЙЛЫ ПРОБ НЕ СУДЯТСЯ: пробе законно достать материал, чтобы сверить его
//     побайтово, а фикстуре инъекции — написать форму дефекта.
//  2. ИМЯ, СОБРАННОЕ ВО ВРЕМЯ ИСПОЛНЕНИЯ, НЕ УЗНАЁТСЯ: `fmt.Sprintf`,
//     `strings.Join`, `+=` к переменной, срез байтов — это поток данных, а не
//     синтаксис. В дереве такой формы нет; появится — гейт промолчит.
//  3. ГРАНИЦЫ РАЗБОРА ПОТОКА — срез либо карта, скопированные присваиванием,
//     материал, прочитанный владельцем из базы до обёртки в тип, отражение —
//     названы в шапке `login_verifier_flow.go`.
//  4. ГРАНИЦЫ РАСПОЗНАВАТЕЛЯ SQL — имя, собранное во время исполнения,
//     аргумент `format('%I', …)` — названы в шапке `sql_relation_name.go`.
//  5. ПУТЬ ВНЕ GO НЕ СУДИТСЯ: базу судит соседний гейт схемы
//     `internal/repo/kaname/pg` `TestLoginVerifierStaysInsideTheSchema`, тем же
//     распознавателем имени.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strconv"
	"strings"
)

// LoginVerifierSpec — объявление предмета гейта.
type LoginVerifierSpec struct {
	// Accessor — имя единственного выхода материала.
	Accessor string
	// DeclRel — файл, где выход объявлен; DeclType — тип-получатель.
	DeclRel, DeclType string
	// Table — таблица секрета; TableOwnerRel — единственный файл, который её называет.
	Table, TableOwnerRel string
	// AllowedFiles — файл → причина, по которой материал ему нужен. Причина
	// уезжает в перепись: разрешение без названной причины снимается следующим.
	AllowedFiles map[string]string
	// OpaqueConsumers — вызов, которому материал либо имя таблицы отданы по
	// существу, → причина. Ключ — «функция → вызов», как его печатает находка:
	// `Тип.Метод → r.pool.QueryRow`. Объявление без вызова — находка.
	OpaqueConsumers map[string]string
}

// LoginVerifierCensus — объём осмотренного по каждой оси.
type LoginVerifierCensus struct {
	FilesRead, FilesParsed int
	AccessorDecls          int
	AccessorUses           int
	AllowedUses            map[string]int
	// TableNamings — упоминания таблицы по формам записи; OwnerTableNamings —
	// из них у владельца.
	TableNamings      map[string]int
	OwnerTableNamings int
	// Bindings — связанные имена, несущие имя таблицы: «каталог.имя».
	Bindings []string
	// Material, Name — разбор потока материала и имени таблицы.
	Material, Name LoginVerifierFlowCensus
	// ConsumerUses — объявленный потребитель → вызовов с предметом.
	ConsumerUses map[string]int
}

// формы записи имени таблицы — ключи переписи.
const (
	formLiteral = "литерал"
	formSplice  = "склейка"
	formBinding = "связанное имя"
	formForeign = "селектор другого пакета"
)

func (c LoginVerifierCensus) String() string {
	allowed := make([]string, 0, len(c.AllowedUses))
	for f, n := range c.AllowedUses {
		allowed = append(allowed, fmt.Sprintf("%s=%d", f, n))
	}
	sort.Strings(allowed)
	forms := make([]string, 0, 4)
	total := 0
	for _, f := range []string{formLiteral, formSplice, formBinding, formForeign} {
		forms = append(forms, fmt.Sprintf("%s %d", f, c.TableNamings[f]))
		total += c.TableNamings[f]
	}
	consumers := make([]string, 0, len(c.ConsumerUses))
	for k, n := range c.ConsumerUses {
		consumers = append(consumers, fmt.Sprintf("«%s»=%d", k, n))
	}
	sort.Strings(consumers)
	return fmt.Sprintf("перепись: не-тестовых файлов Go прочитано %d (разобрано %d) · объявлений выхода %d · "+
		"обращений к выходу %d, из них в разрешённых файлах [%s] · упоминаний таблицы %d (%s), "+
		"из них у владельца %d · связанных имён, несущих таблицу, %d %v · поток материала: %s · "+
		"поток имени таблицы: %s · потребителей объявлено %d [%s]",
		c.FilesRead, c.FilesParsed, c.AccessorDecls, c.AccessorUses, strings.Join(allowed, " "),
		total, strings.Join(forms, ", "), c.OwnerTableNamings, len(c.Bindings), c.Bindings,
		c.Material, c.Name, len(c.ConsumerUses), strings.Join(consumers, " "))
}

// lvFile — разобранный файл корпуса.
type lvFile struct {
	rel, dir string
	fset     *token.FileSet
	file     *ast.File
}

// lvBinding — константа либо переменная уровня пакета.
type lvBinding struct {
	name     string
	spec     *ast.ValueSpec
	value    ast.Expr
	file     *lvFile
	folded   string
	foldable bool
	bearing  bool
}

// lvFunc — функция либо метод корпуса и файл, где они объявлены.
type lvFunc struct {
	decl *ast.FuncDecl
	file *lvFile
}

// lvIndex — объявления корпуса по каталогу пакета.
type lvIndex struct {
	relation string
	bindings map[string]map[string]*lvBinding
	pkgNames map[string]string
	dirs     []string
	types    map[string]map[string]bool
	funcs    map[string]map[string]lvFunc
	methods  map[string]map[string]map[string]lvFunc // каталог → тип получателя → имя
	// consts — действующие значения каждой спецификации константы: у
	// спецификации без значений в группе `const (…)` — значения предыдущей.
	consts map[*ast.ValueSpec][]ast.Expr
}

// importDir — каталог корпуса, импортированный в файле под именем x; пусто — x
// не имя импорта.
func (ix *lvIndex) importDir(f *lvFile, x ast.Expr) string {
	id, ok := x.(*ast.Ident)
	if !ok || id.Obj != nil {
		return ""
	}
	for _, imp := range f.file.Imports {
		if imp.Name != nil && (imp.Name.Name == "." || imp.Name.Name == "_") {
			continue
		}
		if dir := ix.corpusDir(imp); dir != "" {
			local := ix.pkgNames[dir]
			if imp.Name != nil {
				local = imp.Name.Name
			}
			if local == id.Name {
				return dir
			}
		}
	}
	return ""
}

// dotDirs — каталоги корпуса, импортированные в файл с точкой.
func (ix *lvIndex) dotDirs(f *lvFile) []string {
	var out []string
	for _, imp := range f.file.Imports {
		if imp.Name != nil && imp.Name.Name == "." {
			if dir := ix.corpusDir(imp); dir != "" {
				out = append(out, dir)
			}
		}
	}
	return out
}

func (ix *lvIndex) corpusDir(imp *ast.ImportSpec) string {
	p, err := strconv.Unquote(imp.Path.Value)
	if err != nil {
		return ""
	}
	for _, dir := range ix.dirs {
		if p == dir || strings.HasSuffix(p, "/"+dir) {
			return dir
		}
	}
	return ""
}

// resolve — связанное имя, на которое указывает идентификатор, либо nil.
//
// Идентификатор, разрешённый разбором внутри файла, указывает на своё
// объявление; указывает на иное (локальная переменная с тем же именем) —
// связанного имени нет. Неразрешённый — имя уровня пакета из соседнего файла
// либо из пакета, импортированного с точкой.
func (ix *lvIndex) resolve(f *lvFile, id *ast.Ident) *lvBinding {
	if b := ix.bindings[f.dir][id.Name]; b != nil {
		if id.Obj != nil {
			if spec, ok := id.Obj.Decl.(*ast.ValueSpec); ok && spec == b.spec {
				return b
			}
			return nil
		}
		return b
	}
	if id.Obj != nil {
		return nil
	}
	for _, dir := range ix.dotDirs(f) {
		if b := ix.bindings[dir][id.Name]; b != nil {
			return b
		}
	}
	return nil
}

// resolveSelector — связанное имя другого пакета под селектором `пакет.Имя`.
func (ix *lvIndex) resolveSelector(f *lvFile, sel *ast.SelectorExpr) *lvBinding {
	if dir := ix.importDir(f, sel.X); dir != "" {
		return ix.bindings[dir][sel.Sel.Name]
	}
	return nil
}

// localConst — значение константы, объявленной внутри функции, либо nil.
func (ix *lvIndex) localConst(id *ast.Ident) ast.Expr {
	if id.Obj == nil || id.Obj.Kind != ast.Con {
		return nil
	}
	spec, ok := id.Obj.Decl.(*ast.ValueSpec)
	if !ok {
		return nil
	}
	values := ix.consts[spec]
	for i, n := range spec.Names {
		if n.Name == id.Name && i < len(values) {
			return values[i]
		}
	}
	return nil
}

// isConversion — вызываемое есть тип строки либо среза байтов: `string`,
// `[]byte`, `[]rune`, тип корпуса (своего пакета, локальный, другого пакета).
func (ix *lvIndex) isConversion(f *lvFile, fun ast.Expr) bool {
	switch t := fun.(type) {
	case *ast.ParenExpr:
		return ix.isConversion(f, t.X)
	case *ast.ArrayType:
		id, ok := t.Elt.(*ast.Ident)
		return ok && t.Len == nil && (id.Name == "byte" || id.Name == "rune")
	case *ast.Ident:
		if t.Obj != nil {
			return t.Obj.Kind == ast.Typ
		}
		if ix.types[f.dir][t.Name] {
			return true
		}
		for _, dir := range ix.dotDirs(f) {
			if ix.types[dir][t.Name] {
				return true
			}
		}
		_, fn := ix.funcs[f.dir][t.Name]
		return t.Name == "string" && !fn && ix.bindings[f.dir]["string"] == nil
	case *ast.SelectorExpr:
		if dir := ix.importDir(f, t.X); dir != "" {
			return ix.types[dir][t.Sel.Name]
		}
	}
	return false
}

// fold — свёрнутое значение строкового выражения: литералы, склейка, константы
// и связанные имена, приведения к строковому типу.
func (ix *lvIndex) fold(f *lvFile, e ast.Expr) (string, bool) { return ix.foldDepth(f, e, 0) }

func (ix *lvIndex) foldDepth(f *lvFile, e ast.Expr, depth int) (string, bool) {
	if depth > 64 {
		return "", false
	}
	switch n := e.(type) {
	case *ast.BasicLit:
		if n.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(n.Value)
		return v, err == nil
	case *ast.ParenExpr:
		return ix.foldDepth(f, n.X, depth+1)
	case *ast.BinaryExpr:
		if n.Op != token.ADD {
			return "", false
		}
		l, lok := ix.foldDepth(f, n.X, depth+1)
		r, rok := ix.foldDepth(f, n.Y, depth+1)
		return l + r, lok && rok
	case *ast.Ident:
		if b := ix.resolve(f, n); b != nil {
			return b.folded, b.foldable
		}
		if v := ix.localConst(n); v != nil {
			return ix.foldDepth(f, v, depth+1)
		}
	case *ast.SelectorExpr:
		if b := ix.resolveSelector(f, n); b != nil {
			return b.folded, b.foldable
		}
	case *ast.CallExpr:
		if len(n.Args) == 1 && ix.isConversion(f, n.Fun) {
			return ix.foldDepth(f, n.Args[0], depth+1)
		}
	}
	return "", false
}

// namesTable — значение называет таблицу по грамматике SQL.
func (ix *lvIndex) namesTable(v string) bool { return SQLNamesRelation(v, ix.relation) }

// lvNaming — упоминание таблицы: где и какой формой.
type lvNaming struct {
	pos  token.Pos
	form string
	via  string
}

// namings — упоминания таблицы внутри выражения; каждое — наибольшее целое
// выражение, чьё значение её называет.
func (ix *lvIndex) namings(f *lvFile, root ast.Node) []lvNaming {
	var out []lvNaming
	ast.Inspect(root, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.BasicLit, *ast.BinaryExpr, *ast.ParenExpr:
			expr := e.(ast.Expr)
			v, ok := ix.fold(f, expr)
			if !ok {
				return true
			}
			if !ix.namesTable(v) {
				// Свёрнутое значение таблицы не называет (имя ограничения), но
				// звено внутри может быть связанным именем владельца — оно судится
				// само: константа владельца за его файл не выходит ни в каком виде.
				return true
			}
			form := formSplice
			if _, lit := e.(*ast.BasicLit); lit {
				form = formLiteral
			}
			out = append(out, lvNaming{pos: expr.Pos(), form: form})
			return false
		case *ast.Ident:
			if b := ix.resolve(f, e); b != nil && b.bearing {
				form := formBinding
				if b.file.dir != f.dir {
					form = formForeign // импорт с точкой
				}
				out = append(out, lvNaming{pos: e.Pos(), form: form, via: b.file.dir + "." + b.name})
			}
		case *ast.SelectorExpr:
			if b := ix.resolveSelector(f, e); b != nil && b.bearing {
				out = append(out, lvNaming{pos: e.Pos(), form: formForeign, via: b.file.dir + "." + b.name})
				return false
			}
		case *ast.ValueSpec:
			// Имя объявления — не упоминание: судится значение.
			for _, v := range e.Values {
				out = append(out, ix.namings(f, v)...)
			}
			return false
		case *ast.FuncDecl:
			if e.Body != nil {
				out = append(out, ix.namings(f, e.Body)...)
			}
			return false
		}
		return true
	})
	return out
}

// isAccessor — селектор с именем выхода.
func isAccessor(e ast.Expr, accessor string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == accessor
}

// declLabel — чем назвать объявление в находке: функция либо переменная пакета.
func declLabel(decl ast.Decl) string {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		return "функция " + d.Name.Name
	case *ast.GenDecl:
		var names []string
		for _, sp := range d.Specs {
			if vs, ok := sp.(*ast.ValueSpec); ok {
				for _, n := range vs.Names {
					names = append(names, n.Name)
				}
			}
		}
		if len(names) > 0 {
			return "объявление " + strings.Join(names, ", ")
		}
	}
	return "объявление уровня файла"
}

// indexFile — объявления файла в индекс: связанные имена, типы, функции,
// методы, действующие значения констант (включая объявленные внутри функций).
func (ix *lvIndex) indexFile(f *lvFile) {
	if _, seen := ix.pkgNames[f.dir]; !seen {
		ix.pkgNames[f.dir] = f.file.Name.Name
		ix.dirs = append(ix.dirs, f.dir)
		ix.bindings[f.dir] = map[string]*lvBinding{}
		ix.types[f.dir] = map[string]bool{}
		ix.funcs[f.dir] = map[string]lvFunc{}
		ix.methods[f.dir] = map[string]map[string]lvFunc{}
	}
	ast.Inspect(f.file, func(n ast.Node) bool {
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			return true
		}
		var prev []ast.Expr
		for _, s := range gd.Specs {
			vs := s.(*ast.ValueSpec)
			if len(vs.Values) > 0 {
				prev = vs.Values
			}
			ix.consts[vs] = prev
		}
		return true
	})
	for _, decl := range f.file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			fn := lvFunc{decl: d, file: f}
			if d.Recv == nil {
				ix.funcs[f.dir][d.Name.Name] = fn
				continue
			}
			recvType, _ := receiverTypeName(d)
			if ix.methods[f.dir][recvType] == nil {
				ix.methods[f.dir][recvType] = map[string]lvFunc{}
			}
			ix.methods[f.dir][recvType][d.Name.Name] = fn
		case *ast.GenDecl:
			switch d.Tok {
			case token.TYPE:
				for _, s := range d.Specs {
					ix.types[f.dir][s.(*ast.TypeSpec).Name.Name] = true
				}
			case token.CONST, token.VAR:
				for _, s := range d.Specs {
					vs := s.(*ast.ValueSpec)
					values := vs.Values
					if d.Tok == token.CONST {
						values = ix.consts[vs]
					}
					for i, name := range vs.Names {
						// Имя без значения тоже записывается: присваивание переменной
						// пакета судится по имени, а не по инициализатору.
						var value ast.Expr
						if i < len(values) {
							value = values[i]
						}
						if name.Name == "_" {
							continue
						}
						ix.bindings[f.dir][name.Name] = &lvBinding{name: name.Name, spec: vs, value: value, file: f}
					}
				}
			}
		}
	}
}

// newLVIndex — первый проход гейтов, судящих ЗНАЧЕНИЯ строк Go
// (`AuditLoginVerifierContainment` и `JudgeFailureRowRemovals`): разбор
// корпуса, индекс объявлений по каталогу пакета и неподвижная точка свёртки
// связанных имён. Проход один на оба гейта: вторая копия свёртки разошлась бы с
// первой молча — ровно на той форме записи, которую знает только одна. read —
// сколько файлов начато, включая тот, чей разбор сорвался; files — разобранные.
func newLVIndex(corpus TreeCorpus, relation string) (ix *lvIndex, files []*lvFile, read int, err error) {
	ix = &lvIndex{
		relation: relation, bindings: map[string]map[string]*lvBinding{}, pkgNames: map[string]string{},
		types: map[string]map[string]bool{}, funcs: map[string]map[string]lvFunc{},
		methods: map[string]map[string]map[string]lvFunc{}, consts: map[*ast.ValueSpec][]ast.Expr{},
	}
	for _, rel := range corpus.Rels() {
		read++
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, rel, corpus[rel], parser.ParseComments)
		if perr != nil {
			return nil, files, read, fmt.Errorf("разбор %s: %w — гейт не вправе судить файл, которого он не разобрал", rel, perr)
		}
		f := &lvFile{rel: rel, dir: path.Dir(rel), fset: fset, file: file}
		files = append(files, f)
		ix.indexFile(f)
	}
	sort.Strings(ix.dirs)

	// Неподвижная точка: свёртка и «несёт имя таблицы» у каждого связанного имени.
	// Сведения только прибывают (ложь → истина), поэтому точка достигается; предел
	// прохода — страж от разбора, который Go не собрал бы (цикл инициализации).
	for changed, pass := true, 0; changed; pass++ {
		if pass > 1000 {
			return nil, files, read, fmt.Errorf("свёртка связанных имён не сошлась за %d проходов — цикл инициализации?", pass)
		}
		changed = false
		for _, dir := range ix.dirs {
			for _, b := range ix.bindings[dir] {
				if b.value == nil {
					continue
				}
				folded, foldable := ix.fold(b.file, b.value)
				bearing := len(ix.namings(b.file, b.value)) > 0
				if folded != b.folded || foldable != b.foldable || bearing != b.bearing {
					b.folded, b.foldable, b.bearing = folded, foldable, bearing
					changed = true
				}
			}
		}
	}
	return ix, files, read, nil
}

// AuditLoginVerifierContainment — находки и перепись по корпусу не-тестовых
// файлов. Корпус и объявление приходят ПАРАМЕТРАМИ: инъекция обязана подать
// разбору синтетику, а не это дерево.
func AuditLoginVerifierContainment(corpus TreeCorpus, spec LoginVerifierSpec) ([]string, LoginVerifierCensus, error) {
	c := LoginVerifierCensus{AllowedUses: map[string]int{}, TableNamings: map[string]int{}, ConsumerUses: map[string]int{}}
	for f := range spec.AllowedFiles {
		c.AllowedUses[f] = 0
	}
	for k := range spec.OpaqueConsumers {
		c.ConsumerUses[k] = 0
	}
	if spec.Accessor == "" || spec.Table == "" || spec.DeclRel == "" || spec.DeclType == "" || spec.TableOwnerRel == "" {
		return nil, c, fmt.Errorf("объявление предмета неполно (%+v) — судить нечего", spec)
	}

	// Проход первый: разбор, индекс по каталогу пакета, свёртка связанных имён.
	ix, files, read, err := newLVIndex(corpus, spec.Table)
	c.FilesRead, c.FilesParsed = read, len(files)
	if err != nil {
		return nil, c, err
	}
	for _, dir := range ix.dirs {
		for _, b := range ix.bindings[dir] {
			if b.bearing {
				c.Bindings = append(c.Bindings, dir+"."+b.name)
			}
		}
	}
	sort.Strings(c.Bindings)

	// Проход второй: правила 1 и 2 и переменная пакета, обращающаяся к выходу.
	var findings []string
	var declWhere []string
	for _, f := range files {
		line := func(p token.Pos) int { return f.fset.Position(p).Line }
		_, allowed := spec.AllowedFiles[f.rel]

		for _, decl := range f.file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Name.Name == spec.Accessor {
				c.AccessorDecls++
				// Разбор получателя — общий с соседним гейтом (`provider_road_wire_guard.go`):
				// вторая копия одного разбора разошлась бы с первой молча.
				recvType, _ := receiverTypeName(fn)
				declWhere = append(declWhere, fmt.Sprintf("%s (получатель %s)", f.rel, recvType))
			}
		}

		for _, nm := range ix.namings(f, f.file) {
			c.TableNamings[nm.form]++
			if f.rel == spec.TableOwnerRel {
				c.OwnerTableNamings++
				continue
			}
			via := ""
			if nm.via != "" {
				via = " через " + nm.via
			}
			findings = append(findings, fmt.Sprintf(
				"%s:%d: таблица секрета `%s` названа мимо её адаптера (%s) формой «%s»%s. Второй читатель "+
					"колонки получает материал строкой, не проходя через тип, — и первое правило "+
					"гейта его не увидит",
				f.rel, line(nm.pos), spec.Table, spec.TableOwnerRel, nm.form, via))
		}

		for _, decl := range f.file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || !allowed || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				hit := false
				for _, v := range vs.Values {
					ast.Inspect(v, func(n ast.Node) bool {
						if e, ok := n.(ast.Expr); ok && isAccessor(e, spec.Accessor) {
							hit = true
						}
						return !hit
					})
				}
				if hit {
					findings = append(findings, fmt.Sprintf(
						"%s:%d: переменная пакета `%s` обращается к выходу материала — её читатели "+
							"получают материал мимо разрешённого файла",
						f.rel, line(vs.Pos()), vs.Names[0].Name))
				}
			}
		}
		for _, decl := range f.file.Decls {
			where := declLabel(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != spec.Accessor {
					return true
				}
				c.AccessorUses++
				if allowed {
					c.AllowedUses[f.rel]++
					return true
				}
				findings = append(findings, fmt.Sprintf(
					"%s:%d: материал способа входа выведен из своего типа обращением к `%s` вне "+
						"разрешённых файлов (%s). Дальше он строка, и её ничто не мешает положить в "+
						"поле контракта, нагрузку аудита, журнал либо уведомление базы. Разрешение "+
						"даётся ФАЙЛУ с названной причиной и держится этим гейтом",
					f.rel, line(sel.Pos()), spec.Accessor, where))
				return true
			})
		}
	}

	// Правило 3: вынос материала из разрешённых файлов и имени из файла-владельца.
	allowedSet := map[string]bool{}
	for rel := range spec.AllowedFiles {
		allowedSet[rel] = true
	}
	material := lvSubject{noun: "материал", keep: allowedSet, isSource: func(_ *lvFile, e ast.Expr) bool {
		switch n := e.(type) {
		case *ast.SelectorExpr:
			return n.Sel.Name == spec.Accessor
		case *ast.CallExpr:
			return isAccessor(lvCallee(n.Fun), spec.Accessor)
		}
		return false
	}}
	name := lvSubject{noun: "имя таблицы секрета", suffix: "о", keep: map[string]bool{spec.TableOwnerRel: true},
		isSource: func(f *lvFile, e ast.Expr) bool {
			switch n := e.(type) {
			case *ast.BasicLit, *ast.BinaryExpr:
				v, ok := ix.fold(f, n)
				return ok && ix.namesTable(v)
			case *ast.Ident:
				if b := ix.resolve(f, n); b != nil {
					return b.bearing
				}
				if v := ix.localConst(n); v != nil {
					s, ok := ix.fold(f, v)
					return ok && ix.namesTable(s)
				}
			case *ast.SelectorExpr:
				if b := ix.resolveSelector(f, n); b != nil {
					return b.bearing
				}
			}
			return false
		}}
	var mUsed, nUsed map[string]int
	var mFind, nFind []string
	mFind, c.Material, mUsed = lvRunFlow(ix, files, material, spec.OpaqueConsumers)
	nFind, c.Name, nUsed = lvRunFlow(ix, files, name, spec.OpaqueConsumers)
	findings = append(append(findings, mFind...), nFind...)
	for k := range spec.OpaqueConsumers {
		c.ConsumerUses[k] = mUsed[k] + nUsed[k]
	}

	switch {
	case c.FilesRead == 0:
		return nil, c, fmt.Errorf("%w — «находок ноль» здесь означало бы «прочитано ноль»", ErrEmptyTraversal)
	case c.AccessorDecls != 1:
		return nil, c, fmt.Errorf("выход материала `%s` объявлен %d раз (%s) — премиса «один выход» "+
			"не держится, и селектор с этим именем может означать чужой метод",
			spec.Accessor, c.AccessorDecls, strings.Join(declWhere, "; "))
	case !strings.HasPrefix(declWhere[0], spec.DeclRel+" ") ||
		!strings.HasSuffix(declWhere[0], "получатель "+spec.DeclType+")"):
		return nil, c, fmt.Errorf("выход материала объявлен не там: %s, ожидалось %s на типе %s",
			declWhere[0], spec.DeclRel, spec.DeclType)
	case c.OwnerTableNamings == 0:
		total := 0
		for _, n := range c.TableNamings {
			total += n
		}
		return nil, c, fmt.Errorf("владелец таблицы %s не называет её ни разу (упоминаний по дереву %d) — "+
			"правило второго читателя ослепло, не покраснев", spec.TableOwnerRel, total)
	}
	for _, f := range lvSortedKeys(spec.AllowedFiles) {
		if c.AllowedUses[f] == 0 {
			findings = append(findings, fmt.Sprintf(
				"разрешение файлу %s («%s») без предмета: выход там не используется ни разу. "+
					"Разрешение, которому нечего разрешать, есть место, куда вызов вносят "+
					"незамеченным, — снимается вместе с предметом",
				f, spec.AllowedFiles[f]))
		}
	}
	for _, k := range lvSortedKeys(spec.OpaqueConsumers) {
		if c.ConsumerUses[k] == 0 {
			findings = append(findings, fmt.Sprintf(
				"потребитель «%s» («%s») объявлен без предмета: ни материал, ни имя таблицы этому вызову "+
					"не отданы. Объявление, которому нечего разрешать, есть место, куда вызов вносят "+
					"незамеченным, — снимается вместе с предметом",
				k, spec.OpaqueConsumers[k]))
		}
	}
	sort.Strings(findings)
	return findings, c, nil
}

func lvSortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
