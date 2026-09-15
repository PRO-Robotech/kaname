// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_verifier_containment.go — ЯДРО гейта: проверочный материал способа входа
// выходит из своего типа ТОЛЬКО в названном файле, и таблицу секрета называет
// ТОЛЬКО её адаптер (фаза Ф2, `kacho#1268`).
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
// У утечки из кода Go две СИНТАКСИЧЕСКИ УЗНАВАЕМЫЕ формы:
//
//  1. ВЫЗОВ ВЫХОДА вне разрешённого ФАЙЛА — материал достан строкой и дальше
//     ничем не защищён: его можно положить в поле контракта, в нагрузку аудита,
//     в журнал, в уведомление базы;
//  2. ВТОРОЙ ЧИТАТЕЛЬ КОЛОНКИ — оператор, называющий таблицу секрета мимо её
//     адаптера, читает материал строкой, не проходя через тип вовсе.
//
// Разрешение даётся ФАЙЛУ, а не пакету. Пакет адаптера — 70 не-тестовых
// файлов; разрешение каталогу пропускало вызов выхода в любом из них, и шапка
// владельца, называвшая себя «единственным местом», утверждала шире сделанного.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СУДИТСЯ И КАК — ВСЕ ЗАКОННЫЕ ФОРМЫ ЗАПИСИ ПРЕДМЕТА
//
// Судится РАЗБОРОМ, а не текстом: комментарий, объясняющий выход, и строка с
// его именем законны и обязаны остаться — гейт, краснеющий на собственном
// объяснении, снимают первым.
//
// Выход (правило 1) записывается ОДНОЙ синтаксической формой — селектором с его
// именем: вызов, значение метода и выражение метода. Сверх вызова вне
// разрешённого файла находкой является ВЫНОС материала из разрешённого файла
// так, что его дальнейший путь гейт не видит:
//
//   - возврат, чьё значение НЕСЁТ материал (вызов выхода, его приведение к
//     `string`/`[]byte`, склейка, составной литерал с ним). Непрозрачный вызов
//     (сверка хеша) материал не несёт — несёт его результат сверки;
//   - переменная уровня пакета, чьё значение обращается к выходу;
//   - присваивание материала переменной уровня пакета и отправка в канал.
//
// Имя таблицы (правило 2) записывается ЧЕТЫРЬМЯ формами, и распознаватель знает
// все четыре:
//
//   - ЛИТЕРАЛ, где имя стоит целым словом. Имена ограничений (`<таблица>_pkey`)
//     им не являются — «слово» здесь в смысле идентификатора SQL;
//   - СКЛЕЙКА литералов и констант: судится свёрнутое значение, а не части,
//     поэтому `"user_login_" + "methods"` — таблица, а `<таблица> + "_pkey"` —
//     имя ограничения;
//   - СВЯЗАННОЕ ИМЯ: константа или переменная уровня пакета, чьё значение
//     называет таблицу (замыкание по цепочке имён — неподвижная точка). Сама
//     константа владельца — такое имя, и её использование в соседнем файле того
//     же пакета есть второй читатель;
//   - СЕЛЕКТОР ДРУГОГО ПАКЕТА на такое имя.
//
// Сверх форм имени — ВЫНОС имени владельцем: функция файла-владельца,
// возвращающая строку, в которой названа таблица. Её вызывающие гейту не видны.
// Предикат владельца, возвращающий `bool` («это наша таблица?»), имени не
// выносит — именно им переводчик отказов сверяет таблицу отказа.
//
// Объявление предмета (имя выхода, файл и тип, где он объявлен, имя таблицы,
// разрешённые файлы) приходит ПАРАМЕТРОМ из файла пробы. Причина — не вкус:
// литерал имени таблицы в этом файле сделал бы гейт своей же первой находкой,
// а файл пробы в корпус не входит by construction.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕМИСЫ — ОТКАЗ, А НЕ МОЛЧАНИЕ
//
//   - выход объявлен РОВНО ОДИН раз, в названном файле, на названном типе.
//     Иначе селектор с тем же именем означает не этот выход, и перепись мерит
//     чужой метод;
//   - файл-владелец таблицы называет её хоть раз: иначе второе правило ослепло;
//   - каждый разрешённый файл выход ИСПОЛЬЗУЕТ: разрешение без предмета —
//     место, куда вызов вносят незамеченным (послабление обязано истекать само).
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
//  1. ФАЙЛЫ ПРОБ НЕ СУДЯТСЯ: пробе законно достать материал, чтобы сверить его
//     побайтово, а фикстуре инъекции — написать форму дефекта.
//  2. ИМЯ, СОБРАННОЕ ВО ВРЕМЯ ИСПОЛНЕНИЯ, НЕ УЗНАЁТСЯ: `fmt.Sprintf`,
//     `strings.Join`, срез байтов — это поток данных, а не синтаксис. В дереве
//     такой формы нет; появится — гейт промолчит, и это его граница.
//  3. ПОТОК МАТЕРИАЛА ВНУТРИ РАЗРЕШЁННОГО ФАЙЛА НЕ ПРОСЛЕЖИВАЕТСЯ дальше
//     названных выносов: поле структуры, замыкание, указатель — тоже поток
//     данных. Разрешённый файл один, и его держит ревью.
//  4. ОТРАЖЕНИЕ НЕ УЗНАЁТСЯ: доступ к неэкспортированному полю через `reflect`
//     либо `unsafe` синтаксического следа выхода не оставляет.
//  5. ПУТЬ ВНЕ ГО НЕ СУДИТСЯ: базу судит соседний гейт схемы
//     `internal/repo/kaname/pg` `TestLoginVerifierStaysInsideTheSchema`.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"regexp"
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
	return fmt.Sprintf("перепись: не-тестовых файлов Go прочитано %d (разобрано %d) · объявлений выхода %d · "+
		"обращений к выходу %d, из них в разрешённых файлах [%s] · упоминаний таблицы %d (%s), "+
		"из них у владельца %d · связанных имён, несущих таблицу, %d %v",
		c.FilesRead, c.FilesParsed, c.AccessorDecls, c.AccessorUses, strings.Join(allowed, " "),
		total, strings.Join(forms, ", "), c.OwnerTableNamings, len(c.Bindings), c.Bindings)
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

// lvIndex — связанные имена по каталогу пакета и имена пакетов по каталогу.
type lvIndex struct {
	tableWord *regexp.Regexp
	bindings  map[string]map[string]*lvBinding
	pkgNames  map[string]string
	dirs      []string
}

// resolve — связанное имя, на которое указывает идентификатор, либо nil.
//
// Идентификатор, разрешённый разбором внутри файла, указывает на своё
// объявление; указывает на иное (локальная переменная с тем же именем) —
// связанного имени нет. Неразрешённый — имя уровня пакета из соседнего файла.
func (ix *lvIndex) resolve(f *lvFile, id *ast.Ident) *lvBinding {
	b := ix.bindings[f.dir][id.Name]
	if b == nil {
		return nil
	}
	if id.Obj != nil {
		if spec, ok := id.Obj.Decl.(*ast.ValueSpec); ok && spec == b.spec {
			return b
		}
		return nil
	}
	return b
}

// resolveSelector — связанное имя другого пакета под селектором `пакет.Имя`.
func (ix *lvIndex) resolveSelector(f *lvFile, sel *ast.SelectorExpr) *lvBinding {
	x, ok := sel.X.(*ast.Ident)
	if !ok || x.Obj != nil {
		return nil
	}
	for _, imp := range f.file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		for _, dir := range ix.dirs {
			if p != dir && !strings.HasSuffix(p, "/"+dir) {
				continue
			}
			local := ix.pkgNames[dir]
			if imp.Name != nil {
				local = imp.Name.Name
			}
			if local == x.Name {
				return ix.bindings[dir][sel.Sel.Name]
			}
		}
	}
	return nil
}

// fold — свёрнутое значение строкового выражения из литералов и связанных имён.
func (ix *lvIndex) fold(f *lvFile, e ast.Expr) (string, bool) {
	switch n := e.(type) {
	case *ast.BasicLit:
		if n.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(n.Value)
		return v, err == nil
	case *ast.ParenExpr:
		return ix.fold(f, n.X)
	case *ast.BinaryExpr:
		if n.Op != token.ADD {
			return "", false
		}
		l, lok := ix.fold(f, n.X)
		r, rok := ix.fold(f, n.Y)
		return l + r, lok && rok
	case *ast.Ident:
		if b := ix.resolve(f, n); b != nil && b.foldable {
			return b.folded, true
		}
	case *ast.SelectorExpr:
		if b := ix.resolveSelector(f, n); b != nil && b.foldable {
			return b.folded, true
		}
	}
	return "", false
}

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
			if ix.tableWord.MatchString(v) {
				form := formSplice
				if _, lit := e.(*ast.BasicLit); lit {
					form = formLiteral
				}
				out = append(out, lvNaming{pos: expr.Pos(), form: form})
			}
			return false
		case *ast.Ident:
			if b := ix.resolve(f, e); b != nil && b.bearing {
				out = append(out, lvNaming{pos: e.Pos(), form: formBinding, via: b.file.dir + "." + b.name})
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

// carriesMaterial — значение выражения несёт материал: сам выход, его
// приведение к строке либо срезу байтов, склейка, составной литерал с ним.
// Непрозрачный вызов не несёт: несёт его результат, а не аргумент.
func carriesMaterial(e ast.Expr, accessor string) bool {
	switch n := e.(type) {
	case *ast.SelectorExpr:
		return n.Sel.Name == accessor
	case *ast.CallExpr:
		if isAccessor(n.Fun, accessor) {
			return true
		}
		if isConversion(n.Fun) && len(n.Args) == 1 {
			return carriesMaterial(n.Args[0], accessor)
		}
		return false
	case *ast.ParenExpr:
		return carriesMaterial(n.X, accessor)
	case *ast.BinaryExpr:
		return n.Op == token.ADD && (carriesMaterial(n.X, accessor) || carriesMaterial(n.Y, accessor))
	case *ast.UnaryExpr:
		return n.Op == token.AND && carriesMaterial(n.X, accessor)
	case *ast.CompositeLit:
		for _, el := range n.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				el = kv.Value
			}
			if carriesMaterial(el, accessor) {
				return true
			}
		}
	}
	return false
}

// isConversion — приведение к строке либо к срезу байтов.
func isConversion(fun ast.Expr) bool {
	switch t := fun.(type) {
	case *ast.Ident:
		return t.Name == "string"
	case *ast.ArrayType:
		id, ok := t.Elt.(*ast.Ident)
		return ok && t.Len == nil && (id.Name == "byte" || id.Name == "rune")
	case *ast.ParenExpr:
		return isConversion(t.X)
	}
	return false
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

// returnsString — среди результатов функции есть строка (в любом составе).
func returnsString(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	found := false
	for _, r := range fn.Type.Results.List {
		ast.Inspect(r.Type, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "string" {
				found = true
			}
			return !found
		})
	}
	return found
}

// AuditLoginVerifierContainment — находки и перепись по корпусу не-тестовых
// файлов. Корпус и объявление приходят ПАРАМЕТРАМИ: инъекция обязана подать
// разбору синтетику, а не это дерево.
func AuditLoginVerifierContainment(corpus TreeCorpus, spec LoginVerifierSpec) ([]string, LoginVerifierCensus, error) {
	c := LoginVerifierCensus{AllowedUses: map[string]int{}, TableNamings: map[string]int{}}
	for f := range spec.AllowedFiles {
		c.AllowedUses[f] = 0
	}
	if spec.Accessor == "" || spec.Table == "" || spec.DeclRel == "" || spec.DeclType == "" || spec.TableOwnerRel == "" {
		return nil, c, fmt.Errorf("объявление предмета неполно (%+v) — судить нечего", spec)
	}
	tableWord, err := regexp.Compile(`(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(spec.Table) + `($|[^A-Za-z0-9_])`)
	if err != nil {
		return nil, c, fmt.Errorf("имя таблицы %q не образует предиката: %w", spec.Table, err)
	}

	// Проход первый: разбор и связанные имена по каталогу пакета.
	ix := &lvIndex{tableWord: tableWord, bindings: map[string]map[string]*lvBinding{}, pkgNames: map[string]string{}}
	var files []*lvFile
	for _, rel := range corpus.Rels() {
		c.FilesRead++
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, rel, corpus[rel], parser.ParseComments)
		if perr != nil {
			return nil, c, fmt.Errorf("разбор %s: %w — гейт не вправе судить файл, которого он не разобрал", rel, perr)
		}
		c.FilesParsed++
		f := &lvFile{rel: rel, dir: path.Dir(rel), fset: fset, file: file}
		files = append(files, f)
		if _, seen := ix.pkgNames[f.dir]; !seen {
			ix.pkgNames[f.dir] = file.Name.Name
			ix.dirs = append(ix.dirs, f.dir)
			ix.bindings[f.dir] = map[string]*lvBinding{}
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, name := range vs.Names {
					// Имя без значения тоже записывается: присваивание материала
					// переменной пакета судится по имени, а не по инициализатору.
					var value ast.Expr
					if i < len(vs.Values) {
						value = vs.Values[i]
					}
					if name.Name == "_" {
						continue
					}
					ix.bindings[f.dir][name.Name] = &lvBinding{name: name.Name, spec: vs, value: value, file: f}
				}
			}
		}
	}
	sort.Strings(ix.dirs)

	// Неподвижная точка: свёртка и «несёт имя таблицы» у каждого связанного имени.
	// Сведения только прибывают (ложь → истина), поэтому точка достигается; предел
	// прохода — страж от разбора, который Go не собрал бы (цикл инициализации).
	for changed, pass := true, 0; changed; pass++ {
		if pass > 1000 {
			return nil, c, fmt.Errorf("свёртка связанных имён не сошлась за %d проходов — цикл инициализации?", pass)
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
	for _, dir := range ix.dirs {
		for _, b := range ix.bindings[dir] {
			if b.bearing {
				c.Bindings = append(c.Bindings, dir+"."+b.name)
			}
		}
	}
	sort.Strings(c.Bindings)

	// Проход второй: находки.
	var findings []string
	var declWhere []string
	for _, f := range files {
		line := func(p token.Pos) int { return f.fset.Position(p).Line }
		_, allowed := spec.AllowedFiles[f.rel]

		for _, decl := range f.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Recv != nil && fn.Name.Name == spec.Accessor {
				c.AccessorDecls++
				// Разбор получателя — общий с соседним гейтом (`provider_road_wire_guard.go`):
				// вторая копия одного разбора разошлась бы с первой молча.
				recvType, _ := receiverTypeName(fn)
				declWhere = append(declWhere, fmt.Sprintf("%s (получатель %s)", f.rel, recvType))
			}
			if f.rel == spec.TableOwnerRel && fn.Body != nil && returnsString(fn) {
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					ret, ok := n.(*ast.ReturnStmt)
					if !ok {
						return true
					}
					for _, r := range ret.Results {
						if len(ix.namings(f, r)) > 0 {
							findings = append(findings, fmt.Sprintf(
								"%s:%d: владелец отдаёт имя таблицы секрета `%s` наружу функцией `%s` — её "+
									"вызывающие называют таблицу мимо адаптера, и второе правило гейта их не видит",
								f.rel, line(ret.Pos()), spec.Table, fn.Name.Name))
							return false
						}
					}
					return true
				})
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

		// Выход: обращение вне разрешённого файла; вынос из разрешённого.
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
				switch node := n.(type) {
				case *ast.SelectorExpr:
					if node.Sel.Name != spec.Accessor {
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
						f.rel, line(node.Pos()), spec.Accessor, where))
				case *ast.ReturnStmt:
					if !allowed {
						return true
					}
					for _, r := range node.Results {
						if carriesMaterial(r, spec.Accessor) {
							findings = append(findings, fmt.Sprintf(
								"%s:%d: возврат выносит материал из разрешённого файла (%s) — вызывающие "+
									"получают строку мимо гейта", f.rel, line(node.Pos()), where))
							break
						}
					}
				case *ast.AssignStmt:
					if !allowed {
						return true
					}
					for i, lhs := range node.Lhs {
						id, ok := lhs.(*ast.Ident)
						if !ok || i >= len(node.Rhs) || ix.resolve(f, id) == nil {
							continue
						}
						if carriesMaterial(node.Rhs[i], spec.Accessor) {
							findings = append(findings, fmt.Sprintf(
								"%s:%d: материал присвоен переменной пакета `%s` (%s) — её читатели "+
									"получают его мимо разрешённого файла", f.rel, line(node.Pos()), id.Name, where))
						}
					}
				case *ast.SendStmt:
					if allowed && carriesMaterial(node.Value, spec.Accessor) {
						findings = append(findings, fmt.Sprintf(
							"%s:%d: материал отправлен в канал (%s) — получатель берёт его мимо "+
								"разрешённого файла", f.rel, line(node.Pos()), where))
					}
				}
				return true
			})
		}
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
	files2 := make([]string, 0, len(spec.AllowedFiles))
	for f := range spec.AllowedFiles {
		files2 = append(files2, f)
	}
	sort.Strings(files2)
	for _, f := range files2 {
		if c.AllowedUses[f] == 0 {
			findings = append(findings, fmt.Sprintf(
				"разрешение файлу %s («%s») без предмета: выход там не используется ни разу. "+
					"Разрешение, которому нечего разрешать, есть место, куда вызов вносят "+
					"незамеченным, — снимается вместе с предметом",
				f, spec.AllowedFiles[f]))
		}
	}
	sort.Strings(findings)
	return findings, c, nil
}
