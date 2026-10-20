// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// binding_subject_pair.go — гейт на доступ к ОДИНОЧНОЙ паре субъекта выдачи
// вне закрытого перечня мест (kaname#917).
//
// # Предмет
//
// Выдача несёт полный перечень субъектов (`AccessBinding.Subjects`, таблица
// `access_binding_subjects`), а прежняя пара `SubjectType`/`SubjectID`
// (колонки `subject_type`/`subject_id` строки `access_bindings`) осталась
// проекцией первой строки набора и якорем уникальности действующей выдачи.
// Чтение, смотрящее только пару, у выдачи нескольким субъектам видит одного
// из них: так материализатор и снятие разворачивали выдачу первому субъекту
// (kaname#880), а чтения по субъекту не находили выдачу второго (kaname#888).
// Поведение исправлено, но новое чтение пары ничто не останавливало — этот
// гейт и есть остановка.
//
// # Единица — место, а не строка
//
// Место — функция (метод с именем получателя; пакетный уровень — своим
// именем), в которой стоит доступ. Ведомость `BindingSubjectPairLedger`
// называет каждое законное место, ТОЧНОЕ число доступов в нём и основание.
// Новое место — находка с координатой файла и строки; изменившееся число в
// перечисленном месте — тоже находка: иначе перечисленная функция пропускала
// бы любое новое чтение. Запись ведомости без доступа — находка: исключение,
// которому нечего исключать, истекает само.
//
// # Две оси узнавания
//
// Go — по ТИПАМ, а не по написанию: доступ — это селектор, который проверка
// типов разрешила в поле `SubjectType`/`SubjectID` структуры
// `domain.AccessBinding`, либо ключ составного литерала этой структуры.
// Одноимённые поля фильтра страницы, события смены субъекта, гранта
// администратора кластера — другие объекты и в счёт не идут.
//
// SQL — по строковым литералам Go, без учёта регистра: упоминание колонки
// `subject_type`/`subject_id` считается обращением к ПАРЕ, когда его
// квалификатор связан с `access_bindings` (псевдоним ищется в литерале, затем
// в литералах того же места, затем в пакете — если там он однозначен); когда
// квалификатора нет, а ближайшая по скобкам область, где названа таблица,
// называет `access_bindings` либо таблиц в литерале нет вовсе (фрагмент
// условия чужого запроса); и когда квалификатор не разрешён (глагол формата
// `%[1]s.`, неизвестный псевдоним). Перечень FROM через запятую
// (`FROM a x, access_bindings y`) разбирается целиком. Имя CTE (`WITH live AS (…)`) и производной
// таблицы (`FROM (…) d`) разрешается в таблицы верхнего уровня своего тела:
// тело над `access_bindings` делает имя таблицей пары, тело без таблицы —
// неразрешённым. Неразрешённое считается парой намеренно: ошибка в эту сторону
// стоит строки ведомости, в обратную — пропущенного чтения.
//
// # Радиус
//
// Каждый пакет каталогов `BindingPairDirs` (домен выдачи, её use-case и слой
// репозитория) независимо от того, какой бинарь его линкует, а файлы — по
// ограничениям ПРОД-сборки (binding_subject_pair_load.go). Непроверочный файл
// радиуса вне прод-сборки — находка, пока его нет в ведомости
// `BindingPairOutsideBuildLedger`.
//
// # Граница названа, а не умолчана
//
// Гейт НЕ видит: имени колонки, собранного из кусков (конкатенация, формат);
// таблицы в кавычках (`"access_bindings"`); выборки `SELECT *` и колонок,
// названных не по имени (`RETURNING *`, `row_to_json`), — колонки пары в
// литерале нет; доступа через рефлексию и через копию в другой тип; кода вне
// каталогов радиуса. SQL-комментарий снимается от `--` до конца строки и
// внутри строки SQL `'…--…'` тоже — колонка за ним в той строке не судится.
// Замена одного доступа другим при том же числе внутри места из ведомости не
// видна: ведомость судит число и наличие ветви набора, а не какую ветвь.

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// BindingPairDomainPkg — пакет, объявляющий выдачу.
const BindingPairDomainPkg = "/internal/domain"

// BindingPairType — тип выдачи.
const BindingPairType = "AccessBinding"

// BindingPairFields — поля одиночной пары.
var BindingPairFields = []string{"SubjectType", "SubjectID"}

// BindingPairTable — таблица, колонки пары которой судит SQL-ось.
const BindingPairTable = "access_bindings"

// BindingPairSetTable — таблица набора субъектов.
const BindingPairSetTable = "access_binding_subjects"

// BindingPairSubjectType — тип члена набора.
const BindingPairSubjectType = "Subject"

// BindingPairColumns — колонки пары.
var BindingPairColumns = []string{"subject_type", "subject_id"}

// BindingPairDirs — каталоги радиуса относительно корня модуля. Домен —
// в радиусе: метод выдачи, читающий пару, иначе выносил бы чтение из-под гейта
// одним вызовом.
var BindingPairDirs = []string{
	"internal/domain",
	"internal/apps/kaname/api/access_binding",
	"internal/repo/kaname/pg",
}

// Формы доступа.
const (
	BindingPairFormSelector = "селектор поля"
	BindingPairFormLiteral  = "ключ составного литерала"
	BindingPairFormSQL      = "колонка в SQL"
)

// BindingPairClass — закрытый словарь оснований записи ведомости.
type BindingPairClass string

const (
	// BindingPairProjection — запись проекции: пара выводится из набора при
	// нормализации либо переносится между полем и колонкой строки.
	BindingPairProjection BindingPairClass = "запись проекции"
	// BindingPairFallback — откат к прежней форме: строка, у которой набор не
	// прочитан или пуст, читается по паре; рядом обязан стоять разбор набора.
	BindingPairFallback BindingPairClass = "откат к прежней форме"
	// BindingPairUniqueAnchor — якорь уникальности действующей выдачи: частный
	// UNIQUE базы стоит на паре, и текст отказа называет то, на чём он стоит.
	BindingPairUniqueAnchor BindingPairClass = "якорь уникальности"
	// BindingPairLegacyInput — прежняя форма запроса: пара пришла от клиента и
	// становится входом нормализации набора.
	BindingPairLegacyInput BindingPairClass = "прежняя форма запроса"
)

// BindingPairClasses — словарь целиком; основание вне него — находка.
var BindingPairClasses = []BindingPairClass{
	BindingPairProjection, BindingPairFallback, BindingPairUniqueAnchor, BindingPairLegacyInput,
}

// BindingPairEntry — законное место: точное число доступов и основание.
type BindingPairEntry struct {
	// Go — доступов к полям пары (селектор и ключ литерала).
	Go int
	// SQL — обращений к колонкам пары в литералах.
	SQL int
	// Class — основание из закрытого словаря.
	Class BindingPairClass
	// Why — почему место читает пару, а не набор.
	Why string
}

// BindingPairAccess — один найденный доступ.
type BindingPairAccess struct {
	Place string
	Pos   string
	Form  string
	What  string
}

// BindingPairCensus — исход обхода радиуса.
type BindingPairCensus struct {
	Packages int
	Files    int
	Lines    int
	// Literals — строковых литералов с признаком SQL, прочитанных SQL-осью.
	Literals int
	// SetRefs — упоминаний колонок, разрешённых в набор либо чужую таблицу.
	SetRefs int
	// OutsideBuild — непроверочные файлы радиуса по дереву, не попавшие в
	// прод-сборку (ограничения сборки).
	OutsideBuild []string
	Accesses     []BindingPairAccess
	// SetEvidence — места, где читается и набор: значение типа Subject либо
	// []Subject (Go) или таблица набора в литерале места (SQL).
	SetEvidence map[string]bool
}

// Summary — перепись одной строкой.
func (c BindingPairCensus) Summary() string {
	goN, sqlN := 0, 0
	for _, a := range c.Accesses {
		if a.Form == BindingPairFormSQL {
			sqlN++
		} else {
			goN++
		}
	}
	return fmt.Sprintf("пакетов %d · файлов %d · строк %d · литералов SQL %d · доступов к паре: Go %d, SQL %d · "+
		"колонок набора и чужих таблиц %d · мест %d · файлов радиуса вне прод-сборки %d %v",
		c.Packages, c.Files, c.Lines, c.Literals, goN, sqlN, c.SetRefs, len(c.Places()), len(c.OutsideBuild), c.OutsideBuild)
}

// Places — доступы, сгруппированные по месту.
func (c BindingPairCensus) Places() map[string][]BindingPairAccess {
	out := map[string][]BindingPairAccess{}
	for _, a := range c.Accesses {
		out[a.Place] = append(out[a.Place], a)
	}
	return out
}

// BindingPairSpec — что судится.
type BindingPairSpec struct {
	ModuleRoot string
	// Dirs — каталоги радиуса; пусто — BindingPairDirs.
	Dirs []string
	// Overlay — путь импорта → каталог копии пакета (инъекции).
	Overlay map[string]string
	// OnDisk — непроверочные файлы радиуса по дереву (относительно корня
	// модуля): всё, что в прод-сборку не попало, судится ведомостью.
	OnDisk []string
}

// CollectBindingSubjectPair обходит радиус и собирает доступы к паре.
// Ошибка — гейт НЕ ИСПОЛНИЛСЯ: радиус не собран, предмет гейта снят либо
// обход пуст. Это не зелёное и не находка.
func CollectBindingSubjectPair(ctx context.Context, spec BindingPairSpec) (BindingPairCensus, error) {
	dirs := spec.Dirs
	if len(dirs) == 0 {
		dirs = BindingPairDirs
	}
	l, err := bindingPairListingFor(ctx, spec.ModuleRoot, dirs)
	if err != nil {
		return BindingPairCensus{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	prog, err := l.program(spec.Overlay)
	if err != nil {
		return BindingPairCensus{}, err
	}

	domainPkg := prog.byPath[l.modulePath+BindingPairDomainPkg]
	if domainPkg == nil || domainPkg.types == nil {
		return BindingPairCensus{}, fmt.Errorf("предмет гейта снят: пакета %s нет в разборе радиуса %v", BindingPairDomainPkg, dirs)
	}
	fields, err := bindingPairFieldObjects(domainPkg.types)
	if err != nil {
		return BindingPairCensus{}, err
	}

	subjectObj := domainPkg.types.Scope().Lookup(BindingPairSubjectType)
	if subjectObj == nil {
		return BindingPairCensus{}, fmt.Errorf("предмет гейта снят: типа %s.%s нет — набору субъектов нечем быть",
			BindingPairDomainPkg, BindingPairSubjectType)
	}

	var census BindingPairCensus
	seen := map[string]bool{}
	for _, sp := range prog.pkgs {
		display := l.displayDir(sp.path)
		if !inBindingPairRadius(display, dirs) {
			continue
		}
		census.Packages++
		pp := &bindingPairPkg{fset: prog.fset, c: &census}
		for _, f := range sp.files {
			name := prog.fset.Position(f.Pos()).Filename
			seen[name] = true
			census.Files++
			census.Lines += prog.fset.File(f.Pos()).LineCount()
			pp.collectFile(f, sp.info, fields, subjectObj.Type())
		}
		pp.resolve()
	}
	for _, rel := range spec.OnDisk {
		if inBindingPairRadius(pathDir(rel), dirs) && !seen[rel] {
			census.OutsideBuild = append(census.OutsideBuild, rel)
		}
	}
	sort.Strings(census.OutsideBuild)
	if census.Files == 0 {
		return census, fmt.Errorf("обход пуст: в радиусе %v ни одного файла прод-сборки в %s — «ноль находок» здесь "+
			"означало бы «ноль прочитанного»", dirs, spec.ModuleRoot)
	}
	return census, nil
}

// pathDir — каталог относительного пути с прямыми разделителями.
func pathDir(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i]
	}
	return "."
}

// inBindingPairRadius — каталог пакета внутри радиуса.
func inBindingPairRadius(dir string, dirs []string) bool {
	for _, d := range dirs {
		if dir == d || strings.HasPrefix(dir, d+"/") {
			return true
		}
	}
	return false
}

// bindingPairFieldObjects — объекты полей пары в типе выдачи.
func bindingPairFieldObjects(pkg *types.Package) (map[types.Object]string, error) {
	obj := pkg.Scope().Lookup(BindingPairType)
	if obj == nil {
		return nil, fmt.Errorf("предмет гейта снят: типа %s.%s нет — снять гейт вместе с ним", pkg.Path(), BindingPairType)
	}
	st, ok := obj.Type().Underlying().(*types.Struct)
	if !ok {
		return nil, fmt.Errorf("предмет гейта снят: %s.%s — не структура", pkg.Path(), BindingPairType)
	}
	out := map[types.Object]string{}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		for _, want := range BindingPairFields {
			if f.Name() == want {
				out[f] = want
			}
		}
	}
	if len(out) != len(BindingPairFields) {
		return nil, fmt.Errorf("предмет гейта снят: у %s найдено %d полей пары из %d %v — снять гейт вместе с парой",
			BindingPairType, len(out), len(BindingPairFields), BindingPairFields)
	}
	return out, nil
}

// bindingPairSpan — тело места.
type bindingPairSpan struct {
	from, to token.Pos
	name     string
}

// placeOf — место позиции: функция либо пакетный уровень.
func placeOf(spans []bindingPairSpan, file string, pos token.Pos) string {
	for _, s := range spans {
		if pos >= s.from && pos < s.to {
			return file + "::" + s.name
		}
	}
	return file + "::<пакетный уровень>"
}

// bindingPairLit — строковый литерал с признаком SQL и его место.
type bindingPairLit struct {
	pos   token.Pos
	place string
	sql   string
}

// bindingPairPkg — разбор одного пакета: доступы Go и литералы SQL, которые
// разрешаются после обхода всех файлов (псевдоним таблицы бывает объявлен в
// литерале другой функции того же пакета).
type bindingPairPkg struct {
	fset  *token.FileSet
	c     *BindingPairCensus
	lits  []bindingPairLit
	spans map[string][]bindingPairSpan
}

// collectFile — доступы Go одного файла и его литералы SQL.
func (pp *bindingPairPkg) collectFile(f *ast.File, info *types.Info, fields map[types.Object]string, subjectT types.Type) {
	fset, c := pp.fset, pp.c
	file := fset.Position(f.Pos()).Filename
	var spans []bindingPairSpan
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			name := d.Name.Name
			if d.Recv != nil && len(d.Recv.List) > 0 {
				name = roleProjectionTypeName(bindingPairRecv(d.Recv.List[0].Type)) + "." + name
			}
			spans = append(spans, bindingPairSpan{from: d.Pos(), to: d.End(), name: name})
		case *ast.GenDecl:
			// Пакетная константа или переменная — место своим именем: перечень
			// колонок и предикат, лежащие рядом, — разные места.
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				names := make([]string, len(vs.Names))
				for i, n := range vs.Names {
					names[i] = n.Name
				}
				spans = append(spans, bindingPairSpan{from: vs.Pos(), to: vs.End(),
					name: d.Tok.String() + " " + strings.Join(names, ", ")})
			}
		}
	}
	add := func(pos token.Pos, form, what string) {
		p := fset.Position(pos)
		c.Accesses = append(c.Accesses, BindingPairAccess{
			Place: placeOf(spans, file, pos),
			Pos:   fmt.Sprintf("%s:%d", p.Filename, p.Line),
			Form:  form,
			What:  what,
		})
	}
	subjectsT := types.NewSlice(subjectT)

	tags := map[*ast.BasicLit]bool{}
	var lits []*ast.BasicLit
	ast.Inspect(f, func(n ast.Node) bool {
		if e, ok := n.(ast.Expr); ok {
			if tv, ok := info.Types[e]; ok && tv.Type != nil &&
				(types.Identical(tv.Type, subjectT) || types.Identical(tv.Type, subjectsT)) {
				c.markSet(placeOf(spans, file, e.Pos()))
			}
		}
		switch x := n.(type) {
		case *ast.Field:
			if x.Tag != nil {
				tags[x.Tag] = true
			}
		case *ast.SelectorExpr:
			if sel := info.Selections[x]; sel != nil && sel.Kind() == types.FieldVal {
				if name, ok := fields[sel.Obj()]; ok {
					add(x.Sel.Pos(), BindingPairFormSelector, "."+name)
				}
			}
		case *ast.KeyValueExpr:
			if id, ok := x.Key.(*ast.Ident); ok {
				if name, ok := fields[info.Uses[id]]; ok {
					add(id.Pos(), BindingPairFormLiteral, name+":")
				}
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				lits = append(lits, x)
			}
		}
		return true
	})
	if pp.spans == nil {
		pp.spans = map[string][]bindingPairSpan{}
	}
	pp.spans[file] = spans

	for _, lit := range lits {
		if tags[lit] {
			continue
		}
		text, err := strconv.Unquote(lit.Value)
		if err != nil {
			continue
		}
		text = asciiLower(stripSQLComments(text))
		if !sqlMarker.MatchString(text) {
			continue
		}
		c.Literals++
		pp.lits = append(pp.lits, bindingPairLit{pos: lit.Pos(), place: placeOf(spans, file, lit.Pos()), sql: text})
	}
}

// resolve — колонки пары в литералах пакета: псевдоним ищется в самом
// литерале, затем в литералах того же места, затем в пакете (только если по
// пакету он называет одну таблицу).
func (pp *bindingPairPkg) resolve() {
	c := pp.c
	byPlace := map[string]map[string]string{}
	byPkg := map[string]map[string]bool{}
	infos := make([]sqlInfo, len(pp.lits))
	for i, l := range pp.lits {
		infos[i] = sqlAnalyze(l.sql)
		if byPlace[l.place] == nil {
			byPlace[l.place] = map[string]string{}
		}
		for alias, table := range infos[i].aliases {
			byPlace[l.place][alias] = table
			if byPkg[alias] == nil {
				byPkg[alias] = map[string]bool{}
			}
			byPkg[alias][table] = true
			if table == BindingPairSetTable {
				c.markSet(l.place)
			}
		}
	}
	pkgAliases := map[string]string{}
	for alias, tables := range byPkg {
		if len(tables) == 1 {
			for t := range tables {
				pkgAliases[alias] = t
			}
		}
	}
	for i, l := range pp.lits {
		for _, r := range bindingPairColRefs(l.sql) {
			if bindingPairRefIsPair(r, infos[i], byPlace[l.place], pkgAliases) {
				p := pp.fset.Position(l.pos)
				c.Accesses = append(c.Accesses, BindingPairAccess{
					Place: l.place,
					Pos:   fmt.Sprintf("%s:%d", p.Filename, p.Line),
					Form:  BindingPairFormSQL,
					What:  r.String(),
				})
			} else {
				c.SetRefs++
			}
		}
	}
}

// markSet — в месте читается набор субъектов.
func (c *BindingPairCensus) markSet(place string) {
	if c.SetEvidence == nil {
		c.SetEvidence = map[string]bool{}
	}
	c.SetEvidence[place] = true
}

// bindingPairRecv — тип получателя без параметров типа.
func bindingPairRecv(expr ast.Expr) ast.Expr {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return &ast.StarExpr{X: bindingPairRecv(t.X)}
	case *ast.IndexExpr:
		return t.X
	case *ast.IndexListExpr:
		return t.X
	default:
		return expr
	}
}

// sqlMarker — признак SQL в литерале: ключевое слово оператора, сравнение
// либо перечень через запятую (список колонок без ключевого слова — тоже SQL).
// Союзы и предлоги (`and`, `or`, `on`, `as`) признаком не служат: ими полон
// текст ошибки, называющий колонку («subject_id %q on a non-system …»).
var sqlMarker = regexp.MustCompile(`(?i)\b(select|insert|update|delete|where|from|join|values|returning|coalesce|exists|any|between|order\s+by|group\s+by|is\s+(?:not\s+)?null|in\s*\()|[=<>,]`)

// sqlTableRe — таблица после FROM/JOIN/INTO/UPDATE/USING и её псевдоним.
var sqlTableRe = regexp.MustCompile(`(?i)\b(?:from|join|into|update|using)\s+(?:only\s+)?(?:kaname\.)?([a-z_][a-z0-9_]*)(?:\s+(?:as\s+)?([a-z_][a-z0-9_]*))?`)

// sqlCommaTableRe — следующая таблица перечня FROM через запятую (в начале
// остатка литерала) и её псевдоним.
var sqlCommaTableRe = regexp.MustCompile(`^\s*,\s*(?:only\s+)?(?:kaname\.)?([a-z_][a-z0-9_]*)(?:\s+(?:as\s+)?([a-z_][a-z0-9_]*))?`)

// sqlNotAlias — слова, которые за таблицей стоят, но псевдонимом не являются.
var sqlNotAlias = map[string]bool{
	"where": true, "on": true, "set": true, "using": true, "join": true, "left": true, "right": true,
	"inner": true, "outer": true, "full": true, "cross": true, "natural": true, "order": true,
	"group": true, "limit": true, "offset": true, "values": true, "returning": true, "for": true,
	"union": true, "except": true, "intersect": true, "having": true, "window": true, "default": true,
	"select": true, "lateral": true, "and": true, "or": true, "as": true, "do": true, "conflict": true,
	"with": true, "into": true, "from": true, "fetch": true, "tablesample": true, "only": true,
}

// sqlUnresolved — значение имени, таблицу которого разбор не установил (тело
// CTE либо подзапроса без названной таблицы): обращение через него — пара.
const sqlUnresolved = "<не разрешено>"

// sqlInfo — разбор одного литерала: скобки, таблицы по скобкам, псевдонимы.
type sqlInfo struct {
	groups []int
	// byGroup — начало скобки (-1 — верхний уровень) → таблицы, названные
	// прямо в ней (CTE и производные — уже разрешёнными).
	byGroup map[int][]string
	// aliases — псевдоним, имя таблицы, имя CTE и производной → таблица.
	aliases map[string]string
}

// sqlCTERe — имя CTE: `WITH [RECURSIVE] name AS [NOT] [MATERIALIZED] (` либо
// следующее через запятую.
var sqlCTERe = regexp.MustCompile(`(?:\bwith\s+(?:recursive\s+)?|,\s*)([a-z_][a-z0-9_]*)\s+as\s+(?:not\s+)?(?:materialized\s+)?\(`)

// sqlDerivedRe — производная таблица: `FROM|JOIN [LATERAL] (`.
var sqlDerivedRe = regexp.MustCompile(`\b(?:from|join)\s+(?:lateral\s+)?\(`)

// sqlAfterParenAliasRe — псевдоним сразу за закрывающей скобкой подзапроса.
var sqlAfterParenAliasRe = regexp.MustCompile(`^\s+(?:as\s+)?([a-z_][a-z0-9_]*)`)

// sqlAnalyze разбирает литерал (уже в нижнем регистре, без комментариев).
func sqlAnalyze(s string) sqlInfo {
	info := sqlInfo{groups: sqlGroups(s), byGroup: map[int][]string{}, aliases: map[string]string{}}
	closeOf := sqlCloseParens(s)

	type named struct {
		name  string
		open  int // скобка тела
		owner int // скобка, где имя видно колонкам без квалификатора
	}
	var derived []named
	for _, m := range sqlCTERe.FindAllStringSubmatchIndex(s, -1) {
		derived = append(derived, named{name: s[m[2]:m[3]], open: m[1] - 1, owner: -2})
	}
	for _, m := range sqlDerivedRe.FindAllStringIndex(s, -1) {
		open := m[1] - 1
		end, ok := closeOf[open]
		if !ok {
			continue
		}
		am := sqlAfterParenAliasRe.FindStringSubmatch(s[end+1:])
		if am == nil || sqlNotAlias[am[1]] {
			continue
		}
		derived = append(derived, named{name: am[1], open: open, owner: info.groups[open]})
	}

	// Таблицы, названные прямо в каждой скобке.
	direct := map[int][]string{}
	for _, m := range sqlTableRe.FindAllStringSubmatchIndex(s, -1) {
		table := s[m[2]:m[3]]
		if sqlNotAlias[table] {
			continue
		}
		g := info.groups[m[0]]
		direct[g] = append(direct[g], table)
		info.aliases[table] = table
		end := m[3]
		if m[4] >= 0 {
			if alias := s[m[4]:m[5]]; !sqlNotAlias[alias] {
				info.aliases[alias] = table
				end = m[5]
			}
		}
		// Перечень таблиц через запятую — только после FROM: после INTO,
		// UPDATE, USING запятая стоит в списке колонок и присваиваний.
		if !strings.HasPrefix(strings.ToLower(s[m[0]:]), "from") {
			continue
		}
		for {
			cm := sqlCommaTableRe.FindStringSubmatchIndex(s[end:])
			if cm == nil {
				break
			}
			base := end
			ctable := s[base+cm[2] : base+cm[3]]
			if sqlNotAlias[ctable] {
				break
			}
			direct[g] = append(direct[g], ctable)
			info.aliases[ctable] = ctable
			end = base + cm[3]
			if cm[4] >= 0 {
				if alias := s[base+cm[4] : base+cm[5]]; !sqlNotAlias[alias] {
					info.aliases[alias] = ctable
					end = base + cm[5]
				}
			}
		}
	}
	// Имя CTE или производной разрешается в таблицы верхнего уровня тела;
	// тело само бывает над производной — отсюда неподвижная точка.
	resolved := map[string]string{}
	resolve := func(t string) string {
		if r, ok := resolved[t]; ok {
			return r
		}
		return t
	}
	for round := 0; round <= len(derived); round++ {
		changed := false
		for _, d := range derived {
			var cands []string
			for _, t := range direct[d.open] {
				cands = append(cands, resolve(t))
			}
			for _, inner := range derived {
				if inner.owner == d.open {
					cands = append(cands, resolve(inner.name))
				}
			}
			r := sqlPickTable(cands)
			if resolved[d.name] != r {
				resolved[d.name] = r
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	for g, tables := range direct {
		for _, t := range tables {
			info.byGroup[g] = append(info.byGroup[g], resolve(t))
		}
	}
	for _, d := range derived {
		if d.owner != -2 {
			info.byGroup[d.owner] = append(info.byGroup[d.owner], resolve(d.name))
		}
		info.aliases[d.name] = resolve(d.name)
	}
	for alias, t := range info.aliases {
		info.aliases[alias] = resolve(t)
	}
	return info
}

// sqlPickTable — во что разрешается тело: таблица пары, если она среди
// таблиц тела; неразрешённое, если тело без таблиц либо над неразрешённым;
// иначе — первая таблица тела (набор либо чужая таблица).
func sqlPickTable(cands []string) string {
	if len(cands) == 0 {
		return sqlUnresolved
	}
	for _, want := range []string{BindingPairTable, sqlUnresolved} {
		for _, t := range cands {
			if t == want {
				return want
			}
		}
	}
	return cands[0]
}

// sqlCloseParens — открывающая скобка → закрывающая (вне '…').
func sqlCloseParens(s string) map[int]int {
	out := map[int]int{}
	var stack []int
	quoted := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\'':
			quoted = !quoted
		case quoted:
		case s[i] == '(':
			stack = append(stack, i)
		case s[i] == ')' && len(stack) > 0:
			out[stack[len(stack)-1]] = i
			stack = stack[:len(stack)-1]
		}
	}
	return out
}

// sqlGroups — для каждой позиции текста: начало самой внутренней открытой
// скобки (-1 — верхний уровень). Скобки внутри '…' не считаются.
func sqlGroups(s string) []int {
	groups := make([]int, len(s)+1)
	var stack []int
	quoted := false
	for i := 0; i < len(s); i++ {
		top := -1
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		groups[i] = top
		switch {
		case s[i] == '\'':
			quoted = !quoted
		case quoted:
		case s[i] == '(':
			stack = append(stack, i)
		case s[i] == ')' && len(stack) > 0:
			stack = stack[:len(stack)-1]
		}
	}
	groups[len(s)] = -1
	return groups
}

// scopeTables — таблицы, видимые неквалифицированной колонке в позиции at:
// названные в той же скобке, что колонка; нет таких — во внешней, и так до
// верхнего уровня (внутренний запрос затеняет внешний, как в самом SQL).
// Пусто — таблицы колонки в литерале нет (фрагмент условия чужого запроса).
func (info sqlInfo) scopeTables(at int) []string {
	for g := info.groups[at]; ; {
		if t := info.byGroup[g]; len(t) > 0 {
			return t
		}
		if g < 0 {
			return nil
		}
		g = info.groups[g]
	}
}

// asciiLower — нижний регистр латиницы без смены длины: позиции разбора
// остаются позициями исходного текста.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// bindingPairColRef — одно упоминание колонки пары.
type bindingPairColRef struct {
	at        int
	column    string
	qualifier string
	// format — квалификатор — глагол формата (`%[1]s.`, `%s.`).
	format bool
}

func (r bindingPairColRef) String() string {
	switch {
	case r.format:
		return "<формат>." + r.column
	case r.qualifier != "":
		return r.qualifier + "." + r.column
	default:
		return r.column
	}
}

// bindingPairColRefs — упоминания колонок пары в тексте литерала.
func bindingPairColRefs(s string) []bindingPairColRef {
	var out []bindingPairColRef
	for _, col := range BindingPairColumns {
		for i := 0; ; {
			j := strings.Index(s[i:], col)
			if j < 0 {
				break
			}
			at := i + j
			i = at + len(col)
			if at > 0 && isSQLIdent(s[at-1]) {
				continue
			}
			if i < len(s) && isSQLIdent(s[i]) {
				continue
			}
			ref := bindingPairColRef{at: at, column: col}
			if at > 0 && s[at-1] == '.' {
				q := at - 1
				for q > 0 && isSQLIdent(s[q-1]) {
					q--
				}
				ref.qualifier = s[q : at-1]
				if q > 0 && (s[q-1] == ']' || s[q-1] == '%') || q == at-1 {
					ref.format = true
				}
			}
			out = append(out, ref)
		}
	}
	return out
}

func isSQLIdent(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// bindingPairRefIsPair — упоминание обращается к паре `access_bindings`
// (либо не разрешено и потому считается парой).
func bindingPairRefIsPair(r bindingPairColRef, info sqlInfo, place, pkg map[string]string) bool {
	if r.format {
		return true
	}
	if r.qualifier != "" {
		for _, m := range []map[string]string{info.aliases, place, pkg} {
			if t, ok := m[r.qualifier]; ok {
				return t == BindingPairTable || t == sqlUnresolved
			}
		}
		return true
	}
	scope := info.scopeTables(r.at)
	if len(scope) == 0 {
		return true
	}
	for _, t := range scope {
		if t == BindingPairTable || t == sqlUnresolved {
			return true
		}
	}
	return false
}

// JudgeBindingSubjectPair сверяет перепись с ведомостью и возвращает находки.
func JudgeBindingSubjectPair(census BindingPairCensus, ledger map[string]BindingPairEntry) []string {
	var findings []string
	places := census.Places()
	keys := make([]string, 0, len(places))
	for k := range places {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, place := range keys {
		acc := places[place]
		goN, sqlN := 0, 0
		var where []string
		for _, a := range acc {
			if a.Form == BindingPairFormSQL {
				sqlN++
			} else {
				goN++
			}
			where = append(where, a.Pos+" "+a.Form+" "+a.What)
		}
		entry, listed := ledger[place]
		switch {
		case !listed:
			findings = append(findings, fmt.Sprintf("%s — доступ к одиночной паре субъекта выдачи вне перечня "+
				"(Go %d, SQL %d):\n    %s\nПара — проекция первой строки набора: у выдачи нескольким субъектам чтение пары "+
				"видит одного из них. Перевести место на весь набор (Subjects / access_binding_subjects) либо внести "+
				"в BindingSubjectPairLedger с основанием из закрытого словаря и точным числом.",
				place, goN, sqlN, strings.Join(where, "\n    ")))
		case entry.Class == BindingPairFallback && !census.SetEvidence[place]:
			findings = append(findings, fmt.Sprintf("%s — место записано откатом к прежней форме, но набор субъектов "+
				"в нём не читается (нет значения типа Subject/[]Subject и таблицы %s):\n    %s\nОткат без ветви "+
				"набора — это чтение одной пары, дефект kaname#880/#888.",
				place, BindingPairSetTable, strings.Join(where, "\n    ")))
		case entry.Go != goN || entry.SQL != sqlN:
			findings = append(findings, fmt.Sprintf("%s — в перечисленном месте число доступов к паре изменилось: "+
				"ведомость Go %d, SQL %d; в дереве Go %d, SQL %d:\n    %s\nНовое чтение в законном месте законным "+
				"не становится — перевести его на набор либо обновить запись с основанием.",
				place, entry.Go, entry.SQL, goN, sqlN, strings.Join(where, "\n    ")))
		}
	}
	findings = append(findings, judgeBindingPairOutsideBuild(census.OutsideBuild, BindingPairOutsideBuildLedger)...)
	ledgerKeys := make([]string, 0, len(ledger))
	for k := range ledger {
		ledgerKeys = append(ledgerKeys, k)
	}
	sort.Strings(ledgerKeys)
	for _, place := range ledgerKeys {
		entry := ledger[place]
		if _, ok := places[place]; !ok {
			findings = append(findings, fmt.Sprintf("%s — запись ведомости без предмета: доступа к паре в месте нет, "+
				"исключение истекло — снять запись", place))
		}
		if !bindingPairKnownClass(entry.Class) {
			findings = append(findings, fmt.Sprintf("%s — основание %q вне закрытого словаря %v", place, entry.Class, BindingPairClasses))
		}
		if strings.TrimSpace(entry.Why) == "" {
			findings = append(findings, fmt.Sprintf("%s — запись ведомости без основания словами", place))
		}
	}
	return findings
}

func bindingPairKnownClass(c BindingPairClass) bool {
	for _, k := range BindingPairClasses {
		if c == k {
			return true
		}
	}
	return false
}

// judgeBindingPairOutsideBuild — файл радиуса вне прод-сборки допустим лишь
// записью ведомости; запись без такого файла истекает.
func judgeBindingPairOutsideBuild(outside []string, ledger map[string]string) []string {
	var findings []string
	seen := map[string]bool{}
	for _, rel := range outside {
		seen[rel] = true
		if strings.TrimSpace(ledger[rel]) == "" {
			findings = append(findings, fmt.Sprintf("%s — непроверочный файл радиуса вне прод-сборки (%s): гейт его "+
				"не разбирает, и доступ к паре в нём не виден. Снять ограничение сборки либо внести файл в "+
				"BindingPairOutsideBuildLedger с основанием.", rel, strings.Join(BindingPairProdEnv, " ")))
		}
	}
	keys := make([]string, 0, len(ledger))
	for k := range ledger {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, rel := range keys {
		if !seen[rel] {
			findings = append(findings, fmt.Sprintf("%s — запись ведомости файлов вне прод-сборки без предмета: "+
				"файл в сборке либо снят — снять запись", rel))
		}
	}
	return findings
}
