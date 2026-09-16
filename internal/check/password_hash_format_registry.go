// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// password_hash_format_registry.go — гейт: перечень форматов проверочного
// значения сверен с ПРОВЕРЯЮЩИМИ, которые есть в дереве (приёмка ID-PW-1 §5
// PWV-13 и строка 07.4).
//
// # Предмет
//
// Перечень форматов — закрытый словарь того, что продукт умеет ЧИТАТЬ. Он
// расходится с деревом двумя способами, и оба тихие:
//
//   - запись без проверяющего: формат объявлен, читателя нет. Значение такого
//     формата доезжает до входа и получает исход «формат вне перечня» — то
//     есть человек с верным паролем не входит, а перепись переноса его
//     пропустила, потому что признак в перечне ЕСТЬ;
//   - проверяющий без записи: читатель есть, потолка у него нет. Тогда
//     параметры стоимости берутся из самого значения без всякой границы, и
//     чужой источник назначает цену каждой попытки.
//
// Оба расхождения гейт называет находкой. Снятие записи ВМЕСТЕ с проверяющим он
// пропускает — дерево согласовано, — и это НЕ разрешение снимать: хранилищ
// установок гейт не читает, разрешение даёт перепись каждой из них (Р8,
// PWV-17). Сказано прямо, чтобы зелёный этого гейта не прочитали шире.
//
// # Что судится, и почему признаком СВОЙСТВА, а не именем
//
// «Проверяющий формата есть в дереве» опознаётся не по имени функции — имя
// переименуют, и гейт замолчит, — а по ВЕТВИ КЛАССИФИКАТОРА: в функции выбора
// стоит ветвь, которая по признаку формата уходит в свою функцию. Признак
// берётся из строковой константы, на которую ветвь ссылается, то есть из того
// же места, откуда его берёт исполняемый код.
//
// Отсюда же строка 07.4: ни функция выбора, ни функции её ветвей не упоминают
// типа настройки «что писать». Выбор проверяющего производен от хранимого
// значения; прочти он настройку — смена настройки молча сделала бы нечитаемой
// уже лежащую популяцию.
//
// # Границы, названные вслух
//
//  1. ЗАПИСИ ПЕРЕЧНЯ приходят ДОВОДОМ, а не разбором: их объявляет домен, и он
//     же их проверяет. Гейт судит поданное — тем же, чем судил бы прочитанное,
//     но без второго разбора одного предмета.
//  2. ВТОРОЕ ОБЪЯВЛЕНИЕ перечня ищется по составному литералу записи вне файла
//     перечня. Литерал в пробе сюда не попадает: корпус не-тестовый.
//  3. ЭТАЛОН ПОЛА приходит доводом и правится вместе с нормой, на которой
//     стоит. Читать его из текста приёмки гейт не вправе: он сверялся бы с
//     прозой, а не с нормой (§8 приёмки).
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

// phfFile — разобранный файл корпуса.
type phfFile struct {
	rel  string
	fset *token.FileSet
	file *ast.File
}

// line — строка позиции: находка обязана называть координату.
func (f *phfFile) line(pos token.Pos) int { return f.fset.Position(pos).Line }

// funcDecl — объявление функции по имени; метод по имени не ищется: предмет
// гейта — функции файла проверяющего.
func (f *phfFile) funcDecl(name string) *ast.FuncDecl {
	for _, decl := range f.file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// phfParse — разбор корпуса. Файл, который не разбирается, — ОТКАЗ премисы, а
// не пропуск: «ноль находок» на неразобранном файле неотличимо от «ноль
// прочитанного».
func phfParse(corpus TreeCorpus) (map[string]*phfFile, error) {
	out := make(map[string]*phfFile, len(corpus))
	for _, rel := range corpus.Rels() {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, rel, corpus[rel], parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("%s не разобран: %w", rel, err)
		}
		out[rel] = &phfFile{rel: rel, fset: fset, file: file}
	}
	return out, nil
}

// PasswordHashRegistrySpec — объявление предмета. Живёт в файле пробы.
type PasswordHashRegistrySpec struct {
	// RegistryRel — файл, где объявлен перечень.
	RegistryRel string
	// VerifierRel — файл проверяющего: тот, где стоит классификатор.
	VerifierRel string
	// SelectorFunc — имя функции выбора проверяющего.
	SelectorFunc string
	// SettingType — имя типа настройки «что писать»: его не должно быть ни в
	// функции выбора, ни в функциях её ветвей.
	SettingType string
	// RecordType — имя типа записи перечня: по его составному литералу ищется
	// второе объявление перечня.
	RecordType string
	// FloorReference — эталон пола: формат → параметр → величина. Норма, на
	// которой он стоит, названа в пробе.
	FloorReference map[string]map[string]uint32
}

// PasswordHashRecordView — запись перечня в том виде, в каком её судит гейт.
type PasswordHashRecordView struct {
	Format   string
	Writable bool
	// Params — параметры стоимости формата, в объявленном порядке.
	Params []string
	// Ceiling, Floor — потолок и пол по параметрам.
	Ceiling, Floor map[string]uint32
	// Range — область допустимости: параметр → [нижняя, верхняя] включительно.
	Range map[string][2]uint32
}

// PasswordHashRegistryCensus — перепись гейта. Печатается ВСЕГДА: «ноль
// расхождений» обязано быть отличимо от «ничего не прочитано».
type PasswordHashRegistryCensus struct {
	FilesRead      int
	Records        int
	Writable       int
	Branches       int
	PairsChecked   int
	SettingLookups int
}

func (c PasswordHashRegistryCensus) String() string {
	return fmt.Sprintf("перепись: не-тестовых файлов Go прочитано %d · записей перечня %d (из них записываемых %d) · "+
		"ветвей классификатора %d · пар «запись × параметр» осмотрено %d · тел, осмотренных на чтение настройки, %d",
		c.FilesRead, c.Records, c.Writable, c.Branches, c.PairsChecked, c.SettingLookups)
}

// AuditPasswordHashFormatRegistry — сверка перечня с деревом.
func AuditPasswordHashFormatRegistry(corpus TreeCorpus, records []PasswordHashRecordView, spec PasswordHashRegistrySpec) (
	[]string, PasswordHashRegistryCensus, error,
) {
	var census PasswordHashRegistryCensus
	if spec.RegistryRel == "" || spec.VerifierRel == "" || spec.SelectorFunc == "" ||
		spec.SettingType == "" || spec.RecordType == "" {
		return nil, census, fmt.Errorf("%w: объявление предмета неполно", ErrEmptyTraversal)
	}
	if len(corpus) == 0 {
		return nil, census, fmt.Errorf("%w: корпус пуст — читать было нечего", ErrEmptyTraversal)
	}
	// Пустой перечень — ОТКАЗ, а не проход: сверять было бы нечего, и зелёное
	// означало бы «форматов нет», то есть «читать продукт не умеет ничего».
	if len(records) == 0 {
		return nil, census, fmt.Errorf("%w: перечень форматов пуст — сверять нечего, "+
			"а «ноль расхождений» на пустом перечне неотличимо от «ничего не прочитано»", ErrEmptyTraversal)
	}

	files, err := phfParse(corpus)
	if err != nil {
		return nil, census, err
	}
	census.FilesRead = len(files)
	census.Records = len(records)

	var findings []string

	// ── Записи перечня: потолок, пол, записываемость (13.2, 13.4, 13.5, 13.6).
	for _, r := range records {
		if r.Writable {
			census.Writable++
		}
		for _, p := range r.Params {
			census.PairsChecked++
			ceiling, hasCeiling := r.Ceiling[p]
			rng, hasRange := r.Range[p]
			if !hasRange {
				findings = append(findings, fmt.Sprintf(
					"запись %q: у параметра %q нет области допустимости — судить потолок не с чем", r.Format, p))
				continue
			}
			if !hasCeiling {
				findings = append(findings, fmt.Sprintf(
					"запись %q: потолок по параметру %q не задан — параметры стоимости берутся из самого "+
						"значения, и без потолка цену каждой попытки назначает чужой источник", r.Format, p))
				continue
			}
			if ceiling < rng[0] {
				findings = append(findings, fmt.Sprintf(
					"запись %q: потолок %q = %d ниже нижней границы допустимости %d — такой потолок не пропускает ничего",
					r.Format, p, ceiling, rng[0]))
			}
			if ceiling >= rng[1] {
				findings = append(findings, fmt.Sprintf(
					"запись %q: потолок %q = %d не ниже верхней границы допустимости %d — он не ограничивает ничего "+
						"сверх спецификации, и значения «выше потолка» на этом формате не существует, "+
						"так что PWV-14 на нём неконструируем", r.Format, p, ceiling, rng[1]))
			}
		}
		findings = append(findings, auditRecordFloor(r, spec)...)
	}
	if census.Writable == 0 {
		findings = append(findings, "записываемых форматов в перечне ноль — настройке «что писать» "+
			"нечего было бы назвать (PWV-16)")
	}

	// ── Дерево: ветви классификатора и чтение настройки (13.1, 07.4).
	verifier, ok := files[spec.VerifierRel]
	if !ok {
		return nil, census, fmt.Errorf("%w: файла проверяющего %s в корпусе нет — сверять перечень не с чем",
			ErrEmptyTraversal, spec.VerifierRel)
	}
	branches, branchFuncs, err := passwordVerifierBranches(verifier, spec.SelectorFunc)
	if err != nil {
		return nil, census, err
	}
	census.Branches = len(branches)

	declared := map[string]bool{}
	for _, r := range records {
		declared[r.Format] = true
	}
	for _, r := range records {
		if !branches[r.Format] {
			findings = append(findings, fmt.Sprintf(
				"формат %q объявлен перечнем, а проверяющего у него в дереве нет: значение такого формата "+
					"дойдёт до входа и получит исход «формат вне перечня» — человек с верным паролем не "+
					"войдёт, а перепись переноса его пропустит, потому что признак в перечне есть. "+
					"Находка при ЛЮБОМ числе строк этого формата", r.Format))
		}
	}
	for marker := range branches {
		if !declared[marker] {
			findings = append(findings, fmt.Sprintf(
				"проверяющий читает признак %q, которого в перечне нет: у такого читателя нет ни потолка, "+
					"ни отметки записываемости — параметры стоимости берутся из самого значения без границы",
				marker))
		}
	}

	// 07.4: ни выбор, ни ветви не упоминают типа настройки «что писать».
	for _, fn := range append([]string{spec.SelectorFunc}, branchFuncs...) {
		census.SettingLookups++
		if pos, found := funcMentionsType(verifier, fn, spec.SettingType); found {
			findings = append(findings, fmt.Sprintf(
				"%s:%d: функция %s читает тип настройки %q — выбор проверяющего обязан быть производен от "+
					"ХРАНИМОГО значения: прочти он настройку, смена настройки молча сделала бы нечитаемой "+
					"уже лежащую популяцию", spec.VerifierRel, verifier.line(pos), fn, spec.SettingType))
		}
	}

	// Второе объявление перечня.
	for rel, f := range files {
		if rel == spec.RegistryRel {
			continue
		}
		if pos, found := fileBuildsRecord(f, spec.RecordType); found {
			findings = append(findings, fmt.Sprintf(
				"%s:%d: запись перечня `%s` строится вне файла перечня (%s) — перечень объявляется ровно "+
					"одним местом, иначе два объявления разойдутся молча",
				rel, f.line(pos), spec.RecordType, spec.RegistryRel))
		}
	}

	sort.Strings(findings)
	return findings, census, nil
}

// auditRecordFloor — пол записи: у только читаемой его нет, у записываемой он
// не выше потолка, хотя бы по одному параметру ниже него (13.4) и не ниже
// эталона (13.5).
func auditRecordFloor(r PasswordHashRecordView, spec PasswordHashRegistrySpec) []string {
	var findings []string
	if !r.Writable {
		for p := range r.Floor {
			findings = append(findings, fmt.Sprintf(
				"запись %q: у только читаемого формата объявлен пол по параметру %q — пол отвечает на "+
					"вопрос «писать ли такое», а этот формат продукт не пишет", r.Format, p))
		}
		return findings
	}

	belowBySome := false
	for _, p := range r.Params {
		floor, hasFloor := r.Floor[p]
		if !hasFloor {
			findings = append(findings, fmt.Sprintf(
				"запись %q: у записываемого формата нет пола по параметру %q", r.Format, p))
			continue
		}
		ceiling, hasCeiling := r.Ceiling[p]
		if hasCeiling && floor > ceiling {
			findings = append(findings, fmt.Sprintf(
				"запись %q: пол %q = %d выше потолка %d — область настройки «что писать» пуста",
				r.Format, p, floor, ceiling))
		}
		if hasCeiling && floor < ceiling {
			belowBySome = true
		}
		if want, ok := spec.FloorReference[r.Format][p]; ok && floor < want {
			findings = append(findings, fmt.Sprintf(
				"запись %q: пол %q = %d ниже эталона %d — эталоном стоит строка «хеш нового пароля» нормы, "+
					"на которой пол держится; опущенный одной правкой перечня, он понизил бы стойкость "+
					"каждого нового пароля молча", r.Format, p, floor, want))
		}
	}
	if !belowBySome {
		findings = append(findings, fmt.Sprintf(
			"запись %q: пол равен потолку по каждому параметру — область настройки «что писать» из одной "+
				"точки, и смена параметров (PWV-07) невыразима", r.Format))
	}
	return findings
}

// passwordVerifierBranches — ветви классификатора: признак формата → есть.
// Вторым значением — имена функций, в которые ветви уходят.
func passwordVerifierBranches(f *phfFile, selector string) (map[string]bool, []string, error) {
	decl := f.funcDecl(selector)
	if decl == nil {
		return nil, nil, fmt.Errorf("%w: функции выбора %s в файле проверяющего нет — "+
			"признак «у формата есть проверяющий» судить нечем", ErrEmptyTraversal, selector)
	}
	consts := f.stringConsts()

	branches := map[string]bool{}
	var funcs []string
	ast.Inspect(decl, func(n ast.Node) bool {
		clause, ok := n.(*ast.CaseClause)
		if !ok || len(clause.List) == 0 {
			return true
		}
		var markers []string
		for _, cond := range clause.List {
			ast.Inspect(cond, func(x ast.Node) bool {
				id, ok := x.(*ast.Ident)
				if !ok {
					return true
				}
				if lit, ok := consts[id.Name]; ok {
					if marker := strings.Trim(lit, "$"); marker != "" {
						markers = append(markers, marker)
					}
				}
				return true
			})
		}
		if len(markers) == 0 {
			return true
		}
		for _, stmt := range clause.Body {
			ast.Inspect(stmt, func(x ast.Node) bool {
				call, ok := x.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok {
					funcs = append(funcs, id.Name)
				}
				return true
			})
		}
		for _, m := range markers {
			branches[m] = true
		}
		return true
	})
	sort.Strings(funcs)
	return branches, funcs, nil
}

// funcMentionsType — тело функции упоминает названный тип.
func funcMentionsType(f *phfFile, name, typeName string) (token.Pos, bool) {
	decl := f.funcDecl(name)
	if decl == nil {
		return token.NoPos, false
	}
	var at token.Pos
	found := false
	ast.Inspect(decl, func(n ast.Node) bool {
		if found {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && id.Name == typeName {
			at, found = id.Pos(), true
			return false
		}
		return true
	})
	return at, found
}

// fileBuildsRecord — файл строит составной литерал записи перечня.
func fileBuildsRecord(f *phfFile, recordType string) (token.Pos, bool) {
	var at token.Pos
	found := false
	ast.Inspect(f.file, func(n ast.Node) bool {
		if found {
			return false
		}
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		// Тип литерала называется ТРЕМЯ формами, и знать надо все: сама запись
		// (`R{…}`), срез записей (`[]R{…}`) и карта с записью значением
		// (`map[K]R{…}`). Перечень объявлен именно срезом, поэтому предикат,
		// знающий одну форму, не нашёл бы второго объявления в той же форме, в
		// какой написано первое, — и молчал бы, ничего не измерив.
		if phfNamesRecordType(lit.Type, recordType) {
			at, found = lit.Pos(), true
		}
		return !found
	})
	return at, found
}

// phfNamesRecordType — выражение типа называет запись перечня.
func phfNamesRecordType(expr ast.Expr, recordType string) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name == recordType
	case *ast.SelectorExpr:
		return t.Sel.Name == recordType
	case *ast.StarExpr:
		return phfNamesRecordType(t.X, recordType)
	case *ast.ArrayType:
		return phfNamesRecordType(t.Elt, recordType)
	case *ast.MapType:
		return phfNamesRecordType(t.Value, recordType)
	default:
		return false
	}
}

// stringConsts — строковые константы файла: имя → значение.
func (f *phfFile) stringConsts() map[string]string {
	out := map[string]string{}
	for _, decl := range f.file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, s := range gd.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if v, err := strconv.Unquote(lit.Value); err == nil {
					out[name.Name] = v
				}
			}
		}
	}
	return out
}
