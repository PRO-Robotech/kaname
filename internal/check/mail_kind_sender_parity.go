// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_kind_sender_parity.go — перепись ВИДОВ ПИСЬМА против их ОТПРАВИТЕЛЕЙ
// (приёмка `docs/engineering/acceptance/recovery-of-access.md`, Р3, сценарии
// Ф5-10 и Ф5-11; задача PRO-Robotech/kacho#1271).
//
// # Две стороны одного словаря
//
// Вид письма объявлен ДВАЖДЫ, и оба объявления обязательны:
//
//   - СХЕМОЙ — ограничением на колонку вида события очереди писем: строку
//     другого вида база не принимает. Это закрытый словарь того, что вообще
//     может лечь в очередь;
//   - ПРИМЕНИТЕЛЕМ — функцией формы `drainer.Applier` (`func(ctx, eventType
//     string, payload T) error`), которая ветвится на своём параметре вида и
//     сдаёт письмо узлу. Вид, на который применитель не ветвится, у него —
//     «неизвестный», и строка отравляется, а не отправляется.
//
// Расходятся они молча: миграция и функция правятся разными коммитами, и
// каждая по отдельности зелена. Гейт кладёт их рядом.
//
// # Что распознаётся — все законные формы записи, по каждой инъекция
//
// Схема: `CONSTRAINT … CHECK ((event_type = ANY (ARRAY['…'::text, …])))` в теле
// `CREATE TABLE`, и то же выражение в `ALTER TABLE … ADD CONSTRAINT`.
// Ограничение, снятое `DROP CONSTRAINT` и не объявленное заново, из словаря
// уходит. Читается ТОЛЬКО секция `+goose Up`: секция отката несёт то же имя с
// обратным смыслом. Последнее живое объявление побеждает — в порядке версий
// миграций, а он же и лексикографический порядок имён.
//
// Применитель: сравнения `eventType ==`/`!=` с константой либо литералом и
// `switch eventType { case …: }`. Константа разрешается через словарь строковых
// констант прод-корпуса (общий помощник семейства дренажа); неразрешимое имя
// считается отдельно в переписи, а не молчит.
//
// Обе стороны судят по УЗЛУ, а не по подстроке: проза этого же файла несёт
// каждое из искомых слов.
//
// # Чем ограничено — сказано вслух
//
// Пространство видов письма — `mail.`. Словарь очереди, ни один вид которого
// не в этом пространстве, к письмам не относится и переписью не учитывается.
// Применитель, ветвящийся на вид через промежуточную переменную
// (`k := eventType; if k == …`), распознавателю невидим; в дереве такой формы
// нет, и её появление обязано прийти сюда новой инъекцией, а не молчанием.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// MailKindNamespace — приставка всякого вида письма. Единственное объявление
// предмета обеих осей.
const MailKindNamespace = "mail."

// MailEventKindColumn — колонка очереди, несущая вид события.
const MailEventKindColumn = "event_type"

// MailSenderSite — ОДИН применитель, принимающий вид: файл, строка и имя
// функции. Строка указывает на место сравнения, имя — на функцию, которая и
// есть отправитель.
type MailSenderSite struct {
	File string
	Line int
	Func string
}

// MailKindInventory — перепись обеих сторон и объём осмотренного.
type MailKindInventory struct {
	// Kinds — виды письма живой схемы, отсортированы.
	Kinds []string
	// KindSite — файл миграции, чьё объявление словаря живое (последнее).
	KindSite string
	// Senders — вид → применители, принимающие его (по функции, без повторов).
	Senders map[string][]MailSenderSite
	// Appliers — функций формы применителя найдено (всего, не только почтовых).
	Appliers int

	MigrationsRead         int
	VocabularyDeclarations int
	GoFilesRead            int
	ComparisonSites        int
	// UnresolvedComparisons — сравнения параметра вида с именем, чьё значение
	// словарь констант не знает. Слепая зона названа числом, а не спрятана.
	UnresolvedComparisons int
}

// KindsWithSender — вторая величина переписи: сколько видов схемы приняты
// хотя бы одним применителем.
func (inv MailKindInventory) KindsWithSender() int {
	n := 0
	for _, k := range inv.Kinds {
		if len(inv.Senders[k]) > 0 {
			n++
		}
	}
	return n
}

// Findings — расхождения двух сторон, по три оси, детерминированно.
func (inv MailKindInventory) Findings() []string {
	var out []string
	schema := map[string]bool{}
	for _, k := range inv.Kinds {
		schema[k] = true
		switch n := len(inv.Senders[k]); {
		case n == 0:
			out = append(out, fmt.Sprintf(
				"вид письма %q объявлен схемой (%s), но НИ ОДИН применитель его не принимает: "+
					"строка этого вида ляжет в очередь и отравится как «неизвестный вид» — "+
					"письмо не уйдёт, и заметит это только дежурный по возрасту старейшей "+
					"неотправленной", k, inv.KindSite))
		case n > 1:
			names := make([]string, 0, n)
			for _, s := range inv.Senders[k] {
				names = append(names, fmt.Sprintf("%s:%d %s", s.File, s.Line, s.Func))
			}
			out = append(out, fmt.Sprintf(
				"у вида письма %q ДВА отправителя (%s): два читателя одной настройки "+
					"разойдутся молча, и два счётчика об одном предмете будут спорить "+
					"(ID-MAIL-1 Р23, Ф5 Р3)", k, strings.Join(names, "; ")))
		}
	}
	accepted := make([]string, 0, len(inv.Senders))
	for k := range inv.Senders {
		accepted = append(accepted, k)
	}
	sort.Strings(accepted)
	for _, k := range accepted {
		if schema[k] {
			continue
		}
		for _, s := range inv.Senders[k] {
			out = append(out, fmt.Sprintf(
				"%s:%d %s принимает вид письма %q, которого схема очереди не допускает: "+
					"ветвь не исполнится никогда, а выглядит как поддержка вида "+
					"(отправитель без вида)", s.File, s.Line, s.Func, k))
		}
	}
	return out
}

// MailKindInventoryOf — перепись по двум корпусам: миграции и прод-файлы Go.
//
// ТРИ ИСХОДА: перепись собрана; читать не удалось (ошибка с координатой);
// прочитано ноль по любой из сторон — ErrEmptyTraversal, и это не «находок
// нет».
func MailKindInventoryOf(migrations, corpus TreeCorpus) (MailKindInventory, error) {
	inv := MailKindInventory{Senders: map[string][]MailSenderSite{}}

	kinds, site, migrationsRead, decls, err := MailKindsOfSchema(migrations)
	if err != nil {
		return inv, err
	}
	inv.Kinds, inv.KindSite = kinds, site
	inv.MigrationsRead, inv.VocabularyDeclarations = migrationsRead, decls

	senders, census, serr := MailSendersOf(corpus)
	if serr != nil {
		return inv, serr
	}
	inv.Senders = senders
	inv.Appliers = census.Appliers
	inv.GoFilesRead = census.FilesRead
	inv.ComparisonSites = census.ComparisonSites
	inv.UnresolvedComparisons = census.Unresolved
	return inv, nil
}

var (
	// mailCheckRe — ограничение на колонку вида с перечнем в ARRAY.
	// Имя ограничения — необязательная группа: в теле CREATE TABLE оно стоит
	// перед CHECK, в ALTER TABLE — после ADD CONSTRAINT (обе формы ниже).
	mailCheckRe = regexp.MustCompile(
		`(?is)\bCONSTRAINT\s+("?[\w]+"?)\s+CHECK\s*\(\s*\(?\s*` + MailEventKindColumn +
			`\s*=\s*ANY\s*\(\s*ARRAY\s*\[([^\]]*)\]`)
	// mailKindLitRe — один элемент перечня: строковый литерал с приведением или
	// без него.
	mailKindLitRe = regexp.MustCompile(`'([^']+)'`)
	// mailDropConstraintRe — снятие ограничения по имени.
	mailDropConstraintRe = regexp.MustCompile(`(?is)\bDROP\s+CONSTRAINT\s+(?:IF\s+EXISTS\s+)?("?[\w]+"?)`)
	gooseUpRe            = regexp.MustCompile(`(?m)^\s*--\s*\+goose\s+Up\b`)
	gooseDownRe          = regexp.MustCompile(`(?m)^\s*--\s*\+goose\s+Down\b`)
)

// gooseUpSection — секция наката миграции. Без маркеров — весь файл (так
// записаны своды до появления маркеров); с маркерами — от `Up` до `Down`.
func gooseUpSection(body string) string {
	up := gooseUpRe.FindStringIndex(body)
	if up == nil {
		return body
	}
	rest := body[up[1]:]
	if down := gooseDownRe.FindStringIndex(rest); down != nil {
		return rest[:down[0]]
	}
	return rest
}

// MailKindsOfSchema — виды письма по корпусу миграций: последнее живое
// объявление словаря на колонке вида, чей перечень лежит в пространстве
// `mail.`.
//
// Возвращает отсортированные виды, файл живого объявления, число прочитанных
// миграций и число осмотренных объявлений словаря на колонке вида (включая
// не-почтовые — они считаются, но в словарь не идут).
func MailKindsOfSchema(migrations TreeCorpus) (kinds []string, site string, read, decls int, err error) {
	if len(migrations) == 0 {
		return nil, "", 0, 0, fmt.Errorf("%w: корпус миграций пуст — о схеме не прочитано ничего",
			ErrEmptyTraversal)
	}
	type vocab struct {
		kinds []string
		site  string
	}
	live := map[string]vocab{} // имя ограничения → живой словарь
	for _, rel := range migrations.Rels() {
		read++
		// Секция наката берётся ДО снятия комментариев: маркер goose — сам
		// комментарий, и после снятия его не отличить.
		body := stripSQLComments(gooseUpSection(migrations[rel]))
		// Порядок операторов внутри файла несущий: DROP, стоящий после ADD того
		// же имени, снимает объявленное. Поэтому оба вида находок сшиваются по
		// позиции, а не обрабатываются двумя проходами.
		type op struct {
			pos  int
			name string
			add  []string
			drop bool
		}
		var ops []op
		for _, m := range mailCheckRe.FindAllStringSubmatchIndex(body, -1) {
			decls++
			name := normalizeSQLName(body[m[2]:m[3]])
			var ks []string
			for _, lm := range mailKindLitRe.FindAllStringSubmatch(body[m[4]:m[5]], -1) {
				ks = append(ks, lm[1])
			}
			if !anyInMailNamespace(ks) {
				continue
			}
			ops = append(ops, op{pos: m[0], name: name, add: ks})
		}
		for _, m := range mailDropConstraintRe.FindAllStringSubmatchIndex(body, -1) {
			ops = append(ops, op{pos: m[0], name: normalizeSQLName(body[m[2]:m[3]]), drop: true})
		}
		sort.Slice(ops, func(i, j int) bool { return ops[i].pos < ops[j].pos })
		for _, o := range ops {
			if o.drop {
				delete(live, o.name)
				continue
			}
			live[o.name] = vocab{kinds: o.add, site: rel}
		}
	}
	if len(live) == 0 {
		return nil, "", read, decls, fmt.Errorf("%w: в %d файлах миграций не найдено живого словаря "+
			"видов письма (объявлений словаря на колонке %s осмотрено %d, в пространстве %q — 0)",
			ErrEmptyTraversal, read, MailEventKindColumn, decls, MailKindNamespace)
	}
	seen := map[string]bool{}
	names := make([]string, 0, len(live))
	for n := range live {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		v := live[n]
		site = v.site
		for _, k := range v.kinds {
			if !seen[k] {
				seen[k] = true
				kinds = append(kinds, k)
			}
		}
	}
	sort.Strings(kinds)
	return kinds, site, read, decls, nil
}

func anyInMailNamespace(kinds []string) bool {
	for _, k := range kinds {
		if strings.HasPrefix(k, MailKindNamespace) {
			return true
		}
	}
	return false
}

// MailSenderCensus — объём осмотренного на стороне Go.
type MailSenderCensus struct {
	FilesRead       int
	Appliers        int
	ComparisonSites int
	Unresolved      int
}

// MailSendersOf — применители, принимающие виды письма, по прод-корпусу Go.
//
// Применитель опознаётся ФОРМОЙ подписи (`drainer.Applier`), а не именем:
// имя — соглашение, форма — то, что дренаж исполняет. Сравнение параметра вида
// с константой либо литералом, значение которого лежит в пространстве `mail.`,
// делает функцию отправителем этого вида.
func MailSendersOf(corpus TreeCorpus) (map[string][]MailSenderSite, MailSenderCensus, error) {
	census := MailSenderCensus{}
	if len(corpus) == 0 {
		return nil, census, fmt.Errorf("%w: прод-корпус Go пуст", ErrEmptyTraversal)
	}
	consts, _, cerr := stringConstantsOf(corpus)
	if cerr != nil {
		return nil, census, cerr
	}
	senders := map[string][]MailSenderSite{}
	fset := token.NewFileSet()
	for _, rel := range corpus.Rels() {
		file, perr := parser.ParseFile(fset, rel, corpus[rel], parser.SkipObjectResolution)
		if perr != nil {
			return nil, census, fmt.Errorf("разбор %s: %w", rel, perr)
		}
		census.FilesRead++
		var enclosing []string
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				if len(enclosing) > 0 {
					enclosing = enclosing[:len(enclosing)-1]
				}
				return true
			}
			switch v := n.(type) {
			case *ast.FuncDecl:
				enclosing = append(enclosing, v.Name.Name)
				if param := applierKindParam(v.Type); param != "" {
					census.Appliers++
					scanKindComparisons(fset, rel, v.Name.Name, param, v.Body, consts, senders, &census)
				}
				return true
			case *ast.FuncLit:
				// Имя литерала — ближайшая ИМЕНОВАННАЯ функция выше по стеку,
				// а не соседний узел: между объявлением и литералом стоят
				// операторы, у которых имени нет.
				name := "func"
				for i := len(enclosing) - 1; i >= 0; i-- {
					if enclosing[i] != "" {
						name = enclosing[i] + "/func"
						break
					}
				}
				enclosing = append(enclosing, name)
				if param := applierKindParam(v.Type); param != "" {
					census.Appliers++
					scanKindComparisons(fset, rel, name, param, v.Body, consts, senders, &census)
				}
				return true
			default:
				// Стек имён двигают только функции; прочие узлы его не трогают,
				// поэтому и не отмечаются в нём — иначе выход из узла снял бы
				// чужое имя.
				enclosing = append(enclosing, "")
				return true
			}
		})
	}
	if census.Appliers == 0 {
		return nil, census, fmt.Errorf("%w: в %d прод-файлах Go не найдено ни одной функции "+
			"формы применителя дренажа — отправителей не читал никто", ErrEmptyTraversal, census.FilesRead)
	}
	for k := range senders {
		sort.Slice(senders[k], func(i, j int) bool {
			a, b := senders[k][i], senders[k][j]
			if a.File != b.File {
				return a.File < b.File
			}
			return a.Line < b.Line
		})
	}
	return senders, census, nil
}

// applierKindParam — имя параметра вида, если подпись имеет форму применителя
// дренажа: (context.Context, string, T) error. Пустая строка — не применитель.
func applierKindParam(ft *ast.FuncType) string {
	if ft == nil || ft.Params == nil || ft.Results == nil {
		return ""
	}
	var params []*ast.Field
	for _, f := range ft.Params.List {
		if len(f.Names) == 0 {
			params = append(params, f)
			continue
		}
		for range f.Names {
			params = append(params, f)
		}
	}
	if len(params) != 3 || len(ft.Results.List) != 1 {
		return ""
	}
	if !isSelector(params[0].Type, "context", "Context") {
		return ""
	}
	if !isIdent(params[1].Type, "string") || !isIdent(ft.Results.List[0].Type, "error") {
		return ""
	}
	// Второй параметр обязан быть назван: безымянный вид сравнить не с чем.
	// Поле формы `eventType, payload string` даёт один Field на два имени —
	// параметр вида в нём первый; с параметром контекста поле делиться не
	// может (типы разные), поэтому первое имя поля и есть параметр вида.
	names := params[1].Names
	if len(names) == 0 {
		return ""
	}
	return names[0].Name
}

func isSelector(e ast.Expr, pkg, name string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := s.X.(*ast.Ident)
	return ok && x.Name == pkg && s.Sel.Name == name
}

func isIdent(e ast.Expr, name string) bool {
	i, ok := e.(*ast.Ident)
	return ok && i.Name == name
}

// scanKindComparisons — все места, где тело применителя сравнивает свой
// параметр вида: `param == X`, `param != X`, `X == param` и `switch param {
// case X, Y: }`. Каждое разрешённое значение в пространстве `mail.` делает
// функцию отправителем вида — один раз на функцию, сколько бы сравнений в ней
// ни стояло: два `if` в одном применителе не суть два отправителя.
func scanKindComparisons(
	fset *token.FileSet, rel, fn, param string, body *ast.BlockStmt,
	consts map[string]string, senders map[string][]MailSenderSite, census *MailSenderCensus,
) {
	if body == nil {
		return
	}
	accepted := map[string]int{} // вид → строка первого сравнения
	note := func(e ast.Expr) {
		census.ComparisonSites++
		val, ok := kindValueOf(e, consts)
		if !ok {
			census.Unresolved++
			return
		}
		if !strings.HasPrefix(val, MailKindNamespace) {
			return
		}
		if _, seen := accepted[val]; !seen {
			accepted[val] = fset.Position(e.Pos()).Line
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.BinaryExpr:
			if v.Op != token.EQL && v.Op != token.NEQ {
				return true
			}
			if isIdent(v.X, param) {
				note(v.Y)
			} else if isIdent(v.Y, param) {
				note(v.X)
			}
		case *ast.SwitchStmt:
			if v.Tag == nil || !isIdent(v.Tag, param) {
				return true
			}
			for _, st := range v.Body.List {
				cc, ok := st.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, e := range cc.List {
					note(e)
				}
			}
		}
		return true
	})
	for val, line := range accepted {
		senders[val] = append(senders[val], MailSenderSite{File: rel, Line: line, Func: fn})
	}
}

// kindValueOf — значение операнда сравнения: литерал, константа этого пакета
// либо селектор `pkg.Const` — все через словарь строковых констант корпуса.
func kindValueOf(e ast.Expr, consts map[string]string) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.Ident:
		s, ok := consts[v.Name]
		return s, ok
	case *ast.SelectorExpr:
		s, ok := consts[v.Sel.Name]
		return s, ok
	case *ast.ParenExpr:
		return kindValueOf(v.X, consts)
	}
	return "", false
}
