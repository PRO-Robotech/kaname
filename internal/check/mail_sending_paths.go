// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_sending_paths.go — пути, кладущие письмо в отправку (MAIL-47 приёмки
// `docs/specs/sub-phase-ID-MAIL-1-mail-delivery-acceptance.md`, воркспейс;
// §10 п. 19, порядок работ §11 шаг 6а; задача `kacho#2670`).
//
// # Предмет
//
// Видов письма у продукта ТРИ, и отправители у них разные (решение Р23):
// приглашение составляет и отправляет НАШ код — его предмет строка в нашей
// базе, о которой поставщик личности не знает; подтверждение адреса и
// восстановление доступа отправляет почтовый процесс ПОСТАВЩИКА — их
// предъявители принадлежат ему. Признак нарушения назван там же: вид письма с
// двумя отправителями — либо вид письма без единого.
//
// # Гейт утверждает ЗЕРКАЛО, и граница названа прямо
//
// Об отправителе, живущем в ЧУЖОМ процессе, дерево службы не говорит ничего: его
// здесь нет и быть не может, а проверка, требующая утверждения о непрочитанном,
// есть «ноль находок» без прочтения (приёмка, круг 6, замечание В3). Поэтому
// утверждается измеримое у НАС: путей отправки РОВНО ОДИН, он отправляет только
// приглашение, путей чужих видов — ноль. Значит вида с двумя отправителями нет.
// Что письма подтверждения и восстановления действительно уходят, утверждают
// MAIL-01/MAIL-04 на поднятом стенде — у приёмника, а не здесь.
//
// # Что считается ПУТЁМ ОТПРАВКИ — две стороны, и обе нужны
//
//  1. РАЗГОВОР С ПОЧТОВЫМ УЗЛОМ — объявление (функция, метод, переменная
//     пакета), в котором стоит ссылка на функцию транспорта, ОТКРЫВАЮЩУЮ
//     разговор. Ссылка, а не вызов: функция, взятая значением, открывает
//     разговор там, куда её передали. Путь — ОБЪЯВЛЕНИЕ, а не вызов: два
//     открывающих вызова в одной функции суть один путь (запасной узел,
//     повторное соединение), и счёт по вызовам назвал бы вторым отправителем
//     то, что им не является.
//  2. СЛОВАРЬ ОЧЕРЕДИ ОТПРАВКИ — литерал вида события `mail.<вид>.send`.
//     Отправка идёт через очередь в нашей базе (Р25), и вид письма объявляет
//     автор намерения. Вторая сторона ловит то, чего первая не видит by
//     construction: наш общий транспорт, которому очередь подала письмо
//     ЧУЖОГО вида, — путь один, а видов два.
//
// # Вид пути — по ИМЕНАМ его объявления, и неузнанное отвергается
//
// Вид читается из идентификаторов объявления пути (имя, тип получателя, типы
// параметров) закрытым словарём — никогда из комментариев и строк. Объявление,
// не называющее ни одного вида, — ОТКАЗ «вид не распознан», а не догадка:
// новый вид письма есть решение продукта, и разбор его не выдумывает. Названное
// двумя видами — тоже отказ. Путь, названный приглашением ложно, от счёта не
// уходит: второй путь приглашения — находка сам по себе.
//
// # Формы записи транспорта — известные и ОТВЕРГНУТЫЕ
//
// Известна одна форма, и она единственная в дереве: `net/smtp` с открывающими
// `Dial`, `NewClient`, `SendMail`, под своим именем пакета либо псевдонимом.
// Точечный импорт транспорта неразбираем (открывающий вызов не отличить от
// своей функции того же имени) — отказ. Импорт, чей путь говорит о почте и не
// является ни известным транспортом, ни `net/mail` (разбор адресов, разговора
// не открывает), ни пакетом своего модуля, — отказ «форма, которой разбор не
// знает». Иначе путь отправки уезжал бы из-под наблюдения, не давая ни
// красного, ни зелёного (`testing.md` §«Гейт на класс», п. 7).
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
// Разговор, собранный руками поверх голого сокета (команды протокола строками),
// и словарь очереди иной формы, чем `mail.<вид>.send`. Ни того, ни другого в
// дереве нет; появятся — распознаватель учится им тем же изменением.
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

// MailKind — вид письма продукта.
type MailKind string

// Закрытый словарь видов письма: видов три (§0 п. 1 приёмки), и четвёртый есть
// решение продукта, а не находка разбора.
const (
	// MailKindInvite — приглашение; отправитель — НАШ код (Р23).
	MailKindInvite MailKind = "приглашение"
	// MailKindVerification — подтверждение адреса; отправитель — почтовый
	// процесс поставщика (Р23).
	MailKindVerification MailKind = "подтверждение адреса"
	// MailKindRecovery — восстановление доступа; отправитель — почтовый
	// процесс поставщика (Р23).
	MailKindRecovery MailKind = "восстановление доступа"
)

// ourMailKind — единственный вид, чей отправитель наш код.
const ourMailKind = MailKindInvite

// mailKindWords — как вид называется в ИДЕНТИФИКАТОРАХ. Имена в коде латинские
// (ban #17), поэтому словарь одноязычный by construction.
var mailKindWords = []struct {
	kind MailKind
	re   *regexp.Regexp
}{
	{MailKindInvite, regexp.MustCompile(`(?i)invit`)},
	{MailKindVerification, regexp.MustCompile(`(?i)verif|confirm`)},
	{MailKindRecovery, regexp.MustCompile(`(?i)recover|reset`)},
}

// mailTransportOpeners — функции транспорта, ОТКРЫВАЮЩИЕ разговор с узлом, по
// пути импорта. `PlainAuth`, `CRAMMD5Auth` и типы пакета разговора не
// открывают и путём не являются.
var mailTransportOpeners = map[string]map[string]bool{
	"net/smtp": {"Dial": true, "NewClient": true, "SendMail": true},
}

// mailNotTransport — импорты с «почтой» в пути, разговора с узлом не
// открывающие: разбор и сборка адресов.
var mailNotTransport = map[string]bool{"net/mail": true}

// mailishImport — путь импорта, говорящий о почте.
var mailishImport = regexp.MustCompile(`(?i)smtp|mail`)

// mailQueueEvent — вид события очереди отправки.
var mailQueueEvent = regexp.MustCompile(`^mail\.([a-z][a-z0-9_]*)\.send$`)

// MailSendSite — путь отправки: объявление, открывающее разговор с узлом.
type MailSendSite struct {
	File string
	// Line — строка ПЕРВОЙ ссылки на открывающую функцию в объявлении.
	Line int
	// Path — объявление: `(*InviteMailSender).Send`, `deliver`, `var notify`.
	Path string
	// Opener — `net/smtp.NewClient`.
	Opener string
	// Kinds — виды, названные именами объявления: ноль — не распознан, больше
	// одного — неоднозначен.
	Kinds []MailKind
	// Names — имена, по которым читался вид; для текста находки.
	Names []string
}

// MailQueueKind — вид письма, объявленный словарём очереди отправки.
type MailQueueKind struct {
	File    string
	Line    int
	Literal string
	// Kind — пусто, если вид не распознан.
	Kind MailKind
}

// MailFormRefusal — форма почтового транспорта, которой разбор не знает.
type MailFormRefusal struct {
	File   string
	Line   int
	Import string
	Why    string
}

// MailSendingFacts — всё, что разбор одного исходника вынес о почтовой
// отправке, и объём осмотренного.
type MailSendingFacts struct {
	Sites   []MailSendSite
	Queue   []MailQueueKind
	Refused []MailFormRefusal
	// Imports — прочитано спецификаций импорта.
	Imports int
	// Literals — прочитано строковых литералов (кроме путей импорта).
	Literals int
}

// MailSendingVerdict — вердикт дерева.
type MailSendingVerdict struct {
	// Paths — путей отправки найдено.
	Paths int
	// Kinds — различных РАСПОЗНАННЫХ видов письма, которые кладутся в отправку.
	Kinds []MailKind
	// Findings — находки; пусто — зеркало держится.
	Findings []string
}

// ScanMailSending разбирает ОДИН исходник.
//
// ownModule — путь своего модуля: пакеты модуля с «почтой» в пути импорта —
// наш код, и разбор судит их содержимое там, где они лежат, а не имя импорта.
func ScanMailSending(file string, src []byte, ownModule string) (MailSendingFacts, error) {
	var facts MailSendingFacts
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution)
	if err != nil {
		return MailSendingFacts{}, err
	}

	// Локальное имя пакета → путь импорта транспорта.
	transport := map[string]string{}
	importLits := map[*ast.BasicLit]bool{}
	for _, spec := range f.Imports {
		facts.Imports++
		importLits[spec.Path] = true
		path, uerr := strconv.Unquote(spec.Path.Value)
		if uerr != nil {
			continue
		}
		line := fset.Position(spec.Pos()).Line
		if _, known := mailTransportOpeners[path]; known {
			switch {
			case spec.Name == nil:
				transport[path[strings.LastIndex(path, "/")+1:]] = path
			case spec.Name.Name == ".":
				facts.Refused = append(facts.Refused, MailFormRefusal{
					File: file, Line: line, Import: path,
					Why: "точечный импорт транспорта: открывающий вызов неотличим от своей " +
						"функции того же имени, и путь отправки уехал бы из-под наблюдения",
				})
			case spec.Name.Name == "_":
				// Импорт ради побочного действия ссылок не даёт — пути нет.
			default:
				transport[spec.Name.Name] = path
			}
			continue
		}
		if mailNotTransport[path] || !mailishImport.MatchString(path) {
			continue
		}
		if ownModule != "" && (path == ownModule || strings.HasPrefix(path, ownModule+"/")) {
			continue
		}
		facts.Refused = append(facts.Refused, MailFormRefusal{
			File: file, Line: line, Import: path,
			Why: "путь импорта говорит о почте, а форма транспорта разбору неизвестна — " +
				"научите распознаватель прежде, чем пользоваться ею",
		})
	}

	// Локальные имена, ЗАТЕНЯЮЩИЕ имя пакета транспорта. Разбор без
	// разрешения объектов не знает, чем является `smtp` в `smtp.NewClient()`,
	// поэтому объявленное в файле локально (переменная, параметр, результат,
	// приёмник) имя пакета транспорта исключается из ссылок в ЕГО области —
	// объявлении верхнего уровня, где оно заведено.
	for _, decl := range f.Decls {
		shadowed := shadowedNames(decl, transport)
		declPath, declNames := mailDeclIdentity(decl)
		var site *MailSendSite
		ast.Inspect(decl, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.BasicLit:
				if v.Kind != token.STRING || importLits[v] {
					return true
				}
				facts.Literals++
				lit, uerr := strconv.Unquote(v.Value)
				if uerr != nil {
					return true
				}
				if m := mailQueueEvent.FindStringSubmatch(lit); m != nil {
					kinds := mailKindsOf(m[1])
					q := MailQueueKind{File: file, Line: fset.Position(v.Pos()).Line, Literal: lit}
					if len(kinds) == 1 {
						q.Kind = kinds[0]
					}
					facts.Queue = append(facts.Queue, q)
				}
			case *ast.SelectorExpr:
				pkg, ok := v.X.(*ast.Ident)
				if !ok || shadowed[pkg.Name] {
					return true
				}
				path, ok := transport[pkg.Name]
				if !ok || !mailTransportOpeners[path][v.Sel.Name] {
					return true
				}
				if site == nil {
					site = &MailSendSite{
						File:   file,
						Line:   fset.Position(v.Pos()).Line,
						Path:   declPath,
						Opener: path + "." + v.Sel.Name,
						Names:  declNames,
						Kinds:  mailKindsOf(declNames...),
					}
				}
			}
			return true
		})
		if site != nil {
			facts.Sites = append(facts.Sites, *site)
		}
	}
	// Литералы вне объявлений верхнего уровня (их нет в Go, кроме путей
	// импорта) не существуют; перепись литералов полна.
	return facts, nil
}

// mailKindsOf — виды, названные именами. Порядок — порядок словаря.
func mailKindsOf(names ...string) []MailKind {
	var out []MailKind
	for _, w := range mailKindWords {
		for _, n := range names {
			if w.re.MatchString(n) {
				out = append(out, w.kind)
				break
			}
		}
	}
	return out
}

// mailDeclIdentity — как объявление называется и какими ИМЕНАМИ оно говорит о
// своём предмете: имя, тип получателя, типы параметров; у переменных и
// констант пакета — их имена и тип.
func mailDeclIdentity(decl ast.Decl) (string, []string) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		names := []string{d.Name.Name}
		path := d.Name.Name
		if d.Recv != nil && len(d.Recv.List) > 0 {
			recv := typeIdents(d.Recv.List[0].Type)
			names = append(names, recv...)
			if len(recv) > 0 {
				star := ""
				if _, ok := d.Recv.List[0].Type.(*ast.StarExpr); ok {
					star = "*"
				}
				path = fmt.Sprintf("(%s%s).%s", star, recv[0], d.Name.Name)
			}
		}
		if d.Type.Params != nil {
			for _, p := range d.Type.Params.List {
				names = append(names, typeIdents(p.Type)...)
			}
		}
		return path, names
	case *ast.GenDecl:
		var names []string
		for _, s := range d.Specs {
			switch sp := s.(type) {
			case *ast.ValueSpec:
				for _, n := range sp.Names {
					names = append(names, n.Name)
				}
				if sp.Type != nil {
					names = append(names, typeIdents(sp.Type)...)
				}
			case *ast.TypeSpec:
				names = append(names, sp.Name.Name)
			}
		}
		return d.Tok.String() + " " + strings.Join(names, ", "), names
	}
	return "", nil
}

// typeIdents — имена, называющие тип: `*pkg.InviteMailEvent` → InviteMailEvent.
func typeIdents(e ast.Expr) []string {
	var out []string
	ast.Inspect(e, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			out = append(out, v.Sel.Name)
			return false
		case *ast.Ident:
			out = append(out, v.Name)
		}
		return true
	})
	return out
}

// shadowedNames — имена пакетов транспорта, которые объявление заводит
// локально: параметром, результатом, приёмником, переменной, константой, типом.
func shadowedNames(decl ast.Decl, transport map[string]string) map[string]bool {
	out := map[string]bool{}
	if len(transport) == 0 {
		return out
	}
	mark := func(id *ast.Ident) {
		if id != nil {
			if _, ok := transport[id.Name]; ok {
				out[id.Name] = true
			}
		}
	}
	markFields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				mark(n)
			}
		}
	}
	ast.Inspect(decl, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.FuncDecl:
			markFields(v.Recv)
			markFields(v.Type.Params)
			markFields(v.Type.Results)
		case *ast.FuncLit:
			markFields(v.Type.Params)
			markFields(v.Type.Results)
		case *ast.AssignStmt:
			if v.Tok == token.DEFINE {
				for _, l := range v.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						mark(id)
					}
				}
			}
		case *ast.ValueSpec:
			// Переменная уровня пакета с именем пакета транспорта затеняет его
			// во всём файле; такую форму разбор не различает и отказом не
			// производит — компилятор отверг бы двойное объявление имени.
			if _, isTop := decl.(*ast.GenDecl); !isTop {
				for _, id := range v.Names {
					mark(id)
				}
			}
		case *ast.RangeStmt:
			if v.Tok == token.DEFINE {
				if id, ok := v.Key.(*ast.Ident); ok {
					mark(id)
				}
				if id, ok := v.Value.(*ast.Ident); ok {
					mark(id)
				}
			}
		case *ast.TypeSwitchStmt:
			if a, ok := v.Assign.(*ast.AssignStmt); ok {
				for _, l := range a.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						mark(id)
					}
				}
			}
		}
		return true
	})
	return out
}

// JudgeMailSending выносит вердикт по фактам всего дерева.
func JudgeMailSending(facts []MailSendingFacts) MailSendingVerdict {
	var (
		sites   []MailSendSite
		queue   []MailQueueKind
		refused []MailFormRefusal
	)
	for _, f := range facts {
		sites = append(sites, f.Sites...)
		queue = append(queue, f.Queue...)
		refused = append(refused, f.Refused...)
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
	sort.Slice(queue, func(i, j int) bool {
		if queue[i].File != queue[j].File {
			return queue[i].File < queue[j].File
		}
		return queue[i].Line < queue[j].Line
	})
	sort.Slice(refused, func(i, j int) bool {
		if refused[i].File != refused[j].File {
			return refused[i].File < refused[j].File
		}
		return refused[i].Line < refused[j].Line
	})

	v := MailSendingVerdict{Paths: len(sites)}
	kinds := map[MailKind]bool{}
	var ourPaths []string
	for _, s := range sites {
		coord := fmt.Sprintf("%s:%d %s (%s)", s.File, s.Line, s.Path, s.Opener)
		switch len(s.Kinds) {
		case 0:
			v.Findings = append(v.Findings, fmt.Sprintf(
				"%s — путь отправки: вид письма по его объявлению не распознан (прочитаны "+
					"имена %v). Видов у продукта три (приглашение · подтверждение адреса · "+
					"восстановление доступа), и четвёртый — решение продукта, а не находка "+
					"разбора: назовите вид в объявлении пути", coord, s.Names))
			continue
		case 1:
		default:
			v.Findings = append(v.Findings, fmt.Sprintf(
				"%s — объявление пути называет несколько видов письма %v (имена %v): у "+
					"пути вид ОДИН, и какой из названных он отправляет, из объявления не "+
					"видно", coord, s.Kinds, s.Names))
			continue
		}
		k := s.Kinds[0]
		kinds[k] = true
		if k != ourMailKind {
			v.Findings = append(v.Findings, fmt.Sprintf(
				"%s — наш путь отправляет вид «%s», а его отправитель — почтовый процесс "+
					"поставщика (решение Р23). Наш отправитель чужого вида есть второй "+
					"отправитель этого вида (Р1): какое письмо уйдёт, решал бы порядок, а не "+
					"решение", coord, k))
			continue
		}
		ourPaths = append(ourPaths, coord)
	}
	for _, q := range queue {
		coord := fmt.Sprintf("%s:%d %q", q.File, q.Line, q.Literal)
		switch {
		case q.Kind == "":
			v.Findings = append(v.Findings, fmt.Sprintf(
				"%s — словарь очереди отправки объявляет вид письма, который не "+
					"распознан. Видов у продукта три, и четвёртый — решение продукта: "+
					"назовите его", coord))
		case q.Kind != ourMailKind:
			kinds[q.Kind] = true
			v.Findings = append(v.Findings, fmt.Sprintf(
				"%s — словарь очереди отправки кладёт в отправку вид «%s», а его "+
					"отправитель — почтовый процесс поставщика (решение Р23): общий "+
					"транспорт, которому очередь подала письмо чужого вида, — это наш "+
					"второй отправитель этого вида", coord, q.Kind))
		default:
			kinds[q.Kind] = true
		}
	}
	switch {
	case len(ourPaths) == 0:
		v.Findings = append(v.Findings, fmt.Sprintf(
			"вид письма «%s» без производителя: путей отправки, отправляющих его, в "+
				"дереве ноль (§12 п. 3а приёмки). Его отправитель — наш код (Р23), и "+
				"другого у него нет: приглашение создаётся успешно, а письмо не уходит "+
				"никогда", ourMailKind))
	case len(ourPaths) > 1:
		v.Findings = append(v.Findings, fmt.Sprintf(
			"у вида «%s» путей отправки %d, а решение Р1 требует ОДНОГО — какой "+
				"сработает, решал бы порядок, а не решение:\n  %s",
			ourMailKind, len(ourPaths), strings.Join(ourPaths, "\n  ")))
	}
	for _, r := range refused {
		v.Findings = append(v.Findings, fmt.Sprintf("%s:%d — импорт %q: %s", r.File, r.Line, r.Import, r.Why))
	}
	for k := range kinds {
		v.Kinds = append(v.Kinds, k)
	}
	sort.Slice(v.Kinds, func(i, j int) bool { return v.Kinds[i] < v.Kinds[j] })
	return v
}
