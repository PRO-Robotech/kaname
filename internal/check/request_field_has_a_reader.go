// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// request_field_has_a_reader.go — разбор: у КАЖДОГО поля сообщения запроса есть
// читатель в прод-коде своей службы (задача kacho#1351).
//
// # Предмет
//
// Поле запроса, которое принимают и не читают, тише отказа: вызывающий получает
// УСПЕХ и уверен, что его параметр применён. Продукт обещает возможность,
// которой нет. Обнаруживается это не отладкой, а последствиями — в чужой.
//
// Норма контракта, которую гейт исполняет: у поля публичного запроса ОБЯЗАН
// быть читатель в прод-коде своей службы; отсутствие — находка, а не стиль.
// Законных исходов у непрочитанного поля три, четвёртого нет: реализовать ·
// отвергать явно, называя поле, синхронно · снять с контракта, зарезервировав
// И номер, И имя. «Молча принять и выбросить» исходом не является.
//
// # Почему разбор УЗЛОВ, а не поиск имени геттера по дереву
//
// Имя геттера НЕ уникально. Замер на `lane/wb-s4-remnant`, единицы названы:
//
//	# сообщений, объявляющих ОДИН И ТОТ ЖЕ геттер, — 57
//	grep -c 'func (x \*[A-Za-z]*) GetAccountId()' pkg/api/kaname/cloud/iam/v1/*.pb.go
//	# различных ИМЁН геттеров, встречающихся в прод-коде, — 150
//	git grep -ohE '\.Get[A-Za-z0-9_]+\(' -- '*.go' ':!*_test.go' ':!pkg/api' | sort -u | wc -l
//
// Полей в сообщениях запроса при этом 295 (перепись гейта, печатается каждым
// прогоном). То есть предикат по ИМЕНИ различает 150 значений там, где предмет
// имеет 295, а одно имя `GetAccountId` покрывает 57 разных полей: мёртвое поле
// выглядело бы живым оттого, что где-то рядом живёт его тёзка.
//
// Поэтому читатель опознаётся парой «получатель × селектор»: идентификатор, чей
// ОБЪЯВЛЕННЫЙ тип есть `*<пакет>.<Сообщение>`, и обращение к полю через него.
// Число 295 в этой шапке — снимок; живое печатает перепись.
//
// # Что читателем НЕ является, и это решение, а не упущение
//
//   - СБОРКА запроса (`&iamv1.XRequest{AccountId: …}`) — это сторона
//     ПРОИЗВОДИТЕЛЯ. Засчитав её, гейт разрешил бы полю жить оттого, что его
//     кто-то заполняет, — ровно то состояние, которое он заведён ловить;
//   - проба. Прод-код судится прод-кодом: поле, которое читает только проба,
//     арендатору не служит;
//   - сгенерированный код (`pkg/api/**`). Он объявляет геттер у КАЖДОГО поля
//     by construction, поэтому засчитанный читателем делает гейт тождественно
//     зелёным.
//
// # Граница названа: запрос, ушедший в вызов ЦЕЛИКОМ
//
// Запрос, переданный дальше целиком (`h.uc.Execute(ctx, req)`), прослеживается
// ровно до того вызываемого, чей параметр объявлен тем же типом: дальше цепочка
// обрывается на интерфейсе или на своей структуре входа. Такие передачи НЕ
// прощаются молча — они печатаются переписью отдельной величиной, потому что
// «поле прочитано» и «запрос уехал целиком, а поле, может, и не прочитано» —
// разные вердикты, и второй обязан быть видим.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
)

// ProtoField — поле сообщения контракта.
type ProtoField struct {
	// Name — имя поля в контракте (`account_id`).
	Name string
	// Getter — имя геттера, которое по этому имени порождает генератор
	// (`GetAccountId`). Вычисляется, а не угадывается; сходимость с
	// генератором проверяет предпосылка гейта.
	Getter string
	// Line — строка объявления в файле контракта.
	Line int
	// Deprecated — поле помечено `[deprecated = true]`.
	//
	// Пометка И ЕСТЬ объявление «не применяется»: генератор проносит её в
	// клиентские стабы, поэтому вызывающий предупреждён — а именно
	// непредупреждённость и есть предмет запрета. Такое поле выводится из
	// популяции и печатается переписью отдельно; снимут пометку — гейт
	// начнёт судить его снова, то есть послабление истекает само.
	Deprecated bool
}

// ProtoMessage — сообщение контракта и его поля верхнего уровня.
type ProtoMessage struct {
	Name   string
	File   string
	Fields []ProtoField
}

// RequestUse — употребление сообщения как запроса глагола.
type RequestUse struct {
	File    string
	Service string
	RPC     string
	Message string
	// Internal — глагол объявлен службой с приставкой `Internal`, то есть на
	// внешний маршрутизатор не попадает (ban #6).
	Internal bool
	// ScopeFields — поля, названные `scope_extractor.from_request_field`.
	// У них читатель есть, и он объявлен ЗДЕСЬ ЖЕ: край берёт по этому имени
	// объект, про который спрашивает модель прав. Прод-кода службы такое поле
	// может не касаться вовсе — и это не «принято-и-проигнорировано», а
	// разделение обязанностей между краем и службой.
	ScopeFields []string
}

// ProtoSurface — то, что разбор вынул из одного файла контракта.
type ProtoSurface struct {
	Requests []RequestUse
	Messages []ProtoMessage
}

// GoCamelCase переводит имя поля контракта в имя геттера так же, как это делает
// генератор: разделитель снимается, следующая за ним буква поднимается в
// верхний регистр, цифры остаются как есть.
//
// Начальные заглавные НЕ схлопываются в инициализмы: генератор даёт `AccountId`,
// а не `AccountID`, и гейт обязан спрашивать то имя, которое в дереве есть.
func GoCamelCase(field string) string {
	var b strings.Builder
	up := true
	for _, r := range field {
		if r == '_' {
			up = true
			continue
		}
		if up && r >= 'a' && r <= 'z' {
			b.WriteRune(r - ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
		up = false
	}
	return b.String()
}

// ProtoSurfaceIn разбирает один файл контракта.
//
// Разбор идёт по ГЛУБИНЕ СКОБОК, а не по первой закрывающей на своей строке:
// пустое сообщение записывают одной строкой (`message X {}`), и построчный
// разбор проглатывал бы его тело вместе со следующим сообщением, приписывая
// запросу поля ответа. Это наблюдалось: первая редакция замера дала две находки,
// обе ложные и обе этой формы.
func ProtoSurfaceIn(file, src string) (ProtoSurface, error) {
	var out ProtoSurface
	lines := strings.Split(src, "\n")

	// свернуть к телу блока, начинающегося на строке start
	bodyOf := func(start int) (body []int, next int) {
		depth := 0
		for i := start; i < len(lines); i++ {
			depth += strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
			if i > start || depth > 0 {
				body = append(body, i)
			}
			if depth <= 0 && i >= start {
				return body, i + 1
			}
		}
		return body, len(lines)
	}

	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		switch {
		case strings.HasPrefix(line, "service ") && strings.Contains(line, "{"):
			name := blockName(line, "service ")
			internal := strings.HasPrefix(name, "Internal")
			body, next := bodyOf(i)
			// Поле области приписывается ПОСЛЕДНЕМУ объявленному глаголу:
			// `scope_extractor` стоит внутри его блока настроек, и другого
			// хозяина у него в этом месте файла нет.
			cur := -1
			for _, j := range body {
				if m := rpcRequest(lines[j]); m != "" {
					out.Requests = append(out.Requests, RequestUse{
						File: file, Service: name, RPC: rpcName(lines[j]),
						Message: m, Internal: internal,
					})
					cur = len(out.Requests) - 1
					continue
				}
				if f := scopeField(lines[j]); f != "" && cur >= 0 {
					out.Requests[cur].ScopeFields = append(out.Requests[cur].ScopeFields, f)
				}
			}
			i = next
		case strings.HasPrefix(line, "message ") && strings.Contains(line, "{"):
			name := blockName(line, "message ")
			body, next := bodyOf(i)
			msg := ProtoMessage{Name: name, File: file}
			depth := 0
			for _, j := range body {
				text := lines[j]
				trimmed := strings.TrimSpace(text)
				skip := trimmed == "" ||
					strings.HasPrefix(trimmed, "//") ||
					strings.HasPrefix(trimmed, "reserved") ||
					declaresContractOption(trimmed) ||
					strings.HasPrefix(trimmed, "}")
				// поля верхнего уровня и поля внутри `oneof` — и те и другие
				// получают геттер у сообщения, поэтому глубина `oneof` не
				// выводит их из популяции; глубина блока настроек — выводит.
				if !skip && depth >= 0 && !strings.HasPrefix(trimmed, "oneof") {
					if f, ok := protoFieldOf(trimmed); ok {
						f.Line = j + 1
						msg.Fields = append(msg.Fields, f)
					}
				}
				if declaresContractOption(trimmed) || depth > 0 {
					depth += strings.Count(text, "{") - strings.Count(text, "}")
					if depth < 0 {
						depth = 0
					}
				}
			}
			out.Messages = append(out.Messages, msg)
			i = next
		default:
			i++
		}
	}
	return out, nil
}

// scopeField достаёт имя поля из `from_request_field: "<имя>"`.
func scopeField(line string) string {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "//") || !strings.Contains(t, "from_request_field") {
		return ""
	}
	open := strings.Index(t, "\"")
	if open < 0 {
		return ""
	}
	rest := t[open+1:]
	closeIdx := strings.Index(rest, "\"")
	if closeIdx < 0 {
		return ""
	}
	return rest[:closeIdx]
}

func blockName(line, kw string) string {
	rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), kw))
	if idx := strings.IndexAny(rest, " \t{"); idx >= 0 {
		rest = rest[:idx]
	}
	return rest
}

func rpcName(line string) string {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "rpc ") {
		return ""
	}
	rest := strings.TrimSpace(strings.TrimPrefix(t, "rpc "))
	if idx := strings.IndexAny(rest, " \t("); idx >= 0 {
		rest = rest[:idx]
	}
	return rest
}

func rpcRequest(line string) string {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "rpc ") {
		return ""
	}
	open := strings.Index(t, "(")
	closeIdx := strings.Index(t, ")")
	if open < 0 || closeIdx < open {
		return ""
	}
	arg := strings.TrimSpace(t[open+1 : closeIdx])
	arg = strings.TrimPrefix(arg, "stream ")
	arg = strings.TrimSpace(arg)
	if dot := strings.LastIndex(arg, "."); dot >= 0 {
		arg = arg[dot+1:]
	}
	return arg
}

// protoFieldOf распознаёт объявление поля: `<тип> <имя> = <номер>`.
// declaresContractOption — строка объявляет ОПЦИЮ контракта, а не поле `optional`.
//
// Прежний предикат брал приставку `option` и потому глотал `optional int32 x = 3;`:
// слово «optional» начинается с «option». Два поля уходили из-под наблюдения, и
// вердикт был не красным и не зелёным — он МОЛЧАЛ.
//
// Различает следующий знак: у опции за словом идёт пробел либо скобка
// (`option (kacho.api.v1.foo) = ...`), у поля — буква.
func declaresContractOption(trimmed string) bool {
	const kw = "option"
	if !strings.HasPrefix(trimmed, kw) {
		return false
	}
	rest := trimmed[len(kw):]
	if rest == "" {
		return true
	}
	c := rest[0]
	return c == ' ' || c == '\t' || c == '('
}

func protoFieldOf(line string) (ProtoField, bool) {
	eq := strings.Index(line, "=")
	if eq < 0 {
		return ProtoField{}, false
	}
	head := strings.TrimSpace(line[:eq])
	tail := strings.TrimSpace(line[eq+1:])
	if tail == "" || tail[0] < '0' || tail[0] > '9' {
		return ProtoField{}, false
	}
	// `map<string, string> labels` — запятая внутри типа не делит поля.
	// После среза остаётся ОДНО слово — имя поля, и требовать двух здесь нельзя:
	// именно так девятнадцать полей `labels` уходили из-под наблюдения молча.
	parametrised := strings.Contains(head, "<")
	if idx := strings.LastIndex(head, ">"); idx >= 0 {
		head = strings.TrimSpace(head[idx+1:])
	}
	parts := strings.Fields(head)
	switch {
	case len(parts) == 0:
		return ProtoField{}, false
	case len(parts) == 1 && !parametrised:
		// голое слово без типа полем не является: `option java_package = "x"`
		// сюда не доходит, но строка вида `foo = 1` — не объявление поля
		return ProtoField{}, false
	}
	name := parts[len(parts)-1]
	for _, r := range name {
		ok := r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return ProtoField{}, false
		}
	}
	return ProtoField{
		Name:       name,
		Getter:     "Get" + GoCamelCase(name),
		Deprecated: strings.Contains(line, "deprecated") && strings.Contains(line, "true"),
	}, true
}

// RequestFieldRead — прочтение поля запроса в прод-коде.
type RequestFieldRead struct {
	Message string
	// Selector — имя, через которое обратились: `GetAccountId` либо `AccountId`.
	Selector string
	File     string
	Line     int
}

// RequestFieldReadsIn разбирает один прод-файл Go и возвращает прочтения полей
// запроса вместе с перечнем запросов, ушедших в вызов целиком.
//
// Идентификатор считается запросом, когда его ОБЪЯВЛЕННЫЙ тип есть указатель на
// известное сообщение: параметр функции, результат, объявление переменной либо
// присваивание от составного литерала. Псевдоним, связанный присваиванием от
// такого идентификатора, наследует связь — ровно та форма, которой пользуются
// обработчики.
func RequestFieldReadsIn(file, src string, messages map[string]bool) ([]RequestFieldRead, []string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, nil, fmt.Errorf("разбор %s: %w", file, err)
	}

	w := &requestWalk{file: file, fset: fset, messages: messages, seenWhole: map[string]bool{}}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		scope := map[string]string{}
		w.bindFields(scope, fn.Type.Params)
		w.bindFields(scope, fn.Type.Results)
		w.walk(fn.Body, scope)
	}
	return w.reads, w.whole, nil
}

// requestWalk — обход с ОБЛАСТЬЮ ВИДИМОСТИ на функцию.
//
// Область на функцию, а не на файл, — свойство несущее, а не аккуратность.
// Обработчики одного файла называют параметр одинаково (`req`), и плоская
// карта «идентификатор → сообщение» на весь файл оставляет последнюю связь:
// прочтения ВСЕХ глаголов приписываются ОДНОМУ сообщению. Наблюдалось на первой
// редакции этого разбора: 31 прочтение из `api/user/handler.go` — все приписаны
// `GetUserRequest`, хотя принадлежали пяти разным сообщениям, — и 230 полей
// объявлены мёртвыми при живых читателях. Числа исторические: они о СЛОМАННОМ
// разборе, перемерить их нечем, и ось C инъекции стережёт возврат этой формы.
type requestWalk struct {
	file      string
	fset      *token.FileSet
	messages  map[string]bool
	reads     []RequestFieldRead
	whole     []string
	seenWhole map[string]bool
}

// messageOf — имя сообщения по СИНТАКСИЧЕСКОМУ типу `*<пакет>.<Сообщение>`.
func (w *requestWalk) messageOf(e ast.Expr) string {
	star, ok := e.(*ast.StarExpr)
	if !ok {
		return ""
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if _, ok := sel.X.(*ast.Ident); !ok {
		return ""
	}
	if w.messages[sel.Sel.Name] {
		return sel.Sel.Name
	}
	return ""
}

func (w *requestWalk) bindFields(scope map[string]string, fl *ast.FieldList) {
	if fl == nil {
		return
	}
	for _, fld := range fl.List {
		m := w.messageOf(fld.Type)
		if m == "" {
			continue
		}
		for _, n := range fld.Names {
			if n.Name != "_" {
				scope[n.Name] = m
			}
		}
	}
}

// walk обходит тело, ведя свою область. Вложенная функция получает КОПИЮ
// области — она замыкает внешние имена, но её собственные наружу не выходят.
func (w *requestWalk) walk(body ast.Node, scope map[string]string) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.FuncLit:
			inner := make(map[string]string, len(scope))
			for k, val := range scope {
				inner[k] = val
			}
			w.bindFields(inner, v.Type.Params)
			w.bindFields(inner, v.Type.Results)
			if v.Body != nil {
				w.walk(v.Body, inner)
			}
			return false
		case *ast.ValueSpec:
			if m := w.messageOf(v.Type); m != "" {
				for _, n := range v.Names {
					if n.Name != "_" {
						scope[n.Name] = m
					}
				}
			}
		case *ast.AssignStmt:
			w.bindAssign(scope, v)
		case *ast.SelectorExpr:
			id, ok := v.X.(*ast.Ident)
			if !ok {
				return true
			}
			m, ok := scope[id.Name]
			if !ok {
				return true
			}
			w.reads = append(w.reads, RequestFieldRead{
				Message: m, Selector: v.Sel.Name,
				File: w.file, Line: w.fset.Position(v.Sel.Pos()).Line,
			})
		case *ast.CallExpr:
			for _, arg := range v.Args {
				id, ok := arg.(*ast.Ident)
				if !ok {
					continue
				}
				m, ok := scope[id.Name]
				if !ok {
					continue
				}
				key := m + "|" + w.file
				if !w.seenWhole[key] {
					w.seenWhole[key] = true
					w.whole = append(w.whole, m)
				}
			}
		}
		return true
	})
}

func (w *requestWalk) bindAssign(scope map[string]string, v *ast.AssignStmt) {
	for i, rhs := range v.Rhs {
		if i >= len(v.Lhs) {
			break
		}
		lhs, ok := v.Lhs[i].(*ast.Ident)
		if !ok || lhs.Name == "_" {
			continue
		}
		switch r := rhs.(type) {
		case *ast.UnaryExpr: // &iamv1.XRequest{…}
			if cl, ok := r.X.(*ast.CompositeLit); ok {
				if sel, ok := cl.Type.(*ast.SelectorExpr); ok && w.messages[sel.Sel.Name] {
					scope[lhs.Name] = sel.Sel.Name
				}
			}
		case *ast.Ident: // псевдоним: r := req
			if m, ok := scope[r.Name]; ok {
				scope[lhs.Name] = m
			}
		}
	}
}

// RequestFieldCensus — перепись обхода и находки.
type RequestFieldCensus struct {
	ProtoFiles     int
	GoFiles        int
	Services       int
	RequestUses    int
	Messages       int
	Fields         int
	PublicFields   int
	InternalFields int
	// WholePassed — сообщений, ушедших в вызов целиком: их поля судить нечем,
	// и они выведены из вердикта ЯВНО, а не прощены молча.
	WholePassed   int
	EscapedFields int
	// ScopeReadFields — полей, чей читатель — край (`scope_extractor`).
	ScopeReadFields int
	// DeprecatedFields — полей, помеченных `deprecated`.
	DeprecatedFields int
	Findings         []string
}

// Summary — перепись строкой: «ноль находок» обязано быть отличимо от «ноль
// прочитанного», поэтому объём осмотренного печатается всегда.
func (c RequestFieldCensus) Summary() string {
	return fmt.Sprintf(
		"файлов контракта %d · прод-файлов Go %d · служб %d · глаголов %d · "+
			"сообщений запроса %d · полей %d (публичных %d, внутренних %d) · "+
			"из них ВНЕ вердикта: ушли в вызов целиком %d сообщений / %d полей, "+
			"читает край %d, помечено deprecated %d · СУЖДЕНО полей %d · находок %d",
		c.ProtoFiles, c.GoFiles, c.Services, c.RequestUses, c.Messages,
		c.Fields, c.PublicFields, c.InternalFields,
		c.WholePassed, c.EscapedFields, c.ScopeReadFields, c.DeprecatedFields,
		c.Fields-c.EscapedFields-c.ScopeReadFields-c.DeprecatedFields, len(c.Findings))
}

// JudgeRequestFieldReaders сводит популяцию контракта с прочтениями прод-кода.
//
// Судится ПОЛЕ, а не сообщение: сообщение, у которого прочитана половина полей,
// проходило бы, и непрочитанная половина осталась бы невидимой.
func JudgeRequestFieldReaders(
	surfaces []ProtoSurface,
	reads []RequestFieldRead,
	whole []string,
	protoFiles, goFiles int,
) RequestFieldCensus {
	census := RequestFieldCensus{ProtoFiles: protoFiles, GoFiles: goFiles}

	msgFields := map[string][]ProtoField{}
	msgFile := map[string]string{}
	services := map[string]bool{}
	usedBy := map[string][]RequestUse{}

	for _, s := range surfaces {
		for _, m := range s.Messages {
			msgFields[m.Name] = m.Fields
			msgFile[m.Name] = m.File
		}
		for _, u := range s.Requests {
			services[u.Service] = true
			usedBy[u.Message] = append(usedBy[u.Message], u)
		}
	}
	census.Services = len(services)

	readSel := map[string]bool{} // "<сообщение>|<селектор>"
	for _, r := range reads {
		readSel[r.Message+"|"+r.Selector] = true
	}
	wholeSeen := map[string]bool{}
	for _, m := range whole {
		wholeSeen[m] = true
	}

	var msgNames []string
	for m := range usedBy {
		msgNames = append(msgNames, m)
	}
	sort.Strings(msgNames)

	for _, m := range msgNames {
		fields, known := msgFields[m]
		if !known {
			// сообщение объявлено вне разбираемого дерева контракта —
			// об его полях гейт не утверждает ничего
			continue
		}
		census.Messages++
		census.RequestUses += len(usedBy[m])
		internalOnly := true
		scope := map[string]bool{}
		for _, u := range usedBy[m] {
			if !u.Internal {
				internalOnly = false
			}
			for _, f := range u.ScopeFields {
				scope[f] = true
			}
		}
		escaped := wholeSeen[m]
		if escaped {
			census.WholePassed++
		}
		for _, f := range fields {
			census.Fields++
			if internalOnly {
				census.InternalFields++
			} else {
				census.PublicFields++
			}
			switch {
			case escaped:
				census.EscapedFields++
				continue
			case scope[f.Name]:
				census.ScopeReadFields++
				continue
			case f.Deprecated:
				census.DeprecatedFields++
				continue
			}
			if readSel[m+"|"+f.Getter] || readSel[m+"|"+GoCamelCase(f.Name)] {
				continue
			}
			lane := "публичный"
			if internalOnly {
				lane = "внутренний"
			}
			census.Findings = append(census.Findings, fmt.Sprintf(
				"%s:%d %s.%s (%s, %s) — читателя в прод-коде нет: "+
					"вызывающий получает УСПЕХ, а параметр не применён",
				msgFile[m], f.Line, m, f.Name, f.Getter, lane))
		}
	}
	sort.Strings(census.Findings)
	return census
}

// GeneratedGettersIn возвращает пары «сообщение|геттер», объявленные
// сгенерированным файлом, — в форме `<Сообщение>|<Геттер>`.
//
// Читается ОБЪЯВЛЕНИЕ метода узлом разбора, а не строка с `func (x *`: имя
// сообщения встречается в этом файле и комментарием, и строковым литералом
// дескриптора, и поиск по тексту засчитал бы их.
func GeneratedGettersIn(src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "generated.go", src, parser.SkipObjectResolution)
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		if !strings.HasPrefix(fn.Name.Name, "Get") {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		id, ok := star.X.(*ast.Ident)
		if !ok {
			continue
		}
		out = append(out, id.Name+"|"+fn.Name.Name)
	}
	return out
}
