// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service

// shadow_coverage_gate_test.go — вопрос, который спрашивают у движка, обязан
// спрашиваться и у формы E.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ГЕЙТ, А НЕ ПЕРЕЧЕНЬ ПРОБ
//
// Проба утверждает свойство вопросов, которые УЖЕ написаны. Свойство, которое
// здесь требуется, — про вопросы, которых ещё нет: следующий метод, спросивший
// движок и не спросивший форму E, обязан покраснеть сам, без того чтобы кто-то
// вспомнил дописать ему пробу. Именно так класс и завёлся: сравнение написали у
// одного обработчика, остальные вопросы остались без спрашивающего, и «формы
// сходятся» годилось бы как утверждение, пока никто не пересчитает вопросы.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ГЕЙТ СЧИТАЕТ ВОПРОСОМ К ДВИЖКУ
//
// ВЫЗОВ метода на порте движка (`s.relations.<...>(...)`) — прямой либо через
// другие методы того же типа. Не «упоминание поля»: проверка порта на nil и
// приведение его к расширенному интерфейсу вопросом не являются, и требовать от
// них сравнения значило бы ловить форму вместо существа. Законный близнец такой
// формы в дереве есть (`StructuralFallbackReachable`), и гейт обязан на нём
// МОЛЧАТЬ — это его отрицательный контроль, и он утверждается ниже числом.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serviceReceiverType — тип, чьи методы отвечают вопросы решения о доступе.
const serviceReceiverType = "AuthorizeService"

// methodFacts — что метод делает своими руками.
type methodFacts struct {
	name       string
	exported   bool
	asksEngine bool     // зовёт метод на порте движка САМ
	asksShadow bool     // трогает теневое сравнение САМ
	calls      []string // методы того же типа, которые он зовёт
	pos        string
}

// collectServiceMethods разбирает не-тестовые файлы пакета и собирает факты о
// методах типа serviceReceiverType.
func collectServiceMethods(t *testing.T, dir string) (map[string]*methodFacts, int) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("разбор пакета %s: %v", dir, err)
	}
	out := make(map[string]*methodFacts)
	files := 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			files++
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 || fn.Body == nil {
					continue
				}
				recvName, recvType := receiverOf(fn)
				if recvType != serviceReceiverType {
					continue
				}
				mf := &methodFacts{
					name:     fn.Name.Name,
					exported: fn.Name.IsExported(),
					pos:      fset.Position(fn.Pos()).String(),
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					// s.relations.<method>(...) — вопрос к движку.
					if inner, ok := sel.X.(*ast.SelectorExpr); ok {
						if isIdent(inner.X, recvName) && inner.Sel.Name == "relations" {
							mf.asksEngine = true
						}
						// s.shadow.<method>(...) — обращение к сравнению.
						if isIdent(inner.X, recvName) && inner.Sel.Name == "shadow" {
							mf.asksShadow = true
						}
						return true
					}
					// s.<method>(...) — вызов соседнего метода того же типа.
					if isIdent(sel.X, recvName) {
						mf.calls = append(mf.calls, sel.Sel.Name)
					}
					return true
				})
				out[mf.name] = mf
			}
		}
	}
	if files == 0 {
		t.Fatalf("в %s не прочитано ни одного файла — «ноль находок» тогда означало бы "+
			"«ноль прочитанного»", dir)
	}
	return out, files
}

func receiverOf(fn *ast.FuncDecl) (name, typ string) {
	f := fn.Recv.List[0]
	if len(f.Names) > 0 {
		name = f.Names[0].Name
	}
	switch e := f.Type.(type) {
	case *ast.StarExpr:
		if id, ok := e.X.(*ast.Ident); ok {
			typ = id.Name
		}
	case *ast.Ident:
		typ = e.Name
	}
	return name, typ
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && name != "" && id.Name == name
}

// reaches — достигает ли метод свойства (движок / сравнение) сам или через соседей.
func reaches(methods map[string]*methodFacts, name string, own func(*methodFacts) bool,
	seen map[string]bool) bool {
	m, ok := methods[name]
	if !ok || seen[name] {
		return false
	}
	seen[name] = true
	if own(m) {
		return true
	}
	for _, callee := range m.calls {
		if reaches(methods, callee, own, seen) {
			return true
		}
	}
	return false
}

// ГЕЙТ: каждый вопрос к движку задаётся и форме E.
func TestEveryEngineAskingQuestionAlsoAsksTheShadowForm(t *testing.T) {
	methods, files := collectServiceMethods(t, ".")

	var asking, comparing, notAsking int
	var findings []string
	for name, m := range methods {
		engine := reaches(methods, name, func(f *methodFacts) bool { return f.asksEngine }, map[string]bool{})
		if !m.exported {
			continue
		}
		if !engine {
			notAsking++
			continue
		}
		asking++
		if reaches(methods, name, func(f *methodFacts) bool { return f.asksShadow }, map[string]bool{}) {
			comparing++
			continue
		}
		findings = append(findings, m.name+" ("+m.pos+")")
	}

	// Перепись печатается ВСЕГДА: «ноль находок» обязано быть отличимо от «ноль
	// прочитанного», а «гейт зелен» — от «гейту нечего было рассматривать».
	t.Logf("осмотрено: файлов %d, методов типа %s %d; из них внешних, спрашивающих движок — %d "+
		"(сравнивают %d), внешних без вопроса к движку — %d",
		files, serviceReceiverType, len(methods), asking, comparing, notAsking)

	// Проверка СВОЕЙ предпосылки. Гейт обоснован тем, что в дереве есть обе формы:
	// вопросы к движку и внешние методы, которые его ни о чём не спрашивают. Если
	// не стало ни тех, ни других — молчание гейта означает не соблюдение правила, а
	// исчезновение его предмета.
	if asking == 0 {
		t.Fatalf("вопросов к движку не найдено вовсе — предпосылка гейта исчезла: он молчит "+
			"не потому, что правило соблюдено, а потому, что рассматривать нечего (%d методов)",
			len(methods))
	}
	if notAsking == 0 {
		t.Fatal("не найдено ни одного внешнего метода БЕЗ вопроса к движку — исчез " +
			"отрицательный контроль: гейт, который метит всё подряд, неотличим от гейта, " +
			"ловящего существо")
	}

	if len(findings) > 0 {
		t.Fatalf("вопрос уходит движку, но не форме E: %s\n"+
			"Вопрос без спрашивающего оставляет сходимость измеренной на другом подмножестве: "+
			"«расхождений нет» тогда верно про те вопросы, которые сравниваются, и молчит про "+
			"остальные. Спросите форму E рядом (service/shadow_port.go, askShadow*) — либо, "+
			"если она этого вопроса не умеет, назовите остаток в реестре ниже с предикатом "+
			"снятия.", strings.Join(findings, ", "))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// РЕЕСТР ВОСЬМИ ВОПРОСОВ
//
// Гейт выше держит вопросы, которые отвечает ОДИН use-case. Вопросов решения о
// доступе у сервиса больше, и два из них форма E сегодня не умеет. Молчаливого
// пропуска у них быть не должно: остаток называется ПОИМЁННО и снабжён
// предикатом, который срабатывает от ВНЕШНЕГО факта — от того, что форма E
// научилась новому вопросу, — а не от чьей-то памяти.

// decisionQuestion — вопрос решения о доступе, который сервис отвечает.
type decisionQuestion struct {
	// rpc — как вопрос называется на поверхности.
	rpc string
	// answeredBy — координата, где ответ формируется.
	answeredBy string
	// comparedVia — метод AuthorizeService, у которого стоит сравнение; пусто у
	// остатка.
	comparedVia string
	// remainderWhy — почему форма E сегодня не отвечает; пусто у сравниваемых.
	remainderWhy string
}

func decisionQuestions() []decisionQuestion {
	return []decisionQuestion{
		{rpc: "AuthorizeService.Check", answeredBy: "service.AuthorizeService.check", comparedVia: "Check"},
		{rpc: "AuthorizeService.BatchCheck", answeredBy: "service.AuthorizeService.check", comparedVia: "BatchCheck"},
		{rpc: "AuthorizeService.ListObjects", answeredBy: "service.AuthorizeService.ListObjects", comparedVia: "ListObjects"},
		{rpc: "AuthorizeService.ListSubjects", answeredBy: "service.AuthorizeService.ListSubjects", comparedVia: "ListSubjects"},
		{rpc: "AuthorizeService.ExpandRelations", answeredBy: "service.AuthorizeService.ExpandRelations", comparedVia: "ExpandRelations"},
		{rpc: "InternalIAMService.Check", answeredBy: "service.AuthorizeService.CheckRelation", comparedVia: "CheckRelation"},
		{
			rpc:        "AuthorizeService.WhoAmI",
			answeredBy: "apps/kacho/api/authorize/whoami.go",
			remainderWhy: "вопрос не про объект: спрашивается уровень вызывающего на кластере, " +
				"а кластер не входит в типы, о которых форма E умеет говорить (у него нет " +
				"строки-зеркала и цепи областей)",
		},
		{
			rpc:        "InternalIAMService.GetRoleCompiled",
			answeredBy: "apps/kacho/api/internal_iam/get_role_compiled.go",
			remainderWhy: "вопрос не про субъекта: спрашивается проекция РОЛИ в глаголы, " +
				"а форма E отвечает про пару субъект-объект",
		},
	}
}

// formEQuestionCount — сколько вопросов форма E умеет отвечать СЕГОДНЯ.
//
// Это и есть предикат снятия остатка: он срабатывает от внешнего факта — формы E,
// научившейся новому, — а не от того, вспомнит ли кто-нибудь пересмотреть реестр.
const formEQuestionCount = 4

// ГЕЙТ: реестр вопросов не расходится с деревом, а остаток истекает сам.
func TestEveryDecisionQuestionIsEitherComparedOrDeclaredWithAPredicate(t *testing.T) {
	methods, _ := collectServiceMethods(t, ".")

	var compared, remainder int
	for _, q := range decisionQuestions() {
		switch {
		case q.comparedVia != "":
			compared++
			m, ok := methods[q.comparedVia]
			if !ok {
				t.Errorf("реестр называет %q сравниваемым через %s — такого метода в дереве нет",
					q.rpc, q.comparedVia)
				continue
			}
			if !reaches(methods, m.name, func(f *methodFacts) bool { return f.asksShadow }, map[string]bool{}) {
				t.Errorf("реестр объявляет %q сравниваемым, но %s форму E не спрашивает (%s) — "+
					"объявление, разошедшееся с деревом, читается как выполненное обещание",
					q.rpc, q.comparedVia, m.pos)
			}
		case q.remainderWhy == "":
			t.Errorf("вопрос %q не сравнивается и не назван остатком — молчаливый пропуск: "+
				"он неотличим от забытого", q.rpc)
		default:
			remainder++
			if _, err := os.Stat(filepath.Join("..", q.answeredBy)); err != nil {
				t.Errorf("реестр называет остаток %q отвечаемым в %s — координаты нет: %v",
					q.rpc, q.answeredBy, err)
			}
		}
	}

	got := countFormEQuestions(t, filepath.Join("..", "repo", "kacho", "pg", "relverdict"))
	t.Logf("осмотрено: вопросов решения о доступе %d (сравниваются %d, остаток %d); "+
		"вопросов, которые умеет форма E, — %d", len(decisionQuestions()), compared, remainder, got)

	if got != formEQuestionCount {
		t.Fatalf("форма E отвечает %d вопросов, реестр рассчитан на %d.\n"+
			"Это и есть истечение остатка: если вопросов стало БОЛЬШЕ — назовите, какой из "+
			"объявленных остатков закрыт, и спросите форму E рядом с движком; если МЕНЬШЕ — "+
			"сравнение опирается на то, чего уже нет.", got, formEQuestionCount)
	}
}

// countFormEQuestions считает вопросы формы E — экспортированные функции пакета,
// принимающие транзакцию чтения.
//
// Считается ПРЕДМЕТ, а не имя: вопрос формы E — это функция, задающая запрос к
// её собственным таблицам, и распознаётся она по тому, что берёт транзакцию.
// Сборщик источника (`NewAsker`) её не берёт и вопросом не считается.
func countFormEQuestions(t *testing.T, dir string) int {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("разбор формы E (%s): %v", dir, err)
	}
	n := 0
	read := 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			read++
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || !fn.Name.IsExported() {
					continue
				}
				for _, param := range fn.Type.Params.List {
					if sel, ok := param.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Tx" {
						n++
						break
					}
				}
			}
		}
	}
	if read == 0 {
		t.Fatalf("в %s не прочитано ни одного файла", dir)
	}
	return n
}
