// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_verbs_pass_the_limiter_test.go — гейт на КЛАСС (приёмка ID-MAIL-1,
// Р22, §10 п. 17; MAIL-25, MAIL-42; задача продукта #1775): каждый глагол
// НАШИХ контрактов, отправляющий письмо, проходит через ограничитель частоты,
// и перечень таких глаголов ВЫВОДИТСЯ из контрактов, а не выписан.
//
// # Как выводится перечень
//
// Контракт → обработчик → use-case → писатель очереди. Гейт читает дескрипторы
// служб контракта (`protoregistry`), находит в дереве `internal/apps/kaname/api`
// типы-обработчики (структуры, вкладывающие `Unimplemented<Служба>Server`),
// по телу метода-RPC узнаёт поле use-case'а, которое он зовёт, и по методам
// этого use-case'а — зовёт ли тот `EmitInviteMail`. Глагол контракта, чей
// use-case ставит намерение письма, и есть «глагол, отправляющий письмо».
// Выписанный перечень разошёлся бы с деревом молча: следующий такой глагол
// завели бы без ограничения, и заметить это было бы неоткуда.
//
// # Что утверждается
//
//  1. глаголов, отправляющих письмо, найдено больше нуля — иначе перечень
//     пуст, и «все проходят» зеленело бы на пустом обходе;
//  2. КАЖДОЕ намерение письма в use-case'ах несёт поле `Limit` — ограничение
//     едет с намерением, а не подразумевается;
//  3. единственный писатель очереди писем (`invite_mail_outbox.EmitTx`) зовётся
//     из ОДНОГО места не-тестового дерева — метода `EmitInviteMail` писателя, —
//     и тот списывает окно (`chargeInviteMailWindowTx`) РАНЬШЕ постановки.
//     Так ограничитель стоит на пути каждого глагола по построению: второго
//     пути к письму у use-case нет.
//
// Разбор синтаксисом, а не поиском подстроки: имена вызовов стоят и в godoc.
package api_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// Регистрирует дескрипторы контрактов службы в protoregistry.
	_ "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const (
	mailEmitPort     = "EmitInviteMail"
	mailQueueWriter  = "EmitTx"
	mailQueuePackage = "invite_mail_outbox"
	mailWindowCharge = "chargeInviteMailWindowTx"
	mailContractPkg  = "kaname.cloud.iam.v1"
)

// parsedPackage — разобранные не-тестовые файлы одного каталога.
type parsedPackage struct {
	dir   string
	files []*ast.File
}

func parseAPITree(t *testing.T, root string) []parsedPackage {
	t.Helper()
	fset := token.NewFileSet()
	byDir := map[string]*parsedPackage{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			return perr
		}
		dir := filepath.Dir(path)
		if byDir[dir] == nil {
			byDir[dir] = &parsedPackage{dir: dir}
		}
		byDir[dir].files = append(byDir[dir].files, f)
		return nil
	})
	if err != nil {
		t.Fatalf("обход %s: %v", root, err)
	}
	out := make([]parsedPackage, 0, len(byDir))
	for _, p := range byDir {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	return out
}

// contractServices — службы контракта: имя → перечень методов.
func contractServices(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	protoregistry.GlobalFiles.RangeFilesByPackage(protoreflect.FullName(mailContractPkg), func(fd protoreflect.FileDescriptor) bool {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			s := svcs.Get(i)
			ms := s.Methods()
			for j := 0; j < ms.Len(); j++ {
				out[string(s.Name())] = append(out[string(s.Name())], string(ms.Get(j).Name()))
			}
		}
		return true
	})
	if len(out) == 0 {
		t.Fatalf("в protoregistry нет ни одной службы пакета %s — контракт не прочитан", mailContractPkg)
	}
	return out
}

// handlerType — тип-обработчик: имя, служба контракта, поля use-case'ов.
type handlerType struct {
	name    string
	service string
	fields  map[string]string // имя поля → имя типа use-case'а (без `*`)
}

// handlerTypes — обработчики пакета: структуры, вкладывающие
// `Unimplemented<Служба>Server`.
func handlerTypes(p parsedPackage) []handlerType {
	var out []handlerType
	for _, f := range p.files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				h := handlerType{name: ts.Name.Name, fields: map[string]string{}}
				for _, fld := range st.Fields.List {
					typeName := typeIdent(fld.Type)
					if len(fld.Names) == 0 {
						if strings.HasPrefix(typeName, "Unimplemented") && strings.HasSuffix(typeName, "Server") {
							h.service = strings.TrimSuffix(strings.TrimPrefix(typeName, "Unimplemented"), "Server")
						}
						continue
					}
					for _, n := range fld.Names {
						h.fields[n.Name] = typeName
					}
				}
				if h.service != "" {
					out = append(out, h)
				}
			}
		}
	}
	return out
}

// typeIdent — имя типа выражения без указателя и квалификатора пакета.
func typeIdent(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return typeIdent(x.X)
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.Ident:
		return x.Name
	}
	return ""
}

// receiverType — имя типа приёмника метода без указателя.
func receiverType(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	return typeIdent(fd.Recv.List[0].Type)
}

// methodsOf — объявления методов типа в пакете.
func methodsOf(p parsedPackage, typ string) []*ast.FuncDecl {
	var out []*ast.FuncDecl
	for _, f := range p.files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && receiverType(fd) == typ {
				out = append(out, fd)
			}
		}
	}
	return out
}

// calledFieldsIn — поля приёмника, у которых тело метода что-то зовёт:
// `h.<поле>.<метод>(…)` → <поле>.
func calledFieldsIn(fd *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	if fd.Recv == nil || len(fd.Recv.List) == 0 || len(fd.Recv.List[0].Names) == 0 {
		return out
	}
	recv := fd.Recv.List[0].Names[0].Name
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		inner, ok := sel.X.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := inner.X.(*ast.Ident); ok && id.Name == recv {
			out[inner.Sel.Name] = true
		}
		return true
	})
	return out
}

// callsMethodNamed — есть ли в теле вызов `<что-то>.<name>(…)`.
func callsMethodNamed(body ast.Node, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

// intentLiteralsWithoutLimit — литералы намерения письма в теле, у которых
// нет ключа `Limit`.
func intentLiteralsWithoutLimit(body ast.Node) int {
	missing := 0
	ast.Inspect(body, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || typeIdent(cl.Type) != "InviteMailIntent" {
			return true
		}
		hasLimit := false
		for _, el := range cl.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Limit" {
					hasLimit = true
				}
			}
		}
		if !hasLimit {
			missing++
		}
		return true
	})
	return missing
}

// mailVerb — глагол контракта, отправляющий письмо, и что о нём измерено.
type mailVerb struct {
	fqn             string
	useCase         string
	intentsNoLimit  int
	intentsTotalLit int
}

// deriveMailVerbs — перечень глаголов, отправляющих письмо, выведенный из
// контрактов через обработчики и use-case'ы. Второе число — глаголов
// контракта осмотрено (знаменатель обхода).
func deriveMailVerbs(t *testing.T, root string) ([]mailVerb, int) {
	t.Helper()
	services := contractServices(t)
	pkgs := parseAPITree(t, root)
	var verbs []mailVerb
	examined := 0
	for _, p := range pkgs {
		for _, h := range handlerTypes(p) {
			methods, known := services[h.service]
			if !known {
				continue
			}
			rpcs := map[string]bool{}
			for _, m := range methods {
				rpcs[m] = true
			}
			for _, fd := range methodsOf(p, h.name) {
				if !rpcs[fd.Name.Name] {
					continue
				}
				examined++
				for field := range calledFieldsIn(fd) {
					ucType, ok := h.fields[field]
					if !ok {
						continue
					}
					sendsMail := false
					noLimit, total := 0, 0
					for _, ucm := range methodsOf(p, ucType) {
						if callsMethodNamed(ucm.Body, mailEmitPort) {
							sendsMail = true
							noLimit += intentLiteralsWithoutLimit(ucm.Body)
							total += countIntentLiterals(ucm.Body)
						}
					}
					if sendsMail {
						verbs = append(verbs, mailVerb{
							fqn:             mailContractPkg + "." + h.service + "/" + fd.Name.Name,
							useCase:         ucType,
							intentsNoLimit:  noLimit,
							intentsTotalLit: total,
						})
					}
				}
			}
		}
	}
	sort.Slice(verbs, func(i, j int) bool { return verbs[i].fqn < verbs[j].fqn })
	return verbs, examined
}

func countIntentLiterals(body ast.Node) int {
	n := 0
	ast.Inspect(body, func(x ast.Node) bool {
		if cl, ok := x.(*ast.CompositeLit); ok && typeIdent(cl.Type) == "InviteMailIntent" {
			n++
		}
		return true
	})
	return n
}

// queueWriterFindings — утверждение 3: единственный писатель очереди зовётся
// из одного места, и то списывает окно раньше постановки.
func queueWriterFindings(t *testing.T, repoRoot string) (findings []string, callers int) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Сам пакет очереди зовёт свой EmitTx только объявлением — его не
			// осматриваем; пробы — тоже.
			if d.Name() == mailQueuePackage || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			emitPos, chargePos := token.NoPos, token.NoPos
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					if pkg, ok := fun.X.(*ast.Ident); ok && pkg.Name == mailQueuePackage && fun.Sel.Name == mailQueueWriter {
						if emitPos == token.NoPos {
							emitPos = call.Pos()
						}
					}
				case *ast.Ident:
					if fun.Name == mailWindowCharge && chargePos == token.NoPos {
						chargePos = call.Pos()
					}
				}
				return true
			})
			if emitPos == token.NoPos {
				continue
			}
			callers++
			where := fset.Position(emitPos)
			if fd.Name.Name != mailEmitPort {
				findings = append(findings, where.String()+": писатель очереди писем зовётся не из "+mailEmitPort+
					", а из "+fd.Name.Name+" — второй путь к письму, минующий ограничитель")
				continue
			}
			if chargePos == token.NoPos || chargePos > emitPos {
				findings = append(findings, where.String()+": "+mailEmitPort+" ставит намерение, не списав окно "+
					"адресата ("+mailWindowCharge+") раньше постановки — ограничитель стоит не на пути письма")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("обход %s: %v", repoRoot, err)
	}
	return findings, callers
}

func TestEveryMailSendingVerbPassesTheRateLimiter(t *testing.T) {
	apiRoot := apiDirForForwardGate(t)
	repoRoot := filepath.Clean(filepath.Join(apiRoot, "..", "..", ".."))

	verbs, examined := deriveMailVerbs(t, apiRoot)
	names := make([]string, 0, len(verbs))
	for _, v := range verbs {
		names = append(names, v.fqn+" ← "+v.useCase)
	}
	findings, callers := queueWriterFindings(t, repoRoot)

	t.Logf("перепись: глаголов контракта осмотрено %d · отправляющих письмо %d — %v · "+
		"мест постановки в очередь %d", examined, len(verbs), names, callers)

	if examined == 0 {
		t.Fatal("ни один метод обработчика не сопоставлен с глаголом контракта — обход пуст, вердикта нет")
	}
	if len(verbs) == 0 {
		t.Fatal("глаголов, отправляющих письмо, не найдено — либо их нет (тогда предмет гейта исчез), " +
			"либо распознаватель ослеп; «все проходят» на пустом перечне не вердикт")
	}
	for _, v := range verbs {
		if v.intentsTotalLit == 0 {
			t.Errorf("%s (%s): зовёт %s, а литерала намерения не строит — намерение собирается вне use-case'а, "+
				"и ограничение в нём не видно", v.fqn, v.useCase, mailEmitPort)
		}
		if v.intentsNoLimit > 0 {
			t.Errorf("%s (%s): %d намерение(й) письма без поля Limit — ограничение частоты не едет с намерением",
				v.fqn, v.useCase, v.intentsNoLimit)
		}
	}
	if callers == 0 {
		t.Fatal("писатель очереди писем не зовётся нигде — очередь мертва, вердикта о порядке нет")
	}
	if callers > 1 {
		t.Errorf("писатель очереди писем зовётся из %d мест — второй путь к письму минует ограничитель", callers)
	}
	for _, f := range findings {
		t.Error(f)
	}
}
