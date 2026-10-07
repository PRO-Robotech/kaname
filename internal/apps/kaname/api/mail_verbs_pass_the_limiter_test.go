// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_verbs_pass_the_limiter_test.go — гейт на КЛАСС (приёмка ID-MAIL-1,
// Р22, §10 п. 17; MAIL-25, MAIL-42; задача продукта #1775; приёмка
// `recovery-of-access.md` ред. 5, Р8, Ф5-28 — kaname#246): каждый НАШ глагол,
// отправляющий письмо, проходит через ограничитель частоты, и перечень таких
// глаголов ВЫВОДИТСЯ из дерева, а не выписан.
//
// # Как выводится перечень — две формы глагола, каждая своим обходом
//
//  1. ГЛАГОЛЫ КОНТРАКТОВ. Дескрипторы служб (`protoregistry`) → типы-
//     обработчики в `internal/apps/kaname/api` (структуры, вкладывающие
//     `Unimplemented<Служба>Server`) → поле use-case'а, которое зовёт тело
//     метода-RPC.
//  2. МАРШРУТЫ ПОЛОСЫ ВХОДА. Регистрация маршрутов слушателя
//     `internal/handler/loginlanehttp` (`HandleFunc(<путь>, method(<метод>,
//     <обработчик>))`) → глагол порта полосы, который зовёт обработчик →
//     адаптер порта в композиционном корне `cmd/kaname` (тип, чьи методы
//     покрывают порт) → поле use-case'а, которое зовёт метод адаптера.
//
// От use-case'а обе формы идут одним обходом: методы типа и функции пакетов
// дерева, которые они зовут, транзитивно — до вызова ПОРТА ПИСЬМА. Порты
// письма тоже выводятся, а не выписываются: это функции дерева, зовущие
// писателя очереди писем (`invite_mail_outbox.Emit*Tx`). Выписанный перечень
// разошёлся бы с деревом молча: следующий почтовый глагол завели бы без
// ограничения, и заметить это было бы неоткуда.
//
// # Что утверждается
//
//  1. обход каждой формы непуст, и перечень знает запрос кода восстановления
//     (`POST /iam/v1/auth/recovery`, Ф5-28); число найденных глаголов НЕ
//     утверждается — следующий почтовый глагол гейт обязан найти, а не
//     покраснеть на счёте;
//  2. каждый вызов порта письма на пути глагола ограничен одной из ДВУХ
//     законных форм: (а) писатель очереди порта списывает окно адресата
//     (`chargeInviteMailWindowTx`) раньше постановки, и намерение письма
//     (`…MailIntent`) несёт поле `Limit`; (б) предел писем решён вставкой
//     строки кода (`InsertVerificationCodePaced`, kaname#456 Р9; у смены
//     адреса — `InsertEmailChangeCodePaced`, kaname#635 Р6) либо применением
//     такой строки (`PresentEmailChangeCode`: уведомление о смене — одно на
//     применённый код, а коды выдаются под темпом, kaname#635 Р7) в той же
//     функции РАНЬШЕ вызова порта — писатель такого порта окна не списывает,
//     предел решает его вызывающий. Вызов порта, не ограниченный ни одной
//     формой, — находка с координатой вызова;
//  3. каждый писатель очереди писем зовётся из ОДНОГО места не-тестового
//     дерева, и место, списывающее окно, делает это РАНЬШЕ постановки:
//     второго пути к письму у use-case нет.
//
// Разбор синтаксисом, а не поиском подстроки: имена вызовов стоят и в godoc.
package api_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"

	// Регистрирует дескрипторы контрактов службы в protoregistry.
	_ "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const (
	mailQueuePackage  = "invite_mail_outbox"
	mailWindowCharge  = "chargeInviteMailWindowTx"
	mailCallerPaced   = "InsertVerificationCodePaced"
	mailIntentSuffix  = "MailIntent"
	mailContractPkg   = "kaname.cloud.iam.v1"
	laneRecoveryRoute = "POST /iam/v1/auth/recovery"
)

// mailCallerPacedBy — вызовы, которыми вызывающий решает предел писем раньше
// порта (форма (б) утверждения 2): вставка строки кода под темпом человека и
// применение такой строки. Перечень закрыт; пополняется приёмкой, назвавшей
// темп своего письма.
var mailCallerPacedBy = map[string]bool{
	mailCallerPaced:              true,
	"InsertEmailChangeCodePaced": true,
	"PresentEmailChangeCode":     true,
}

// parsedPackage — разобранные не-тестовые файлы одного каталога.
type parsedPackage struct {
	dir   string
	fset  *token.FileSet
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
			byDir[dir] = &parsedPackage{dir: dir, fset: fset}
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
		if !ok || !isMailIntent(cl.Type) {
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

// isMailIntent — литерал намерения письма: тип `…MailIntent` любого вида.
func isMailIntent(e ast.Expr) bool {
	return strings.HasSuffix(typeIdent(e), mailIntentSuffix)
}

// mailPort — порт письма: функция дерева, зовущая писателя очереди писем, и
// списывает ли она окно адресата сама.
type mailPort struct {
	charged bool
}

// mailSite — вызов порта письма на пути глагола и его ограничение.
type mailSite struct {
	port           string
	where          string
	charged        bool // писатель порта списывает окно адресата
	paced          bool // предел решён вставкой строки кода раньше вызова
	intents        int  // литералов намерения в функции вызова
	intentsNoLimit int  // из них без поля Limit
}

// mailVerb — глагол, отправляющий письмо, и что о нём измерено.
type mailVerb struct {
	fqn             string
	useCase         string
	sites           []mailSite
	intentsNoLimit  int
	intentsTotalLit int
}

// unlimitedSites — вызовы порта, не ограниченные ни одной законной формой.
func (v mailVerb) unlimitedSites() []mailSite {
	var out []mailSite
	for _, s := range v.sites {
		if !s.charged && !s.paced {
			out = append(out, s)
		}
	}
	return out
}

// apiIndex — функции и методы разобранного дерева по пакету (база каталога).
type apiIndex struct {
	pkgs  map[string]parsedPackage
	funcs map[string]map[string]*ast.FuncDecl // пакет → имя функции → объявление
	owner map[*ast.FuncDecl]parsedPackage
}

func indexAPI(pkgs []parsedPackage) apiIndex {
	ix := apiIndex{pkgs: map[string]parsedPackage{}, funcs: map[string]map[string]*ast.FuncDecl{},
		owner: map[*ast.FuncDecl]parsedPackage{}}
	for _, p := range pkgs {
		base := filepath.Base(p.dir)
		ix.pkgs[base] = p
		ix.funcs[base] = map[string]*ast.FuncDecl{}
		for _, f := range p.files {
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				ix.owner[fd] = p
				if fd.Recv == nil {
					ix.funcs[base][fd.Name.Name] = fd
				}
			}
		}
	}
	return ix
}

// mailSitesOf — вызовы порта письма, достижимые из методов use-case'а: методы
// типа и функции пакетов дерева, которые они зовут, транзитивно.
func mailSitesOf(ix apiIndex, pkgBase, ucType string, ports map[string]mailPort) []mailSite {
	p, ok := ix.pkgs[pkgBase]
	if !ok {
		return nil
	}
	var (
		sites []mailSite
		seen  = map[*ast.FuncDecl]bool{}
		walk  func(fd *ast.FuncDecl)
	)
	walk = func(fd *ast.FuncDecl) {
		if seen[fd] {
			return
		}
		seen[fd] = true
		owner := ix.owner[fd]
		ownerBase := filepath.Base(owner.dir)
		var pacedAt []token.Pos
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && mailCallerPacedBy[sel.Sel.Name] {
					pacedAt = append(pacedAt, call.Pos())
				}
			}
			return true
		})
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				if port, isPort := ports[fun.Sel.Name]; isPort {
					paced := false
					for _, at := range pacedAt {
						if at < call.Pos() {
							paced = true
						}
					}
					sites = append(sites, mailSite{
						port: fun.Sel.Name, where: owner.fset.Position(call.Pos()).String(),
						charged: port.charged, paced: paced,
						intents: countIntentLiterals(fd.Body), intentsNoLimit: intentLiteralsWithoutLimit(fd.Body),
					})
					return true
				}
				// Функция другого пакета дерева: `<пакет>.<Функция>(…)`.
				if pkg, ok := fun.X.(*ast.Ident); ok {
					if next, ok := ix.funcs[pkg.Name][fun.Sel.Name]; ok {
						walk(next)
					}
				}
				// Метод того же типа: `<приёмник>.<метод>(…)`.
				if id, ok := fun.X.(*ast.Ident); ok && fd.Recv != nil && len(fd.Recv.List) > 0 &&
					len(fd.Recv.List[0].Names) > 0 && id.Name == fd.Recv.List[0].Names[0].Name {
					for _, m := range methodsOf(owner, receiverType(fd)) {
						if m.Name.Name == fun.Sel.Name {
							walk(m)
						}
					}
				}
			case *ast.Ident:
				// Функция своего пакета.
				if next, ok := ix.funcs[ownerBase][fun.Name]; ok {
					walk(next)
				}
			}
			return true
		})
	}
	for _, m := range methodsOf(p, ucType) {
		if m.Body != nil {
			walk(m)
		}
	}
	return sites
}

// newMailVerb — глагол из найденных вызовов порта; nil — письма глагол не шлёт.
func newMailVerb(fqn, useCase string, sites []mailSite) *mailVerb {
	if len(sites) == 0 {
		return nil
	}
	v := &mailVerb{fqn: fqn, useCase: useCase, sites: sites}
	seen := map[string]bool{}
	for _, s := range sites {
		// Литералы считаются по функции вызова однажды, и только у порта,
		// чей писатель списывает окно: у формы «предел решён вставкой» окно
		// с намерением не едет.
		if !s.charged || seen[s.where+"|"+s.port] {
			continue
		}
		seen[s.where+"|"+s.port] = true
		v.intentsTotalLit += s.intents
		v.intentsNoLimit += s.intentsNoLimit
	}
	return v
}

// deriveMailVerbs — перечень глаголов КОНТРАКТОВ, отправляющих письмо. Второе
// число — глаголов контракта осмотрено (знаменатель обхода).
func deriveMailVerbs(t *testing.T, root string, ports map[string]mailPort) ([]mailVerb, int) {
	t.Helper()
	services := contractServices(t)
	pkgs := parseAPITree(t, root)
	ix := indexAPI(pkgs)
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
					fqn := mailContractPkg + "." + h.service + "/" + fd.Name.Name
					if v := newMailVerb(fqn, ucType, mailSitesOf(ix, filepath.Base(p.dir), ucType, ports)); v != nil {
						verbs = append(verbs, *v)
					}
				}
			}
		}
	}
	sort.Slice(verbs, func(i, j int) bool { return verbs[i].fqn < verbs[j].fqn })
	return verbs, examined
}

// laneRoute — маршрут слушателя полосы входа.
type laneRoute struct {
	method  string // GET, POST
	path    string
	handler string // метод слушателя
}

// parseDir — разобранные не-тестовые файлы одного каталога (без подкаталогов).
func parseDir(t *testing.T, dir string) parsedPackage {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("каталог %s: %v", dir, err)
	}
	p := parsedPackage{dir: dir, fset: token.NewFileSet()}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(p.fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("разбор %s: %v", name, perr)
		}
		p.files = append(p.files, f)
	}
	return p
}

// stringConsts — строковые константы пакета: имя → значение.
func stringConsts(p parsedPackage) map[string]string {
	out := map[string]string{}
	for _, f := range p.files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, n := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						out[n.Name] = strings.Trim(lit.Value, "\"`")
					}
				}
			}
		}
	}
	return out
}

// laneRoutes — маршруты, которые слушатель регистрирует:
// `HandleFunc(<путь>, <приёмник>.method(http.Method<M>, <приёмник>.<обработчик>))`.
func laneRoutes(p parsedPackage) []laneRoute {
	consts := stringConsts(p)
	var out []laneRoute
	for _, f := range p.files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "HandleFunc" {
				return true
			}
			var path string
			switch a := call.Args[0].(type) {
			case *ast.Ident:
				path = consts[a.Name]
			case *ast.BasicLit:
				path = strings.Trim(a.Value, "\"`")
			}
			wrap, ok := call.Args[1].(*ast.CallExpr)
			if !ok || len(wrap.Args) != 2 || path == "" {
				return true
			}
			m, ok := wrap.Args[0].(*ast.SelectorExpr)
			if !ok || !strings.HasPrefix(m.Sel.Name, "Method") {
				return true
			}
			h, ok := wrap.Args[1].(*ast.SelectorExpr)
			if !ok {
				return true
			}
			out = append(out, laneRoute{
				method: strings.ToUpper(strings.TrimPrefix(m.Sel.Name, "Method")), path: path, handler: h.Sel.Name,
			})
			return true
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path+out[i].method < out[j].path+out[j].method })
	return out
}

// interfaces — интерфейсы пакета: имя → имена методов.
func interfaces(p parsedPackage) map[string][]string {
	out := map[string][]string{}
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
				it, ok := ts.Type.(*ast.InterfaceType)
				if !ok {
					continue
				}
				for _, m := range it.Methods.List {
					for _, n := range m.Names {
						out[ts.Name.Name] = append(out[ts.Name.Name], n.Name)
					}
				}
			}
		}
	}
	return out
}

// structFields — поля структур пакета: тип → поле → (пакет, тип) поля.
func structFields(p parsedPackage) map[string]map[string][2]string {
	out := map[string]map[string][2]string{}
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
				fields := map[string][2]string{}
				for _, fld := range st.Fields.List {
					e := fld.Type
					if star, ok := e.(*ast.StarExpr); ok {
						e = star.X
					}
					var q [2]string
					switch x := e.(type) {
					case *ast.SelectorExpr:
						if pkg, ok := x.X.(*ast.Ident); ok {
							q = [2]string{pkg.Name, x.Sel.Name}
						}
					case *ast.Ident:
						q = [2]string{"", x.Name}
					}
					for _, n := range fld.Names {
						fields[n.Name] = q
					}
				}
				out[ts.Name.Name] = fields
			}
		}
	}
	return out
}

// laneVerbsCalled — глаголы порта полосы, которые зовёт обработчик маршрута
// (`<приёмник>.<поле-порт>.<Глагол>(…)`), и имя интерфейса порта.
func laneVerbsCalled(p parsedPackage, fields map[string][2]string, ifaces map[string][]string, handler string) (out []string, iface string) {
	for _, f := range p.files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv == nil || fd.Name.Name != handler || len(fd.Recv.List[0].Names) == 0 {
				continue
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
				if id, ok := inner.X.(*ast.Ident); !ok || id.Name != recv {
					return true
				}
				q, ok := fields[inner.Sel.Name]
				if !ok || q[0] != "" {
					return true
				}
				for _, m := range ifaces[q[1]] {
					if m == sel.Sel.Name {
						out = append(out, m)
						iface = q[1]
					}
				}
				return true
			})
		}
	}
	return out, iface
}

// deriveLaneMailVerbs — перечень МАРШРУТОВ полосы входа, отправляющих письмо.
// Второе число — маршрутов осмотрено (знаменатель обхода). Ошибка — обход
// пуст либо цепочка «маршрут → порт → адаптер» не прослеживается: вердикта нет.
func deriveLaneMailVerbs(t *testing.T, handlerDir, rootDir, apiRoot string, ports map[string]mailPort) ([]mailVerb, int, error) {
	t.Helper()
	hp := parseDir(t, handlerDir)
	routes := laneRoutes(hp)
	ifaces := interfaces(hp)
	hfields := structFields(hp)

	// Порт полосы — интерфейс пакета слушателя, который зовут обработчики.
	byRoute := map[string][]string{}
	portIface := ""
	for _, r := range routes {
		for typ, fields := range hfields {
			if len(methodsOf(hp, typ)) == 0 {
				continue
			}
			verbs, iface := laneVerbsCalled(hp, fields, ifaces, r.handler)
			byRoute[r.method+" "+r.path] = append(byRoute[r.method+" "+r.path], verbs...)
			if iface != "" {
				portIface = iface
			}
		}
	}
	if portIface == "" {
		return nil, len(routes), fmt.Errorf("полоса входа: ни один обработчик маршрута не зовёт порт полосы — "+
			"обход пуст (маршрутов %d)", len(routes))
	}

	// Адаптер порта в композиционном корне — тип, чьи методы покрывают порт.
	cp := parseDir(t, rootDir)
	cfields := structFields(cp)
	var adapter string
	for typ := range cfields {
		have := map[string]bool{}
		for _, m := range methodsOf(cp, typ) {
			have[m.Name.Name] = true
		}
		all := len(ifaces[portIface]) > 0
		for _, m := range ifaces[portIface] {
			if !have[m] {
				all = false
			}
		}
		if all {
			if adapter != "" {
				return nil, len(routes), fmt.Errorf("полоса входа: порт %s покрывают два типа корня (%s, %s) — "+
					"адаптер не однозначен", portIface, adapter, typ)
			}
			adapter = typ
		}
	}
	if adapter == "" {
		return nil, len(routes), fmt.Errorf("полоса входа: в %s нет типа, чьи методы покрывают порт %s — "+
			"адаптер не найден", rootDir, portIface)
	}

	ix := indexAPI(parseAPITree(t, apiRoot))
	var verbs []mailVerb
	for _, r := range routes {
		key := r.method + " " + r.path
		for _, verb := range byRoute[key] {
			for _, m := range methodsOf(cp, adapter) {
				if m.Name.Name != verb {
					continue
				}
				for field := range calledFieldsIn(m) {
					q, ok := cfields[adapter][field]
					if !ok || q[0] == "" {
						continue
					}
					if v := newMailVerb(key, q[0]+"."+q[1], mailSitesOf(ix, q[0], q[1], ports)); v != nil {
						verbs = append(verbs, *v)
					}
				}
			}
		}
	}
	sort.Slice(verbs, func(i, j int) bool { return verbs[i].fqn < verbs[j].fqn })
	return verbs, len(routes), nil
}

func countIntentLiterals(body ast.Node) int {
	n := 0
	ast.Inspect(body, func(x ast.Node) bool {
		if cl, ok := x.(*ast.CompositeLit); ok && isMailIntent(cl.Type) {
			n++
		}
		return true
	})
	return n
}

// queueWriterFindings — утверждение 3 и вывод портов письма: каждый писатель
// очереди писем (`invite_mail_outbox.Emit*Tx`) зовётся из одного места; место,
// списывающее окно, списывает его раньше постановки. Порт — функция, зовущая
// писателя; charged — списывает ли она окно сама.
func queueWriterFindings(t *testing.T, repoRoot string) (findings []string, callers int, ports map[string]mailPort) {
	t.Helper()
	fset := token.NewFileSet()
	ports = map[string]mailPort{}
	sitesByWriter := map[string][]string{}
	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Сам пакет очереди зовёт своих писателей только объявлением — его
			// не осматриваем; пробы — тоже.
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
					if pkg, ok := fun.X.(*ast.Ident); ok && pkg.Name == mailQueuePackage &&
						strings.HasPrefix(fun.Sel.Name, "Emit") && strings.HasSuffix(fun.Sel.Name, "Tx") {
						if emitPos == token.NoPos {
							emitPos = call.Pos()
						}
						sitesByWriter[fun.Sel.Name] = append(sitesByWriter[fun.Sel.Name],
							fset.Position(call.Pos()).String()+" "+fd.Name.Name)
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
			if chargePos != token.NoPos && chargePos > emitPos {
				findings = append(findings, where.String()+": "+fd.Name.Name+" ставит намерение, не списав окно "+
					"адресата ("+mailWindowCharge+") раньше постановки — ограничитель стоит не на пути письма")
			}
			ports[fd.Name.Name] = mailPort{charged: chargePos != token.NoPos && chargePos < emitPos}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("обход %s: %v", repoRoot, err)
	}
	writers := make([]string, 0, len(sitesByWriter))
	for w := range sitesByWriter {
		writers = append(writers, w)
	}
	sort.Strings(writers)
	for _, w := range writers {
		if sites := sitesByWriter[w]; len(sites) > 1 {
			findings = append(findings, "писатель очереди писем "+mailQueuePackage+"."+w+" зовётся из "+
				strconv.Itoa(len(sites))+" мест "+strings.Join(sites, " · ")+" — второй путь к письму, минующий ограничитель")
		}
	}
	return findings, callers, ports
}

// verbFindings — находки утверждения 2 по одному глаголу.
func verbFindings(v mailVerb) []string {
	var out []string
	if v.intentsNoLimit > 0 {
		out = append(out, fmt.Sprintf("%s (%s): %d намерение(й) письма без поля Limit — ограничение частоты не едет с намерением",
			v.fqn, v.useCase, v.intentsNoLimit))
	}
	charged := false
	for _, s := range v.sites {
		charged = charged || s.charged
	}
	if charged && v.intentsTotalLit == 0 {
		out = append(out, fmt.Sprintf("%s (%s): зовёт порт письма, а литерала намерения не строит — намерение "+
			"собирается вне use-case'а, и ограничение в нём не видно", v.fqn, v.useCase))
	}
	for _, s := range v.unlimitedSites() {
		out = append(out, fmt.Sprintf("%s: глагол %s (%s) ставит письмо портом %s без списания: писатель порта окна "+
			"адресата не списывает, и предел писем (%s) раньше вызова не решён", s.where, v.fqn, v.useCase, s.port,
			strings.Join(sortedPacedBy(), " · ")))
	}
	return out
}

func TestEveryMailSendingVerbPassesTheRateLimiter(t *testing.T) {
	apiRoot := apiDirForForwardGate(t)
	repoRoot := filepath.Clean(filepath.Join(apiRoot, "..", "..", ".."))
	handlerDir := platformtree.RequirePath(t, "services/iam/internal/handler/loginlanehttp")
	rootDir := platformtree.RequirePath(t, "services/iam/cmd/kaname")

	findings, callers, ports := queueWriterFindings(t, repoRoot)
	if callers == 0 || len(ports) == 0 {
		t.Fatal("писатель очереди писем не зовётся нигде — очередь мертва, портов письма нет, вердикта о порядке нет")
	}
	portNames := make([]string, 0, len(ports))
	for p, m := range ports {
		form := "предел у вызывающего"
		if m.charged {
			form = "списывает окно"
		}
		portNames = append(portNames, p+" ("+form+")")
	}
	sort.Strings(portNames)

	contract, examined := deriveMailVerbs(t, apiRoot, ports)
	lane, routes, err := deriveLaneMailVerbs(t, handlerDir, rootDir, apiRoot, ports)
	if err != nil {
		t.Fatal(err)
	}
	render := func(vs []mailVerb) []string {
		out := make([]string, 0, len(vs))
		for _, v := range vs {
			out = append(out, v.fqn+" ← "+v.useCase)
		}
		return out
	}
	names := append(render(contract), render(lane)...)

	t.Logf("перепись: портов письма %d — %v · мест постановки в очередь %d", len(ports), portNames, callers)
	t.Logf("перепись: глаголов контракта осмотрено %d · отправляющих письмо %d — %v", examined, len(contract), render(contract))
	t.Logf("перепись: маршрутов полосы входа осмотрено %d · отправляющих письмо %d — %v", routes, len(lane), render(lane))

	if examined == 0 {
		t.Fatal("ни один метод обработчика не сопоставлен с глаголом контракта — обход пуст, вердикта нет")
	}
	if routes == 0 {
		t.Fatal("ни одного маршрута полосы входа не найдено — обход пуст, вердикта нет")
	}
	if len(contract) == 0 || len(lane) == 0 {
		t.Fatalf("глаголов, отправляющих письмо, не найдено в форме: контрактов %d, полосы входа %d — либо их нет "+
			"(тогда предмет гейта исчез), либо распознаватель ослеп; «все проходят» на пустом перечне не вердикт",
			len(contract), len(lane))
	}
	for _, v := range append(append([]mailVerb{}, contract...), lane...) {
		for _, f := range verbFindings(v) {
			t.Error(f)
		}
	}
	// Ф5-28: запрос кода восстановления — наш глагол, отправляющий письмо
	// (Р8, MAIL-25), и выведенный перечень обязан его знать.
	if !strings.Contains(strings.Join(names, " "), laneRecoveryRoute) {
		t.Errorf("выведенный перечень глаголов, отправляющих письмо, не знает запроса кода восстановления "+
			"(%s) — перечень %v", laneRecoveryRoute, names)
	}
	for _, f := range findings {
		t.Error(f)
	}
}

func sortedPacedBy() []string {
	out := make([]string, 0, len(mailCallerPacedBy))
	for k := range mailCallerPacedBy {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
