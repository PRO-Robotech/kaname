// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"strconv"
	"strings"
)

// CensusRPCProducers доказывает конкретный путь интерфейса RPC через wiring.
// Вход — полный tracked корпус, включая supporting files без SQL-литералов.
// Имена ниже — координаты проверяемого протокола, а не разрешение пакету:
// каждый переход требует import identity, receiver и связанную переменную/поле.
func CensusRPCProducers(corpus map[string][]byte) (map[string]bool, int, error) {
	files := map[string]*ast.File{}
	for rel, src := range corpus {
		file, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.SkipObjectResolution)
		if err != nil {
			return nil, 0, fmt.Errorf("разбор %s: %w", rel, err)
		}
		files[rel] = file
	}
	const api = "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	const app = "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	const pg = "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	wire := files["cmd/kaname/wiring.go"]
	registration := files["cmd/kaname/grpc_register.go"]
	handler := files["internal/apps/kaname/api/internal_iam/handler.go"]
	usecase := files["internal/apps/kaname/api/internal_iam/register_resource.go"]
	adapter := files["internal/repo/kaname/pg/resource_mirror_emitter.go"]
	if wire == nil || registration == nil || handler == nil || usecase == nil || adapter == nil {
		return nil, 0, fmt.Errorf("неполный корпус пути RPC→mirror")
	}
	result := map[string]bool{}
	if !routeProductionProof(files, wire, registration, handler, usecase, adapter, api, app, pg) {
		// Ноль здесь означает «путь не доказан данным bounded predicate»,
		// а не утверждение об отсутствии фактического production writer.
		return result, 0, nil
	}
	routes := 0
	for rel, file := range files {
		if !strings.HasSuffix(rel, "_test.go") {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// Узкий admission: constructor обязан быть верхним оператором
			// функции; имя имеет единственное объявление/запись во всём теле,
			// включая вложенные блоки и closures. Неоднозначность краснит.
			bindings := map[string]token.Pos{}
			writes := routeLocalBindings(fn)
			visitBody := func(visit func(ast.Node)) {
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if _, closure := n.(*ast.FuncLit); closure {
						return false
					}
					if n != nil {
						visit(n)
					}
					return true
				})
			}
			for _, stmt := range fn.Body.List {
				a, ok := stmt.(*ast.AssignStmt)
				if !ok || a.Tok != token.DEFINE || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
					continue
				}
				id, ok := routeUnparen(a.Lhs[0]).(*ast.Ident)
				if !ok || writes[id.Name] != 1 {
					continue
				}
				call, ok := routeUnparen(a.Rhs[0]).(*ast.CallExpr)
				if ok && routeImportedCall(file, call, api, "NewInternalIAMServiceClient") {
					bindings[id.Name] = a.End()
				}
			}

			visitBody(func(n ast.Node) {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return
				}
				sel, ok := routeUnparen(call.Fun).(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "RegisterResource" {
					return
				}
				id, ok := routeUnparen(sel.X).(*ast.Ident)
				if !ok || bindings[id.Name] == token.NoPos || call.Pos() <= bindings[id.Name] || writes[id.Name] != 1 || len(call.Args) != 2 {
					return
				}
				ptr, ok := routeUnparen(call.Args[1]).(*ast.UnaryExpr)
				if !ok || ptr.Op != token.AND {
					return
				}
				lit, ok := routeUnparen(ptr.X).(*ast.CompositeLit)
				if !ok {
					return
				}
				typ, ok := routeUnparen(lit.Type).(*ast.SelectorExpr)
				if !ok || typ.Sel.Name != "RegisterResourceRequest" {
					return
				}
				alias, ok := routeUnparen(typ.X).(*ast.Ident)
				if !ok || !routeAliasUnshadowed(file, alias.Name) || routeImport(file, alias.Name) != api {
					return
				}
				result[path.Dir(rel)+"/"+file.Name.Name] = true
				routes++
			})
		}
	}
	return result, routes, nil
}

func routeImport(file *ast.File, alias string) string {
	for _, im := range file.Imports {
		p, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			continue
		}
		name := path.Base(p)
		if im.Name != nil {
			name = im.Name.Name
		}
		if name == alias {
			return p
		}
	}
	return ""
}

// routeUnparen сохраняет одну семантику binding/lvalue/callee при любых скобках.
func routeUnparen(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}
func routeIdent(e ast.Expr, name string) bool {
	id, ok := routeUnparen(e).(*ast.Ident)
	return ok && id.Name == name
}
func routeSelector(e ast.Expr, receiver, field string) bool {
	sel, ok := routeUnparen(e).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == field && routeIdent(sel.X, receiver)
}
func routeNestedSelector(e ast.Expr, receiver, field, method string) bool {
	sel, ok := routeUnparen(e).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == method && routeSelector(sel.X, receiver, field)
}
func routeImportedCall(file *ast.File, c *ast.CallExpr, pkg, name string) bool {
	sel, ok := routeUnparen(c.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := routeUnparen(sel.X).(*ast.Ident)
	return ok && routeAliasUnshadowed(file, id.Name) && routeImport(file, id.Name) == pkg
}
func routeAny(n ast.Node, predicate func(ast.Node) bool) bool {
	if n == nil {
		return false
	}
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		if node != nil && predicate(node) {
			found = true
		}
		return true
	})
	return found
}
func routeAnyCall(n ast.Node, predicate func(*ast.CallExpr) bool) bool {
	return routeAny(n, func(node ast.Node) bool { c, ok := node.(*ast.CallExpr); return ok && predicate(c) })
}
func routeFunction(file *ast.File, name string) *ast.FuncDecl {
	var result *ast.FuncDecl
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			if result != nil {
				return nil
			}
			result = fn
		}
	}
	return result
}
func routeMethod(file *ast.File, receiver, name string) *ast.FuncDecl {
	var result *ast.FuncDecl
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != name || len(fn.Recv.List) != 1 {
			continue
		}
		typ := fn.Recv.List[0].Type
		if ptr, ok := routeUnparen(typ).(*ast.StarExpr); ok {
			typ = ptr.X
		}
		if routeIdent(typ, receiver) {
			if result != nil {
				return nil
			}
			result = fn
		}
	}
	return result
}

func routeType(file *ast.File, typ ast.Expr, pkg, name string) bool {
	if ptr, ok := routeUnparen(typ).(*ast.StarExpr); ok {
		typ = ptr.X
	}
	if pkg == "" {
		return routeIdent(typ, name)
	}
	sel, ok := routeUnparen(typ).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := routeUnparen(sel.X).(*ast.Ident)
	return ok && routeImport(file, id.Name) == pkg
}
func routeFieldType(file *ast.File, owner, field, pkg, name string) bool {
	return routeAny(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || spec.Name.Name != owner {
			return false
		}
		st, ok := spec.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, f := range st.Fields.List {
			for _, id := range f.Names {
				if id.Name == field && routeType(file, f.Type, pkg, name) {
					return true
				}
			}
		}
		return false
	})
}

// routeLocalBindings намеренно считает и вложенные/неисполненные объявления:
// это отказ доказать неоднозначный binding, а не разрешение по имени.
func routeLocalBindings(fn *ast.FuncDecl) map[string]int {
	names := map[string]int{}
	ast.Inspect(fn, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if id, ok := routeUnparen(lhs).(*ast.Ident); ok {
					names[id.Name]++
				}
			}
		case *ast.ValueSpec:
			for _, id := range node.Names {
				names[id.Name]++
			}
		case *ast.Field:
			for _, id := range node.Names {
				names[id.Name]++
			}
		case *ast.RangeStmt:
			for _, lhs := range []ast.Expr{node.Key, node.Value} {
				if id, ok := routeUnparen(lhs).(*ast.Ident); ok {
					names[id.Name]++
				}
			}
		case *ast.IncDecStmt:
			if id, ok := routeUnparen(node.X).(*ast.Ident); ok {
				names[id.Name]++
			}
		}
		return true
	})
	return names
}
func routeAliasUnshadowed(file *ast.File, alias string) bool {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && routeLocalBindings(fn)[alias] != 0 {
			return false
		}
	}
	return true
}

// routeProductionProof связывает именно владельцев registration/buildServices,
// их однозначные локальные bindings, returned object и последующие assignments.
func routeProductionProof(files map[string]*ast.File, wire, registration, handler, usecase, adapter *ast.File, api, app, pg string) bool {
	const appDir = "internal/apps/kaname/api/internal_iam"
	build := routeFunction(wire, "buildServices")
	reg := routeFunction(registration, "registerInternalServices")
	if build == nil || reg == nil || build.Body == nil || reg.Body == nil {
		return false
	}
	if !routeParameter(reg, "svcs", registration, "", "services") || !routeParameter(reg, "srv", registration, "google.golang.org/grpc", "ServiceRegistrar") || routeLocalBindings(reg)["svcs"] != 1 || routeLocalBindings(reg)["srv"] != 1 {
		return false
	}
	registered := routeExecutableCall(reg.Body, func(c *ast.CallExpr) bool {
		return routeImportedCall(registration, c, api, "RegisterInternalIAMServiceServer") && len(c.Args) == 2 && routeIdent(c.Args[0], "srv") && routeSelector(c.Args[1], "svcs", "internalIAMHandler")
	})
	if !registered || !routeBindingUntouched(reg, "svcs", "internalIAMHandler") {
		return false
	}
	// Единственный непосредственный return владельца, не literal в decoy/closure.
	var returned *ast.CompositeLit
	returns := 0
	for _, stmt := range build.Body.List {
		if ret, ok := stmt.(*ast.ReturnStmt); ok {
			returns++
			if len(ret.Results) == 1 {
				returned = routeReturnedLiteral(ret.Results[0], "services")
			}
		}
	}
	executableReturns := 0
	ast.Inspect(build.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if _, ok := n.(*ast.ReturnStmt); ok {
			executableReturns++
		}
		return true
	})
	if returns != 1 || executableReturns != 1 || returned == nil {
		return false
	}
	var handlerName string
	for _, elt := range returned.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok && routeIdent(kv.Key, "internalIAMHandler") {
			if handlerName != "" {
				return false
			}
			id, ok := routeUnparen(kv.Value).(*ast.Ident)
			if !ok {
				return false
			}
			handlerName = id.Name
		}
	}
	if handlerName == "" {
		return false
	}
	handlerInit := routeDirectDefinition(build, handlerName)
	if handlerInit == nil {
		return false
	}
	var ucName string
	handlerBase, ok := routeUnwrapChain(files, wire, handlerInit.Rhs[0], appDir, "Handler", "registrar", true, func(c *ast.CallExpr) bool {
		sel, ok := routeUnparen(c.Fun).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WithResourceRegistrar" {
			return true
		}
		if len(c.Args) != 2 || ucName != "" {
			return false
		}
		id, ok := routeUnparen(c.Args[0]).(*ast.Ident)
		if !ok {
			return false
		}
		ucName = id.Name
		return true
	})
	if !ok || !routeImportedCall(wire, handlerBase, app, "NewHandler") || ucName == "" || ucName == handlerName {
		return false
	}
	ucInit := routeDirectDefinition(build, ucName)
	if ucInit == nil || ucInit.Pos() >= handlerInit.Pos() {
		return false
	}
	ucBase, ok := routeUnwrapChain(files, wire, ucInit.Rhs[0], appDir, "RegisterResourceUseCase", "mirror", false, nil)
	if !ok || !routeImportedCall(wire, ucBase, app, "NewRegisterResourceUseCase") || len(ucBase.Args) < 2 {
		return false
	}
	mirror, ok := routeUnparen(ucBase.Args[1]).(*ast.CallExpr)
	if !ok || !routeImportedCall(wire, mirror, pg, "NewResourceMirrorEmitter") || len(mirror.Args) != 0 {
		return false
	}
	if !routeLaterAssignments(files, wire, build, ucInit, handlerInit, ucName, appDir, "RegisterResourceUseCase", "mirror") || !routeLaterAssignments(files, wire, build, handlerInit, nil, handlerName, appDir, "Handler", "registrar") {
		return false
	}
	if !routeConstructor(adapter, "NewResourceMirrorEmitter", "ResourceMirrorEmitter", "", -1) || !routeConstructor(usecase, "NewRegisterResourceUseCase", "RegisterResourceUseCase", "mirror", 1) || !routeConstructor(handler, "NewHandler", "Handler", "", -1) {
		return false
	}
	if !routeFieldType(wire, "services", "internalIAMHandler", app, "Handler") || !routeFieldType(handler, "Handler", "registrar", "", "resourceRegistrar") || !routeFieldType(usecase, "RegisterResourceUseCase", "mirror", "", "resourceMirrorEmitter") {
		return false
	}
	rpc := routeMethod(handler, "Handler", "RegisterResource")
	if rpc == nil || len(rpc.Type.Params.List) < 2 || !routeType(handler, rpc.Type.Params.List[1].Type, api, "RegisterResourceRequest") {
		return false
	}
	if !routeMethodsPreserve(files, appDir, "Handler", "RegisterResource", "registrar", map[string]bool{}) {
		return false
	}
	receiver := routeReceiver(rpc)
	if receiver == "" || !routeExecutableCall(rpc.Body, func(c *ast.CallExpr) bool { return routeNestedSelector(c.Fun, receiver, "registrar", "Register") }) {
		return false
	}
	if !routeMethodsPreserve(files, appDir, "RegisterResourceUseCase", "Register", "mirror", map[string]bool{}) || !routeMethodPath(files, appDir, "RegisterResourceUseCase", "Register", "mirror", "UpsertTx", map[string]bool{}) {
		return false
	}
	adapterMethod := routeMethod(adapter, "ResourceMirrorEmitter", "UpsertTx")
	if adapterMethod == nil || !routeBindingUntouched(adapterMethod, routeReceiver(adapterMethod), "") {
		return false
	}
	return routeExecutableCall(adapterMethod.Body, func(c *ast.CallExpr) bool {
		return routeImportedCall(adapter, c, "github.com/PRO-Robotech/kaname/"+EdgeProducerImport, EdgeProducerCall)
	})
}

func routeExecutableCall(node ast.Node, predicate func(*ast.CallExpr) bool) bool {
	found := false
	if node == nil {
		return false
	}
	ast.Inspect(node, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.FuncLit, *ast.DeferStmt, *ast.GoStmt:
			return false
		}
		if c, ok := n.(*ast.CallExpr); ok && predicate(c) {
			found = true
		}
		return true
	})
	return found
}
func routeParameter(fn *ast.FuncDecl, name string, file *ast.File, pkg, typ string) bool {
	for _, field := range fn.Type.Params.List {
		for _, id := range field.Names {
			if id.Name == name {
				return routeType(file, field.Type, pkg, typ)
			}
		}
	}
	return false
}
func routeReceiver(fn *ast.FuncDecl) string {
	if fn == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 {
		return ""
	}
	return fn.Recv.List[0].Names[0].Name
}
func routeReturnedLiteral(expr ast.Expr, typ string) *ast.CompositeLit {
	ptr, ok := routeUnparen(expr).(*ast.UnaryExpr)
	if !ok || ptr.Op != token.AND {
		return nil
	}
	lit, ok := routeUnparen(ptr.X).(*ast.CompositeLit)
	if !ok || !routeIdent(lit.Type, typ) {
		return nil
	}
	return lit
}
func routeDirectDefinition(fn *ast.FuncDecl, name string) *ast.AssignStmt {
	var result *ast.AssignStmt
	for _, stmt := range fn.Body.List {
		if a, ok := stmt.(*ast.AssignStmt); ok && a.Tok == token.DEFINE && len(a.Lhs) == 1 && len(a.Rhs) == 1 && routeIdent(a.Lhs[0], name) {
			if result != nil {
				return nil
			}
			result = a
		}
	}
	return result
}

// Constructor admission намеренно узок: один прямой return &ExpectedType{...}.
// Правильный discarded literal и перезаписанный parameter сюда не проходят.
func routeConstructor(file *ast.File, name, typ, protected string, parameter int) bool {
	fn := routeFunction(file, name)
	if fn == nil || fn.Body == nil || len(fn.Body.List) != 1 || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	ptr, ok := routeUnparen(fn.Type.Results.List[0].Type).(*ast.StarExpr)
	if !ok || !routeIdent(ptr.X, typ) {
		return false
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	lit := routeReturnedLiteral(ret.Results[0], typ)
	if lit == nil {
		return false
	}
	params := map[string]bool{}
	for _, f := range fn.Type.Params.List {
		for _, id := range f.Names {
			params[id.Name] = true
		}
	}
	protectedParam := ""
	if parameter >= 0 {
		if parameter >= len(fn.Type.Params.List) || len(fn.Type.Params.List[parameter].Names) != 1 {
			return false
		}
		protectedParam = fn.Type.Params.List[parameter].Names[0].Name
		if !routeType(file, fn.Type.Params.List[parameter].Type, "", "resourceMirrorEmitter") {
			return false
		}
	}
	seen := map[string]bool{}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return false
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || seen[key.Name] {
			return false
		}
		seen[key.Name] = true
		value, ok := routeUnparen(kv.Value).(*ast.Ident)
		if !ok || !params[value.Name] {
			return false
		}
		if key.Name == protected && value.Name != protectedParam {
			return false
		}
	}
	return protected == "" || seen[protected]
}

func routeMethodIn(files map[string]*ast.File, dir, typ, name string) *ast.FuncDecl {
	var result *ast.FuncDecl
	for rel, file := range files {
		if path.Dir(rel) == dir && !strings.HasSuffix(rel, "_test.go") {
			if fn := routeMethod(file, typ, name); fn != nil {
				if result != nil {
					return nil
				}
				result = fn
			}
		}
	}
	return result
}

// Fluent admission: только исходные parameters → неприкосновенные поля и return
// того же receiver. Calls, целиковая перезапись и скрытая мутация не допускаются.
func routeFluentPreserves(files map[string]*ast.File, dir, typ, method, protected string, setter bool) bool {
	fn := routeMethodIn(files, dir, typ, method)
	receiver := routeReceiver(fn)
	if receiver == "" || fn.Body == nil || len(fn.Body.List) < 1 || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	ptr, ok := routeUnparen(fn.Type.Results.List[0].Type).(*ast.StarExpr)
	if !ok || !routeIdent(ptr.X, typ) {
		return false
	}
	bindings := routeLocalBindings(fn)
	if bindings[receiver] != 1 {
		return false
	}
	params := map[string]bool{}
	for _, f := range fn.Type.Params.List {
		for _, id := range f.Names {
			if bindings[id.Name] != 1 {
				return false
			}
			params[id.Name] = true
		}
	}
	protectedWrites := 0
	for i, stmt := range fn.Body.List {
		if i == len(fn.Body.List)-1 {
			ret, ok := stmt.(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 || !routeIdent(ret.Results[0], receiver) {
				return false
			}
			continue
		}
		a, ok := stmt.(*ast.AssignStmt)
		if !ok || a.Tok != token.ASSIGN || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
			return false
		}
		field, ok := routeUnparen(a.Lhs[0]).(*ast.SelectorExpr)
		if !ok || !routeIdent(field.X, receiver) {
			return false
		}
		param, ok := routeUnparen(a.Rhs[0]).(*ast.Ident)
		if !ok || !params[param.Name] {
			return false
		}
		if field.Sel.Name == protected {
			protectedWrites++
			if !setter || len(fn.Type.Params.List) < 1 || len(fn.Type.Params.List[0].Names) != 1 || param.Name != fn.Type.Params.List[0].Names[0].Name {
				return false
			}
		}
	}
	if setter {
		return protectedWrites == 1
	}
	return protectedWrites == 0
}

// Раскрывается только fluent receiver chain; arguments не могут дополнить её
// constructor из discarded/невызываемого выражения.
func routeUnwrapChain(files map[string]*ast.File, file *ast.File, expr ast.Expr, dir, typ, protected string, allowSetter bool, visit func(*ast.CallExpr) bool) (*ast.CallExpr, bool) {
	for {
		c, ok := routeUnparen(expr).(*ast.CallExpr)
		if !ok {
			return nil, false
		}
		sel, ok := routeUnparen(c.Fun).(*ast.SelectorExpr)
		if !ok {
			return nil, false
		}
		if id, ok := routeUnparen(sel.X).(*ast.Ident); ok && routeImport(file, id.Name) != "" && routeAliasUnshadowed(file, id.Name) {
			return c, true
		}
		setter := allowSetter && sel.Sel.Name == "WithResourceRegistrar"
		if !routeFluentPreserves(files, dir, typ, sel.Sel.Name, protected, setter) || (visit != nil && !visit(c)) {
			return nil, false
		}
		expr = sel.X
	}
}

func routeLaterAssignments(files map[string]*ast.File, file *ast.File, fn *ast.FuncDecl, initial, consumer *ast.AssignStmt, name, dir, typ, protected string) bool {
	valid := routeMethodValuesAbsent(files, dir, typ, fn, name)
	ast.Inspect(fn, func(n ast.Node) bool {
		if !valid {
			return false
		}
		if lit, ok := n.(*ast.FuncLit); ok {
			if routeAny(lit, func(n ast.Node) bool { id, ok := n.(*ast.Ident); return ok && id.Name == name }) {
				valid = false
			}
			return false
		}
		switch node := n.(type) {
		case *ast.ValueSpec:
			for _, id := range node.Names {
				if id.Name == name {
					valid = false
				}
			}
			for _, value := range node.Values {
				if routeWiringReceiverEscapes(files, fn, value, name, dir, typ, protected) {
					valid = false
				}
			}
		case *ast.CallExpr:
			if sel, ok := routeUnparen(node.Fun).(*ast.SelectorExpr); ok && routeIdent(sel.X, name) && !routeFluentPreserves(files, dir, typ, sel.Sel.Name, protected, false) {
				valid = false
			}
			for i, arg := range node.Args {
				if routeWiringReceiverEscapes(files, fn, arg, name, dir, typ, protected) {
					allowed := false
					if consumer != nil && node.Pos() >= consumer.Pos() && node.End() <= consumer.End() {
						if sel, ok := routeUnparen(node.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "WithResourceRegistrar" && i == 0 && routeIdent(arg, name) {
							allowed = true
						}
					}
					if _, ok := routeUnparen(node.Fun).(*ast.Ident); ok && routeIdent(arg, name) {
						allowed = routeBoundObserverCall(files, fn, node, name, dir, typ, protected)
					}
					if !allowed {
						valid = false
					}
				}
			}
		case *ast.UnaryExpr:
			if node.Op == token.AND && routeAddressOfBinding(node.X, name) {
				valid = false
			}
		case *ast.Field:
			for _, id := range node.Names {
				if id.Name == name {
					valid = false
				}
			}
		case *ast.RangeStmt:
			for _, lhs := range []ast.Expr{node.Key, node.Value} {
				if routeIdent(lhs, name) {
					valid = false
				}
			}
		case *ast.AssignStmt:
			if node == initial {
				return true
			}
			for _, rhs := range node.Rhs {
				if routeWiringReceiverEscapes(files, fn, rhs, name, dir, typ, protected) && node != consumer {
					// Только присваивание тому же binding сохраняет владение fluent result.
					// Новый alias или передача результата неизвестному helper-у — escape.
					if node.Tok != token.ASSIGN || len(node.Lhs) != 1 || len(node.Rhs) != 1 || !routeIdent(node.Lhs[0], name) || !routeReassignmentChain(files, rhs, name, dir, typ, protected) {
						valid = false
					}
				}
			}
			for _, lhs := range node.Lhs {
				if routeIdent(lhs, name) {
					if node.Pos() < initial.Pos() || node.Tok != token.ASSIGN || len(node.Lhs) != 1 || len(node.Rhs) != 1 || !routeReassignmentChain(files, node.Rhs[0], name, dir, typ, protected) {
						valid = false
					}
				} else if routeExprHasName(lhs, name) {
					valid = false
				}
			}
		}
		return true
	})
	return valid
}
func routeReassignmentChain(files map[string]*ast.File, expr ast.Expr, name, dir, typ, protected string) bool {
	calls := 0
	for {
		if routeIdent(expr, name) {
			return calls > 0
		}
		c, ok := routeUnparen(expr).(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := routeUnparen(c.Fun).(*ast.SelectorExpr)
		if !ok || !routeFluentPreserves(files, dir, typ, sel.Sel.Name, protected, false) {
			return false
		}
		calls++
		expr = sel.X
	}
}
func routeExprHasName(expr ast.Expr, name string) bool {
	return routeAny(expr, func(n ast.Node) bool { id, ok := n.(*ast.Ident); return ok && id.Name == name })
}

// Без типизатора допускается только неизменённый receiver binding. Его адрес,
// alias, запись порта/целого receiver или передача receiver helper-у снимают proof.
func routeBindingUntouched(fn *ast.FuncDecl, receiver, protected string) bool {
	if fn == nil || receiver == "" || routeLocalBindings(fn)[receiver] != 1 {
		return false
	}
	valid := true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if routeIdent(lhs, receiver) {
					valid = false
				}
				if star, ok := routeUnparen(lhs).(*ast.StarExpr); ok && routeExprHasName(star.X, receiver) {
					valid = false
				}
				if protected != "" && routeSelector(lhs, receiver, protected) {
					valid = false
				}
			}
			for _, rhs := range node.Rhs {
				if routeBareReceiver(rhs, receiver) {
					valid = false
				}
			}
		case *ast.ValueSpec:
			for _, value := range node.Values {
				if routeBareReceiver(value, receiver) {
					valid = false
				}
			}
		case *ast.CallExpr:
			for _, arg := range node.Args {
				if routeBareReceiver(arg, receiver) {
					valid = false
				}
			}
		case *ast.UnaryExpr:
			if node.Op == token.AND && routeAddressOfBinding(node.X, receiver) {
				valid = false
			}
		}
		return true
	})
	return valid
}
func routeBareReceiver(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && routeIdent(sel.X, name) {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return true
	})
	return found
}
func routeMethodsPreserve(files map[string]*ast.File, dir, typ, method, protected string, seen map[string]bool) bool {
	if seen[method] {
		return true
	}
	fn := routeMethodIn(files, dir, typ, method)
	receiver := routeReceiver(fn)
	if fn == nil || !routeBindingUntouched(fn, receiver, protected) || !routeMethodValuesAbsent(files, dir, typ, fn, receiver) {
		return false
	}
	seen[method] = true
	valid := true
	// Проверяются также потенциальные receiver mutations в closures; сами они
	// executable witnesses не дают. Неизвестный receiver helper — отказ.
	routeAnyCall(fn.Body, func(c *ast.CallExpr) bool {
		if sel, ok := routeUnparen(c.Fun).(*ast.SelectorExpr); ok && routeIdent(sel.X, receiver) {
			if !routeMethodsPreserve(files, dir, typ, sel.Sel.Name, protected, seen) {
				valid = false
			}
		}
		return false
	})
	return valid
}
func routeMethodPath(files map[string]*ast.File, dir, typ, method, protected, target string, seen map[string]bool) bool {
	if seen[method] {
		return false
	}
	seen[method] = true
	fn := routeMethodIn(files, dir, typ, method)
	receiver := routeReceiver(fn)
	if fn == nil || !routeBindingUntouched(fn, receiver, protected) {
		return false
	}
	return routeExecutableCall(fn.Body, func(c *ast.CallExpr) bool {
		if routeNestedSelector(c.Fun, receiver, protected, target) {
			return true
		}
		sel, ok := routeUnparen(c.Fun).(*ast.SelectorExpr)
		return ok && routeIdent(sel.X, receiver) && routeMethodPath(files, dir, typ, sel.Sel.Name, protected, target, seen)
	})
}

// routeBoundObserverCall допускает только unshadowed package observer с одним
// исходным receiver argument и доказанным callback result. Другие nested calls
// продолжают анализироваться: общего исключения для вложенности нет.
func routeBoundObserverCall(files map[string]*ast.File, enclosing *ast.FuncDecl, call *ast.CallExpr, receiver, methodDir, typ, protected string) bool {
	callee, ok := routeUnparen(call.Fun).(*ast.Ident)
	if !ok || routeLocalBindings(enclosing)[callee.Name] != 0 || len(call.Args) != 1 || !routeIdent(call.Args[0], receiver) {
		return false
	}
	return routeObserverPreserves(files, "cmd/kaname", callee.Name, 0, methodDir, typ, protected)
}

func routeWiringReceiverEscapes(files map[string]*ast.File, enclosing *ast.FuncDecl, expr ast.Expr, receiver, dir, typ, protected string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && routeBoundObserverCall(files, enclosing, call, receiver, dir, typ, protected) {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && routeReassignmentChain(files, call, receiver, dir, typ, protected) {
			// Port-preserving fluent возвращает исходный receiver, а не snapshot.
			found = true
			return false
		}
		if sel, ok := n.(*ast.SelectorExpr); ok && routeIdent(sel.X, receiver) {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && id.Name == receiver {
			found = true
		}
		return true
	})
	return found
}

// Разрешённый observer — доказанный локальный reader, не permission по имени.
// Он может вернуть callback; во всём теле и callback сохраняется исходный port.
func routeObserverPreserves(files map[string]*ast.File, dir, name string, argIndex int, methodDir, typ, protected string) bool {
	var fn *ast.FuncDecl
	var owner *ast.File
	for rel, file := range files {
		if path.Dir(rel) == dir && !strings.HasSuffix(rel, "_test.go") {
			if found := routeFunction(file, name); found != nil {
				if fn != nil {
					return false
				}
				fn = found
				owner = file
			}
		}
	}
	if fn == nil || fn.Body == nil || len(fn.Body.List) != 1 || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	declared, ok := routeUnparen(fn.Type.Results.List[0].Type).(*ast.FuncType)
	ret, returned := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok || !returned || len(ret.Results) != 1 {
		return false
	}
	callback, ok := routeUnparen(ret.Results[0]).(*ast.FuncLit)
	if !ok || declared.Params.NumFields() != 0 || callback.Type.Params.NumFields() != 0 || declared.Results == nil || callback.Type.Results == nil || len(declared.Results.List) != 1 || len(callback.Type.Results.List) != 1 {
		return false
	}
	// Callback отдаёт снимок счётчиков, не сам receiver или его callable alias.
	for _, result := range []ast.Expr{declared.Results.List[0].Type, callback.Type.Results.List[0].Type} {
		mapping, ok := routeUnparen(result).(*ast.MapType)
		if !ok || !routeIdent(mapping.Value, "uint64") {
			return false
		}
	}
	var parameters []string
	for _, field := range fn.Type.Params.List {
		for _, id := range field.Names {
			parameters = append(parameters, id.Name)
		}
	}
	if len(parameters) != 1 || argIndex >= len(parameters) {
		return false
	}
	receiver := parameters[argIndex]
	typed := false
	for _, field := range fn.Type.Params.List {
		for _, id := range field.Names {
			if id.Name == receiver {
				typed = routeType(owner, field.Type, "github.com/PRO-Robotech/kaname/"+methodDir, typ)
			}
		}
	}
	if !typed || !routeBindingUntouched(fn, receiver, protected) || !routeMethodValuesAbsent(files, methodDir, typ, fn, receiver) {
		return false
	}
	valid := true
	routeAnyCall(fn.Body, func(c *ast.CallExpr) bool {
		if sel, ok := routeUnparen(c.Fun).(*ast.SelectorExpr); ok && routeIdent(sel.X, receiver) {
			if !routeMethodsPreserve(files, methodDir, typ, sel.Sel.Name, protected, map[string]bool{}) {
				valid = false
			}
		}
		return false
	})
	return valid
}

func routeAddressOfBinding(expr ast.Expr, name string) bool {
	switch routeUnparen(expr).(type) {
	case *ast.Ident, *ast.SelectorExpr, *ast.StarExpr, *ast.IndexExpr:
		return routeExprHasName(expr, name)
	}
	return false
}

// Метод, захваченный как значение, может мутировать receiver позже. Такая форма
// не равна доказанному прямому вызову и не допускается без отдельного анализа.
func routeMethodValuesAbsent(files map[string]*ast.File, dir, typ string, fn *ast.FuncDecl, receiver string) bool {
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	valid := true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && routeIdent(sel.X, receiver) && routeMethodIn(files, dir, typ, sel.Sel.Name) != nil {
			parent := parents[n]
			for {
				if _, ok := parent.(*ast.ParenExpr); !ok {
					break
				}
				parent = parents[parent]
			}
			call, ok := parent.(*ast.CallExpr)
			if !ok || routeUnparen(call.Fun) != sel {
				valid = false
			}
		}
		return true
	})
	return valid
}
