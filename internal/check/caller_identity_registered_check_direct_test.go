// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"strings"
	"testing"
)

const checkHandlerPackage = "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
const checkModuleReader = checkNarrowingProfilePackage + ".Roster.FromContext"

type checkRegistrationPath struct {
	maker, registered, adapter, narrowing string
}

// DirectCheckNarrowingPairForTest proves the declaration mutation at the direct
// reader of the registered Check. The exhaustive tree gate uses the full caller
// resolver for transitive readers and effects.
func DirectCheckNarrowingPairForTest(t *testing.T, ctx context.Context, root, missing string, declared []CallerReadDeclaration) (lawful, negative CheckNarrowingWitness, err error) {
	t.Helper()
	inputs, err := loadCheckNarrowingInputs(ctx, root, missing)
	if err != nil {
		return lawful, negative, err
	}
	withRow, path, err := directRegisteredCheckFacts(inputs.withRow.program)
	if err != nil {
		return lawful, negative, fmt.Errorf("Check с записью: %w", err)
	}
	withoutRow, otherPath, err := directRegisteredCheckFacts(inputs.withoutRow.program)
	if err != nil {
		return lawful, negative, fmt.Errorf("Check без записи: %w", err)
	}
	if path != otherPath || !slices.Equal(withRow.reads, withoutRow.reads) {
		return lawful, negative, fmt.Errorf("типизированные пути регистрации или чтения Check различаются между копиями")
	}
	if err := ctx.Err(); err != nil {
		return lawful, negative, err
	}
	t.Logf("REGISTERED_CHECK_DIRECT_PATH maker=%s registration=%s adapter=%s narrowing=%s",
		path.maker, path.registered, path.adapter, path.narrowing)
	return withRow.witness(inputs.withRow.table, declared), withoutRow.witness(inputs.withoutRow.table, declared), nil
}

func directRegisteredCheckFacts(p *surfaceProgram) (checkNarrowingFacts, checkRegistrationPath, error) {
	// Collect typed call and write indices. No resolve or fixed-point solver is
	// needed for this path of concrete calls and single source assignments.
	flow := newSurfaceFlow(p)
	flow.collect()
	handler, path, err := directCheckRegistration(flow)
	if err != nil {
		return checkNarrowingFacts{}, path, err
	}
	facts := checkNarrowingFacts{readSet: map[string]bool{}, appliedNarrow: map[string]bool{}}
	body := flow.decls[handler]
	if body.decl == nil || body.decl.Body == nil {
		return facts, path, fmt.Errorf("тело зарегистрированного Check отсутствует")
	}
	var moduleReads []*ast.CallExpr
	ast.Inspect(body.decl.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		if call, ok := node.(*ast.CallExpr); ok {
			if producer := callerProducer(callerFunction(body.pkg, call.Fun)); producer != "" {
				row := CallerIdentityRead{checkNarrowingRPC, producer, handler.FullName(), p.fset.Position(call.Pos()).String()}
				facts.reads = append(facts.reads, row)
				facts.readSet[row.RPC+"\x00"+row.Producer+"\x00"+row.Site] = true
				if producer == checkModuleReader {
					moduleReads = append(moduleReads, call)
				}
			}
		}
		return true
	})
	if len(moduleReads) != 1 {
		return facts, path, fmt.Errorf("ожидалось одно прямое чтение личности модуля в Check, найдено %d", len(moduleReads))
	}
	narrowing := directCheckNarrowingCall(flow, handler, moduleReads[0])
	if narrowing == nil {
		return facts, path, fmt.Errorf("чтение в Check не связано с типизированным вызовом сужения")
	}
	path.narrowing = p.fset.Position(narrowing.Pos()).String()
	facts.appliedNarrow[checkNarrowingRPC] = true
	return facts, path, nil
}

func directCheckRegistration(flow *surfaceFlow) (*types.Func, checkRegistrationPath, error) {
	p := flow.prog
	api := p.byPath[checkNarrowingAPI]
	if api == nil {
		return nil, checkRegistrationPath{}, fmt.Errorf("исходники регистрации InternalIAMService отсутствуют")
	}
	root := p.root.types.Scope()
	start, _ := root.Lookup("runServe").(*types.Func)
	build, _ := root.Lookup("buildServices").(*types.Func)
	register, _ := root.Lookup("registerInternalServices").(*types.Func)
	generated, _ := api.types.Scope().Lookup("RegisterInternalIAMServiceServer").(*types.Func)
	if start == nil || build == nil || register == nil || generated == nil {
		return nil, checkRegistrationPath{}, fmt.Errorf("точки сборки и регистрации Check не найдены")
	}
	startSites, registrationSites := flow.idx.calls[register], flow.idx.calls[generated]
	if len(startSites) != 1 || startSites[0].fk.fn != start || len(startSites[0].call.Args) < 2 ||
		len(registrationSites) != 1 || registrationSites[0].fk.fn != register || len(registrationSites[0].call.Args) != 2 {
		return nil, checkRegistrationPath{}, fmt.Errorf("ожидался путь runServe → registerInternalServices → RegisterInternalIAMServiceServer")
	}
	startSite, site := startSites[0], registrationSites[0]
	startRegistrar, ok := ast.Unparen(startSite.call.Args[0]).(*ast.CallExpr)
	if !ok {
		return nil, checkRegistrationPath{}, fmt.Errorf("runServe не передаёт внутренний регистратор")
	}
	registrar := callerFunction(startSite.pkg, startRegistrar.Fun)
	if registrar == nil || registrar.Pkg() != p.root.types || registrar.Name() != "internalRegistrar" {
		return nil, checkRegistrationPath{}, fmt.Errorf("runServe не передаёт внутренний регистратор")
	}
	services := callerVariable(startSite.pkg, startSite.call.Args[1])
	source := directCheckAssignedCall(flow.idx, services, start)
	if source == nil || source.Pos() >= startSite.call.Pos() || callerFunction(startSite.pkg, source.Fun) != build {
		return nil, checkRegistrationPath{}, fmt.Errorf("регистратор Check не получает результат buildServices из runServe")
	}
	handlerArg, ok := ast.Unparen(site.call.Args[1]).(*ast.SelectorExpr)
	params := register.Type().(*types.Signature).Params()
	if !ok || params.Len() < 2 || callerVariable(site.pkg, handlerArg.X) != params.At(1) ||
		callerVariable(site.pkg, site.call.Args[0]) != params.At(0) {
		return nil, checkRegistrationPath{}, fmt.Errorf("не подтверждена передача обработчика и регистратора из сборки cmd/kaname")
	}
	field := callerVariable(site.pkg, handlerArg)
	if field == nil || !field.IsField() || field.Name() != "internalIAMHandler" {
		return nil, checkRegistrationPath{}, fmt.Errorf("Check не получает поле internalIAMHandler")
	}
	maker := directCheckMaker(flow, build, field)
	if maker == nil {
		return nil, checkRegistrationPath{}, fmt.Errorf("не подтверждён NewHandler с WithModuleRoster для зарегистрированного поля Check")
	}
	concrete := site.pkg.info.TypeOf(handlerArg)
	pointer, ok := types.Unalias(concrete).(*types.Pointer)
	if !ok || !isNamed(pointer.Elem(), checkHandlerPackage, "Handler") {
		return nil, checkRegistrationPath{}, fmt.Errorf("Check зарегистрирован с другим типом получателя: %v", concrete)
	}
	handler, selection, _ := types.LookupFieldOrMethod(concrete, true, api.types, "Check")
	method, ok := handler.(*types.Func)
	if !ok || isIfaceMethod(method) || len(selection) != 1 {
		return nil, checkRegistrationPath{}, fmt.Errorf("Check не разрешён как прямой метод конкретного обработчика")
	}
	adapter := directCheckServiceAdapter(flow, api, generated)
	if adapter == nil {
		return nil, checkRegistrationPath{}, fmt.Errorf("сгенерированная регистрация не связывает дескриптор Check с его вызовом")
	}
	return method.Origin(), checkRegistrationPath{
		maker: p.fset.Position(maker.Pos()).String(), registered: p.fset.Position(site.call.Pos()).String(),
		adapter: p.fset.Position(adapter.Pos()).String(),
	}, nil
}

func directCheckAssignedCall(index *resolveIndex, variable *types.Var, owner *types.Func) *ast.CallExpr {
	refs := index.varWrites[variable]
	if variable == nil || index.addrTaken[variable] || len(refs) != 1 || refs[0].fk.fn != owner || refs[0].tuple != -1 {
		return nil
	}
	call, _ := ast.Unparen(refs[0].expr).(*ast.CallExpr)
	return call
}

func directCheckMaker(flow *surfaceFlow, build *types.Func, field *types.Var) *ast.CallExpr {
	returns := flow.idx.returns[fkey{fn: build}]
	writes := flow.idx.fieldWrites[field]
	if field == nil || len(returns) != 1 || len(returns[0]) != 1 || len(writes) != 1 || writes[0].fk.fn != build {
		return nil
	}
	ret := returns[0][0]
	address, ok := ast.Unparen(ret.expr).(*ast.UnaryExpr)
	if !ok || address.Op != token.AND {
		return nil
	}
	literal, ok := ast.Unparen(address.X).(*ast.CompositeLit)
	if !ok || directCheckField(ret.pkg, literal, field) != writes[0].expr {
		return nil
	}
	call := directCheckAssignedCall(flow.idx, callerVariable(ret.pkg, writes[0].expr), build)
	var roster bool
	for call != nil {
		fn := callerFunction(ret.pkg, call.Fun)
		if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != checkHandlerPackage {
			return nil
		}
		recv := fn.Type().(*types.Signature).Recv()
		if recv == nil {
			if fn.Name() == "NewHandler" && roster {
				return call
			}
			return nil
		}
		results := flow.idx.returns[fkey{fn: fn.Origin()}]
		if len(results) != 1 || len(results[0]) != 1 || callerVariable(results[0][0].pkg, results[0][0].expr) != recv {
			return nil
		}
		roster = roster || fn.Name() == "WithModuleRoster"
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return nil
		}
		call, _ = ast.Unparen(sel.X).(*ast.CallExpr)
	}
	return nil
}

func directCheckField(sp *surfaceSrcPkg, literal *ast.CompositeLit, field types.Object) ast.Expr {
	for _, element := range literal.Elts {
		if item, ok := element.(*ast.KeyValueExpr); ok {
			if id, ok := item.Key.(*ast.Ident); ok && sp.info.Uses[id] == field {
				return item.Value
			}
		}
	}
	return nil
}

func directCheckNamedField(sp *surfaceSrcPkg, literal *ast.CompositeLit, name string) ast.Expr {
	field, _, _ := types.LookupFieldOrMethod(sp.info.TypeOf(literal), false, nil, name)
	if field == nil {
		return nil
	}
	return directCheckField(sp, literal, field)
}

func directCheckServiceAdapter(flow *surfaceFlow, api *surfaceSrcPkg, register *types.Func) *ast.CallExpr {
	descriptor, _ := api.types.Scope().Lookup("InternalIAMService_ServiceDesc").(*types.Var)
	refs := flow.idx.varWrites[descriptor]
	body := flow.decls[register]
	params := register.Type().(*types.Signature).Params()
	if descriptor == nil || len(refs) != 1 || body.decl == nil || body.decl.Body == nil || params.Len() != 2 {
		return nil
	}
	registered := false
	for node := range ast.Preorder(body.decl.Body) {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			continue
		}
		fn := callerFunction(api, call.Fun)
		address, addr := ast.Unparen(call.Args[0]).(*ast.UnaryExpr)
		selector, selected := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "google.golang.org/grpc" && fn.Name() == "RegisterService" &&
			selected && callerVariable(api, selector.X) == params.At(0) &&
			addr && address.Op == token.AND && callerVariable(api, address.X) == descriptor && callerVariable(api, call.Args[1]) == params.At(1) {
			registered = true
		}
	}
	literal, ok := ast.Unparen(refs[0].expr).(*ast.CompositeLit)
	if !registered || !ok || directCheckConst(api, directCheckNamedField(api, literal, "ServiceName")) != "kaname.cloud.iam.v1.InternalIAMService" {
		return nil
	}
	methods, ok := directCheckNamedField(api, literal, "Methods").(*ast.CompositeLit)
	if !ok {
		return nil
	}
	var adapter *types.Func
	for _, elem := range methods.Elts {
		entry, ok := elem.(*ast.CompositeLit)
		if ok && directCheckConst(api, directCheckNamedField(api, entry, "MethodName")) == "Check" {
			if adapter != nil {
				return nil
			}
			adapter = callerFunction(api, directCheckNamedField(api, entry, "Handler"))
			if adapter == nil {
				return nil
			}
		}
	}
	adapterBody := flow.decls[adapter]
	if adapterBody.decl == nil || adapterBody.decl.Body == nil {
		return nil
	}
	method, _, _ := types.LookupFieldOrMethod(params.At(1).Type(), false, api.types, "Check")
	for node := range ast.Preorder(adapterBody.decl.Body) {
		if call, ok := node.(*ast.CallExpr); ok {
			if fn := callerFunction(api, call.Fun); fn != nil && fn == method {
				return call
			}
		}
	}
	return nil
}

func directCheckConst(sp *surfaceSrcPkg, expression ast.Expr) string {
	value := sp.info.Types[expression].Value
	if value == nil || value.Kind() != constant.String {
		return ""
	}
	return constant.StringVal(value)
}

func directCheckNarrowingCall(flow *surfaceFlow, handler *types.Func, read *ast.CallExpr) *ast.CallExpr {
	decl := flow.decls[handler]
	receiver := handler.Type().(*types.Signature).Recv()
	object, selection, _ := types.LookupFieldOrMethod(receiver.Type(), true, handler.Pkg(), "requireCheckInCallerDomain")
	helper, ok := object.(*types.Func)
	if read == nil || !ok || len(selection) != 1 {
		return nil
	}
	modulePassed := false
	for _, stmt := range decl.decl.Body.List {
		guard, ok := stmt.(*ast.IfStmt)
		if !ok {
			continue
		}
		init, ok := guard.Init.(*ast.AssignStmt)
		if !ok || len(init.Lhs) != 2 || len(init.Rhs) != 1 || ast.Unparen(init.Rhs[0]) != read ||
			callerVariable(decl.pkg, guard.Cond) != callerVariable(decl.pkg, init.Lhs[1]) {
			continue
		}
		for _, stmt := range guard.Body.List {
			use, ok := stmt.(*ast.IfStmt)
			if !ok {
				continue
			}
			assignment, ok := use.Init.(*ast.AssignStmt)
			if !ok || len(assignment.Rhs) != 1 {
				continue
			}
			call, ok := ast.Unparen(assignment.Rhs[0]).(*ast.CallExpr)
			if !ok || len(call.Args) != 2 || callerFunction(decl.pkg, call.Fun) != helper {
				continue
			}
			selection, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !ok || callerVariable(decl.pkg, selection.X) != receiver {
				continue
			}
			if v := callerVariable(decl.pkg, call.Args[0]); v != nil && v == callerVariable(decl.pkg, init.Lhs[0]) {
				modulePassed = true
			}
		}
	}
	params := helper.Type().(*types.Signature).Params()
	if !modulePassed || params.Len() != 2 {
		return nil
	}
	helperBody := flow.decls[helper.Origin()]
	if helperBody.decl == nil || helperBody.decl.Body == nil {
		return nil
	}
	for _, stmt := range helperBody.decl.Body.List {
		guard, ok := stmt.(*ast.IfStmt)
		if !ok {
			continue
		}
		negation, ok := ast.Unparen(guard.Cond).(*ast.UnaryExpr)
		if !ok || negation.Op != token.NOT {
			continue
		}
		call, ok := ast.Unparen(negation.X).(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			continue
		}
		target := callerFunction(helperBody.pkg, call.Fun)
		profile, ok := ast.Unparen(call.Args[1]).(*ast.SelectorExpr)
		if target != nil && target.Pkg() != nil && target.Pkg().Path() == checkNarrowingPackage && target.Name() == "NarrowsCallerArgument" &&
			directCheckConst(helperBody.pkg, call.Args[0]) == checkNarrowingMethod && ok && profile.Sel.Name == "Profile" &&
			callerVariable(helperBody.pkg, profile.X) == params.At(0) {
			return call
		}
	}
	return nil
}
