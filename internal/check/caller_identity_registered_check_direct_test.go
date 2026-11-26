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
	body := flow.decls[handler]
	if body.decl == nil || body.decl.Body == nil {
		return checkNarrowingFacts{}, path, fmt.Errorf("тело зарегистрированного Check отсутствует")
	}
	report := CallerIdentityReport{}
	observations := newCallerReadObservations(&report)
	moduleReads := observeDirectCheckBody(p, callerBody{body.pkg, body.decl.Body, handler.FullName()}, &observations)
	if len(moduleReads) != 1 {
		return checkNarrowingFacts{}, path, fmt.Errorf("ожидалось одно прямое чтение личности модуля в Check, найдено %d", len(moduleReads))
	}
	helper, narrowing := directCheckNarrowingCall(flow, handler, moduleReads[0])
	if narrowing == nil {
		return checkNarrowingFacts{}, path, fmt.Errorf("чтение в Check не связано с типизированным вызовом сужения")
	}
	if _, applied := observations.observeDirectCall(p, helper, narrowing, callerFunction(helper.sp, narrowing.Fun), checkNarrowingRPC); !applied {
		return checkNarrowingFacts{}, path, fmt.Errorf("гейт не подтвердил применение сужения Check")
	}
	observeDirectCheckBody(p, helper, &observations)
	path.narrowing = p.fset.Position(narrowing.Pos()).String()
	return checkNarrowingFacts{
		reads: report.Reads, readSet: observations.readSet, appliedNarrow: observations.appliedNarrow,
	}, path, nil
}

func observeDirectCheckBody(p *surfaceProgram, body callerBody, observations *callerReadObservations) []*ast.CallExpr {
	var moduleReads []*ast.CallExpr
	ast.Inspect(body.node, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		if call, ok := node.(*ast.CallExpr); ok {
			fn := callerFunction(body.sp, call.Fun)
			if producer, _ := observations.observeDirectCall(p, body, call, fn, checkNarrowingRPC); producer == checkModuleReader {
				moduleReads = append(moduleReads, call)
			}
		}
		return true
	})
	return moduleReads
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
	if !ok || !directCheckListener(flow, start, startSite.pkg, startRegistrar) {
		return nil, checkRegistrationPath{}, fmt.Errorf("runServe не передаёт регистратор внутреннего слушателя")
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
	generatedParams := generated.Type().(*types.Signature).Params()
	if generatedParams.Len() != 2 || !types.IsInterface(generatedParams.At(1).Type()) {
		return nil, checkRegistrationPath{}, fmt.Errorf("не найден интерфейс сгенерированной регистрации Check")
	}
	object, _, _ := types.LookupFieldOrMethod(generatedParams.At(1).Type(), false, api.types, "Check")
	method, ok := object.(*types.Func)
	if !ok || !method.Exported() {
		return nil, checkRegistrationPath{}, fmt.Errorf("не найден объявленный RPC Check")
	}
	target := callerRegistrationMethod(generated, method, concrete)
	if target.rpc != checkNarrowingRPC || target.fn == nil || target.indirect {
		return nil, checkRegistrationPath{}, fmt.Errorf("Check не разрешён как прямой метод конкретного обработчика")
	}
	adapter := directCheckServiceAdapter(flow, api, generated, method)
	if adapter == nil {
		return nil, checkRegistrationPath{}, fmt.Errorf("сгенерированная регистрация не связывает дескриптор Check с его вызовом")
	}
	return target.fn.Origin(), checkRegistrationPath{
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

func directCheckListener(flow *surfaceFlow, start *types.Func, sp *surfaceSrcPkg, call *ast.CallExpr) bool {
	registrar := callerFunction(sp, call.Fun)
	if registrar == nil || registrar.Pkg() != sp.types || registrar.Name() != "internalRegistrar" || len(call.Args) != 1 {
		return false
	}
	server := callerVariable(sp, call.Args[0])
	source := directCheckAssignedCall(flow.idx, server, start)
	if source == nil || source.Pos() >= call.Pos() {
		return false
	}
	constructor := callerFunction(sp, source.Fun)
	if constructor == nil || constructor.Pkg() == nil || constructor.Pkg().Path() != "github.com/PRO-Robotech/corelib/grpcsrv" ||
		constructor.Name() != "NewServer" {
		return false
	}
	object, _, _ := types.LookupFieldOrMethod(server.Type(), true, sp.types, "Serve")
	serve, ok := object.(*types.Func)
	if !ok {
		return false
	}
	for _, site := range flow.idx.calls[serve.Origin()] {
		if site.pkg != sp || len(site.call.Args) != 1 {
			continue
		}
		selector, ok := ast.Unparen(site.call.Fun).(*ast.SelectorExpr)
		listener := callerVariable(sp, site.call.Args[0])
		if !ok || callerVariable(sp, selector.X) != server || listener == nil || listener.Name() != "internalListener" {
			continue
		}
		owner := site.fk
		for owner.lit != nil {
			owner = flow.litOwner[owner.lit]
		}
		if owner.fn == start {
			return true
		}
	}
	return false
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

func directCheckServiceAdapter(flow *surfaceFlow, api *surfaceSrcPkg, register, method *types.Func) *ast.CallExpr {
	descriptor, _ := api.types.Scope().Lookup("InternalIAMService_ServiceDesc").(*types.Var)
	refs := flow.idx.varWrites[descriptor]
	body := flow.decls[register]
	params := register.Type().(*types.Signature).Params()
	if descriptor == nil || len(refs) != 1 || body.decl == nil || body.decl.Body == nil || params.Len() != 2 {
		return nil
	}
	registered := false
	for _, statement := range body.decl.Body.List {
		expression, ok := statement.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := ast.Unparen(expression.X).(*ast.CallExpr)
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
	adapterParams := adapter.Type().(*types.Signature).Params()
	statements := adapterBody.decl.Body.List
	if adapterParams.Len() != 4 || len(statements) == 0 {
		return nil
	}
	server, interceptor := adapterParams.At(0), adapterParams.At(3)
	dispatch := directCheckReturnCall(statements[len(statements)-1])
	if dispatch == nil || len(dispatch.Args) != 4 || callerVariable(api, dispatch.Fun) != interceptor {
		return nil
	}
	callback := callerVariable(api, dispatch.Args[3])
	sources := flow.idx.varWrites[callback]
	if callback == nil || len(sources) != 1 || sources[0].fk.fn != adapter || flow.idx.addrTaken[callback] {
		return nil
	}
	lit, ok := ast.Unparen(sources[0].expr).(*ast.FuncLit)
	if !ok || len(lit.Body.List) != 1 || directCheckAdapterCall(api, lit.Body.List[0], method, server) == nil {
		return nil
	}
	for _, st := range statements {
		branch, ok := st.(*ast.IfStmt)
		if !ok || branch.Init != nil || len(branch.Body.List) != 1 {
			continue
		}
		cond, ok := ast.Unparen(branch.Cond).(*ast.BinaryExpr)
		if ok && cond.Op == token.EQL && callerVariable(api, cond.X) == interceptor && callerNil(api, cond.Y) {
			return directCheckAdapterCall(api, branch.Body.List[0], method, server)
		}
	}
	return nil
}

func directCheckReturnCall(statement ast.Stmt) *ast.CallExpr {
	ret, ok := statement.(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return nil
	}
	call, _ := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
	return call
}

func directCheckAdapterCall(sp *surfaceSrcPkg, statement ast.Stmt, method *types.Func, server *types.Var) *ast.CallExpr {
	call := directCheckReturnCall(statement)
	if call == nil || callerFunction(sp, call.Fun) != method {
		return nil
	}
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	receiver, ok := ast.Unparen(selector.X).(*ast.TypeAssertExpr)
	if !ok || callerVariable(sp, receiver.X) != server {
		return nil
	}
	return call
}

func directCheckConst(sp *surfaceSrcPkg, expression ast.Expr) string {
	value := sp.info.Types[expression].Value
	if value == nil || value.Kind() != constant.String {
		return ""
	}
	return constant.StringVal(value)
}

func directCheckNarrowingCall(flow *surfaceFlow, handler *types.Func, read *ast.CallExpr) (callerBody, *ast.CallExpr) {
	decl := flow.decls[handler]
	receiver := handler.Type().(*types.Signature).Recv()
	object, selection, _ := types.LookupFieldOrMethod(receiver.Type(), true, handler.Pkg(), "requireCheckInCallerDomain")
	helper, ok := object.(*types.Func)
	if read == nil || !ok || len(selection) != 1 {
		return callerBody{}, nil
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
		return callerBody{}, nil
	}
	helperBody := flow.decls[helper.Origin()]
	if helperBody.decl == nil || helperBody.decl.Body == nil {
		return callerBody{}, nil
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
		profile, ok := ast.Unparen(call.Args[1]).(*ast.SelectorExpr)
		if directCheckConst(helperBody.pkg, call.Args[0]) == checkNarrowingMethod && ok && profile.Sel.Name == "Profile" &&
			callerVariable(helperBody.pkg, profile.X) == params.At(0) {
			return callerBody{helperBody.pkg, helperBody.decl.Body, helper.FullName()}, call
		}
	}
	return callerBody{}, nil
}
