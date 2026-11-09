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
	"unicode"
)

const directAppDir = "internal/apps/kaname/api/internal_iam"
const directAppImport = "github.com/PRO-Robotech/kaname/" + directAppDir
const directPGImport = "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"

// CensusDirectProducers доказывает отдельную ограниченную форму посева:
// Test → factory, возвращающий свой world → concrete use-case в typed поле →
// вызванные методы этого world → Register → concrete adapter → UpsertTx.
// Ветки, циклы и closures не дают свидетельств вызова. Неизвестная передача
// world/поля, неоднозначное имя и перезапись снимают доказательство. Это не
// общий анализ потока и не замена независимого доказательства RPC-пути.
func CensusDirectProducers(corpus map[string][]byte) (map[string]bool, int, error) {
	files := map[string]*ast.File{}
	packages := map[string]map[string]*ast.File{}
	for rel, body := range corpus {
		f, err := parser.ParseFile(token.NewFileSet(), rel, body, parser.SkipObjectResolution)
		if err != nil {
			return nil, 0, fmt.Errorf("разбор direct producer %s: %w", rel, err)
		}
		files[rel] = f
		if strings.HasSuffix(rel, "_test.go") {
			key := path.Dir(rel) + "/" + f.Name.Name
			if packages[key] == nil {
				packages[key] = map[string]*ast.File{}
			}
			packages[key][rel] = f
		}
	}
	uc := files[directAppDir+"/register_resource.go"]
	adapter := files["internal/repo/kaname/pg/resource_mirror_emitter.go"]
	if uc == nil || adapter == nil {
		return nil, 0, fmt.Errorf("неполный корпус direct use-case→mirror")
	}
	result := map[string]bool{}
	if !directProductionProof(files, uc, adapter) {
		return result, 0, nil
	}
	count := 0
	for key, pkg := range packages {
		booleanBindingsSafe := true
		for _, f := range pkg {
			booleanBindingsSafe = booleanBindingsSafe && directBooleanLiteralsUnshadowed(f)
		}
		if !booleanBindingsSafe {
			continue
		}
		for _, f := range pkg {
			for _, d := range f.Decls {
				factory, ok := d.(*ast.FuncDecl)
				if !ok || factory.Recv != nil || factory.Body == nil || factory.Type.Results == nil {
					continue
				}
				// Оба доказательства чистые: дешёвые отказы формы предшествуют
				// поиску вызовов во всех Test пакета. Критерий A && B не меняется.
				if directFactoryProof(files, pkg, f, factory) && directFactoryCalled(files, pkg, factory) {
					result[key] = true
					count++
				}
			}
		}
	}
	return result, count, nil
}

func directProductionProof(files map[string]*ast.File, uc, adapter *ast.File) bool {
	if !directBooleanLiteralsUnshadowed(uc) || !routeConstructor(uc, "NewRegisterResourceUseCase", "RegisterResourceUseCase", "mirror", 1) ||
		!routeConstructor(adapter, "NewResourceMirrorEmitter", "ResourceMirrorEmitter", "", -1) ||
		!routeFieldType(uc, "RegisterResourceUseCase", "mirror", "", "resourceMirrorEmitter") ||
		!routeMethodsPreserve(files, directAppDir, "RegisterResourceUseCase", "Register", "mirror", map[string]bool{}) ||
		!directWriteIntentProof(uc) {
		return false
	}
	method := routeMethod(adapter, "ResourceMirrorEmitter", "UpsertTx")
	if method == nil || !routeBindingUntouched(method, routeReceiver(method), "") {
		return false
	}
	return directStraightCalls(method.Body, func(c *ast.CallExpr) bool {
		return routeImportedCall(adapter, c, "github.com/PRO-Robotech/kaname/"+EdgeProducerImport, EdgeProducerCall)
	})
}

// Имя Test само по себе недостаточно: требуется сигнатура testing.T и
// непосредственный вызов однозначной factory из того же Go-пакета.
func directTestParameter(file *ast.File, fn *ast.FuncDecl) string {
	if fn.Recv != nil || fn.Type.Params == nil || len(fn.Type.Params.List) != 1 || fn.Type.Results != nil {
		return ""
	}
	field := fn.Type.Params.List[0]
	if len(field.Names) != 1 || !routeType(file, field.Type, "testing", "T") {
		return ""
	}
	ptr, ok := routeUnparen(field.Type).(*ast.StarExpr)
	if !ok {
		return ""
	}
	sel, ok := routeUnparen(ptr.X).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	alias, ok := routeUnparen(sel.X).(*ast.Ident)
	if !ok || !routeAliasUnshadowed(file, alias.Name) {
		return ""
	}
	name := field.Names[0].Name
	if routeLocalBindings(fn)[name] != 1 {
		return ""
	}
	return name
}

func directFactoryCalled(files, pkg map[string]*ast.File, factory *ast.FuncDecl) bool {
	unique := 0
	for _, f := range pkg {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == factory.Name.Name {
				unique++
			}
		}
	}
	if unique != 1 {
		return false
	}
	for _, f := range pkg {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			suffix := []rune(strings.TrimPrefix(fn.Name.Name, "Test"))
			if len(suffix) > 0 && unicode.IsLower(suffix[0]) {
				continue
			}
			param := directTestParameter(f, fn)
			if param == "" || routeLocalBindings(fn)[factory.Name.Name] != 0 {
				continue
			}
			if directStraightCalls(fn.Body, func(c *ast.CallExpr) bool {
				return routeIdent(c.Fun, factory.Name.Name) && len(c.Args) == 1 && routeIdent(c.Args[0], param)
			}, func(branch *ast.IfStmt, previous ast.Stmt) bool {
				return directErrorFatalGuard(files, pkg, f, fn, branch, previous)
			}) {
				return true
			}
		}
	}
	return false
}

func directFactoryProof(files, pkg map[string]*ast.File, file *ast.File, fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 || fn.Type.Params == nil || len(fn.Type.Params.List) != 1 || len(fn.Body.List) < 3 {
		return false
	}
	ptr, ok := routeUnparen(fn.Type.Results.List[0].Type).(*ast.StarExpr)
	if !ok {
		return false
	}
	typ, ok := routeUnparen(ptr.X).(*ast.Ident)
	if !ok {
		return false
	}
	ret, ok := fn.Body.List[len(fn.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	world, ok := routeUnparen(ret.Results[0]).(*ast.Ident)
	if !ok || routeLocalBindings(fn)[world.Name] != 1 {
		return false
	}
	initial := routeDirectDefinition(fn, world.Name)
	if initial == nil || routeReturnedLiteral(initial.Rhs[0], typ.Name) == nil {
		return false
	}
	returns := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if _, ok := n.(*ast.ReturnStmt); ok {
			returns++
		}
		return true
	})
	if returns != 1 {
		return false
	}
	// Поле выводится из assignment и сверяется с единственным объявлением типа.
	for index, stmt := range fn.Body.List {
		a, ok := stmt.(*ast.AssignStmt)
		if !ok || a.Tok != token.ASSIGN || len(a.Lhs) != 1 || len(a.Rhs) != 1 || a.Pos() <= initial.Pos() {
			continue
		}
		lhs, ok := routeUnparen(a.Lhs[0]).(*ast.SelectorExpr)
		if !ok || !routeIdent(lhs.X, world.Name) || !directFieldType(pkg, typ.Name, lhs.Sel.Name) {
			continue
		}
		base, ok := routeUnwrapChain(files, file, a.Rhs[0], directAppDir, "RegisterResourceUseCase", "mirror", false, nil)
		if !ok || !routeImportedCall(file, base, directAppImport, "NewRegisterResourceUseCase") || len(base.Args) < 2 {
			continue
		}
		emitter, ok := routeUnparen(base.Args[1]).(*ast.CallExpr)
		if !ok || !routeImportedCall(file, emitter, directPGImport, "NewResourceMirrorEmitter") || len(emitter.Args) != 0 {
			continue
		}
		prefixSafe := true
		for at, statement := range fn.Body.List[:index] {
			if directStops(statement) {
				var previous ast.Stmt
				if at > 0 {
					previous = fn.Body.List[at-1]
				}
				branch, ok := statement.(*ast.IfStmt)
				if !ok || !directErrorFatalGuard(files, pkg, file, fn, branch, previous) {
					prefixSafe = false
				}
			}
		}
		if !prefixSafe || !directWorldSafe(files, pkg, fn, world.Name, typ.Name, lhs.Sel.Name, initial, a, map[string]bool{}) {
			continue
		}
		tail := &ast.BlockStmt{List: fn.Body.List[index+1 : len(fn.Body.List)-1]}
		if directWorldPath(pkg, tail, world.Name, typ.Name, lhs.Sel.Name, map[string]bool{}) {
			return true
		}
	}
	return false
}

func directFieldType(pkg map[string]*ast.File, typ, field string) bool {
	declarations := 0
	valid := false
	for _, f := range pkg {
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, s := range g.Specs {
				t, ok := s.(*ast.TypeSpec)
				if !ok || t.Name.Name != typ {
					continue
				}
				declarations++
				st, ok := t.Type.(*ast.StructType)
				if !ok || t.Assign.IsValid() {
					continue
				}
				for _, member := range st.Fields.List {
					for _, id := range member.Names {
						if id.Name != field {
							continue
						}
						pointer, ok := routeUnparen(member.Type).(*ast.StarExpr)
						if !ok {
							continue
						}
						selector, ok := routeUnparen(pointer.X).(*ast.SelectorExpr)
						if !ok {
							continue
						}
						alias, ok := routeUnparen(selector.X).(*ast.Ident)
						valid = ok && routeAliasUnshadowed(f, alias.Name) && routeType(f, member.Type, directAppImport, "RegisterResourceUseCase")
					}
				}
			}
		}
	}
	return declarations == 1 && valid
}

func directMethod(pkg map[string]*ast.File, typ, name string) *ast.FuncDecl {
	var found *ast.FuncDecl
	for _, f := range pkg {
		if method := routeMethod(f, typ, name); method != nil {
			if found != nil {
				return nil
			}
			found = method
		}
	}
	return found
}

// Проверяются и невызванные ветки методов: они не доказывают посев, но
// потенциальная мутация всё равно должна снять доказательство неизменности.
func directWorldSafe(files, pkg map[string]*ast.File, fn *ast.FuncDecl, receiver, typ, field string, definition, initial *ast.AssignStmt, seen map[string]bool) bool {
	if fn == nil || fn.Body == nil || (fn.Recv != nil && fn.Type.Results != nil) {
		return false
	}
	clone := *fn
	if definition != nil {
		// Только уже доказанное единственное w := &World{} становится входом
		// проверки неизменности. Общий RPC predicate и последующие записи прежние.
		if definition != routeDirectDefinition(fn, receiver) || routeLocalBindings(fn)[receiver] != 1 {
			return false
		}
		typCopy := *fn.Type
		params := *fn.Type.Params
		params.List = append(append([]*ast.Field{}, params.List...), &ast.Field{Names: []*ast.Ident{ast.NewIdent(receiver)}, Type: fn.Type.Results.List[0].Type})
		typCopy.Params = &params
		clone.Type = &typCopy
	}
	body := *fn.Body
	body.List = nil
	for _, s := range fn.Body.List {
		if s != initial && s != definition {
			body.List = append(body.List, s)
		}
	}
	clone.Body = &body
	if !routeBindingUntouched(&clone, receiver, field) {
		return false
	}
	allowed := map[ast.Node]bool{}
	methodCalls := map[ast.Node]bool{}
	if initial != nil {
		allowed[routeUnparen(initial.Lhs[0])] = true
	}
	valid := true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if !valid {
			return false
		}
		if c, ok := n.(*ast.CallExpr); ok {
			sel, ok := routeUnparen(c.Fun).(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if routeSelector(sel.X, receiver, field) {
				if sel.Sel.Name != "Register" || len(c.Args) != 2 {
					valid = false
					return false
				}
				allowed[routeUnparen(sel.X)] = true
			}
			if routeIdent(sel.X, receiver) {
				methodCalls[sel] = true
				key := typ + "." + sel.Sel.Name
				if seen[key] {
					valid = false
					return false
				}
				seen[key] = true
				method := directMethod(pkg, typ, sel.Sel.Name)
				if method == nil || !directWorldSafe(files, pkg, method, routeReceiver(method), typ, field, nil, nil, seen) {
					valid = false
				}
				delete(seen, key)
			}
		}
		return true
	})
	// Любое другое употребление protected-поля — alias, method value или escape.
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if star, ok := n.(*ast.StarExpr); ok && routeExprHasName(star.X, receiver) {
			valid = false
		}
		if s, ok := n.(*ast.SelectorExpr); ok {
			if routeSelector(s, receiver, field) && !allowed[s] {
				valid = false
			}
			if routeIdent(s.X, receiver) && directMethod(pkg, typ, s.Sel.Name) != nil && !methodCalls[s] {
				valid = false
			}
		}
		return true
	})
	return valid
}

func directWorldPath(pkg map[string]*ast.File, body *ast.BlockStmt, receiver, typ, field string, seen map[string]bool) bool {
	return directStraightCalls(body, func(c *ast.CallExpr) bool {
		if routeNestedSelector(c.Fun, receiver, field, "Register") && len(c.Args) == 2 {
			return true
		}
		sel, ok := routeUnparen(c.Fun).(*ast.SelectorExpr)
		if !ok || !routeIdent(sel.X, receiver) || seen[sel.Sel.Name] {
			return false
		}
		seen[sel.Sel.Name] = true
		method := directMethod(pkg, typ, sel.Sel.Name)
		return method != nil && directWorldPath(pkg, method.Body, routeReceiver(method), typ, field, seen)
	})
}

// Читается только линейная часть до return/перехода/цикла. У if исполняется
// init, но ни одна условная ветка не считается свидетелем. У &&/|| правая
// часть может не вычисляться; аргументы обычного вызова вычисляются всегда.
func directStraightCalls(body *ast.BlockStmt, predicate func(*ast.CallExpr) bool, guards ...func(*ast.IfStmt, ast.Stmt) bool) bool {
	if body == nil {
		return false
	}
	stopped := false
	var expression func(ast.Expr) bool
	expression = func(e ast.Expr) bool {
		if e == nil || stopped {
			return false
		}
		switch n := routeUnparen(e).(type) {
		case *ast.FuncLit:
			stopped = true
			return false
		case *ast.CallExpr:
			// Terminal/closure в аргументах не даёт объявить внешний call живым.
			if directStops(&ast.ExprStmt{X: n}) {
				stopped = true
				return false
			}
			if predicate(n) {
				return true
			}
			for _, arg := range n.Args {
				if expression(arg) {
					return true
				}
			}
		case *ast.BinaryExpr:
			if expression(n.X) {
				return true
			}
			if n.Op != token.LAND && n.Op != token.LOR {
				return expression(n.Y)
			}
		case *ast.UnaryExpr:
			return expression(n.X)
		}
		return false
	}
	var simple func(ast.Stmt) bool
	simple = func(s ast.Stmt) bool {
		switch n := s.(type) {
		case *ast.ExprStmt:
			return expression(n.X)
		case *ast.AssignStmt:
			for _, e := range n.Rhs {
				if expression(e) {
					return true
				}
			}
		case *ast.IfStmt:
			if n.Init != nil {
				return simple(n.Init)
			}
		}
		return false
	}
	for index, s := range body.List {
		if simple(s) {
			return true
		}
		if stopped {
			return false
		}
		if directStops(s) {
			var previous ast.Stmt
			if index > 0 {
				previous = body.List[index-1]
			}
			branch, ok := s.(*ast.IfStmt)
			if !ok || len(guards) != 1 || !guards[0](branch, previous) {
				return false
			}
		}
	}
	return false
}

// Не продолжаем после явного выхода либо неподдержанного перехода. Условный
// return также закрывает путь; исключение — явно false без подмены имени.
func directStops(stmt ast.Stmt) bool {
	if branch, ok := stmt.(*ast.IfStmt); ok {
		if branch.Init != nil && directStops(branch.Init) {
			return true
		}
		if routeIdent(branch.Cond, "false") {
			return branch.Else != nil && directStops(branch.Else)
		}
	}
	return routeAny(stmt, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ReturnStmt, *ast.BranchStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.LabeledStmt:
			return true
		case *ast.FuncLit:
			// Даже немедленная closure требует другого разбора связывания.
			return true
		case *ast.CallExpr:
			return directTerminalCall(node)
		}
		return false
	})
}

func directTerminalCall(call *ast.CallExpr) bool {
	if routeIdent(call.Fun, "panic") {
		return true
	}
	if sel, ok := routeUnparen(call.Fun).(*ast.SelectorExpr); ok {
		switch sel.Sel.Name {
		case "Fatal", "Fatalf", "FailNow", "Skip", "Skipf", "SkipNow", "Goexit":
			return true
		}
	}
	return false
}

// Guard разрешён лишь непосредственно после call-result assignment либо в его
// if-init. Параметр, alias, literal, отложенная/ветвящаяся запись не являются
// результатом этого вызова. Известную локальную сигнатуру проверяем по error;
// внешний two-result setup остаётся явно условной предпосылкой, не успехом.
func directErrorFatalGuard(files, pkg map[string]*ast.File, file *ast.File, fn *ast.FuncDecl, branch *ast.IfStmt, previous ast.Stmt) bool {
	if branch.Else != nil || len(branch.Body.List) != 1 || fn.Type.Params == nil {
		return false
	}
	cond, ok := routeUnparen(branch.Cond).(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ || !routeIdent(cond.Y, "nil") {
		return false
	}
	binding, ok := routeUnparen(cond.X).(*ast.Ident)
	if !ok || binding.Name == "_" {
		return false
	}
	tester := directParameterName(fn, 0)
	if tester == "" || binding.Name == tester || !routeParameter(fn, tester, file, "testing", "T") || routeLocalBindings(fn)[tester] != 1 {
		return false
	}
	expr, ok := branch.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	fatal, ok := routeUnparen(expr.X).(*ast.CallExpr)
	if !ok || (!routeSelector(fatal.Fun, tester, "Fatal") && !routeSelector(fatal.Fun, tester, "Fatalf")) {
		return false
	}
	statement := previous
	if branch.Init != nil {
		statement = branch.Init
	}
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || len(assignment.Rhs) != 1 || len(assignment.Lhs) == 0 || len(assignment.Lhs) > 2 || !routeIdent(assignment.Lhs[len(assignment.Lhs)-1], binding.Name) {
		return false
	}
	// Вне if-init принимается только новое прямое объявление результата.
	if assignment.Tok != token.DEFINE && (branch.Init == nil || assignment.Tok != token.ASSIGN || len(assignment.Lhs) != 2) {
		return false
	}
	if len(assignment.Lhs) == 2 && routeIdent(assignment.Lhs[0], binding.Name) {
		return false
	}
	call, ok := routeUnparen(assignment.Rhs[0]).(*ast.CallExpr)
	if !ok || directStops(assignment) {
		return false
	}
	if id, ok := routeUnparen(call.Fun).(*ast.Ident); ok && routeLocalBindings(fn)[id.Name] != 0 {
		return false
	}
	declaration, external := directSetupDeclaration(files, pkg, file, call)
	if external {
		return len(assignment.Lhs) == 2
	}
	if declaration == nil || declaration.Type.Results == nil {
		return false
	}
	results := []ast.Expr{}
	for _, field := range declaration.Type.Results.List {
		n := len(field.Names)
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			results = append(results, field.Type)
		}
	}
	return len(results) == len(assignment.Lhs) && routeIdent(results[len(results)-1], "error")
}

// Разрешаются только package function и constructor().Method с видимой
// сигнатурой; локальные function values и произвольные receiver chains закрыты.
func directSetupDeclaration(files, pkg map[string]*ast.File, file *ast.File, call *ast.CallExpr) (*ast.FuncDecl, bool) {
	if id, ok := routeUnparen(call.Fun).(*ast.Ident); ok {
		var found *ast.FuncDecl
		for _, f := range pkg {
			if !directPredeclaredNameUnshadowed(f, "error") {
				return nil, false
			}
			if fn := routeFunction(f, id.Name); fn != nil {
				if found != nil {
					return nil, false
				}
				found = fn
			}
		}
		return found, false
	}
	sel, ok := routeUnparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	if alias, ok := routeUnparen(sel.X).(*ast.Ident); ok {
		imported := routeImport(file, alias.Name)
		if imported == "" || !routeAliasUnshadowed(file, alias.Name) {
			return nil, false
		}
		const module = "github.com/PRO-Robotech/kaname/"
		if !strings.HasPrefix(imported, module) {
			return nil, true
		}
		var found *ast.FuncDecl
		for rel, f := range files {
			if path.Dir(rel) == strings.TrimPrefix(imported, module) && !strings.HasSuffix(rel, "_test.go") {
				if !directPredeclaredNameUnshadowed(f, "error") {
					return nil, false
				}
				if fn := routeFunction(f, sel.Sel.Name); fn != nil {
					if found != nil {
						return nil, false
					}
					found = fn
				}
			}
		}
		return found, false
	}
	constructor, ok := routeUnparen(sel.X).(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	decl, external := directSetupDeclaration(files, pkg, file, constructor)
	if external || decl == nil || decl.Type.Results == nil || len(decl.Type.Results.List) != 1 {
		return nil, false
	}
	pointer, ok := routeUnparen(decl.Type.Results.List[0].Type).(*ast.StarExpr)
	if !ok {
		return nil, false
	}
	typ, ok := routeUnparen(pointer.X).(*ast.Ident)
	if !ok {
		return nil, false
	}
	owner, ok := routeUnparen(constructor.Fun).(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	alias, ok := routeUnparen(owner.X).(*ast.Ident)
	if !ok {
		return nil, false
	}
	dir := strings.TrimPrefix(routeImport(file, alias.Name), "github.com/PRO-Robotech/kaname/")
	return routeMethodIn(files, dir, typ.Name, sel.Sel.Name), false
}

// Здесь доказан только существующий протокол Register→emit→emitAttempt:
// literal true, неизменённые параметры write/row и положительная ветвь write.
// Имена параметров выводятся из сигнатур; других цепей/циклов этот прибор
// не угадывает. Старый RPC call-graph predicate этим не меняется.
func directWriteIntentProof(file *ast.File) bool {
	register := routeMethod(file, "RegisterResourceUseCase", "Register")
	emit := routeMethod(file, "RegisterResourceUseCase", "emit")
	attempt := routeMethod(file, "RegisterResourceUseCase", "emitAttempt")
	if register == nil || emit == nil || attempt == nil {
		return false
	}
	ctx := directParameterName(register, 0)
	input := directParameterName(register, 1)
	if ctx == "" || input == "" || routeLocalBindings(register)[ctx] != 1 || routeLocalBindings(register)[input] != 1 || routeLocalBindings(register)["true"] != 0 {
		return false
	}
	start := directUniqueImmediateCall(register.Body, routeReceiver(register), "emit", "")
	if directCallCount(register, routeReceiver(register), "emit") != 1 || start == nil || len(start.Args) != 4 || !routeIdent(start.Args[0], ctx) || !routeIdent(start.Args[3], "true") || !directRegistrationRow(file, register, start, input) {
		return false
	}
	ectx, erow, ewrite := directParameterName(emit, 0), directParameterName(emit, 2), directParameterName(emit, 3)
	actx, arow, awrite := directParameterName(attempt, 0), directParameterName(attempt, 2), directParameterName(attempt, 3)
	if !directWriteParameters(file, emit, erow, ewrite) || !directWriteParameters(file, attempt, arow, awrite) {
		return false
	}
	// Поддерживается ровно один retry-for с ненулевой константой и direct call.
	var forward *ast.CallExpr
	for _, stmt := range emit.Body.List {
		if loop, ok := stmt.(*ast.ForStmt); ok {
			if forward != nil || !directPositiveLoop(file, emit, loop) {
				return false
			}
			forward = directUniqueImmediateCall(loop.Body, routeReceiver(emit), "emitAttempt", ewrite)
			break
		}
		if !directProductionPrefix(stmt, ewrite) {
			return false
		}
	}
	if forward == nil || len(forward.Args) != 6 || !routeIdent(forward.Args[0], ectx) || !routeIdent(forward.Args[1], directParameterName(emit, 1)) || !routeIdent(forward.Args[2], erow) || !routeIdent(forward.Args[3], ewrite) {
		return false
	}
	if directCallCount(emit, routeReceiver(emit), "emitAttempt") != 1 {
		return false
	}
	// Upsert обязан стоять непосредственно в положительной ветви того же bool.
	var upsert *ast.CallExpr
	for _, stmt := range attempt.Body.List {
		if branch, ok := stmt.(*ast.IfStmt); ok && branch.Init == nil && routeIdent(branch.Cond, awrite) {
			candidate := directUniqueImmediateCall(branch.Body, routeReceiver(attempt)+".mirror", "UpsertTx", awrite)
			if candidate != nil {
				upsert = candidate
				break
			}
		}
		if !directProductionPrefix(stmt, awrite) {
			return false
		}
	}
	if upsert == nil || len(upsert.Args) != 3 || !routeIdent(upsert.Args[0], actx) || !routeIdent(upsert.Args[2], arow) {
		return false
	}
	// Транзакция — собственный Begin той же попытки, а не чужой параметр/alias.
	tx, ok := routeUnparen(upsert.Args[1]).(*ast.Ident)
	if !ok || routeLocalBindings(attempt)[tx.Name] != 1 {
		return false
	}
	txBound := false
	for _, stmt := range attempt.Body.List {
		a, ok := stmt.(*ast.AssignStmt)
		if !ok || a.Tok != token.DEFINE || len(a.Lhs) != 2 || len(a.Rhs) != 1 || !routeIdent(a.Lhs[0], tx.Name) {
			continue
		}
		call, ok := routeUnparen(a.Rhs[0]).(*ast.CallExpr)
		txBound = ok && routeNestedSelector(call.Fun, routeReceiver(attempt), "txb", "Begin") && len(call.Args) == 1 && routeIdent(call.Args[0], actx)
	}
	return txBound && directCallCount(attempt, routeReceiver(attempt)+".mirror", "UpsertTx") == 1
}

func directParameterName(fn *ast.FuncDecl, index int) string {
	if fn == nil || fn.Type.Params == nil {
		return ""
	}
	at := 0
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if at == index {
				return name.Name
			}
			at++
		}
	}
	return ""
}

func directWriteParameters(file *ast.File, fn *ast.FuncDecl, row, write string) bool {
	if row == "" || write == "" || !routeParameter(fn, row, file, "github.com/PRO-Robotech/kaname/internal/service", "ResourceMirrorRow") || !routeParameter(fn, write, file, "", "bool") {
		return false
	}
	counts := routeLocalBindings(fn)
	if counts[row] != 1 || counts[write] != 1 {
		return false
	}
	return !routeAny(fn.Body, func(n ast.Node) bool {
		u, ok := n.(*ast.UnaryExpr)
		return ok && u.Op == token.AND && (routeAddressOfBinding(u.X, row) || routeAddressOfBinding(u.X, write))
	})
}

func directReceiverCall(call *ast.CallExpr, receiver, method string) bool {
	owner, field, nested := strings.Cut(receiver, ".")
	if nested {
		return routeNestedSelector(call.Fun, owner, field, method)
	}
	return routeSelector(call.Fun, receiver, method)
}

func directCallCount(fn *ast.FuncDecl, receiver, method string) int {
	count := 0
	routeAnyCall(fn.Body, func(c *ast.CallExpr) bool {
		if directReceiverCall(c, receiver, method) {
			count++
		}
		return false
	})
	return count
}

// Вызов находится только в непосредственном assignment либо if-init.
// Call в условной ветви, closure, другом цикле или строке не подходит.
func directUniqueImmediateCall(body *ast.BlockStmt, receiver, method, truth string) *ast.CallExpr {
	for _, stmt := range body.List {
		candidate := stmt
		if branch, ok := stmt.(*ast.IfStmt); ok {
			candidate = branch.Init
		}
		if a, ok := candidate.(*ast.AssignStmt); ok && len(a.Rhs) == 1 {
			if c, ok := routeUnparen(a.Rhs[0]).(*ast.CallExpr); ok && directReceiverCall(c, receiver, method) {
				return c
			}
		}
		if !directProductionPrefix(stmt, truth) {
			return nil
		}
	}
	return nil
}

// В product-пути остаются его обычные отказы на неизвестных входах. При этом
// заведомо истинный guard и ранний безусловный выход не прячут мёртвый call.
func directProductionPrefix(stmt ast.Stmt, truth string) bool {
	if branch, ok := stmt.(*ast.IfStmt); ok {
		if branch.Init != nil && !directProductionPrefix(branch.Init, truth) {
			return false
		}
		// Вычисление Cond предшествует выбору ветви. Поглощающий bool operand
		// не стирает terminal/closure; даже short-circuited closure закрываем
		// консервативно, без отдельного анализа её достижимости.
		if directStops(&ast.ExprStmt{X: branch.Cond}) {
			return false
		}
		value, known := directBool(branch.Cond, truth)
		if !known {
			// Неизвестное выражение с фиксированным write не объявляем
			// динамической предпосылкой. Нужна хотя бы одна продолжающая ветвь.
			if (truth != "" && routeExprHasName(branch.Cond, truth)) || !directDynamicGuard(branch.Cond) || routeAny(branch, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					return directTerminalCall(node)
				case *ast.FuncLit, *ast.BranchStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.LabeledStmt:
					return true
				}
				return false
			}) {
				return false
			}
			thenContinues := directProductionPrefix(branch.Body, truth)
			elseContinues := branch.Else == nil || directProductionPrefix(branch.Else, truth)
			return thenContinues || elseContinues
		}
		if value {
			for _, s := range branch.Body.List {
				if !directProductionPrefix(s, truth) {
					return false
				}
			}
			return true
		}
		return branch.Else == nil || directProductionPrefix(branch.Else, truth)
	}
	if block, ok := stmt.(*ast.BlockStmt); ok {
		for _, s := range block.List {
			if !directProductionPrefix(s, truth) {
				return false
			}
		}
		return true
	}
	// Отложенная уборка не является свидетельством. Сохранность receiver и
	// отсутствие записи/адреса write/row проверены отдельно по всему телу.
	if _, ok := stmt.(*ast.DeferStmt); ok {
		return true
	}
	return !directStops(stmt)
}

// true/false обозначают предобъявленные константы только при отсутствии
// локальной или пакетной подмены. Неизвестное связывание не вычисляем.
func directBooleanLiteralsUnshadowed(file *ast.File) bool {
	return directPredeclaredNameUnshadowed(file, "true") && directPredeclaredNameUnshadowed(file, "false") && directPredeclaredNameUnshadowed(file, "nil")
}

func directPredeclaredNameUnshadowed(file *ast.File, name string) bool {
	if !routeAliasUnshadowed(file, name) {
		return false
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil && d.Name.Name == name {
				return false
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.ValueSpec:
					for _, id := range s.Names {
						if id.Name == name {
							return false
						}
					}
				case *ast.TypeSpec:
					if s.Name.Name == name {
						return false
					}
				}
			}
		}
	}
	return true
}

// Неподдержанный naked bool/сравнение с bool literal может быть alias write.
// Обычные nil/error, строковые и доменные call guards остаются предусловиями.
func directDynamicGuard(expr ast.Expr) bool {
	switch e := routeUnparen(expr).(type) {
	case *ast.BinaryExpr:
		if e.Op == token.LAND || e.Op == token.LOR {
			return directDynamicGuard(e.X) && directDynamicGuard(e.Y)
		}
		if e.Op != token.EQL && e.Op != token.NEQ {
			return false
		}
		if routeIdent(e.X, "true") || routeIdent(e.X, "false") || routeIdent(e.Y, "true") || routeIdent(e.Y, "false") {
			return false
		}
		// Поддержанные сравнения динамического входа — с nil/пустой строкой.
		// x==x, арифметику и произвольные constant comparisons не угадываем.
		boundary := func(value ast.Expr) bool {
			if routeIdent(value, "nil") {
				return true
			}
			literal, ok := routeUnparen(value).(*ast.BasicLit)
			return ok && literal.Kind == token.STRING && literal.Value == `""`
		}
		return boundary(e.X) != boundary(e.Y)
	case *ast.CallExpr:
		_, selector := routeUnparen(e.Fun).(*ast.SelectorExpr)
		return selector
	case *ast.UnaryExpr:
		return e.Op == token.NOT && directDynamicGuard(e.X)
	}
	return false
}

func directBool(expr ast.Expr, truth string) (bool, bool) {
	if routeIdent(expr, "true") || (truth != "" && routeIdent(expr, truth)) {
		return true, true
	}
	if routeIdent(expr, "false") {
		return false, true
	}
	if u, ok := routeUnparen(expr).(*ast.UnaryExpr); ok && u.Op == token.NOT {
		v, k := directBool(u.X, truth)
		return !v, k
	}
	if b, ok := routeUnparen(expr).(*ast.BinaryExpr); ok {
		x, xKnown := directBool(b.X, truth)
		y, yKnown := directBool(b.Y, truth)
		switch b.Op {
		case token.EQL:
			return x == y, xKnown && yKnown
		case token.NEQ:
			return x != y, xKnown && yKnown
		case token.LAND:
			if (xKnown && !x) || (yKnown && !y) {
				return false, true
			}
			return x && y, xKnown && yKnown
		case token.LOR:
			if (xKnown && x) || (yKnown && y) {
				return true, true
			}
			return x || y, xKnown && yKnown
		}
	}
	return false, false
}

func directPositiveLoop(file *ast.File, fn *ast.FuncDecl, loop *ast.ForStmt) bool {
	init, ok := loop.Init.(*ast.AssignStmt)
	if !ok || init.Tok != token.DEFINE || len(init.Lhs) != 1 || len(init.Rhs) != 1 {
		return false
	}
	counter, ok := routeUnparen(init.Lhs[0]).(*ast.Ident)
	if !ok {
		return false
	}
	zero, ok := routeUnparen(init.Rhs[0]).(*ast.BasicLit)
	if !ok || zero.Kind != token.INT || zero.Value != "0" {
		return false
	}
	cond, ok := routeUnparen(loop.Cond).(*ast.BinaryExpr)
	if !ok || cond.Op != token.LSS || !routeIdent(cond.X, counter.Name) {
		return false
	}
	post, ok := loop.Post.(*ast.IncDecStmt)
	if !ok || post.Tok != token.INC || !routeIdent(post.X, counter.Name) {
		return false
	}
	value := cond.Y
	if id, ok := routeUnparen(value).(*ast.Ident); ok {
		found := 0
		for _, d := range file.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, spec := range g.Specs {
				v, ok := spec.(*ast.ValueSpec)
				if !ok || len(v.Names) != 1 || len(v.Values) != 1 || v.Names[0].Name != id.Name {
					continue
				}
				found++
				value = v.Values[0]
			}
		}
		if found != 1 {
			return false
		}
		// Локальная подмена package constant не наследует его значение.
		if routeLocalBindings(fn)[id.Name] != 0 {
			return false
		}
	}
	number, ok := routeUnparen(value).(*ast.BasicLit)
	if !ok || number.Kind != token.INT {
		return false
	}
	n, err := strconv.ParseInt(number.Value, 0, 64)
	return err == nil && n > 0
}

// Начальная строка зеркала берётся именно из разобранного registerInput.
// Это закрытая форма существующего конструктора строки, без сравнения файла
// целиком и без разрешения передать вместо row другой локальный объект.
func directRegistrationRow(file *ast.File, fn *ast.FuncDecl, call *ast.CallExpr, input string) bool {
	tuple, ok := routeUnparen(call.Args[1]).(*ast.Ident)
	row, rok := routeUnparen(call.Args[2]).(*ast.CompositeLit)
	if !ok || !rok || !routeType(file, row.Type, "github.com/PRO-Robotech/kaname/internal/service", "ResourceMirrorRow") || len(row.Elts) != 7 {
		return false
	}
	counts := routeLocalBindings(fn)
	if counts[tuple.Name] != 1 || counts["validateTuple"] != 0 || counts["sourceVersion"] != 0 {
		return false
	}
	tupleBound := false
	objectType, objectID, labels := "", "", ""
	for _, stmt := range fn.Body.List {
		if stmt.Pos() >= call.Pos() {
			break
		}
		a, ok := stmt.(*ast.AssignStmt)
		if !ok || a.Tok != token.DEFINE || len(a.Rhs) != 1 {
			continue
		}
		c, ok := routeUnparen(a.Rhs[0]).(*ast.CallExpr)
		if !ok {
			continue
		}
		if len(a.Lhs) == 2 && routeIdent(a.Lhs[0], tuple.Name) && routeIdent(c.Fun, "validateTuple") && len(c.Args) == 1 && routeIdent(c.Args[0], input) {
			tupleBound = true
		}
		if len(a.Lhs) == 2 && routeSelector(c.Fun, tuple.Name, "splitObject") && len(c.Args) == 0 {
			first, fok := a.Lhs[0].(*ast.Ident)
			second, sok := a.Lhs[1].(*ast.Ident)
			if fok && sok {
				objectType, objectID = first.Name, second.Name
			}
		}
		if len(a.Lhs) == 1 && routeSelector(c.Fun, input, "GetLabels") && len(c.Args) == 0 {
			if id, ok := a.Lhs[0].(*ast.Ident); ok {
				labels = id.Name
			}
		}
	}
	if !tupleBound || objectType == "" || objectID == "" || labels == "" || counts[objectType] != 1 || counts[objectID] != 1 || counts[labels] != 1 {
		return false
	}
	seen := map[string]bool{}
	for _, element := range row.Elts {
		kv, ok := element.(*ast.KeyValueExpr)
		if !ok {
			return false
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || seen[key.Name] {
			return false
		}
		seen[key.Name] = true
		switch key.Name {
		case "ObjectType":
			if !routeIdent(kv.Value, objectType) {
				return false
			}
		case "ObjectID":
			if !routeIdent(kv.Value, objectID) {
				return false
			}
		case "Labels":
			if !routeIdent(kv.Value, labels) {
				return false
			}
		case "SourceVersion":
			c, ok := routeUnparen(kv.Value).(*ast.CallExpr)
			if !ok || !routeIdent(c.Fun, "sourceVersion") || len(c.Args) != 1 || !routeIdent(c.Args[0], input) {
				return false
			}
		default:
			getter := map[string]string{"ParentProjectID": "GetParentProjectId", "ParentAccountID": "GetParentAccountId", "ParentChain": "GetParentChain"}[key.Name]
			c, ok := routeUnparen(kv.Value).(*ast.CallExpr)
			if getter == "" || !ok || !routeSelector(c.Fun, input, getter) || len(c.Args) != 0 {
				return false
			}
		}
	}
	return true
}
