// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"bytes"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/printer"
	"go/scanner"
	"go/token"
	"go/types"
	"strings"
)

// Закрытая форма сравнивает полную AST-последовательность, а не имена места
// или число доступов. Printer берёт AST без комментариев; scanner сохраняет
// операторы, literal values и границы statements. Symbol identity проверяется
// вызывающим отдельно. Unsupported переписывание не даёт разрешения.
func bindingPairGoShape(node ast.Node, expected string) bool {
	// Обе стороны проходят один AST printer. Raw expected сохранял конечную
	// запятую многострочного literal, а actual с пустым FileSet её не печатал.
	// Парсим ровно один statement; не удаляем запятые из списка токенов.
	parsed, err := parser.ParseFile(token.NewFileSet(), "expected.go", "package shape\nfunc proof() {\n"+expected+"\n}\n", 0)
	if err != nil || len(parsed.Decls) != 1 {
		return false
	}
	function, ok := parsed.Decls[0].(*ast.FuncDecl)
	if !ok || function.Body == nil || len(function.Body.List) != 1 {
		return false
	}
	var canonical bytes.Buffer
	if printer.Fprint(&canonical, token.NewFileSet(), function.Body.List[0]) != nil {
		return false
	}
	var printed bytes.Buffer
	if printer.Fprint(&printed, token.NewFileSet(), node) != nil {
		return false
	}
	var a, b scanner.Scanner
	a.Init(token.NewFileSet().AddFile("actual", -1, printed.Len()), printed.Bytes(), nil, 0)
	b.Init(token.NewFileSet().AddFile("expected", -1, canonical.Len()), canonical.Bytes(), nil, 0)
	for {
		_, at, av := a.Scan()
		_, bt, bv := b.Scan()
		if at != bt || (at != token.SEMICOLON && av != bv) {
			return false
		}
		if at == token.EOF {
			return true
		}
	}
}

func bindingPairHasTypedQuery(node ast.Node, info *types.Info) bool {
	calls := 0
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || info.Selections[sel] == nil {
			return true
		}
		fn, ok := info.Selections[sel].Obj().(*types.Func)
		if ok && fn.Pkg() != nil && fn.Pkg().Path() == "github.com/jackc/pgx/v5" && fn.Name() == "Query" {
			calls++
		}
		return true
	})
	return calls == 1
}

func bindingPairGoProofs(file *ast.File, info *types.Info, pairFields map[types.Object]string, subjectT types.Type) map[token.Pos]BindingPairClass {
	out := map[token.Pos]BindingPairClass{}
	fields := map[types.Object]string{}
	var domain *types.Package
	for field, name := range pairFields {
		fields[field] = name
		domain = field.Pkg()
	}
	if domain == nil {
		return out
	}
	bindingT := domain.Scope().Lookup(BindingPairType).Type()
	st, ok := bindingT.Underlying().(*types.Struct)
	if !ok {
		return out
	}
	for i := 0; i < st.NumFields(); i++ {
		if st.Field(i).Name() == "Subjects" {
			fields[st.Field(i)] = "Subjects"
		}
	}
	field := func(e ast.Expr, name string) (*types.Var, token.Pos) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok || info.Selections[sel] == nil {
			return nil, token.NoPos
		}
		selection := info.Selections[sel]
		base, ok := sel.X.(*ast.Ident)
		if !ok || selection.Kind() != types.FieldVal || len(selection.Index()) != 1 || fields[selection.Obj()] != name {
			return nil, token.NoPos
		}
		variable, _ := info.ObjectOf(base).(*types.Var)
		return variable, sel.Sel.Pos()
	}
	object := func(e ast.Expr) types.Object {
		id, ok := e.(*ast.Ident)
		if !ok {
			return nil
		}
		return info.ObjectOf(id)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		// Новая singleton выдача: обе projection fields и единственный член
		// Subjects получены из того же typed Subject в том же struct literal.
		if lit, ok := n.(*ast.CompositeLit); ok && types.Identical(info.TypeOf(lit), bindingT) {
			values := map[string]*ast.KeyValueExpr{}
			for _, element := range lit.Elts {
				kv, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if ok && fields[info.Uses[key]] != "" {
					values[fields[info.Uses[key]]] = kv
				}
			}
			if values["SubjectType"] != nil && values["SubjectID"] != nil && values["Subjects"] != nil {
				set, ok := values["Subjects"].Value.(*ast.CompositeLit)
				if ok && types.Identical(info.TypeOf(set), types.NewSlice(subjectT)) && len(set.Elts) == 1 {
					member := object(set.Elts[0])
					valid := member != nil && types.Identical(member.Type(), subjectT)
					for _, key := range []string{"SubjectType", "SubjectID"} {
						sel, ok := values[key].Value.(*ast.SelectorExpr)
						name := "Type"
						if key == "SubjectID" {
							name = "ID"
						}
						valid = valid && ok && object(sel.X) == member && info.Selections[sel] != nil && info.Selections[sel].Obj().Name() == name
					}
					if valid {
						out[values["SubjectType"].Key.Pos()], out[values["SubjectID"].Key.Pos()] = BindingPairSingleton, BindingPairSingleton
					}
				}
			}
		}
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, statement := range block.List {
			// Полный Subjects присваивается локальной переменной; pair используется
			// только в len==0 ветви, после которой целиком обходится тот же slice.
			init, ok := statement.(*ast.AssignStmt)
			if !ok || init.Tok != token.DEFINE || len(init.Lhs) != 1 || len(init.Rhs) != 1 || i+2 >= len(block.List) {
				continue
			}
			binding, _ := field(init.Rhs[0], "Subjects")
			set := object(init.Lhs[0])
			guard, gok := block.List[i+1].(*ast.IfStmt)
			loop, lok := block.List[i+2].(*ast.RangeStmt)
			if binding == nil || set == nil || !gok || !lok || guard.Init != nil || guard.Else != nil || len(guard.Body.List) != 1 || object(loop.X) != set {
				continue
			}
			cond, ok := guard.Cond.(*ast.BinaryExpr)
			if !ok || cond.Op != token.EQL || info.Types[cond.Y].Value == nil || info.Types[cond.Y].Value.Kind() != constant.Int || constant.Sign(info.Types[cond.Y].Value) != 0 {
				continue
			}
			length, ok := cond.X.(*ast.CallExpr)
			if !ok || len(length.Args) != 1 || object(length.Args[0]) != set {
				continue
			}
			builtin, ok := object(length.Fun).(*types.Builtin)
			if !ok || builtin.Name() != "len" {
				continue
			}
			fallback, ok := guard.Body.List[0].(*ast.AssignStmt)
			if !ok || fallback.Tok != token.ASSIGN || len(fallback.Lhs) != 1 || object(fallback.Lhs[0]) != set || len(fallback.Rhs) != 1 {
				continue
			}
			slice, ok := fallback.Rhs[0].(*ast.CompositeLit)
			if !ok || !types.Identical(info.TypeOf(slice), types.NewSlice(subjectT)) || len(slice.Elts) != 1 {
				continue
			}
			member, ok := slice.Elts[0].(*ast.CompositeLit)
			if !ok || len(member.Elts) != 2 {
				continue
			}
			positions := map[string]token.Pos{}
			for _, element := range member.Elts {
				kv, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || (key.Name != "Type" && key.Name != "ID") {
					continue
				}
				receiver, pos := field(kv.Value, "Subject"+key.Name)
				if receiver == binding {
					positions[key.Name] = pos
				}
			}
			if len(positions) == 2 && bindingPairGoShape(loop, bindingPairDelegationFanout) && len(loop.Body.List) == 2 && bindingPairOnlyErrorGuard(loop.Body.List[0], info) && bindingPairOnlyErrorGuard(loop.Body.List[1], info) {
				out[positions["Type"]], out[positions["ID"]] = BindingPairGuardedFanout, BindingPairGuardedFanout
			}
		}
		// SQL full-set scan и NormalizeSubjects находятся в одной неизменённой
		// straight-line форме; Get использует тот же id, а b после Get не меняется.
		for i := range block.List {
			first, ok := block.List[i].(*ast.AssignStmt)
			if !ok || len(first.Rhs) != 1 {
				continue
			}
			call, ok := first.Rhs[0].(*ast.CallExpr)
			if !ok || len(call.Args) != 4 {
				continue
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			literal, isLiteral := call.Args[1].(*ast.BasicLit)
			if !ok || selector.Sel.Name != "Query" || !isLiteral || !strings.Contains(literal.Value, "access_binding_subjects") {
				continue
			}
			j := i + 11
			if j > len(block.List) {
				continue
			}
			window := &ast.BlockStmt{List: block.List[i:j]}
			if !bindingPairGoShape(window, bindingPairStagedSubjectScan) || !bindingPairHasTypedQuery(window, info) {
				continue
			}
			storedBinding, storedID := bindingPairStagedGet(block.List[:i], info)
			if storedBinding == nil {
				continue
			}
			query := window.List[0].(*ast.AssignStmt).Rhs[0].(*ast.CallExpr)
			queriedID := query.Args[2].(*ast.CallExpr).Args[0]
			if object(queriedID) != storedID {
				continue
			}
			ast.Inspect(window, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || len(call.Args) != 3 {
					return true
				}
				fn, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || info.Uses[fn.Sel] != domain.Scope().Lookup("NormalizeSubjects") {
					return true
				}
				b1, p1 := field(call.Args[1], "SubjectType")
				b2, p2 := field(call.Args[2], "SubjectID")
				if b1 == storedBinding && b1 == b2 {
					out[p1], out[p2] = BindingPairStagedSet, BindingPairStagedSet
				}
				return true
			})
		}
		return true
	})
	return out
}

func bindingPairOnlyErrorGuard(statement ast.Stmt, info *types.Info) bool {
	guard, ok := statement.(*ast.IfStmt)
	if !ok || guard.Else != nil || len(guard.Body.List) != 1 {
		return false
	}
	assignment, ok := guard.Init.(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return false
	}
	id, ok := assignment.Lhs[0].(*ast.Ident)
	if !ok {
		return false
	}
	cond, ok := guard.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ {
		return false
	}
	left, ok := cond.X.(*ast.Ident)
	if !ok || info.ObjectOf(left) != info.ObjectOf(id) {
		return false
	}
	right, ok := cond.Y.(*ast.Ident)
	if !ok || right.Name != "nil" {
		return false
	}
	ret, ok := guard.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	returned, ok := ret.Results[0].(*ast.Ident)
	return ok && info.ObjectOf(returned) == info.ObjectOf(id)
}

func bindingPairStagedGet(prefix []ast.Stmt, info *types.Info) (*types.Var, types.Object) {
	var binding *types.Var
	var key types.Object
	for _, statement := range prefix {
		if bindingPairGoShape(statement, "b, err := reader.Get(ctx, id)") {
			if binding != nil {
				return nil, nil
			}
			assignment := statement.(*ast.AssignStmt)
			call := assignment.Rhs[0].(*ast.CallExpr)
			selector := call.Fun.(*ast.SelectorExpr)
			selection := info.Selections[selector]
			if selection == nil {
				return nil, nil
			}
			receiver := selection.Recv()
			if ptr, ok := receiver.(*types.Pointer); ok {
				receiver = ptr.Elem()
			}
			named, ok := receiver.(*types.Named)
			if !ok || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg" || named.Obj().Name() != "abReader" {
				return nil, nil
			}
			binding, _ = info.ObjectOf(assignment.Lhs[0].(*ast.Ident)).(*types.Var)
			key = info.ObjectOf(call.Args[1].(*ast.Ident))
			continue
		}
		if binding != nil {
			valid := true
			containsTracked := func(node ast.Node) {
				ast.Inspect(node, func(child ast.Node) bool {
					if id, ok := child.(*ast.Ident); ok && (info.ObjectOf(id) == binding || info.ObjectOf(id) == key) {
						valid = false
					}
					return true
				})
			}
			ast.Inspect(statement, func(n ast.Node) bool {
				if assignment, ok := n.(*ast.AssignStmt); ok {
					for _, lhs := range assignment.Lhs {
						containsTracked(lhs)
					}
				}
				if unary, ok := n.(*ast.UnaryExpr); ok && unary.Op == token.AND {
					containsTracked(unary.X)
				}
				if increment, ok := n.(*ast.IncDecStmt); ok {
					containsTracked(increment.X)
				}
				return true
			})
			if !valid {
				return nil, nil
			}
		}
	}
	return binding, key
}

// MaxSubjects+1 выявляет overflow; NormalizeSubjects его отвергает. Между
// Query и normalize не допускаются фильтр, срез или пропуск rows.Next.
const bindingPairStagedSubjectScan = `{
	rows, err := tx.Query(ctx, ` + "`" + `SELECT subject_type,subject_id FROM kaname.access_binding_subjects WHERE binding_id=$1 ORDER BY ordinal,subject_type,subject_id LIMIT $2` + "`" + `, string(id), domain.MaxSubjectsPerBinding+1)
	if err != nil {
		return err
	}
	var subjects []domain.Subject
	for rows.Next() {
		var subject domain.Subject
		if err = rows.Scan(&subject.Type, &subject.ID); err != nil {
			rows.Close()
			return err
		}
		subjects = append(subjects, subject)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if err = s.charge(len(subjects)); err != nil {
		return err
	}
	subjects, err = domain.NormalizeSubjects(subjects, b.SubjectType, b.SubjectID)
	if err != nil {
		return err
	}
	for _, tuple := range s.request.Tuples.BuildRoleTuples(b, subjects, s.request.Role) {
		if err = s.saveTuple(ctx, tx, id, "new", tuple); err != nil {
			return err
		}
	}
}`

// Оба события используют текущий member s; [0], фильтр или ранний выход
// не должны проходить только потому, что внешний range всё ещё полный.
const bindingPairDelegationFanout = `for _, s := range subjects {
			if err = w.AccessBindingsW().EmitSubjectChangeEvent(ctx, abrepo.SubjectChangeEvent{SubjectID: string(s.ID), SubjectType: string(s.Type), EventType: "binding_revoke", Op: "binding_delete"}); err != nil {
				return err
			}
			if err = w.AccessBindingsW().EmitAuditEvent(ctx, abrepo.AuditEvent{
				EventType: "iam.access_binding.delegation_revoked", Actor: actor, SubjectType: string(s.Type), SubjectID: string(s.ID),
				ResourceType: string(b.ResourceType), ResourceID: b.ResourceID, RoleID: string(b.RoleID), BindingID: string(b.ID), TenantAccountID: string(d.AccountID),
				ExtraPayload: map[string]any{"delegation_id": string(d.ID), "revocation_reason": "delegation_revoked"},
			}); err != nil {
				return err
			}
		}`
