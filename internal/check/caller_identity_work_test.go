// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

func TestCallerIdentityTypeWorkMemoClosesCyclesBeforePublishing(t *testing.T) {
	param := types.NewTypeParam(types.NewTypeName(token.NoPos, nil, "T", nil), types.NewInterfaceType(nil, nil).Complete())
	a := types.NewNamed(types.NewTypeName(token.NoPos, nil, "A", nil), nil, nil)
	b := types.NewNamed(types.NewTypeName(token.NoPos, nil, "B", nil), nil, nil)
	a.SetUnderlying(types.NewStruct([]*types.Var{types.NewField(token.NoPos, nil, "B", types.NewPointer(b), false), types.NewField(token.NoPos, nil, "T", param, false)}, nil))
	b.SetUnderlying(types.NewStruct([]*types.Var{types.NewField(token.NoPos, nil, "A", types.NewPointer(a), false)}, nil))
	g := &callerGraph{}
	if !g.hasCallerTypeParam(a) || !g.hasCallerTypeParam(b) {
		t.Fatal("цикл потерял достижимый параметр типа")
	}
	before := g.work.TypeVisits
	for range 100 {
		if !g.hasCallerTypeParam(b) || !g.hasCallerTypeParam(a) {
			t.Fatal("кэш опубликовал промежуточное false")
		}
	}
	if g.work.TypeVisits != before || g.work.TypeHits < 200 {
		t.Fatalf("повторно обойдён завершённый граф типов: %+v", g.work)
	}
	plain := types.NewNamed(types.NewTypeName(token.NoPos, nil, "A", nil), nil, nil)
	plain.SetUnderlying(types.NewStruct([]*types.Var{types.NewField(token.NoPos, nil, "A", types.NewPointer(plain), false)}, nil))
	if g.hasCallerTypeParam(plain) {
		t.Fatal("новый объект того же имени унаследовал ответ прежнего исходника")
	}
	before = g.work.TypeVisits
	if g.hasCallerTypeParam(plain) || g.work.TypeVisits != before {
		t.Fatal("замкнутый отрицательный компонент пересчитан")
	}
	t.Logf("WORK %+v", g.work)
}

func TestCallerIdentitySignatureWorkMemoDoesNotRepeatTypeGraphs(t *testing.T) {
	g := &callerGraph{pure: &callerPureMemo{signatures: map[callerSignaturePair]bool{}}}
	makeSignature := func(typ types.Type) *types.Signature {
		return types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, nil, "value", typ)), types.NewTuple(), false)
	}
	a, b := makeSignature(types.Typ[types.String]), makeSignature(types.Typ[types.Int])
	if g.signatureCompatible(a, b) {
		t.Fatal("разные конкретные подписи приняты")
	}
	before := g.work.TypeVisits
	for range 100 {
		if g.signatureCompatible(a, b) {
			t.Fatal("кэш изменил ответ")
		}
	}
	if g.work.SignatureEvaluations != 1 || g.work.SignatureHits != 100 || g.work.TypeVisits != before {
		t.Fatalf("подпись и графы типов пересчитаны: %+v", g.work)
	}
	t.Logf("WORK %+v", g.work)
}

// builtin/conversion не выполняют тело функции с совпавшей подписью.
func TestCallerIdentityMayDoesNotDispatchBuiltinsOrConversions(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "may.go", `package fixture
 func principal() {}
 func reader[T any](value T) int { principal(); return 0 }
 func builtin() { _ = len([]byte{}) }
 type callback func(int) int
 func conversion() { _ = callback(nil) }
 `, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	if _, err := (&types.Config{}).Check("fixture", fset, []*ast.File{file}, info); err != nil {
		t.Fatal(err)
	}
	producerPkg := types.NewPackage("github.com/PRO-Robotech/corelib/operations", "operations")
	ast.Inspect(file, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "principal" && info.Uses[id] != nil {
			info.Uses[id] = types.NewFunc(id.Pos(), producerPkg, "PrincipalFromContext", types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false))
		}
		return true
	})
	sp := &surfaceSrcPkg{info: info}
	g := &callerGraph{bodies: map[callerNode]callerBody{}, methods: map[string][]*types.Func{}, ctx: context.Background()}
	nodes := map[string]callerNode{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			node := callerNode{fn: info.Defs[fn.Name].(*types.Func)}
			nodes[fn.Name.Name] = node
			g.bodies[node] = callerBody{sp: sp, node: fn.Body, name: fn.Name.Name}
		}
	}
	g.prepareCallerSignatures()
	g.callerMayRead()
	if !g.may[nodes["reader"]] {
		t.Fatal("положительный reader не попал в MAY")
	}
	for _, name := range []string{"builtin", "conversion"} {
		if g.may[nodes[name]] {
			t.Errorf("%s получил чужой reader по подписи", name)
		}
	}
}
