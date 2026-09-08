// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// shared_operations_test.go closes the one hop the analyser cannot walk.
//
// iam's seven ListOperations handlers all delegate to shared.ListOperationsUseCase,
// which lives in a different package, and the analyser's walk deliberately stops at
// the package boundary. So the profile accepts the DELEGATION ("listOp.Execute") as
// the evidence of SubjectScoped — and that would be an unchecked claim moved one
// package over unless something asserts what is on the other side.
//
// This is that something: the shared use-case must narrow by the caller taken from
// the context, not by an id the request supplied.
package auditlistfilter

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// sharedUseCaseDir locates internal/apps/kaname/shared relative to this file.
func sharedUseCaseDir(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — the tree was never opened, so nothing is proven")
	}
	// services/iam/tools/auditlistfilter → services/iam
	svc := filepath.Dir(filepath.Dir(filepath.Dir(self)))
	dir := filepath.Join(svc, "internal", "apps", "kaname", "shared")
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("shared use-case package not found at %s — the delegation this profile "+
			"accepts as evidence points at a package that is not there", dir)
	}
	return dir
}

// TestSharedListOperations_NarrowsByCaller asserts the far side of the delegation.
func TestSharedListOperations_NarrowsByCaller(t *testing.T) {
	dir := sharedUseCaseDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	var found *ast.FuncDecl
	files := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", e.Name(), perr)
		}
		files++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "Execute" || fn.Recv == nil || fn.Body == nil {
				continue
			}
			if receiverIs(fn, "ListOperationsUseCase") {
				found = fn
			}
		}
	}
	t.Logf("parsed %d file(s) in %s", files, dir)
	if files == 0 {
		t.Fatal("parsed no files — zero findings must not be reachable from zero reads")
	}
	if found == nil {
		t.Fatal("shared.ListOperationsUseCase has no Execute — the seven ListOperations " +
			"handlers delegate to something that is no longer there, and the profile's " +
			"SubjectScoped evidence has lost its subject")
	}

	if !callsNamed(found, "ListForCaller") {
		t.Error("shared.ListOperationsUseCase.Execute does not reach operations.ListForCaller: " +
			"the seven iam ListOperations RPCs are declared SubjectScoped on the strength of " +
			"delegating here, and this is what makes that true. If the narrowing moved, the " +
			"declarations must move with it — do not relax this.")
	}

	// The paired positive: the predicate must be able to answer NO, or the assertion
	// above is satisfied by a walker that says yes to everything.
	if callsNamed(found, "ThisCallDoesNotExistAnywhere") {
		t.Fatal("the call-detection predicate reports a call that cannot be there — it answers " +
			"yes unconditionally, so the assertion above proves nothing")
	}
}

func receiverIs(fn *ast.FuncDecl, typeName string) bool {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return false
	}
	e := fn.Recv.List[0].Type
	if st, ok := e.(*ast.StarExpr); ok {
		e = st.X
	}
	id, ok := e.(*ast.Ident)
	return ok && id.Name == typeName
}

func callsNamed(fn *ast.FuncDecl, name string) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			if f.Name == name {
				found = true
			}
		case *ast.SelectorExpr:
			if f.Sel.Name == name {
				found = true
			}
		}
		return !found
	})
	return found
}
