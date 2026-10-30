// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// formProbeRootAnchorInjections feeds the production root to the same wiring
// guard used by the form probe. Each negative changes only the binding of one
// call against its lawful twin; unused decoys must not count as a violation.
func formProbeRootAnchorInjections(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		sources[name] = string(src)
		names = append(names, name)
	}
	sort.Strings(names)
	root, ok := sources["serve.go"]
	if !ok {
		t.Fatal("production root is absent: injection has no input")
	}
	anchors := formProbeRootAnchors(t, formProbeFuncName(publicChainUnderProbe))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "serve.go", root, 0)
	if err != nil {
		t.Fatal(err)
	}
	var signature string
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == anchors.assembler && fn.Body != nil {
			// Preserve the real signature, including every imported parameter type.
			signature = "func" + root[fset.Position(fn.Type.Params.Pos()).Offset:fset.Position(fn.Body.Pos()).Offset]
		}
	}
	if signature == "" {
		t.Fatal("production assembler declaration is absent")
	}
	const constructorCall = "grpcSrv := grpcsrv.NewServer("
	const assemblerCall = "publicUnaryLinks, publicStreamLinks, err := "
	shadow := anchors.assembler + " := " + signature + "{ return nil, nil, nil }\n"
	wrapper := "\nfunc NewServer(opts ...grpc.ServerOption) *grpc.Server { return grpcsrv.NewServer(opts[0]) }\n"
	type edit struct{ old, new string }
	for _, tc := range []struct {
		name  string
		edits []edit
		alias bool
		want  int
		text  string
	}{
		{name: "lawful production root"},
		{name: "X01 twin unused local NewServer", edits: []edit{{root, root + wrapper}}},
		{name: "X01 local NewServer drops options", edits: []edit{{root, root + wrapper}, {constructorCall, "grpcSrv := NewServer("}}, want: 2, text: "раскрыт не прямым доводом NewServer"},
		{name: "X03 twin shadow in separate block", edits: []edit{{assemblerCall, "{\n" + shadow + "_ = " + anchors.assembler + "\n}\n" + assemblerCall}}},
		{name: "X03 closure shadows assembler", edits: []edit{{assemblerCall, shadow + assemblerCall}}, want: 1, text: "не присвоен ни в одной функции"},
		{name: "lawful constructor import alias", edits: []edit{{`"github.com/PRO-Robotech/corelib/grpcsrv"`, `serverfactory "github.com/PRO-Robotech/corelib/grpcsrv"`}}, alias: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := root
			for _, e := range tc.edits {
				if n := strings.Count(changed, e.old); n != 1 {
					t.Fatalf("injection fragment occurs %d times, expected 1: %q", n, e.old)
				}
				changed = strings.Replace(changed, e.old, e.new, 1)
			}
			if tc.alias {
				changed = strings.ReplaceAll(changed, "grpcsrv.", "serverfactory.")
			}
			fset := token.NewFileSet()
			var files []*ast.File
			for _, name := range names {
				src := sources[name]
				if name == "serve.go" {
					src = changed
				}
				f, err := parser.ParseFile(fset, name, src, 0)
				if err != nil {
					t.Fatalf("injected root does not parse: %v", err)
				}
				files = append(files, f)
			}
			got := formProbeChainReachesListener(fset, files, anchors)
			if len(got) != tc.want {
				t.Fatalf("violations %d, expected %d: %v", len(got), tc.want, got)
			}
			for _, why := range got {
				if !strings.Contains(why, tc.text) {
					t.Errorf("expected reason %q, got %s", tc.text, why)
				}
			}
			t.Logf("production files %d; violations %d: %v", len(files), len(got), got)
		})
	}
}
