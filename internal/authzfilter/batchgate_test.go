// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// batchgate_test.go — the census that makes the batched page cost a statement
// about the SERVICE rather than about one function.
//
// The sibling batch_test.go proves that VisibleSet asks in batches when it can.
// That is a property of one function, and it is worth exactly as much as the
// answer to a different question: does every read surface reach the store THROUGH
// that function, holding a checker that can answer in batches?
//
// Both halves are needed and neither implies the other. A surface that filters
// its page some other way is outside the measurement entirely (that is what
// TestRelationQuestionsStayInsideTheMeasuredPath refuses). A surface that goes
// through VisibleSet but hands it a checker without the capability silently takes
// the fallback: correct rows, 2000 round-trips, and no test anywhere would go red
// — the fakes in this package implement the capability themselves, so they cannot
// notice its absence in production wiring.
package authzfilter

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// batchCapablePortType — the declared type a visibility checker must have at a
// call site.
//
// The requirement is on the DECLARED type, not on what happens to be passed:
// clients.RelationQueries carries BatchCheckWithContext, so a value declared as
// that type is batch-capable by compilation rather than by inspection. Any other
// declared type is a value this gate cannot vouch for — it may satisfy the narrow
// ObjectChecker port and take the per-object fallback while looking identical at
// the call site.
const batchCapablePortType = "clients.RelationQueries"

// visibilityEntryPoints — the names through which a page reaches the relation
// store, and which argument of each carries the checker.
//
// Keyed by the exact selector as it is written at a call site, because that is
// what the scanner reads. A rename of either function makes the corresponding
// premise below fail rather than making this gate quietly stop finding anything.
var visibilityEntryPoints = map[string]int{
	"authzfilter.VisibleSet": 1, // (ctx, chk, subject, objectType, ids)
	"authzfilter.Visible":    1, // (ctx, chk, subject, objectType, id)
}

// wantVisibilityCallSites — how many call sites exist in the use-case tree today.
//
// Pinned as a number so a TENTH read surface cannot be added without a human
// re-reading this gate. That is the whole reason the count is here: the
// per-site assertion below already covers every site the scan finds, but a new
// surface that never calls these functions at all is invisible to it, and a
// surface that does call them is invisible to nothing except a count that
// changed.
const wantVisibilityCallSites = 8

type visibilityCallSite struct {
	file    string
	dir     string // the package the site lives in; port declarations are scoped to it
	fn      string
	checker string // the argument expression, as written
}

// portKey scopes a declared name to its package. A bare name would be satisfied
// by any sibling package that happens to use the same field name — which is
// exactly how this gate first passed an injected defect.
func portKey(dir, name string) string { return dir + "\x00" + name }

// TestVisibilityCallSitesAllHoldABatchCapableChecker — the census.
func TestVisibilityCallSitesAllHoldABatchCapableChecker(t *testing.T) {
	// Premise: the names the scanner looks for must be the names this package
	// actually exports. A rename would otherwise leave the gate scanning for
	// something that cannot appear, reporting a clean tree forever.
	for name := range visibilityEntryPoints {
		short := strings.TrimPrefix(name, "authzfilter.")
		require.NotNil(t, packageLevelFunc(t, ".", short),
			"premise: %q is no longer declared in this package; the gate would keep scanning "+
				"for a name that cannot appear", short)
	}

	sites, files, ports := scanVisibilityCallSites(t, serviceTreeRoot)

	require.NotZero(t, files,
		"premise (volume): nothing was read under %s — 'no findings' would mean 'nothing was "+
			"looked at'", serviceTreeRoot)
	require.NotZero(t, len(sites),
		"premise (positive control): no visibility call site was recognised anywhere under %s; "+
			"the gate must SEE the legitimate ones before its silence means anything", serviceTreeRoot)

	t.Logf("read %d non-test files under %s; visibility call sites=%d (expected %d); "+
		"names declared as %s in those packages=%d",
		files, serviceTreeRoot, len(sites), wantVisibilityCallSites, batchCapablePortType, len(ports))

	var uncertain []string
	for _, s := range sites {
		if ports[portKey(s.dir, checkerBaseName(s.checker))] {
			continue
		}
		uncertain = append(uncertain, s.file+": "+s.fn+" passes "+s.checker)
	}
	sort.Strings(uncertain)
	assert.Empty(t, uncertain,
		"a page filtered through a checker not declared as %s takes the per-object fallback: it "+
			"returns the right rows and pays one relation-store round-trip per row, which is the "+
			"cost this whole change removed and which no other test can see. Declare the field or "+
			"parameter as %s", batchCapablePortType, batchCapablePortType)

	assert.Equal(t, wantVisibilityCallSites, len(sites),
		"the number of read surfaces filtered through this package changed. That is not a "+
			"failure by itself — update the constant — but a new surface has to be looked at "+
			"once, because the per-site assertion above cannot see a surface that filters its "+
			"page some other way")
}

// TestVisibilityCensusGateFiresOnAnInjectedDefect — the gate, injected in both
// directions on real parsed source.
//
// A gate that has never been shown to fail is a claim about a gate, not a gate.
// The legitimate twin is the half that matters more: the defect direction only
// shows the scanner reacts to SOMETHING, while the twin shows it reacts to the
// right thing, and a gate that reddens on correct code is removed by the first
// person it inconveniences.
func TestVisibilityCensusGateFiresOnAnInjectedDefect(t *testing.T) {
	const defect = `package fake

import "github.com/PRO-Robotech/kaname/internal/authzfilter"

type narrowChecker interface{ nothing() }

type useCase struct{ relationQueries narrowChecker }

func (u *useCase) visibleIDs(ctx context.Context, subject string, ids []string) {
	_, _ = authzfilter.VisibleSet(ctx, u.relationQueries, subject, "account", ids)
}
`
	const legitimate = `package fake

import (
	"github.com/PRO-Robotech/kaname/internal/authzfilter"
	"github.com/PRO-Robotech/kaname/internal/clients"
)

type useCase struct{ relationQueries clients.RelationQueries }

func (u *useCase) visibleIDs(ctx context.Context, subject string, ids []string) {
	_, _ = authzfilter.VisibleSet(ctx, u.relationQueries, subject, "account", ids)
}
`
	for _, tc := range []struct {
		name       string
		src        string
		wantFlags  int
		wantSites  int
		wantReason string
	}{
		{
			name: "checker declared as a narrow port is flagged", src: defect,
			wantFlags: 1, wantSites: 1,
			wantReason: "a checker the gate cannot vouch for must be named",
		},
		{
			name: "the same shape with the batch-capable port is silent", src: legitimate,
			wantFlags: 0, wantSites: 1,
			wantReason: "correct code must not redden the gate, or it will be deleted by the " +
				"first person it inconveniences",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "fake.go"), []byte(tc.src), 0o600))

			sites, files, ports := scanVisibilityCallSites(t, dir)
			require.Equal(t, 1, files, "the injection must be read as one file")
			require.Len(t, sites, tc.wantSites,
				"the scanner must recognise the call site in BOTH directions; a scanner that "+
					"simply fails to see the legitimate one would pass this table for the wrong reason")

			flagged := 0
			for _, s := range sites {
				if !ports[portKey(s.dir, checkerBaseName(s.checker))] {
					flagged++
				}
			}
			require.Equal(t, tc.wantFlags, flagged, tc.wantReason)
		})
	}
}

// scanVisibilityCallSites reads every non-test .go file under root and returns
// the visibility call sites it finds, the number of files read, and the set of
// names declared — as a struct field or as a function parameter — with the
// batch-capable port type in those files.
//
// Declared names are collected PER DIRECTORY, and that detail is the difference
// between a gate and a decoration. Collected per-root they were not: `relationQueries`
// is the field name in six sibling packages, so one package declaring it as a narrow
// port still found the name in the set contributed by the other five, and the gate
// stayed green on the injected defect. The synthetic injection did not catch that,
// because a temp directory holding one file has no siblings to borrow a declaration
// from — the confounder that real source always has. Hence the injection below runs
// against the REAL tree as well.
//
// Per-directory is still name-based rather than type-resolved: full resolution would
// make the gate depend on the tree compiling, which is the one state in which it is
// least likely to be run. Within one package a name has one declaration, so the
// remaining looseness is a shadowed local, which the reported coordinate shows.
func scanVisibilityCallSites(t *testing.T, root string) ([]visibilityCallSite, int, map[string]bool) {
	t.Helper()
	var sites []visibilityCallSite
	ports := map[string]bool{}
	files := 0

	forEachGoFile(t, root, func(path string, file *ast.File) {
		files++
		collectPortDeclarations(filepath.Dir(path), file, ports)

		var enclosing string
		ast.Inspect(file, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok {
				enclosing = fn.Name.Name
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			argIdx, watched := visibilityEntryPoints[pkg.Name+"."+sel.Sel.Name]
			if !watched || argIdx >= len(call.Args) {
				return true
			}
			sites = append(sites, visibilityCallSite{
				file:    path,
				dir:     filepath.Dir(path),
				fn:      enclosing,
				checker: exprText(call.Args[argIdx]),
			})
			return true
		})
	})
	return sites, files, ports
}

// collectPortDeclarations records every field or parameter name declared with the
// batch-capable port type.
func collectPortDeclarations(dir string, file *ast.File, into map[string]bool) {
	record := func(names []*ast.Ident, typ ast.Expr) {
		if exprText(typ) != batchCapablePortType {
			return
		}
		for _, n := range names {
			into[portKey(dir, n.Name)] = true
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.StructType:
			if d.Fields == nil {
				return true
			}
			for _, f := range d.Fields.List {
				record(f.Names, f.Type)
			}
		case *ast.FuncDecl:
			if d.Type == nil || d.Type.Params == nil {
				return true
			}
			for _, p := range d.Type.Params.List {
				record(p.Names, p.Type)
			}
		}
		return true
	})
}

// checkerBaseName reduces `u.relationQueries` / `relationQueries` to the declared
// name, which is what the declaration set is keyed by.
func checkerBaseName(expr string) string {
	if i := strings.LastIndex(expr, "."); i >= 0 {
		return expr[i+1:]
	}
	return expr
}

// exprText renders an expression the way it is written, for reporting and for
// comparing a declared type against its name.
func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return "*" + exprText(v.X)
	default:
		return "<expr>"
	}
}

// packageLevelFunc returns the declaration of a package-level func by name, or
// nil. Used to assert the gate's own premises still have referents.
func packageLevelFunc(t *testing.T, dir, name string) *ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.SkipObjectResolution)
	require.NoError(t, err)
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if ok && fn.Recv == nil && fn.Name.Name == name {
					return fn
				}
			}
		}
	}
	return nil
}

// TestVisibilityCensusGateSurvivesTheSiblingConfounder — the case the first
// version of this gate passed while the defect was live.
//
// The defect direction of the table above was injected into a temp directory
// holding one file. Real source never looks like that: `relationQueries` is the
// field name in six sibling packages, all but one declaring it correctly. With
// declarations collected per-ROOT the one bad package borrowed a declaration from
// its neighbours and the gate stayed green — against the real tree, with the
// defect actually present.
//
// The synthetic injection could not have found this, because the confounder is
// exactly what a temp directory lacks. So it is reproduced here: two packages,
// one legitimate and one not, in the same scan.
func TestVisibilityCensusGateSurvivesTheSiblingConfounder(t *testing.T) {
	root := t.TempDir()
	good := filepath.Join(root, "good")
	bad := filepath.Join(root, "bad")
	require.NoError(t, os.MkdirAll(good, 0o750))
	require.NoError(t, os.MkdirAll(bad, 0o750))

	require.NoError(t, os.WriteFile(filepath.Join(good, "list.go"), []byte(`package good

import (
	"github.com/PRO-Robotech/kaname/internal/authzfilter"
	"github.com/PRO-Robotech/kaname/internal/clients"
)

type useCase struct{ relationQueries clients.RelationQueries }

func (u *useCase) visibleIDs(ctx context.Context, subject string, ids []string) {
	_, _ = authzfilter.VisibleSet(ctx, u.relationQueries, subject, "account", ids)
}
`), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(bad, "list.go"), []byte(`package bad

import "github.com/PRO-Robotech/kaname/internal/authzfilter"

type narrowChecker interface{ nothing() }

type useCase struct{ relationQueries narrowChecker }

func (u *useCase) visibleIDs(ctx context.Context, subject string, ids []string) {
	_, _ = authzfilter.VisibleSet(ctx, u.relationQueries, subject, "project", ids)
}
`), 0o600))

	sites, files, ports := scanVisibilityCallSites(t, root)
	require.Equal(t, 2, files)
	require.Len(t, sites, 2, "both call sites must be recognised, or the counts below mean nothing")

	var flagged []string
	for _, s := range sites {
		if !ports[portKey(s.dir, checkerBaseName(s.checker))] {
			flagged = append(flagged, s.file)
		}
	}
	require.Len(t, flagged, 1,
		"exactly the package that declares the narrow port must be flagged; a name declared "+
			"correctly in a SIBLING package must not vouch for it")
	require.Contains(t, flagged[0], "bad", "and it must be the right one")
}
