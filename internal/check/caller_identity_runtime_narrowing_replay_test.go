// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/constant"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const checkNarrowingPackage = "github.com/PRO-Robotech/kaname/internal/authzguard"
const checkNarrowingProfilePackage = "github.com/PRO-Robotech/kaname/internal/moduleidentity"
const checkNarrowingTable = "internal/authzguard/front_admission.go"
const checkNarrowingMethod = "/kaname.cloud.iam.v1.InternalIAMService/Check"

// CheckNarrowingPairForTest applies the declaration check twice to one completed
// registered traversal. The caller verifies that the two fixture trees differ
// only by the Check row. The loader reads and type-checks the on-disk authzguard
// of each fixture, with identical dependency selection.
func CheckNarrowingPairForTest(t *testing.T, ctx context.Context, root, missing string, declared []CallerReadDeclaration) (lawful, negative CheckNarrowingWitness, err error) {
	t.Helper()
	l, err := newProdListing(ctx, root, []string{"./cmd/kaname/..."})
	if err != nil {
		return lawful, negative, err
	}
	program, err := l.program(nil)
	if err != nil {
		return lawful, negative, err
	}
	withRow, withoutRow, err := checkNarrowingPairTables(l, program, missing)
	if err != nil {
		return lawful, negative, err
	}
	t.Log("Check: обе таблицы прочитаны, подтверждены условия общего обхода регистрации")
	defer callerGraphs.Delete(program)
	facts, err := collectCheckNarrowingFacts(ctx, program, l)
	if err != nil {
		return lawful, negative, err
	}
	// Removing the line shifts coordinates in this file. A reader reaching that
	// file would require an independent traversal to observe its own coordinate.
	for _, read := range facts.report.Reads {
		if strings.HasPrefix(read.Coordinate, checkNarrowingTable+":") {
			return lawful, negative, fmt.Errorf("снятие строки меняет координату чтения %s", read.Coordinate)
		}
	}
	lawful, negative = facts.witness(withRow, declared), facts.witness(withoutRow, declared)
	if err := ctx.Err(); err != nil {
		return CheckNarrowingWitness{}, CheckNarrowingWitness{}, err
	}
	return lawful, negative, nil
}

func checkNarrowingPairTables(l *surfaceListing, program *surfaceProgram, missing string) (withRow, withoutRow map[string]bool, err error) {
	if !checkNarrowingOnlyScalarPredicate(program) {
		return nil, nil, fmt.Errorf("таблица Check или её скалярный потребитель изменились")
	}
	dir := filepath.Join(missing, filepath.Dir(checkNarrowingTable))
	baseFiles, _, err := l.sourceFiles(checkNarrowingPackage, "")
	if err != nil {
		return nil, nil, err
	}
	overlayFiles, _, err := l.sourceFiles(checkNarrowingPackage, dir)
	if err != nil {
		return nil, nil, err
	}
	slices.Sort(baseFiles)
	if !slices.Equal(baseFiles, overlayFiles) {
		return nil, nil, fmt.Errorf("у копий Check различается состав файлов authzguard")
	}
	mutant, err := l.program(map[string]string{checkNarrowingPackage: dir})
	if err != nil {
		return nil, nil, fmt.Errorf("проверка типов близнеца Check без записи: %w", err)
	}
	withRow, err = callerRuntimeNarrowing(program)
	if err != nil {
		return nil, nil, err
	}
	withoutRow, err = callerRuntimeNarrowing(mutant)
	if err != nil {
		return nil, nil, err
	}
	expected := maps.Clone(withRow)
	delete(expected, checkNarrowingRPC)
	if !withRow[checkNarrowingRPC] || !maps.Equal(expected, withoutRow) {
		return nil, nil, fmt.Errorf("ожидалось отсутствие только декларации Check в типизированной таблице близнеца")
	}
	return withRow, withoutRow, nil
}

// The registered walk visits the calls in both branches of conditionals. The
// row may change which branch runs, but it supplies no callable, receiver, or
// write: a private table is consumed only by this scalar comparison predicate.
// Check the typed declaration and all uses before sharing the traversal.
func checkNarrowingOnlyScalarPredicate(program *surfaceProgram) bool {
	sp := program.byPath[checkNarrowingPackage]
	if sp == nil {
		return false
	}
	table, ok := sp.types.Scope().Lookup("callerNarrowedArguments").(*types.Var)
	if !ok || types.TypeString(table.Type(), (*types.Package).Path) != "map[string][]"+checkNarrowingProfilePackage+".Profile" {
		return false
	}
	predicate := sp.types.Scope().Lookup("NarrowsCallerArgument")
	var body *ast.BlockStmt
	var scalarRow bool
	for _, file := range sp.files {
		for node := range ast.Preorder(file) {
			switch d := node.(type) {
			case *ast.FuncDecl:
				if predicate != nil && sp.info.Defs[d.Name] == predicate {
					body = d.Body
				}
			case *ast.ValueSpec:
				if len(d.Names) != 1 || len(d.Values) != 1 || sp.info.Defs[d.Names[0]] != table {
					continue
				}
				if literal, ok := d.Values[0].(*ast.CompositeLit); ok && program.fset.PositionFor(literal.Pos(), false).Filename == checkNarrowingTable {
					scalarRow = checkNarrowingHasScalarRow(sp, literal)
				}
			}
		}
	}
	if body == nil || !scalarRow {
		return false
	}
	const scalarPredicate = `{
	for _, q := range callerNarrowedArguments[fullMethod] {
		if q == p {
			return true
		}
	}
	return false
}`
	var source bytes.Buffer
	if err := format.Node(&source, program.fset, body); err != nil || source.String() != scalarPredicate {
		return false
	}
	uses := 0
	for id, obj := range sp.info.Uses {
		if obj == table {
			if id.Pos() < body.Pos() || id.Pos() >= body.End() {
				return false
			}
			uses++
		}
	}
	return uses == 1
}

func checkNarrowingHasScalarRow(sp *surfaceSrcPkg, literal *ast.CompositeLit) bool {
	for _, elem := range literal.Elts {
		row, ok := elem.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key := sp.info.Types[row.Key].Value
		if key == nil || key.Kind() != constant.String || constant.StringVal(key) != checkNarrowingMethod {
			continue
		}
		profiles, ok := row.Value.(*ast.CompositeLit)
		if !ok || len(profiles.Elts) != 1 {
			return false
		}
		sel, ok := profiles.Elts[0].(*ast.SelectorExpr)
		if !ok {
			return false
		}
		profile, ok := sp.info.Uses[sel.Sel].(*types.Const)
		return ok && profile.Pkg() != nil && profile.Pkg().Path() == checkNarrowingProfilePackage &&
			profile.Name() == "ProfileDataPlane" && profile.Val().Kind() == constant.String
	}
	return false
}

func TestCallerIdentityCheckNarrowingReplayGuard(t *testing.T) {
	const source = `package authzguard
import "github.com/PRO-Robotech/kaname/internal/moduleidentity"
const internalCheckMethod = "/kaname.cloud.iam.v1.InternalIAMService/Check"
var callerNarrowedArguments = map[string][]moduleidentity.Profile{
	internalCheckMethod: {moduleidentity.ProfileDataPlane},
}
func NarrowsCallerArgument(fullMethod string, p moduleidentity.Profile) bool {
	for _, q := range callerNarrowedArguments[fullMethod] {
		if q == p {
			return true
		}
	}
	return false
}`
	for _, tc := range []struct {
		name, profileDecl, input string
		want                     bool
	}{
		{"scalar_predicate", "const", source, true},
		{"another_use", "const", source + "\nvar _ = callerNarrowedArguments", false},
		{"predicate_change", "const", strings.Replace(source, "return true", "return q != p", 1), false},
		{"variable_profile", "var", source, false},
		{"missing_row", "const", strings.Replace(source, "\tinternalCheckMethod: {moduleidentity.ProfileDataPlane},\n", "", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			imports := callerFixtureImporter{}
			load := func(path, filename, input string) *surfaceSrcPkg {
				t.Helper()
				f, err := parser.ParseFile(fset, filename, input, parser.SkipObjectResolution)
				if err != nil {
					t.Fatal(err)
				}
				files := []*ast.File{f}
				info := &types.Info{
					Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{},
				}
				pkg, err := (&types.Config{Importer: imports}).Check(path, fset, files, info)
				if err != nil {
					t.Fatal(err)
				}
				imports[path] = pkg
				return &surfaceSrcPkg{types: pkg, files: files, info: info}
			}
			load(checkNarrowingProfilePackage, "profile.go",
				"package moduleidentity; type Profile string; "+tc.profileDecl+` ProfileDataPlane Profile = "data-plane"`)
			sp := load(checkNarrowingPackage, checkNarrowingTable, tc.input)
			program := &surfaceProgram{fset: fset, byPath: map[string]*surfaceSrcPkg{checkNarrowingPackage: sp}}
			if got := checkNarrowingOnlyScalarPredicate(program); got != tc.want {
				t.Fatalf("reuse guard = %v, want %v", got, tc.want)
			}
		})
	}
}
