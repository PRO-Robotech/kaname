// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Глубина обхода и модели общая; позиции сохранённой цепи — другая ось.
// Равенство recursion и schema больше не является доводом полноты fanout.
package check_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	scopeDepthConstRel     = "internal/repo/kaname/pg/relverdict/query.go"
	scopeDepthMigrationRel = "internal/migrations/0001_initial.sql"
	scopeDepthPlanFileRel  = "internal/authzplan/compile.go"
	scopeDepthSharedRel    = "internal/hierarchy/limits.go"
	scopeDepthSharedImport = "github.com/PRO-Robotech/kaname/internal/hierarchy"
)

// Обе формы настоящего CHECK: исходная миграция и pg_dump.
var reDepthCheck = regexp.MustCompile(`\bdepth BETWEEN 1 AND (\d+)|\bdepth\s*<=\s*(\d+)`)

func TestScopeDepthBoundsAgreeAcrossAllThreePlaces(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	read := func(rel string) string {
		return readFileForDepth(t, filepath.Join(root, filepath.FromSlash(platformtree.Under(prefix, rel))))
	}
	shared := read(scopeDepthSharedRel)
	bound := func(body, name, target string) int {
		n, err := resolveScopeDepth(body, name, shared, target)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return n
	}
	tr := scopeDepthTriple{
		goDepth:       bound(read(scopeDepthConstRel), "MaxAncestorDepth", "MaxPointerHops"),
		planDepth:     findScopeDepthPlan(t, root, prefix, shared),
		pointerDepth:  bound(shared, "MaxPointerHops", ""),
		storedDepth:   bound(shared, "MaxStoredParentLinks", ""),
		fanout:        bound(shared, "MaxImmediateParents", ""),
		sqlDepth:      singleNumber(t, reDepthCheck, read(scopeDepthMigrationRel), "граница схемы"),
		constPath:     platformtree.Under(prefix, scopeDepthConstRel),
		migrationPath: platformtree.Under(prefix, scopeDepthMigrationRel),
		planPath:      platformtree.Under(prefix, scopeDepthPlanFileRel),
		sharedPath:    platformtree.Under(prefix, scopeDepthSharedRel),
	}
	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: SQL traversal=%d, model=%d, shared hops=%d, stored=%d, schema=%d, fanout=%d; четыре источника", tr.goDepth, tr.planDepth, tr.pointerDepth, tr.storedDepth, tr.sqlDepth, tr.fanout)
	for _, finding := range adjudicateScopeDepth(tr) {
		t.Error(finding)
	}
}

type scopeDepthTriple struct {
	goDepth, sqlDepth, planDepth, pointerDepth, storedDepth, fanout int
	constPath, migrationPath, planPath, sharedPath                  string
}

func adjudicateScopeDepth(tr scopeDepthTriple) []string {
	var out []string
	if tr.goDepth != tr.pointerDepth {
		out = append(out, fmt.Sprintf("предел обхода %d (%s) не равен MaxPointerHops %d (%s)", tr.goDepth, tr.constPath, tr.pointerDepth, tr.sharedPath))
	}
	if tr.planDepth != tr.pointerDepth {
		out = append(out, fmt.Sprintf("предел модели %d (%s) не равен MaxPointerHops %d (%s)", tr.planDepth, tr.planPath, tr.pointerDepth, tr.sharedPath))
	}
	if tr.sqlDepth != tr.storedDepth {
		out = append(out, fmt.Sprintf("граница схемы %d (%s) не равна MaxStoredParentLinks %d (%s)", tr.sqlDepth, tr.migrationPath, tr.storedDepth, tr.sharedPath))
	}
	if tr.pointerDepth < 1 || tr.storedDepth < 1 || tr.fanout < 1 {
		out = append(out, fmt.Sprintf("неположительная граница в %s: hops=%d stored=%d fanout=%d", tr.sharedPath, tr.pointerDepth, tr.storedDepth, tr.fanout))
	}
	return out
}

// Разбирается объявление const, а не комментарий с цифрой. Законны literal
// и ссылка на нужную ось ровно известного import; неизвестная форма краснеет.
// Координаты четырёх источников явные: исчезновение любого — ошибка чтения,
// а не отсутствие третьей величины, выдаваемое за согласие.
func resolveScopeDepth(body, name, shared, target string) (int, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "depth.go", body, 0)
	if err != nil {
		return 0, err
	}
	var value ast.Expr
	count := 0
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			v, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range v.Names {
				if ident.Name == name {
					count++
					if len(v.Values) == len(v.Names) {
						value = v.Values[i]
					}
				}
			}
		}
	}
	if count != 1 || value == nil {
		return 0, fmt.Errorf("%s: нужно ровно одно явное const-значение, найдено %d", name, count)
	}
	if literal, ok := value.(*ast.BasicLit); ok && literal.Kind == token.INT {
		n, err := strconv.ParseInt(literal.Value, 0, 32)
		return int(n), err
	}
	selector, ok := value.(*ast.SelectorExpr)
	if !ok || target == "" || selector.Sel.Name != target {
		return 0, fmt.Errorf("%s: неизвестная форма или чужая ось границы", name)
	}
	qualifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return 0, fmt.Errorf("%s: не import selector", name)
	}
	matches := 0
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return 0, err
		}
		alias := filepath.Base(path)
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		if alias == qualifier.Name {
			if path != scopeDepthSharedImport {
				return 0, fmt.Errorf("%s: чужой import %s", name, path)
			}
			matches++
		}
	}
	if matches != 1 {
		return 0, fmt.Errorf("%s: import для %s не единственный", name, qualifier.Name)
	}
	return resolveScopeDepth(shared, target, "", "")
}

// Перепись сохраняет прежний полный repository-index corpus, включая tools.
// Чтение или разбор любого non-test Go-файла не может исчезнуть из результата.
func findScopeDepthPlan(t *testing.T, root, prefix, shared string) int {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(prefix))
	files, err := treecorpus.UnderWithSuffix(dir, ".go")
	if err != nil {
		t.Fatalf("состав Go corpus: %v", err)
	}
	corpus := map[string]string{}
	for _, abs := range files {
		if strings.HasSuffix(abs, "_test.go") {
			continue
		}
		rel, err := filepath.Rel(dir, abs)
		if err != nil {
			t.Fatalf("координата %s: %v", abs, err)
		}
		corpus[filepath.ToSlash(rel)] = readFileForDepth(t, abs)
	}
	n, declarations, err := scopeDepthPlanCensus(corpus, shared)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("MaxPointerDepth: non-test Go файлов=%d, объявлений=%d, значение=%d", len(corpus), declarations, n)
	return n
}

// Законный tools alias ссылается на canonical authzplan, который сам разрешён
// через shared hierarchy. Независимые literals/shared aliases сверяются с ним.
// Два объявления в одном package, local shadow и неизвестная форма — отказ.
func scopeDepthPlanCensus(corpus map[string]string, shared string) (int, int, error) {
	canonical, ok := corpus[scopeDepthPlanFileRel]
	if !ok {
		return 0, 0, fmt.Errorf("нет canonical %s", scopeDepthPlanFileRel)
	}
	n, err := resolveScopeDepth(canonical, "MaxPointerDepth", shared, "MaxPointerHops")
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", scopeDepthPlanFileRel, err)
	}
	paths := make([]string, 0, len(corpus))
	for rel := range corpus {
		paths = append(paths, rel)
	}
	sort.Strings(paths)
	packages := map[string]string{}
	declarations := 0
	for _, rel := range paths {
		body := corpus[rel]
		file, err := parser.ParseFile(token.NewFileSet(), rel, body, 0)
		if err != nil {
			return 0, declarations, fmt.Errorf("%s: %w", rel, err)
		}
		all := 0
		ast.Inspect(file, func(node ast.Node) bool {
			if spec, ok := node.(*ast.ValueSpec); ok {
				for _, ident := range spec.Names {
					if ident.Name == "MaxPointerDepth" {
						all++
					}
				}
			}
			return true
		})
		if all == 0 {
			continue
		}
		var value ast.Expr
		top := 0
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				v := spec.(*ast.ValueSpec)
				for i, ident := range v.Names {
					if ident.Name == "MaxPointerDepth" {
						top++
						if len(v.Values) == len(v.Names) {
							value = v.Values[i]
						}
					}
				}
			}
		}
		if all != 1 || top != 1 || value == nil {
			return 0, declarations, fmt.Errorf("%s: MaxPointerDepth должен быть одним top-level const без local shadow", rel)
		}
		packageKey := filepath.Dir(rel) + ":" + file.Name.Name
		if previous, exists := packages[packageKey]; exists {
			return 0, declarations, fmt.Errorf("MaxPointerDepth задвоен: %s и %s", previous, rel)
		}
		packages[packageKey] = rel
		declarations++
		canonicalAlias := false
		if selector, ok := value.(*ast.SelectorExpr); ok && selector.Sel.Name == "MaxPointerDepth" {
			if qualifier, ok := selector.X.(*ast.Ident); ok {
				matches := 0
				for _, imp := range file.Imports {
					path, err := strconv.Unquote(imp.Path.Value)
					if err != nil {
						return 0, declarations, fmt.Errorf("%s: %w", rel, err)
					}
					alias := filepath.Base(path)
					if imp.Name != nil {
						alias = imp.Name.Name
					}
					if alias == qualifier.Name {
						if path != "github.com/PRO-Robotech/kaname/internal/authzplan" {
							return 0, declarations, fmt.Errorf("%s: чужой alias import %s", rel, path)
						}
						matches++
					}
				}
				canonicalAlias = matches == 1
			}
		}
		if canonicalAlias {
			continue
		}
		actual, err := resolveScopeDepth(body, "MaxPointerDepth", shared, "MaxPointerHops")
		if err != nil {
			return 0, declarations, fmt.Errorf("%s: %w", rel, err)
		}
		if actual != n {
			return 0, declarations, fmt.Errorf("MaxPointerDepth расходится: %s=%d, %s=%d", scopeDepthPlanFileRel, n, rel, actual)
		}
	}
	return n, declarations, nil
}

func readFileForDepth(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- фиксированная координата внутри corpus
	if err != nil {
		t.Fatalf("файл %s не читается: %v", path, err)
	}
	return string(body)
}

func singleNumber(t *testing.T, re *regexp.Regexp, body, what string) int {
	t.Helper()
	ms := re.FindAllStringSubmatch(body, -1)
	if len(ms) == 0 {
		t.Fatalf("%s не найдена: объявление переехало, и «величины совпадают» стало бы "+
			"утверждением ни о чём", what)
	}
	if len(ms) > 1 {
		t.Fatalf("%s объявлена %d раз: она уже задвоена, и расхождение возможно внутри "+
			"одного файла", what, len(ms))
	}
	raw := ""
	for _, g := range ms[0][1:] {
		if g != "" {
			raw = g
			break
		}
	}
	if raw == "" {
		t.Fatalf("%s: совпадение есть, а числа в нём нет — распознаватель нашёл форму, "+
			"из которой не извлекает величину", what)
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("%s не число: %q", what, raw)
	}
	return n
}
