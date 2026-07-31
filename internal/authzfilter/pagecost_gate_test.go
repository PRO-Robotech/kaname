// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// pagecost_gate_test.go — what a page of visibility filtering COSTS, and the
// structural condition that keeps that number meaningful.
//
// The two tests here answer two different questions, and both had to be written
// because answering only the first leaves the number describing one function
// while nine read surfaces are free to stop using it:
//
//   - TestVisibleSet_WorstCasePageCost states the number for the WORST page, not
//     for a convenient one. The sibling headroom test measures a mixed page
//     (a third allowed on the first relation), which is cheaper than the contract
//     permits; the ceiling is what a budget has to survive.
//   - TestRelationQuestionsStayInsideTheMeasuredPath is the structural gate: the
//     number above is a property of ONE function, so it only describes the read
//     surfaces that go through it. A surface that asks its own per-row relation
//     question is outside every measurement in this repository, and nothing else
//     would notice.
package authzfilter

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/validate"
)

// TestVisibleSet_WorstCasePageCost — the ceiling, asserted as a COUNT.
//
// A page is filtered by asking one direct relation question per (object, relation)
// until one of them allows. So the cheapest page asks once per object and the
// dearest asks len(Relations) times per object — and the dearest is every page on
// which the first relation does not resolve: a page a subject cannot see at all,
// and a page a subject sees only through the object-only selector grant. Both are
// ordinary, so the ceiling is not a pathological case.
//
// Counts, not seconds: a question is an HTTP round-trip to the relation store in a
// separate pod, so wall time here would measure this machine and assert nothing
// about a deployment. The same reasoning the sibling page-cost measurement in
// authzcascade writes down at length.
//
// The premises are asserted rather than assumed, because the number is a product
// of exactly two constants: widen Relations or move DefaultParallelism and this
// test must be re-derived, not silently re-baselined.
func TestVisibleSet_WorstCasePageCost(t *testing.T) {
	require.Len(t, Relations, 2,
		"premise: the cost below is len(Relations) questions per object; widening the union "+
			"changes the ceiling and this test must restate it")
	require.Equal(t, 16, DefaultParallelism,
		"premise: the wave count below divides the ceiling by this bound")

	const (
		wantChecks = 2000 // len(Relations) × validate.MaxPageSize
		wantWaves  = 125  // wantChecks / DefaultParallelism
	)
	require.Equal(t, int64(wantChecks), int64(len(Relations))*validate.MaxPageSize,
		"premise: the literal ceiling must agree with the constants it is derived from")

	pageSize := int(validate.MaxPageSize)

	for _, tc := range []struct {
		name string
		// grantFor returns the "<relation>|<object>" the fake oracle should hold for
		// this id, or "" for an object the subject cannot see at all.
		grantFor func(id string) string
		wantSeen int
	}{
		{
			name:     "page the subject cannot see at all",
			grantFor: func(string) string { return "" },
			wantSeen: 0,
		},
		{
			name:     "page visible only through the second relation",
			grantFor: func(id string) string { return Relations[len(Relations)-1] + "|t:" + id },
			wantSeen: int(validate.MaxPageSize),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ids := make([]string, 0, pageSize)
			granted := make([]string, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				id := fmt.Sprintf("obj%04d", i)
				ids = append(ids, id)
				if g := tc.grantFor(id); g != "" {
					granted = append(granted, g)
				}
			}
			f := newFakeChecker(granted...)

			got, err := VisibleSet(context.Background(), f, "user:u1", "t", ids)
			require.NoError(t, err)
			require.Len(t, got, tc.wantSeen, "the verdict itself must be unaffected by how it is counted")

			checks := f.nCalls.Load()
			require.Equal(t, int64(wantChecks), checks,
				"a contract-sized page costs this many relation questions, each one a round-trip")

			waves := (int(checks) + DefaultParallelism - 1) / DefaultParallelism
			require.Equal(t, wantWaves, waves,
				"the bound caps how many are in flight, so it sets DEPTH; it does not reduce the count")

			t.Logf("page=%d ids | relations=%d | questions=%d | in-flight bound=%d | depth=%d waves | "+
				"wall at 10ms per question ≈ %dms, at 50ms ≈ %dms",
				pageSize, len(Relations), checks, DefaultParallelism, waves, waves*10, waves*50)
		})
	}
}

// relationQuestionEntryPoints — every client method that puts a relation question
// on the wire to the relation store. Keyed by NAME, deliberately, and both of the
// ways that can go wrong are asserted below rather than hoped about:
//
//   - a name that stops existing leaves a slot that can never fire again, so the
//     premise test requires each of these to still be declared in the client
//     package (an exception that has nothing left to except is a finding);
//   - a name that is added without being listed here would be invisible to the
//     gate, so every method of the ObjectChecker port must appear in this list,
//     checked by reflection against the port itself.
var relationQuestionEntryPoints = []string{
	"Check",
	"CheckConsistent",
	"CheckWithContext",
	"CheckWithContextConsistent",
	"CheckWithContextualTuples",
	"ListObjects",
}

// useCaseTreeRoot / relationClientRoot — the volume this gate inspects and the
// package whose method names it keys on, relative to this package's directory.
const (
	useCaseTreeRoot    = "../apps/kacho/api"
	relationClientRoot = "../clients"
)

// TestRelationQuestionsStayInsideTheMeasuredPath — the structural gate.
//
// # What it forbids, and why that is the right property
//
// Page visibility costs len(Relations) questions per row, and that number is a
// property of VisibleSet in THIS package: it is measured here, and the bound that
// keeps a page from arriving at the relation store all at once lives here too. A
// read surface that asks its own relation question per row therefore pays a cost
// nothing measures and nothing bounds — and it looks entirely ordinary in review,
// because a loop over a page asking "may this subject see this one?" is exactly
// what the correct implementation does one call deeper.
//
// # Form is not the property — the OBJECT is
//
// "A relation question inside a loop" is the wrong rule, and writing it first is
// how one finds that out: it reports two constructs that are entirely legitimate.
// A relation CASCADE walks a fixed list of relations — `admin > editor > viewer`,
// or this package's own `viewer ∪ v_list` — asking about ONE object. Its cost is
// the length of that list, it does not grow with anything a caller sends, and it
// is the same shape the correct implementation uses one call deeper.
//
// What separates the two is which argument varies with the loop. A cascade varies
// the RELATION and holds the object fixed. A per-row filter varies the OBJECT, so
// its cost is the size of the collection being looped over — and a collection in a
// read surface is a page. So the rule is: inside a loop, a relation question whose
// object (or subject) depends on the iteration is a finding; one that only varies
// the relation is not.
//
// The counter-shape is not left to a one-off injection either: the gate requires
// that it actually SAW questions inside loops and judged them legitimate. Silence
// therefore means "looked at this shape and distinguished it", never "found no
// loops".
//
// # Volume, and why it is asserted
//
// "No findings" and "nothing was read" are the same output. The counts are logged
// and the non-zero ones are required, so a gate that stops reading the tree — a
// moved directory, a build tag, a parse failure — fails instead of passing
// quietly.
//
// # Scope
//
// The volume is the use-case tree: that is where the nine visibility-filtered list
// surfaces live and where a tenth would be written. It is not the whole service —
// AuthorizeService.BatchCheck resolves its (contract-bounded) batch one question at
// a time, which is a known open item with its own number and is not silently
// excepted here: it is simply outside the volume this gate claims, and the volume
// is stated rather than implied.
func TestRelationQuestionsStayInsideTheMeasuredPath(t *testing.T) {
	// Premise 1: the port's own method set must be covered by the names the gate
	// scans for. A rename of the per-object question would otherwise make this gate
	// permanently, invisibly quiet.
	listed := make(map[string]bool, len(relationQuestionEntryPoints))
	for _, n := range relationQuestionEntryPoints {
		listed[n] = true
	}
	portType := reflect.TypeOf((*ObjectChecker)(nil)).Elem()
	require.NotZero(t, portType.NumMethod(), "premise: the port must declare the question it stands for")
	for i := 0; i < portType.NumMethod(); i++ {
		name := portType.Method(i).Name
		require.True(t, listed[name],
			"premise: ObjectChecker.%s is a relation question the gate does not scan for; add it to "+
				"relationQuestionEntryPoints", name)
	}

	// Premise 2: every listed name must still be declared in the relation client.
	// A name with nothing behind it can never fire again, and an exception with
	// nothing left to except is a finding, not a leftover.
	declared, clientFiles := declaredMethodNames(t, relationClientRoot)
	require.NotZero(t, clientFiles, "premise: the relation client package must be readable at %s", relationClientRoot)
	for _, n := range relationQuestionEntryPoints {
		require.True(t, declared[n],
			"premise: %q is no longer declared in %s — the gate would keep scanning for a name that "+
				"cannot appear; re-key it against the methods that exist", n, relationClientRoot)
	}

	// The scan itself.
	scan := scanForPerRowRelationQuestions(t, useCaseTreeRoot, listed)

	// Premise 3 (volume): the scanner must have read real files.
	require.NotZero(t, scan.filesParsed, "premise: nothing was read under %s — the gate proves nothing", useCaseTreeRoot)
	// Premise 4 (positive control, recognition): it must have recognised real
	// entry-point calls. Without this, "no finding" is indistinguishable from "no
	// call matched at all", which is what a rename or a restructure would produce.
	require.NotZero(t, scan.callsSeen,
		"premise: no relation question was recognised anywhere under %s; the gate must SEE the "+
			"legitimate ones before its silence means anything", useCaseTreeRoot)
	// Premise 5 (positive control, DISCRIMINATION): it must have seen questions
	// inside loops and cleared them. This is the counter-shape held permanently:
	// a gate that only ever reports "no question inside any loop" has not shown it
	// can tell a relation cascade from a per-row filter — it has only shown the
	// tree happens to contain no loops it recognises.
	require.NotZero(t, scan.callsInLoop,
		"premise: no relation question inside a loop was seen at all under %s, so this run never "+
			"exercised the distinction the gate exists to make (cascade over relations = legitimate, "+
			"varying the object = finding); re-point the volume or re-key the entry points", useCaseTreeRoot)

	t.Logf("scanned %d files under %s (relation client: %d files, %d method names); "+
		"relation questions seen=%d, inside a loop=%d (cleared as relation cascades=%d), "+
		"not classified because the loop has no iteration variable=%d, findings=%d",
		scan.filesParsed, useCaseTreeRoot, clientFiles, len(declared),
		scan.callsSeen, scan.callsInLoop, scan.callsInLoop-len(scan.findings),
		scan.callsInVarlessLoop, len(scan.findings))

	assert.Empty(t, scan.findings,
		"a relation question whose OBJECT varies with the loop asks the relation store once per row: "+
			"its cost is the size of the collection, which in a read surface is a page. That cost is "+
			"outside VisibleSet, so nothing measures it and nothing bounds how many are in flight. "+
			"Filter the page through authzfilter.VisibleSet instead")
}

// scanResult — what the scan saw, so the caller can assert on the VOLUME and on
// the discrimination, not only on the findings.
type scanResult struct {
	findings    []string
	filesParsed int
	callsSeen   int // matched calls anywhere
	callsInLoop int // matched calls inside a loop that HAS an iteration variable
	// callsInVarlessLoop — matched calls inside `for {}` / `for cond {}`, where the
	// repetition count is not syntactically visible and this scan classifies nothing.
	// Reported, never silently dropped: the size of a blind spot has to be visible.
	callsInVarlessLoop int
}

// Argument positions shared by every entry point in relationQuestionEntryPoints:
// all of them are (ctx, subject, relation, object, …). Only the relation position
// is exempt from making a call per-row, so it is the one that has to be named —
// every other position identifies what the question is ABOUT.
const (
	subjectArgIndex  = 1
	relationArgIndex = 2
)

// scanForPerRowRelationQuestions parses every non-test Go file under root and
// reports the entry-point calls whose question VARIES WITH THE ITERATION of an
// enclosing loop — i.e. the object or the subject depends on the loop variable,
// so the number of round-trips is the size of the collection.
//
// A call that only varies the RELATION is a cascade over a fixed relation list and
// is deliberately not reported: its cost is that list's length, and it is exactly
// what Visible does one call deeper.
//
// Reported conservatively: a call inside a loop that mentions the loop variable
// nowhere in its arguments is also a finding, because then the same question is
// being repeated per iteration — which covers the case of the loop variable being
// copied into a local first, where a syntactic scan cannot follow the value.
//
// No type information is used: the shape is visible without it, and requiring a
// full type-check would make the gate expensive enough to be dropped.
func scanForPerRowRelationQuestions(t *testing.T, root string, listed map[string]bool) scanResult {
	t.Helper()
	fset := token.NewFileSet()
	var res scanResult

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		res.filesParsed++

		// Loop bodies first, as position ranges carrying their iteration variables;
		// then every matched call is classified against the loops enclosing it.
		type loopSpan struct {
			from, to token.Pos
			vars     map[string]bool
		}
		var loops []loopSpan
		ast.Inspect(file, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.ForStmt:
				if s.Body != nil {
					loops = append(loops, loopSpan{s.Body.Pos(), s.Body.End(), identsOfStmt(s.Init)})
				}
			case *ast.RangeStmt:
				if s.Body != nil {
					vars := identsOfExpr(s.Key)
					for k := range identsOfExpr(s.Value) {
						vars[k] = true
					}
					loops = append(loops, loopSpan{s.Body.Pos(), s.Body.End(), vars})
				}
			}
			return true
		})

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !listed[sel.Sel.Name] {
				return true
			}
			res.callsSeen++

			// Union of the iteration variables of every loop enclosing this call.
			iter := map[string]bool{}
			enclosed := false
			for _, l := range loops {
				if call.Pos() >= l.from && call.Pos() < l.to {
					enclosed = true
					for v := range l.vars {
						iter[v] = true
					}
				}
			}
			if !enclosed {
				return true
			}
			if len(iter) == 0 {
				// A loop with no iteration variable: `for {}` / `for cond {}`. Its
				// repetition count is not visible syntactically, so this scan cannot
				// say whether the question varies. Counted and reported rather than
				// dropped — a blind spot nobody can see the size of is the thing this
				// whole finding was about.
				res.callsInVarlessLoop++
				return true
			}
			res.callsInLoop++

			why := perRowReason(call, iter)
			if why == "" {
				return true // a relation cascade — fixed cost, not this gate's business
			}
			pos := fset.Position(call.Pos())
			res.findings = append(res.findings, fmt.Sprintf("%s:%d: %s %s",
				filepath.ToSlash(pos.Filename), pos.Line, sel.Sel.Name, why))
			return true
		})
		return nil
	})
	require.NoError(t, err, "the gate must read its whole volume; a walk error is a failure, not zero findings")

	sort.Strings(res.findings)
	return res
}

// perRowReason classifies one matched call that sits inside a loop: "" when the
// question is loop-invariant except for its relation (a cascade), otherwise the
// reason it is per-row, phrased so a finding can be acted on without re-deriving it.
func perRowReason(call *ast.CallExpr, iter map[string]bool) string {
	mentionsIter := func(e ast.Expr) bool {
		for name := range identsOfExpr(e) {
			if iter[name] {
				return true
			}
		}
		return false
	}

	varying := make([]string, 0, 2)
	anyMention := false
	for i, arg := range call.Args {
		if !mentionsIter(arg) {
			continue
		}
		anyMention = true
		switch i {
		case relationArgIndex:
			// The cascade case: the loop walks relations about ONE object.
		case subjectArgIndex:
			varying = append(varying, "subject")
		default:
			varying = append(varying, "object")
		}
	}
	switch {
	case len(varying) > 0:
		return "varies its " + strings.Join(varying, " and ") + " with the loop"
	case !anyMention:
		// Nothing in the call depends on the iteration, so the identical question
		// is asked once per element — including the case where the loop variable
		// was copied into a local, which a syntactic scan cannot follow.
		return "repeats a question per iteration without depending on it"
	default:
		return ""
	}
}

// identsOfExpr — every identifier appearing in an expression (nil-safe).
func identsOfExpr(e ast.Expr) map[string]bool {
	out := map[string]bool{}
	if e == nil {
		return out
	}
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name != "_" {
			out[id.Name] = true
		}
		return true
	})
	return out
}

// identsOfStmt — identifiers ASSIGNED by a three-clause for's init (its loop
// variables), nil-safe. Only the left-hand side counts: `for i := 0; …` iterates
// over i, not over the 0.
func identsOfStmt(s ast.Stmt) map[string]bool {
	out := map[string]bool{}
	assign, ok := s.(*ast.AssignStmt)
	if !ok {
		return out
	}
	for _, lhs := range assign.Lhs {
		for name := range identsOfExpr(lhs) {
			out[name] = true
		}
	}
	return out
}

// declaredMethodNames returns the set of method names declared under root, and how
// many files it read. Used only to keep the gate's key honest (premise 2).
func declaredMethodNames(t *testing.T, root string) (map[string]bool, int) {
	t.Helper()
	fset := token.NewFileSet()
	names := map[string]bool{}
	files := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		files++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil {
				continue
			}
			names[fn.Name.Name] = true
		}
		return nil
	})
	require.NoError(t, err)
	return names, files
}
