// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

// dearestPredicate returns the object type whose page-membership predicate asks the
// MOST relations, and that predicate. It is derived from the declaration itself —
// every per-type entry plus the default that every unlisted type takes — so the
// ceiling below cannot go on describing a type that stopped being the worst one.
//
// Ties resolve to the lexically smaller type name, so the answer is deterministic.
func dearestPredicate() (string, []string) {
	worstType, worstRels := "", RelationsFor("")
	for typ := range pageRelations {
		rels := RelationsFor(typ)
		if len(rels) > len(worstRels) || (len(rels) == len(worstRels) && (worstType == "" || typ < worstType)) {
			worstType, worstRels = typ, rels
		}
	}
	if worstType == "" {
		// No per-type entry is dearer than the default; any unlisted type exhibits it.
		worstType = "unlisted_type_takes_the_default"
	}
	return worstType, worstRels
}

// TestVisibleSet_WorstCasePageCost — the ceiling, asserted as a COUNT.
//
// A page is filtered by asking one direct relation question per (object, relation)
// until one of them allows. So the cheapest page asks once per object and the
// dearest asks len(RelationsFor(objectType)) times per object — and the dearest is
// every page on which the first relation does not resolve: a page a subject cannot
// see at all, and a page a subject sees only through the object-only selector grant.
// Both are ordinary, so the ceiling is not a pathological case.
//
// The predicate is per-object-type, so the ceiling is measured on the DEAREST type
// and that type is DERIVED here, not named: a literal would quietly stop being the
// worst one the moment a dearer type is declared.
//
// Counts, not seconds: wall time here would measure this machine and assert nothing
// about a deployment. That reasoning is untouched by the question having stopped
// being an HTTP round-trip to a separate pod — it is a query against the service's
// own database now, cheaper per question and still a cost that grows with the page,
// which is the only thing this ceiling is about.
//
// The premises are asserted rather than assumed, because the number is a product
// of exactly two things: widen the dearest type's predicate or move
// DefaultParallelism and this test must be re-derived, not silently re-baselined.
func TestVisibleSet_WorstCasePageCost(t *testing.T) {
	dearestType, dearestRels := dearestPredicate()

	require.Len(t, dearestRels, 2,
		"premise: the cost below is len(RelationsFor(%q)) questions per object; widening any "+
			"type's predicate changes the ceiling and this test must restate it", dearestType)
	require.Equal(t, 16, DefaultParallelism,
		"premise: the wave count below divides the ceiling by this bound")

	const (
		wantChecks = 2000 // len(dearest predicate) × validate.MaxPageSize
		wantWaves  = 125  // wantChecks / DefaultParallelism
	)
	require.Equal(t, int64(wantChecks), int64(len(dearestRels))*validate.MaxPageSize,
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
			name: "page visible only through the second relation",
			grantFor: func(id string) string {
				return dearestRels[len(dearestRels)-1] + "|" + dearestType + ":" + id
			},
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

			got, err := VisibleSet(context.Background(), f, "user:u1", dearestType, ids)
			require.NoError(t, err)
			require.Len(t, got, tc.wantSeen, "the verdict itself must be unaffected by how it is counted")

			checks := f.nCalls.Load()
			require.Equal(t, int64(wantChecks), checks,
				"a contract-sized page costs this many relation questions, each one a round-trip")

			waves := (int(checks) + DefaultParallelism - 1) / DefaultParallelism
			require.Equal(t, wantWaves, waves,
				"the bound caps how many are in flight, so it sets DEPTH; it does not reduce the count")

			t.Logf("type=%s | page=%d ids | relations=%d | questions=%d | in-flight bound=%d | depth=%d waves | "+
				"wall at 10ms per question ≈ %dms, at 50ms ≈ %dms",
				dearestType, pageSize, len(dearestRels), checks, DefaultParallelism, waves, waves*10, waves*50)
		})
	}
}

// entryPointShape — where a listed name is declared, and which of its argument
// positions are exempt from making the question per-row.
//
// The positions have to be per-name rather than global, because the names are not
// all the same function. The door onto the relation form takes (ctx, subject,
// relation, object, …); the read guard takes (ctx, checker, [relation,] type, id)
// and reads its subject from the context. A single global "the relation is argument 2" would
// therefore exempt the guard's TYPE argument and, worse, exempt
// SubjectIsClusterAdmin's SUBJECT — turning a genuine per-row question into a
// cleared cascade. Every position that is not named here identifies what the
// question is ABOUT, which is exactly what must not vary with a loop.
type entryPointShape struct {
	// declaredIn — package root, relative to this package, where the name must
	// still be declared (as a method or as a package-level func).
	declaredIn string
	// subjectArg — index of the subject argument; -1 when the subject comes from
	// the context rather than an argument.
	subjectArg int
	// relationArg — index of the single relation argument; -1 when the relation is
	// fixed by the function itself.
	relationArg int
	// relationVariadicFrom — index at which a variadic relation list begins; -1
	// when there is none. Everything from here on is a relation.
	relationVariadicFrom int
}

// relationQuestionEntryPoints — every call that puts a relation question to the form
// that answers it. Keyed by NAME, deliberately, and all three of the ways that can
// go wrong are asserted below rather than hoped about:
//
// The question no longer leaves the process for another pod: it is resolved by the
// service's own database (repo/kacho/pg/relverdict) behind authzcascade.Client. That
// makes each question cheaper and changes NOTHING about why this gate exists —
// per-row still means one query per row, and a query per row is a cost that grows
// with the page and that nothing here measures.
//
//   - a name that stops existing leaves a slot that can never fire again, so the
//     premise test requires each of these to still be declared in the package it
//     claims (an exception that has nothing left to except is a finding). That
//     premise has now fired for real: with the external relation engine removed
//     (stage S6) three names listed here — `CheckConsistent`,
//     `CheckWithContextualTuples` and `ListObjects` — had nothing behind them
//     anywhere in the tree, and the door itself moved out of `clients`. They are
//     removed and the root re-keyed, which is what the premise is for: a gate
//     scanning for names that cannot appear is quiet for a reason that has nothing
//     to do with the tree being clean;
//   - a name that is added to the PORT without being listed here would be invisible
//     to the gate, so every method of the ObjectChecker port must appear, checked
//     by reflection against the port itself;
//   - a name that is added to the read GUARD without being listed here would be
//     invisible in exactly the same way, and that is not hypothetical — it is the
//     idiom this tree already uses. So the guard's exported package-level functions
//     that reach the store are derived from its source and required to appear, by
//     TestGuardRelationEntryPointsAreAllListed.
//
// Why the guard is listed at all: the question is normally NOT written as a client
// call at a read surface. It is written `authzguard.AllowsVGet(ctx, u.relations,
// "account", id)` — five use-cases ask it that way today — and the client call it
// resolves to sits one package away, lexically outside any loop at the call site.
// Keying only on client method names made that idiom, and a loop around it,
// contribute nothing to any counter, including the blind-spot counter.
var relationQuestionEntryPoints = map[string]entryPointShape{
	// The door onto the relation form: (ctx, subject, relation, object, …).
	"Check":                      {relationClientRoot, 1, 2, -1},
	"CheckWithContext":           {relationClientRoot, 1, 2, -1},
	"CheckWithContextConsistent": {relationClientRoot, 1, 2, -1},
	// BatchCheckWithContext(ctx, subject, relation, objects, condCtx) — the batched
	// door. Argument 3 is the set of objects it asks about, and it is NOT exempted:
	// varying it per iteration means one request per row, which is the same defect as
	// varying a single object — only harder to see, because the call already looks
	// batched.
	"BatchCheckWithContext": {relationClientRoot, 1, 2, -1},

	// Read guard: subject always from ctx, so no subject argument.
	// AllowsVGet(ctx, checker, fgaType, id)                                     — relation fixed ("v_get").
	"AllowsVGet": {relationGuardRoot, -1, -1, -1},
	// AllowsVerb(ctx, checker, relation, fgaType, id).
	"AllowsVerb": {relationGuardRoot, -1, 2, -1},
	// RequireScopeRelation(ctx, checker, scopeType, scopeID, ownerUserID, relations...).
	"RequireScopeRelation": {relationGuardRoot, -1, -1, 5},
	// IsClusterAdmin(ctx, checker) — object fixed; nothing can vary, so a call in a
	// loop repeats one identical question per row.
	"IsClusterAdmin": {relationGuardRoot, -1, -1, -1},
	// IsClusterAdminE(ctx, checker) — та же форма и та же стоимость; отличается
	// лишь тем, что сохраняет ПРИЧИНУ отказа. Заведена, чтобы списочный путь мог
	// отличить «хранилище ответило нет» от «хранилище не ответило»: проглоченная
	// неполадка на супер-гейте отдаёт well-formed 200 с молча суженной страницей.
	// Перечислена по тому же основанию, что и SubjectIsClusterAdminE ниже — вопрос
	// один на запрос, и «один» здесь видит только этот гейт.
	"IsClusterAdminE": {relationGuardRoot, -1, -1, -1},
	// SubjectIsClusterAdmin(ctx, checker, subject) — the subject IS argument 2 here,
	// which is precisely why argument 2 is not globally the relation.
	"SubjectIsClusterAdmin": {relationGuardRoot, 2, -1, -1},
	// SubjectIsClusterAdminE(ctx, checker, subject) — same shape, and listed for
	// the same reason: it is the ONE question a visible-page list puts about its
	// caller (#645), asked once per request. That "once" is a property nothing but
	// this gate can see — the call sits one package away and lexically outside any
	// loop, so a copy of it moved INTO the page loop would cost a question per row
	// and contribute to no counter at all.
	"SubjectIsClusterAdminE": {relationGuardRoot, 2, -1, -1},
	// SubjectIsClusterAdminPlainE(ctx, checker, subject) — the SAME question as the
	// two above, over the plain `Check` port instead of the context-carrying one.
	// It exists because the surfaces that hold only that port must still be able to
	// keep the FAILURE of this question (access_binding's List), and it is listed
	// here for the same reason its siblings are: the call sits one package away and
	// lexically outside any loop, so a copy of it moved INTO a page loop would cost
	// a question per row and contribute to no counter at all.
	"SubjectIsClusterAdminPlainE": {relationGuardRoot, 2, -1, -1},
}

// useCaseTreeRoot — the volume THIS gate inspects; relationClientRoot /
// relationGuardRoot — the packages whose names it keys on. Relative to this
// package's directory.
//
// The volume is the use-case tree and not the whole service ON PURPOSE, and the
// difference is load-bearing: widening it to `..` turns this gate red on six
// legitimate sites, every one of them an IMPLEMENTATION of the measured path
// itself (this package's own VisibleSet, the cascade's batch resolver, the
// authorize use-case's own per-item loop). Those are the thing being measured,
// not surfaces evading measurement.
//
// Its neighbour in batchgate_test.go needs the opposite and takes
// serviceTreeRoot: a surface that calls VisibleSet with a checker of the wrong
// capability is a finding wherever it lives, so restricting THAT census to the
// use-case tree left the rest of the service unexamined. Two questions, two
// volumes; sharing one constant made the narrower answer look like it covered
// the wider question, and a report once cited this gate as proof about a file
// that lay outside it.
const (
	useCaseTreeRoot = "../apps/kacho/api"
	serviceTreeRoot = ".."
	// relationClientRoot points at `authzcascade`, not at `clients`, and that
	// difference is what premise 2 exists to catch. `clients` declares the PORTS
	// (RelationStore, RelationQueries) — interface method sets, which are not function
	// declarations and which this AST scan cannot see. Its IMPLEMENTATION used to live
	// there as well, as methods on the HTTP adapter for the external engine; that
	// adapter was removed in stage S6 and the door is now authzcascade.Client over the
	// service's own relational form. Leaving the old root would have left every listed
	// name "declared nowhere" — which is exactly what premise 2 reported.
	relationClientRoot = "../authzcascade"
	relationGuardRoot  = "../authzguard"
)

// TestRelationQuestionsStayInsideTheMeasuredPath — the structural gate.
//
// # What it forbids, and why that is the right property
//
// Page visibility costs len(RelationsFor(objectType)) questions per row, and that number is a
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
// # Indirection, and the two blind spots that remain
//
// The question is rarely written as a client call at a read surface. It is written
// through a helper — `authzguard.AllowsVGet(...)`, or a wrapper in the surface's
// own package — and the client call then sits outside the loop, one or two frames
// down. A scan keyed only on client method names sees none of that: the wrapper
// call matches no name, so it adds nothing to the findings AND nothing to any
// counter, blind-spot counters included. That is the worst shape a gate can have,
// because its silence is indistinguishable from a clean tree.
//
// Two mechanisms close it, and neither is a list of exceptions:
//
//   - across packages, the guard's exported store-reaching functions are listed as
//     entry points, and the list is DERIVED from the guard's source and required to
//     be complete (TestGuardRelationEntryPointsAreAllListed), so a new guard helper
//     cannot be added silently;
//   - within a package, a call to a local function whose own body reaches an entry
//     point is resolved and treated as one, transitively.
//
// What is still blind, stated rather than implied:
//
//  1. a loop with no iteration variable (`for {}`, `for cond {}`), where the
//     repetition count is not syntactically visible. COUNTED and printed;
//  2. a wrapper declared in a THIRD package — neither the caller's own nor one
//     whose entry points are listed. NOT counted: reaching it needs a type-checked
//     call graph, which would cost more than this gate is worth. Today the only
//     such package is the guard, and mechanism one covers it; the honest statement
//     is that a new intermediary package would need adding to the list, and nothing
//     here would announce that.
//
// # Scope, and the open item that is NOT a scope matter
//
// The volume is the use-case tree: that is where the nine visibility-filtered list
// surfaces live and where a tenth would be written.
//
// AuthorizeService.BatchCheck resolves its (contract-bounded) batch one question at
// a time and remains a known open item with its own number. Calling that "outside
// the volume" would be wrong, and the earlier phrasing here said exactly that:
// widening the volume to internal/service would NOT report it, because its loop
// calls `s.check` — an unexported method that is not, and should not be, an entry
// point. It is blind spot 2 above, one package over, not a question of where this
// gate looks.
func TestRelationQuestionsStayInsideTheMeasuredPath(t *testing.T) {
	// Premise 1: the port's own method set must be covered by the names the gate
	// scans for. A rename of the per-object question would otherwise make this gate
	// permanently, invisibly quiet.
	portType := reflect.TypeOf((*ObjectChecker)(nil)).Elem()
	require.NotZero(t, portType.NumMethod(), "premise: the port must declare the question it stands for")
	for i := 0; i < portType.NumMethod(); i++ {
		name := portType.Method(i).Name
		_, ok := relationQuestionEntryPoints[name]
		require.True(t, ok,
			"premise: ObjectChecker.%s is a relation question the gate does not scan for; add it to "+
				"relationQuestionEntryPoints", name)
	}

	// Premise 2: every listed name must still be declared in the package it claims.
	// A name with nothing behind it can never fire again, and an exception with
	// nothing left to except is a finding, not a leftover. Both a method and a
	// package-level func count: the client declares methods, the guard declares
	// plain functions, and keying the premise on methods alone is what previously
	// made the guard impossible to list.
	declaredByRoot := map[string]map[string]bool{}
	filesByRoot := map[string]int{}
	for _, root := range []string{relationClientRoot, relationGuardRoot} {
		names, files := declaredFuncNames(t, root)
		require.NotZero(t, files, "premise: %s must be readable", root)
		declaredByRoot[root], filesByRoot[root] = names, files
	}
	for n, shape := range relationQuestionEntryPoints {
		require.True(t, declaredByRoot[shape.declaredIn][n],
			"premise: %q is no longer declared in %s — the gate would keep scanning for a name that "+
				"cannot appear; re-key it against what exists", n, shape.declaredIn)
	}

	// The scan itself.
	scan := scanForPerRowRelationQuestions(t, useCaseTreeRoot, relationQuestionEntryPoints)

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

	t.Logf("scanned %d files under %s (client: %d files, guard: %d files, %d entry-point names, "+
		"%d resolved local wrappers); relation questions seen=%d, inside a loop=%d "+
		"(cleared as relation cascades=%d), blind spot 1 — loop without an iteration variable=%d; "+
		"findings=%d",
		scan.filesParsed, useCaseTreeRoot, filesByRoot[relationClientRoot], filesByRoot[relationGuardRoot],
		len(relationQuestionEntryPoints), scan.localWrappersResolved,
		scan.callsSeen, scan.callsInLoop, scan.callsInLoop-len(scan.findings),
		scan.callsInVarlessLoop, len(scan.findings))

	var undeclared []string
	matched := map[string]bool{}
	for _, f := range scan.findings {
		if _, ok := declaredPerRowQuestions[f.key]; ok {
			matched[f.key] = true
			continue
		}
		undeclared = append(undeclared, f.detail)
	}
	assert.Empty(t, undeclared,
		"a relation question whose OBJECT varies with the loop asks the relation store once per row: "+
			"its cost is the size of the collection, which in a read surface is a page. That cost is "+
			"outside VisibleSet, so nothing measures it and nothing bounds how many are in flight. "+
			"Filter the page through authzfilter.VisibleSet instead")

	// The declarations expire themselves. A declaration whose site is gone is a
	// false statement about the tree, and the next reader would take it for a
	// standing exemption covering something.
	var stale []string
	for key := range declaredPerRowQuestions {
		if !matched[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale,
		"these sites are declared in declaredPerRowQuestions but the scan no longer finds a per-row "+
			"relation question there. If it was fixed, delete the declaration — a declaration with "+
			"nothing left to declare is a finding, not a leftover")
}

// declaredPerRowQuestions — the per-row relation questions that exist in the tree
// TODAY, each named with its bound and why it is not yet routed through VisibleSet.
//
// This is a list of exceptions, and the sibling pagination gate refuses to have
// one. The difference is what the two gates are for. That one enforces an order
// that is a one-line change at every site, so any exception would be a decision not
// to make the change. This one reports a COST, and removing a cost means asking the
// relation store about many objects in one request — a design change with its own
// acceptance, not something a gate can demand inline.
//
// The alternative is not "no exceptions". It is what this gate did until now: see
// neither of these, because both ask through an intermediary, and report a clean
// tree. A named, self-expiring declaration is strictly better than a blind spot,
// and it is bounded both ways — an undeclared site fails, and a declaration whose
// site is gone fails too.
//
// Keyed by file + calling name, no line number: a declaration must not expire
// because the function moved down its own file.
var declaredPerRowQuestions = map[string]string{
	"../apps/kacho/api/access_binding/list_by_role.go: requireGrantAuthority": "" +
		"Per-row scope filter over a LIST page: up to TWO relation questions per " +
		"binding whose subject is not the caller — a cluster-administrator question " +
		"that is subject-scoped and therefore constant across the page, plus a " +
		"per-scope admin question — so up to 2000 per contract-sized page, plus " +
		"per-row DB reads for hierarchy scopes. THE BLOCKER THIS DECLARATION USED " +
		"TO NAME IS GONE: it read 'converging it needs the batched question tracked " +
		"in known-divergences §11', and that question exists and is wired " +
		"(authzcascade.Client.BatchCheckWithContext, resolved by ONE read " +
		"transaction over the service's own relational form). What remains is that " +
		"the value here is a clients.RelationStore, whose narrowed method set does " +
		"not carry it, and that the loop interleaves relation questions with DB " +
		"reads — a request-path change to an authorization surface, with its own " +
		"acceptance.",
	"../apps/kacho/api/authorize/handler.go: authorizeCaller": "" +
		"Per-item caller authority in BatchCheck, bounded by the contract at 100 " +
		"items (rejected above that). SAME CORRECTION: this declaration used to say " +
		"it 'converges with the same batched question' as a thing not yet available. " +
		"It is available. Converging is not a substitution — the per-item path also " +
		"runs the super-access cascade and a contextual-tuple fallback on the deny " +
		"side, so the shape is 'batch the common first question, slow path only for " +
		"what it denied'. Tracked as a number in known-divergences §11.",
}

// perRowFinding — one per-row relation question. `key` is file + calling name,
// deliberately WITHOUT the line: a declaration below must survive the site moving
// down its own file, or it would expire on an unrelated edit and teach everyone to
// re-baseline it.
type perRowFinding struct {
	key    string
	detail string
}

// scanResult — what the scan saw, so the caller can assert on the VOLUME and on
// the discrimination, not only on the findings.
type scanResult struct {
	findings    []perRowFinding
	filesParsed int
	callsSeen   int // matched calls anywhere
	callsInLoop int // matched calls inside a loop that HAS an iteration variable
	// callsInVarlessLoop — matched calls inside `for {}` / `for cond {}`, where the
	// repetition count is not syntactically visible and this scan classifies nothing.
	// Blind spot 1. Reported, never silently dropped: the size of a blind spot has
	// to be visible.
	callsInVarlessLoop int
	// localWrappersResolved — package-local functions that were promoted to entry
	// points because their own body reaches one. Reported so that "no findings" can
	// be told apart from "the resolution stopped working".
	localWrappersResolved int
}

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
func scanForPerRowRelationQuestions(t *testing.T, root string, entryPoints map[string]entryPointShape) scanResult {
	t.Helper()
	fset := token.NewFileSet()
	var res scanResult

	// Pass 1: parse the volume, grouped by package directory. Grouping is what
	// makes the local-wrapper resolution below possible — a wrapper and its caller
	// are routinely in different files of the same package.
	byDir := map[string][]*ast.File{}
	var dirs []string
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
		dir := filepath.Dir(path)
		if _, seen := byDir[dir]; !seen {
			dirs = append(dirs, dir)
		}
		byDir[dir] = append(byDir[dir], file)
		return nil
	})
	require.NoError(t, err, "the gate must read its whole volume; a walk error is a failure, not zero findings")
	sort.Strings(dirs)

	for _, dir := range dirs {
		files := byDir[dir]

		// Pass 2, per package: promote local functions whose own body reaches an
		// entry point. Transitive, so a wrapper around a wrapper is still resolved.
		// Their shape is unknown, so nothing about them is exempt: any argument that
		// varies with a loop makes the question per-row, which is the conservative
		// reading and the right one.
		local := newLocalWrappers()
		for changed := true; changed; {
			changed = false
			for _, file := range files {
				for _, decl := range file.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if !ok || fn.Body == nil {
						continue
					}
					set := local.funcs
					if fn.Recv != nil {
						set = local.methods
					}
					if set[fn.Name.Name] || !bodyReachesEntryPoint(fn.Body, entryPoints, local) {
						continue
					}
					set[fn.Name.Name] = true
					changed = true
				}
			}
		}
		res.localWrappersResolved += local.size()

		for _, file := range files {
			loops := loopSpansOf(file)

			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name, shape, matched := matchEntryPoint(call, entryPoints, local)
				if !matched {
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
					// Blind spot 1 — a loop with no iteration variable: `for {}` /
					// `for cond {}`. Its repetition count is not visible syntactically,
					// so this scan cannot say whether the question varies. Counted and
					// reported rather than dropped: a blind spot nobody can see the size
					// of is the thing this whole finding was about.
					res.callsInVarlessLoop++
					return true
				}
				res.callsInLoop++

				why := perRowReason(call, shape, iter)
				if why == "" {
					return true // a relation cascade — fixed cost, not this gate's business
				}
				pos := fset.Position(call.Pos())
				path := filepath.ToSlash(pos.Filename)
				res.findings = append(res.findings, perRowFinding{
					key:    path + ": " + name,
					detail: fmt.Sprintf("%s:%d: %s %s", path, pos.Line, name, why),
				})
				return true
			})
		}
	}

	sort.Slice(res.findings, func(i, j int) bool { return res.findings[i].detail < res.findings[j].detail })
	return res
}

// localWrappers — package-local functions and methods already resolved to reach a
// relation question, kept APART because they are called differently and confusing
// the two is how a name-keyed scan invents findings.
//
// A package-level func is called bare: `requireGrantAuthority(...)`. A method is
// called on a receiver: `h.authorizeCaller(...)`. Matching a method name against
// any selector at all makes `w.AccessBindingsW().Delete(...)` collide with a local
// `Delete`, and `rd.Accounts().Get(...)` with a local `Get` — repository calls that
// ask the relation store nothing. Both were reported as findings by the first
// version of this resolution, which is why the receiver has to be constrained:
// a method call is only matched when its receiver is a plain identifier, never a
// call chain into another object.
type localWrappers struct {
	funcs   map[string]bool // declared with no receiver; matched on bare Ident calls
	methods map[string]bool // declared with a receiver; matched on <ident>.Name calls
}

func newLocalWrappers() localWrappers {
	return localWrappers{funcs: map[string]bool{}, methods: map[string]bool{}}
}

func (l localWrappers) size() int { return len(l.funcs) + len(l.methods) }

// matchEntryPoint recognises a call as a relation question: either a listed name
// (`c.Check(...)`, `authzguard.AllowsVGet(...)`) or a package-local wrapper already
// resolved to reach one. A wrapper has no known argument shape, so it is returned
// with nothing exempt — the conservative reading, and the right one.
func matchEntryPoint(call *ast.CallExpr, entryPoints map[string]entryPointShape, local localWrappers) (string, entryPointShape, bool) {
	opaque := entryPointShape{subjectArg: -1, relationArg: -1, relationVariadicFrom: -1}
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		if shape, ok := entryPoints[fun.Sel.Name]; ok {
			return fun.Sel.Name, shape, true
		}
		// Only `<ident>.Method(...)`: a receiver that is itself a call or a field
		// path belongs to another object, whatever the method happens to be named.
		if _, plain := fun.X.(*ast.Ident); plain && local.methods[fun.Sel.Name] {
			return fun.Sel.Name, opaque, true
		}
	case *ast.Ident:
		if local.funcs[fun.Name] {
			return fun.Name, opaque, true
		}
	}
	return "", opaque, false
}

// bodyReachesEntryPoint reports whether a function body calls a listed entry point
// or an already-resolved local wrapper.
func bodyReachesEntryPoint(body *ast.BlockStmt, entryPoints map[string]entryPointShape, local localWrappers) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if _, _, matched := matchEntryPoint(call, entryPoints, local); matched {
			found = true
			return false
		}
		return true
	})
	return found
}

// loopSpan / loopSpansOf — loop bodies as position ranges carrying their iteration
// variables, so any call can be classified against the loops enclosing it.
type loopSpan struct {
	from, to token.Pos
	vars     map[string]bool
}

func loopSpansOf(file *ast.File) []loopSpan {
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
	return loops
}

// perRowReason classifies one matched call that sits inside a loop: "" when the
// question is loop-invariant except for its relation (a cascade), otherwise the
// reason it is per-row, phrased so a finding can be acted on without re-deriving it.
//
// The exempt positions come from the call's OWN shape, not from a global
// convention: argument 2 is the relation for a client Check and for AllowsVerb, but
// it is the object type for AllowsVGet and the SUBJECT for SubjectIsClusterAdmin.
func perRowReason(call *ast.CallExpr, shape entryPointShape, iter map[string]bool) string {
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
		switch {
		case i == shape.relationArg,
			shape.relationVariadicFrom >= 0 && i >= shape.relationVariadicFrom:
			// The cascade case: the loop walks relations about ONE object.
		case i == shape.subjectArg:
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

// declaredFuncNames returns the set of function names declared under root —
// METHODS AND PACKAGE-LEVEL FUNCS ALIKE — and how many files it read. Used only to
// keep the gate's key honest (premise 2).
//
// Both kinds count, and that is the point: the relation client declares methods,
// the read guard declares plain functions, and a premise that accepted only
// methods is what made the guard impossible to list — the list stayed short, and
// the idiom the tree actually uses stayed invisible.
func declaredFuncNames(t *testing.T, root string) (map[string]bool, int) {
	t.Helper()
	names, files := map[string]bool{}, 0
	forEachGoFile(t, root, func(_ string, file *ast.File) {
		files++
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				names[fn.Name.Name] = true
			}
		}
	})
	return names, files
}

// forEachGoFile parses every non-test Go file under root. A walk or parse error is
// a failure, never zero results.
func forEachGoFile(t *testing.T, root string, fn func(path string, file *ast.File)) {
	t.Helper()
	fset := token.NewFileSet()
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
		fn(path, file)
		return nil
	})
	require.NoError(t, err, "reading %s must succeed; a walk error is a failure, not an empty result", root)
}

// TestGuardRelationEntryPointsAreAllListed — the completeness premise for the
// guard, DERIVED rather than trusted.
//
// The gate keys on names. A name it does not hold is invisible to it, and that is
// not a hypothetical failure mode here: the guard is how this tree writes the
// question, so a new guard helper reaching the store would silently widen the blind
// spot the gate exists to close. Listing the two that exist today would fix the
// instance and leave the class.
//
// So the required set is computed from the guard's own source — every exported
// package-level function whose body transitively reaches a relation question — and
// each member must appear in relationQuestionEntryPoints. Adding a guard helper
// therefore fails this test until it is listed.
//
// Only package-level functions are required. Methods on the guard's own types
// (RelationWriteGate.Authorize, SystemViewerFloor.allow) are wired as interceptors
// on the serving path, not called per row from a read surface; requiring them would
// add names no use-case can call.
func TestGuardRelationEntryPointsAreAllListed(t *testing.T) {
	type fnDecl struct {
		name     string
		exported bool
		body     *ast.BlockStmt
	}
	var decls []fnDecl
	files := 0
	forEachGoFile(t, relationGuardRoot, func(_ string, file *ast.File) {
		files++
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv != nil {
				continue
			}
			decls = append(decls, fnDecl{fn.Name.Name, fn.Name.IsExported(), fn.Body})
		}
	})
	require.NotZero(t, files, "premise: the guard package must be readable at %s", relationGuardRoot)
	require.NotZero(t, len(decls), "premise: the guard must declare package-level functions")

	// Seed with the CLIENT names only: what makes a guard function store-reaching is
	// that it ends up asking the client. Seeding with the guard's own listed names
	// would make the answer depend on the list being checked.
	clientNames := map[string]entryPointShape{}
	for n, s := range relationQuestionEntryPoints {
		if s.declaredIn == relationClientRoot {
			clientNames[n] = s
		}
	}
	require.NotZero(t, len(clientNames), "premise: at least one client entry point must be listed to seed from")

	// Within the guard package its own functions are called bare, so they resolve as
	// local funcs; the client call they end at is a selector on the checker.
	reaching := newLocalWrappers()
	for changed := true; changed; {
		changed = false
		for _, d := range decls {
			if reaching.funcs[d.name] {
				continue
			}
			if bodyReachesEntryPoint(d.body, clientNames, reaching) {
				reaching.funcs[d.name] = true
				changed = true
			}
		}
	}

	var required, missing []string
	for _, d := range decls {
		if d.exported && reaching.funcs[d.name] {
			required = append(required, d.name)
			if _, listed := relationQuestionEntryPoints[d.name]; !listed {
				missing = append(missing, d.name)
			}
		}
	}
	sort.Strings(required)
	sort.Strings(missing)

	require.NotZero(t, len(required),
		"premise: no exported guard function was found to reach a relation question at all — the "+
			"derivation is broken, and its silence would mean nothing")
	t.Logf("guard package-level functions reaching a relation question: %v", required)

	assert.Empty(t, missing,
		"these exported guard functions reach the relation store but are not listed in "+
			"relationQuestionEntryPoints, so a loop around any of them would add nothing to the "+
			"findings and nothing to any counter: %v. Add them with their own argument shape — "+
			"the exempt positions are per-function, not global", missing)
}
