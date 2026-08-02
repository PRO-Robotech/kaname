// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// who_asks_the_store_test.go — the radius, measured over the tree rather than over the
// diff in which the defect was noticed.
//
// The defect was not "three call sites were missed". It was that a question about an
// iam-owned object could be asked of the relation store WITHOUT the second chance the
// api-gateway's gate gives, and the set of places that could do that was never enumerated.
// Naming three of them and fixing those would close the finding and leave the class.
//
// So this gate enumerates, from the syntax tree of the production sources, EVERY place that
// asks the relation store a question, and requires each to be accounted for by lane. A new
// asking site fails the gate until someone says which lane it is in; an entry with nothing
// left to point at also fails, so the list cannot outlive its subject and become the next
// blind spot.
//
// It reads the syntax tree, not the text: a regular expression over source would match the
// word `Check` inside the comment that explains a check, and stay green with the check gone.
// And it asserts how much it examined, so "no findings" stays distinguishable from "nothing
// parsed".

package authzcascade

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// lane — why a site is allowed to ask what it asks.
type lane string

const (
	// laneOwnGate — the receiver is a narrow port (authzguard.RelationChecker,
	// authzfilter.ObjectChecker, clients.RelationStore/RelationQueries) supplied by the
	// composition root, which supplies the wrapped client and has no unwrapped one to
	// supply. These sites therefore get the second chance without knowing it exists, and
	// that is the property that makes the divergence unexpressible rather than merely
	// detectable.
	laneOwnGate lane = "own gate, fed by the composition root"
	// laneClusterOnly — the object is a cluster-scoped or otherwise non-derivable singleton,
	// so no structural fact exists for it and the wrapper changes nothing either way.
	laneClusterOnly lane = "non-derivable object (cluster / proxy singleton)"
	// laneEdge — AuthorizeService, which gives the second chance itself.
	laneEdge lane = "the edge gate, which supplies the facts itself"
	// laneDelivery — the subject of the question IS delivery. Answering it from committed
	// rows would make it report success about a queue that delivered nothing.
	laneDelivery lane = "delivery is the subject of the question"
	// laneWrapper — the wrapper's own call through to the transport.
	laneWrapper lane = "the wrapper itself"
	// laneEnumeration — the ENUMERATION path: the store is asked to produce objects or
	// subjects, and the answer is audit data rather than a gate decision. As with laneEdge,
	// the lane names the path a site is on and not the type of the value it happens to hold,
	// so a transport-thin handler above such a call is in the same lane as the resolve
	// beneath it.
	//
	// These report what the relation store HOLDS, so they reflect the tiers that were
	// materialized and not the ones the cascade resolves structurally at request time: an
	// operator reading "who can act on this" can see fewer principals than the gate would
	// admit.
	//
	// That is a KNOWN and BOUNDED limitation, recorded here rather than left to be
	// rediscovered, and it is NOT the divergence this package exists to prevent — nothing is
	// granted or refused on these answers. Two things keep it that way, both checked
	// elsewhere: an enumeration must never narrow a list to an id-set (the list-filter audit
	// in the leaf services bans it outright, because the store caps such a response with no
	// continuation and a tenant's own rows would vanish), and every gate decision is a
	// named-object question in one of the lanes above.
	//
	// Closing the gap is separate design, not a wrapper: the second chance works by supplying
	// facts about an object already named, and an enumeration has no name to supply them for —
	// it is being asked to produce the names. Whoever takes it on owns the question of how an
	// unbounded tier is reported at all.
	laneEnumeration lane = "an enumeration of delivered relations — audit data, not a gate"
	// laneNotTheStore — a method that merely SHARES the name. Recorded rather than filtered
	// out by shape: a filter on argument count or receiver type would be a premise this gate
	// does not state, and the day it stopped holding the gate would go quiet instead of
	// asking. Naming the site costs one line and keeps the matcher honest.
	laneNotTheStore lane = "not the relation store — same method name, different thing"
)

// askingSites — every production site that asks the relation store a question, keyed
// "<path>:<enclosing function>".
//
// Adding a site is a decision, so it is recorded as one. The lane is what the next reader
// checks against reality.
var askingSites = map[string]lane{
	"internal/handler/iamhooks/http_server.go:readinessHandler": laneNotTheStore,
	// The binding's own child subject ROWS, read from Postgres in the reader-tx
	// (access_binding.ReaderIface, which takes a binding id). It shares a method name with the
	// store's subject enumeration and nothing else: no relation is consulted, so the cascade
	// has no bearing on it. It surfaced only when the matcher stopped filtering by receiver
	// shape, and it is the whole cost of that widening — one recorded line.
	"internal/apps/kacho/api/access_binding/get.go:Execute":                                        laneNotTheStore,
	"internal/authzcascade/own_gates.go:Check":                                                     laneWrapper,
	"internal/authzcascade/own_gates.go:CheckWithContext":                                          laneWrapper,
	"internal/authzcascade/own_gates.go:secondChance":                                              laneWrapper,
	"internal/authzguard/read_authz.go:AllowsVerb":                                                 laneOwnGate,
	"internal/authzguard/scope.go:RequireScopeRelation":                                            laneOwnGate,
	"internal/authzfilter/visibility.go:Visible":                                                   laneOwnGate,
	"internal/apps/kacho/api/access_binding/helpers.go:fgaHoldsScopeAdmin":                         laneOwnGate,
	"internal/apps/kacho/api/account/list_all_operations.go:requireAccountViewAuthority":           laneOwnGate,
	"internal/apps/kacho/api/user/invite_authz.go:cascadeCheck":                                    laneOwnGate,
	"internal/apps/kacho/api/authorize/caller_authority.go:authorizeCaller":                        laneOwnGate,
	"internal/authzguard/cluster_admin_shortcircuit.go:subjectIsClusterAdminE":                     laneClusterOnly,
	"internal/authzguard/system_viewer_floor.go:allow":                                             laneClusterOnly,
	"internal/authzguard/fgaproxy.go:Authorize":                                                    laneClusterOnly,
	"internal/apps/kacho/api/internal_operations/list_iam_operations.go:requireClusterSystemAdmin": laneClusterOnly,
	"internal/apps/kacho/api/internal_iam/force_logout.go:requireSystemAdmin":                      laneClusterOnly,
	"internal/apps/kacho/api/cluster/admin_authz.go:requireClusterSystemAdmin":                     laneClusterOnly,
	"internal/apps/kacho/api/authorize/whoami.go:Execute":                                          laneClusterOnly,
	"internal/service/authorize_service.go:check":                                                  laneEdge,
	"internal/service/authorize_service.go:checkRelationWire":                                      laneEdge,
	"internal/service/authorize_service.go:structuralFallback":                                     laneEdge,
	"internal/apps/kacho/api/authorize/handler.go:Check":                                           laneEdge,
	"internal/apps/kacho/seed/verify_gate.go:VerifyRelationSatisfiesAction":                        laneDelivery,
	"internal/service/authorize_service.go:ListObjects":                                            laneEnumeration,
	"internal/service/authorize_service.go:ListSubjects":                                           laneEnumeration,
	"internal/service/authorize_service.go:ExpandRelations":                                        laneEnumeration,
	"internal/apps/kacho/api/access_binding/expand_access.go:Execute":                              laneEnumeration,
	"internal/apps/kacho/api/authorize/handler.go:ListObjects":                                     laneEnumeration,
	"internal/apps/kacho/api/authorize/handler.go:ListSubjects":                                    laneEnumeration,
}

// questionMethods — the relation-store methods that ASK something. Write methods are not
// questions and are not in scope.
//
// BOTH SHAPES OF QUESTION ARE HERE, and the second was missing. A question can name its
// object ("may this subject act on THIS") or ask the store to produce objects and subjects
// ("which objects", "who can"). Only the first shape was enumerated, so this file claimed to
// cover EVERY place that asks the store while four read methods were invisible to it — and
// the sites they are asked from are precisely the ones whose answers do NOT reflect the
// super-access cascade. The inventory meant to notice a divergence could not see the places
// where one remains.
//
// Naming a method here does not assert that its answer should get the second chance. It
// asserts that the site must declare a lane, so a difference is a recorded decision rather
// than an omission nobody can see.
var questionMethods = map[string]bool{
	// Named-object questions — a gate decision about one object.
	"Check":                      true,
	"CheckWithContext":           true,
	"CheckConsistent":            true,
	"CheckWithContextConsistent": true,
	"CheckWithContextualTuples":  true,
	// Enumeration questions — the store produces the objects or the subjects.
	"ListObjects":  true,
	"ListSubjects": true,
	"ListUsers":    true,
	"Expand":       true,
}

// questionsIn — THE MATCHER, over one parsed file: enclosing function name → the question
// methods asked in it.
//
// Extracted from the walk so its own premise is testable directly
// (TestMatcherSeesEveryShapeOfTheCallAndNothingElse). A matcher that silently ignores one
// SPELLING of the call it exists to find is exactly the blind spot this file is supposed not
// to have, and over the tree that failure is invisible: nothing distinguishes "no such site"
// from "did not look".
func questionsIn(f *ast.File) map[string][]string {
	out := map[string][]string{}
	var fnStack []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			fnStack = append(fnStack, node.Name.Name)
		case *ast.FuncLit:
			// A literal keeps the enclosing declaration's name — the decision belongs to
			// the function a reader would look at, not to an anonymous closure.
			if len(fnStack) > 0 {
				fnStack = append(fnStack, fnStack[len(fnStack)-1])
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || !questionMethods[sel.Sel.Name] {
				return true
			}
			// ANY receiver shape counts. There used to be a filter here admitting only an
			// identifier or a selector, and it read as harmless — a bare function of the same
			// name is already excluded by the SelectorExpr check above, so the filter looked
			// like it was restating that. It was not. It silently dropped a question reached
			// through a call, `holder.relations().Check(…)`, and through a dereference,
			// `(*h).Check(…)`: ordinary ways to reach a dependency, and three of the nine
			// premise cases below. So this file claimed to enumerate every place while some
			// spellings of the most important call were invisible, and the lane comment above
			// disclaimed a receiver-type premise the matcher was in fact making.
			//
			// Widening cannot lose a site and can only add ones that share a method name; each
			// costs one recorded line, which is the trade this gate already chose.
			fn := "?"
			if len(fnStack) > 0 {
				fn = fnStack[len(fnStack)-1]
			}
			out[fn] = append(out[fn], sel.Sel.Name)
		}
		return true
	})
	return out
}

// TestEveryAskingSiteIsAccountedFor — the inventory.
func TestEveryAskingSiteIsAccountedFor(t *testing.T) {
	root := filepath.Join("..", "..") // services/iam
	found := map[string][]string{}    // key → the call expressions seen there
	files, calls := 0, 0

	err := filepath.Walk(root, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.IsDir() {
			// tests/ holds the black-box suite (not Go production sources).
			if info.Name() == "tests" || info.Name() == "testsupport" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		files++
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		for fn, methods := range questionsIn(f) {
			calls += len(methods)
			key := rel + ":" + fn
			found[key] = append(found[key], methods...)
		}
		return nil
	})
	require.NoError(t, err)

	// Premise: the walk must have read a body of sources and found questions in it.
	// Otherwise every assertion below would pass over nothing.
	require.Greater(t, files, 200, "parsed only %d production files — the tree moved", files)
	require.Greater(t, calls, 15, "found only %d relation questions — the matcher stopped matching", calls)

	var unaccounted []string
	for key, methods := range found {
		if _, ok := askingSites[key]; !ok {
			sort.Strings(methods)
			unaccounted = append(unaccounted, key+" ("+strings.Join(methods, ",")+")")
		}
	}
	sort.Strings(unaccounted)
	require.Emptyf(t, unaccounted,
		"these places ask the relation store a question and no lane is recorded for them. "+
			"Say which: a gate fed by the composition root (it gets the second chance and "+
			"needs no code), a non-derivable object, the edge gate, or a question whose "+
			"subject IS delivery, or an enumeration whose answer is audit data and never a "+
			"gate decision. An unrecorded site is how iam's answers came to differ "+
			"from the api-gateway's:\n  %s", strings.Join(unaccounted, "\n  "))

	// The list expires by itself: an entry with nothing left to point at is a false
	// statement about the tree, and the next slow-moving blind spot inherits it.
	var stale []string
	for key := range askingSites {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	require.Emptyf(t, stale,
		"these recorded sites no longer ask anything — remove them, or the list starts "+
			"vouching for code that is gone:\n  %s", strings.Join(stale, "\n  "))

	byLane := map[lane]int{}
	for key := range found {
		byLane[askingSites[key]]++
	}
	t.Logf("examined %d production files; %d relation questions at %d sites", files, calls, len(found))
	for _, l := range []lane{laneOwnGate, laneClusterOnly, laneEdge, laneDelivery, laneEnumeration, laneWrapper, laneNotTheStore} {
		t.Logf("  %2d sites — %s", byLane[l], l)
	}
}

// TestMatcherSeesEveryShapeOfTheCallAndNothingElse — the inventory's own premise.
//
// The inventory above is only worth its claim if the matcher recognises a question however
// it is SPELLED. Over the tree a missed spelling is undetectable — an absent site and an
// unexamined one look identical — so the matcher is fed sources whose answer is known, in
// both directions: every shape a receiver can take must be found, and things that merely
// resemble a question must not be.
//
// The call-receiver case is not hypothetical. It was written as an injection, the matcher
// stayed silent on it, and that silence is what promoted this from a tidy-up to a defect:
// `holder.relations().Check(…)` is an ordinary way to reach a dependency, and it was the one
// spelling of the most important call in the service that the inventory could not see.
func TestMatcherSeesEveryShapeOfTheCallAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want []string // methods expected in func f
	}{
		{
			name: "identifier receiver",
			body: `func f(s S) { s.Check(ctx, "u", "r", "o") }`,
			want: []string{"Check"},
		},
		{
			name: "selector receiver",
			body: `func f(s S) { s.rel.CheckWithContext(ctx, "u", "r", "o", nil) }`,
			want: []string{"CheckWithContext"},
		},
		{
			// The shape that was invisible. Reaching a dependency through an accessor is
			// ordinary Go, and it must not be a way to ask unwatched.
			name: "call receiver",
			body: `func f(s S) { s.relations().Check(ctx, "u", "r", "o") }`,
			want: []string{"Check"},
		},
		{
			name: "pointer-dereference receiver",
			body: `func f(s *S) { (*s).Check(ctx, "u", "r", "o") }`,
			want: []string{"Check"},
		},
		{
			name: "enumeration question",
			body: `func f(s S) { s.store().ListUsers(ctx, "t", "i", "r", nil) }`,
			want: []string{"ListUsers"},
		},
		{
			// A package-level function that happens to share the name is not a question put
			// to a store, and neither is a write.
			name: "bare function of the same name is not a question",
			body: `func f() { Check(ctx, "u", "r", "o") }`,
			want: nil,
		},
		{
			name: "write method is not a question",
			body: `func f(s S) { s.WriteTuples(ctx, nil) }`,
			want: nil,
		},
		{
			// The reason this reads the syntax tree at all: prose about a check is not a check.
			name: "the word in a comment is not a question",
			body: "func f(s S) {\n\t// s.Check(ctx, \"u\", \"r\", \"o\") explains the gate below\n\t_ = s\n}",
			want: nil,
		},
		{
			name: "a string that looks like a call is not a question",
			body: `func f() { _ = "s.Check(ctx, u, r, o)" }`,
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "package p\n\nvar ctx any\n\n" + tc.body + "\n"
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "synthetic.go", src, parser.SkipObjectResolution)
			require.NoError(t, err, "the fixture itself must parse")

			got := questionsIn(f)["f"]
			require.ElementsMatch(t, tc.want, got,
				"the matcher must see a question in every spelling and only in a real one. "+
					"A spelling it misses is a way to ask the relation store unwatched, and over "+
					"the tree that miss is indistinguishable from there being nothing there.")
		})
	}
}
