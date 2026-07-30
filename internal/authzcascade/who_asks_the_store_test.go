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
	"internal/handler/iamhooks/http_server.go:readinessHandler":                                    laneNotTheStore,
	"internal/authzcascade/own_gates.go:Check":                                                     laneWrapper,
	"internal/authzcascade/own_gates.go:CheckWithContext":                                          laneWrapper,
	"internal/authzcascade/own_gates.go:CheckStored":                                               laneWrapper,
	"internal/authzcascade/own_gates.go:askOnce":                                                   laneWrapper,
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
}

// questionMethods — the relation-store methods that ASK something. Write methods are not
// questions and are not in scope.
var questionMethods = map[string]bool{
	"Check":                      true,
	"CheckWithContext":           true,
	"CheckConsistent":            true,
	"CheckWithContextConsistent": true,
	"CheckWithContextualTuples":  true,
	"CheckStored":                true,
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
				// Only a call on a RECEIVER counts. A bare function of the same name is not a
				// question put to the store.
				if _, isIdent := sel.X.(*ast.Ident); !isIdent {
					if _, isSel := sel.X.(*ast.SelectorExpr); !isSel {
						return true
					}
				}
				fn := "?"
				if len(fnStack) > 0 {
					fn = fnStack[len(fnStack)-1]
				}
				calls++
				key := rel + ":" + fn
				found[key] = append(found[key], sel.Sel.Name)
			}
			return true
		})
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
			"subject IS delivery. An unrecorded site is how iam's answers came to differ "+
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
	for _, l := range []lane{laneOwnGate, laneClusterOnly, laneEdge, laneDelivery, laneWrapper, laneNotTheStore} {
		t.Logf("  %2d sites — %s", byLane[l], l)
	}
}
