// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_model_drift_test.go — CI drift-gate (system-design W-1, KAC #177
// follow-up). Closes the fail-open risk that re-opened #177: the FGA emitter
// (access_binding/scope_grant_tuples.go) and the catalog (this package's
// objectTypes + TypeHasVerbRelations) must NEVER drift from the canonical
// authorization model (kacho-proto/.../fga_model.fga). A drift — e.g. a new
// objectTypes entry whose model type has no `v_*`, or a v_*-bearing set that
// claims a tier-only type — would silently emit dangling-relation tuples →
// OpenFGA reject → ErrPermanent → poison fga_outbox → partial-grant desync.
//
// This test parses the canonical DSL directly (no Docker → runs in -short too,
// so the gate fires on every CI run) and asserts, against the model as the
// single source of truth:
//
//	D-1  every authzmap.objectTypes VALUE exists as a `type` in the model.
//	D-2  every v_*-bearing resource-type carries the FULL closed per-verb set
//	     (v_get/v_list/v_create/v_update/v_delete) — a partial set would let a
//	     CRUD verb emit a tuple the model can't satisfy.
//	D-3  authzmap.TypeHasVerbRelations(t) ⟺ the model defines v_* on `t`
//	     (no drift in EITHER direction: the emission guard equals the model).
//	D-4  the tier-only types in objectTypes (account/project — hierarchy
//	     ancestors, not leaf resources) have NO v_* and are TypeHasVerbRelations
//	     =false (documented + enforced: their grants are tier-only / SKIP).
package authzmap_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
)

// closedVerbRelations — the per-verb relation set the emitter materializes
// (mirror of access_binding.closedVerbs, intentionally duplicated here so the
// gate has no dependency on the emitter package and fails independently).
var closedVerbRelations = []string{"v_get", "v_list", "v_create", "v_update", "v_delete"}

// tierOnlyObjectTypes — objectTypes values that carry tier (admin/editor/viewer)
// but NO v_* relations. Documented here so the gate enforces the design decision
// rather than silently tolerating it. Any objectTypes value NOT in this set is
// expected to be a full v_*-bearing resource-type.
//
// rbac-explicit-model-2026 P3 / D-6: `account` and `project` were removed from
// this set — they became verb-bearing (the canonical model now defines the full
// v_* set on both, P2). They KEEP their tier relations (write-authz anchors,
// D-7), but they are no longer tier-ONLY, so they are now expected to carry the
// full closed v_* set (D-2 path), matching authzmap.TypeHasVerbRelations=true.
var tierOnlyObjectTypes = map[string]bool{}

// fgaModelPath resolves the canonical fga_model.fga in the sibling kacho-proto
// checkout. Walks up from the package dir to the dir containing kacho-proto.
func fgaModelPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := wd
	for i := 0; i < 12; i++ {
		cand := filepath.Join(dir, "kacho-proto", "proto", "kacho", "cloud", "iam", "v1", "fga_model.fga")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("canonical fga_model.fga not found (kacho-proto sibling absent) — skipping drift-gate")
	return ""
}

var (
	reType = regexp.MustCompile(`^type (\w+)`)
	// a TOP-LEVEL relation definition: 4-space indent + `define <name>:`.
	// (relations under a type are indented; the type keyword is column 0.)
	reDefine = regexp.MustCompile(`^\s+define (\w+):`)
)

// modelFacts parses the DSL into: set of declared types, and per-type set of
// directly-defined relations.
type modelFacts struct {
	types     map[string]bool
	relations map[string]map[string]bool // type → relation set
}

func parseModel(t *testing.T) modelFacts {
	t.Helper()
	data, err := os.ReadFile(fgaModelPath(t))
	require.NoError(t, err)
	f := modelFacts{types: map[string]bool{}, relations: map[string]map[string]bool{}}
	var cur string
	for _, line := range strings.Split(string(data), "\n") {
		if m := reType.FindStringSubmatch(line); m != nil {
			cur = m[1]
			f.types[cur] = true
			f.relations[cur] = map[string]bool{}
			continue
		}
		if cur == "" {
			continue
		}
		if m := reDefine.FindStringSubmatch(line); m != nil {
			f.relations[cur][m[1]] = true
		}
	}
	return f
}

// hasFullVerbSet reports whether the type defines ALL closed v_* relations.
func (f modelFacts) hasFullVerbSet(typ string) bool {
	rels := f.relations[typ]
	for _, v := range closedVerbRelations {
		if !rels[v] {
			return false
		}
	}
	return true
}

// hasAnyVerbRelation reports whether the type defines AT LEAST one v_* relation.
func (f modelFacts) hasAnyVerbRelation(typ string) bool {
	for _, v := range closedVerbRelations {
		if f.relations[typ][v] {
			return true
		}
	}
	return false
}

func allObjectTypeValues() []string {
	// objectTypes is unexported; enumerate via ObjectType over the closed key
	// set the package documents (kept in lockstep with fga_types.go).
	pairs := [][2]string{
		{"compute", "instance"}, {"compute", "disk"}, {"compute", "image"}, {"compute", "snapshot"},
		{"vpc", "network"}, {"vpc", "subnet"}, {"vpc", "address"}, {"vpc", "securityGroup"},
		{"vpc", "routeTable"}, {"vpc", "gateway"}, {"vpc", "networkInterface"}, {"vpc", "addressPool"},
		{"loadbalancer", "networkLoadBalancers"}, {"loadbalancer", "targetGroups"}, {"loadbalancer", "listeners"},
		{"iam", "account"}, {"iam", "project"}, {"iam", "user"}, {"iam", "serviceAccount"},
		{"iam", "group"}, {"iam", "role"}, {"iam", "accessBinding"}, {"iam", "condition"},
	}
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		if o, ok := authzmap.ObjectType(p[0], p[1]); ok {
			out = append(out, o)
		}
	}
	return out
}

// D-1: every objectTypes value is a declared type in the model.
func TestDrift_ObjectTypesExistInModel(t *testing.T) {
	f := parseModel(t)
	for _, ot := range allObjectTypeValues() {
		require.Truef(t, f.types[ot],
			"objectTypes value %q is NOT a `type` in fga_model.fga (drift → dangling-relation writes)", ot)
	}
}

// D-2 + D-4: each objectTypes value is EITHER a full v_*-bearing resource-type
// OR a documented tier-only type with NO v_*. No partial sets, no surprises.
func TestDrift_VerbBearingTypesHaveFullSet(t *testing.T) {
	f := parseModel(t)
	for _, ot := range allObjectTypeValues() {
		if tierOnlyObjectTypes[ot] {
			// D-4: tier-only type must define NO v_* at all.
			require.Falsef(t, f.hasAnyVerbRelation(ot),
				"tier-only objectType %q unexpectedly defines a v_* relation in the model (update tierOnlyObjectTypes / guard)", ot)
			continue
		}
		// D-2: resource-type must define the FULL closed per-verb set.
		require.Truef(t, f.hasFullVerbSet(ot),
			"resource objectType %q is missing one or more of %v in the model (a CRUD verb would emit an unsatisfiable tuple)", ot, closedVerbRelations)
	}
}

// D-3: the emission guard (authzmap.TypeHasVerbRelations) must equal the model
// EXACTLY for every objectTypes value — no drift in either direction. This is
// the gate that catches a future #177-class fail-open: if someone adds a type
// to objectTypes without v_* but the guard still returns true (or vice-versa),
// the emitter would write dangling tuples again.
func TestDrift_GuardMatchesModel(t *testing.T) {
	f := parseModel(t)
	for _, ot := range allObjectTypeValues() {
		modelHasVerbs := f.hasFullVerbSet(ot)
		guard := authzmap.TypeHasVerbRelations(ot)
		require.Equalf(t, modelHasVerbs, guard,
			"TypeHasVerbRelations(%q)=%v but model full-v_*-set=%v — emission guard drifted from the canonical model", ot, guard, modelHasVerbs)
	}
	// And the documented tier-only set must agree with the guard returning false.
	for ot := range tierOnlyObjectTypes {
		require.Falsef(t, authzmap.TypeHasVerbRelations(ot),
			"tier-only type %q must have TypeHasVerbRelations=false", ot)
	}
}
