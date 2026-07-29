// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// cascade_coverage_test.go — gates on the CLASS, read off the canonical model.
//
// The defect this package fixes is not "one pointer was queued". It is that EVERY
// arm of the super-access cascade is enabled by a tuple only a queue delivers. So
// the radius has to be measured from the model, mechanically, rather than from the
// place the defect was first noticed — and what this package does NOT cover has to
// be a named number rather than a silence.
//
// Three gates:
//
//  1. Coverage — every verb-bearing type whose `super_admin` derives over a
//     structural pointer is either derivable here or explicitly excluded with a
//     reason. A new such type added to the model fails this test.
//  2. The exclusion list expires by itself — an entry that has BECOME derivable is
//     a finding, not a leftover.
//  3. Injection scope — the relations this package supplies are read by `super_admin`
//     and by nothing else, on every type. That is the entire safety argument for
//     supplying them at request time: a TRUE fact about the row can then only open
//     the cascade the decision already grants, never anything besides it.
//
// The gates parse the canonical DSL, and each asserts how much of it it actually
// read, so "zero findings" stays distinguishable from "zero lines examined".

package authzcascade

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// notDerivableHere — types whose structural pointer this package cannot prove,
// with the reason. Keep it factual: the reason is what the next reader checks
// against reality.
//
// Every entry is a type owned by ANOTHER service. Its pointer is written by that
// owner's own register queue, and iam holds at most a queue-fed mirror of it
// (kacho_iam.resource_mirror, filled by RegisterResource) — deriving from that
// would move the dependency to a different queue, not remove it. Making these
// request-time needs the owner to assert the parent scope in the Check request,
// which is a cross-service contract change and is deliberately not smuggled in
// here.
var notDerivableHere = map[string]string{
	"vpc_network":               "owned by kacho-vpc",
	"vpc_subnet":                "owned by kacho-vpc",
	"vpc_security_group":        "owned by kacho-vpc",
	"vpc_route_table":           "owned by kacho-vpc",
	"vpc_address":               "owned by kacho-vpc",
	"vpc_gateway":               "owned by kacho-vpc",
	"vpc_network_interface":     "owned by kacho-vpc",
	"vpc_address_pool":          "owned by kacho-vpc",
	"compute_instance":          "owned by kacho-compute",
	"compute_disk":              "owned by kacho-compute",
	"compute_image":             "owned by kacho-compute",
	"compute_snapshot":          "owned by kacho-compute",
	"nlb_network_load_balancer": "owned by kacho-nlb",
	"nlb_target_group":          "owned by kacho-nlb",
	"nlb_listener":              "owned by kacho-nlb",
	"registry_registry":         "owned by kacho-registry",
	"registry_repository":       "owned by kacho-registry",
	"storage_volume":            "owned by kacho-storage",
	"storage_snapshot":          "owned by kacho-storage",
	"storage_image":             "owned by kacho-storage",
}

// suppliedPairs runs the ACTUAL projections over synthetic rows and returns the
// (object type, relation) pairs this package can put on the wire.
//
// It calls the production projection functions rather than restating their shape,
// so a projection that starts emitting a new relation is picked up by gate 3
// automatically. A declared list would be a second statement of the same thing and
// would drift.
func suppliedPairs() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	add := func(facts []authztypes.TupleKey) {
		for _, f := range facts {
			objType, _, ok := splitForTest(f.Object)
			if !ok {
				continue
			}
			if out[objType] == nil {
				out[objType] = map[string]bool{}
			}
			out[objType][f.Relation] = true
		}
	}
	for _, scope := range []string{"project", "account", "cluster"} {
		add(toConditionalOne(domain.AccessBinding{
			ID: "abn-x", ResourceType: domain.ResourceType(scope), ResourceID: "sc-x",
		}.StructuralParent()))
	}
	add(toConditional(domain.Account{ID: "acc-x", OwnerUserID: "usr-x"}.StructuralFacts()))
	add(toConditional(domain.Project{ID: "prj-x", AccountID: "acc-x"}.StructuralFacts()))
	for _, ot := range []string{"iam_user", "iam_group", "iam_role", "iam_service_account"} {
		add(toConditionalOne(domain.AccountScopedStructuralFact("acc-x", ot, "id-x")))
	}
	add(toConditionalOne(domain.ProjectScopedStructuralFact("prj-x", "iam_condition", "cnd-x")))
	return out
}

func splitForTest(s string) (string, string, bool) {
	i := strings.Index(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

type modelType struct {
	name      string
	relations map[string]string // relation → definition, comments stripped
	order     []string
}

// parseModel reads the canonical DSL. Comment lines are dropped so a relation
// named inside prose is never mistaken for a definition (a gate that greps raw
// text finds its own explanation and stays green).
func parseModel(t *testing.T) map[string]*modelType {
	t.Helper()
	path := modelPath(t)
	raw, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read canonical model %s: %v", path, err)
	}
	defineRE := regexp.MustCompile(`^\s+define\s+(\w+):\s*(.+?)\s*$`)
	typeRE := regexp.MustCompile(`^type\s+(\S+)\s*$`)
	out := map[string]*modelType{}
	var cur *modelType
	lines := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		lines++
		if m := typeRE.FindStringSubmatch(line); m != nil {
			cur = &modelType{name: m[1], relations: map[string]string{}}
			out[m[1]] = cur
			continue
		}
		if m := defineRE.FindStringSubmatch(line); m != nil && cur != nil {
			cur.relations[m[1]] = m[2]
			cur.order = append(cur.order, m[1])
		}
	}
	// Premise check: the parse must have seen a model, not an empty or moved file.
	if len(out) < 20 || lines < 200 {
		t.Fatalf("premise broken: parsed only %d types from %d non-comment lines of %s — "+
			"the DSL moved or the parser stopped matching, so every gate below would "+
			"pass on nothing", len(out), lines, path)
	}
	t.Logf("examined %d types over %d non-comment lines of %s", len(out), lines, filepath.Base(path))
	return out
}

func modelPath(t *testing.T) string {
	t.Helper()
	// authzcascade → internal → iam → services → repo root
	return filepath.Join("..", "..", "..", "..", "proto", "kacho", "cloud", "iam", "v1", "fga_model.fga")
}

// TestEveryCascadedTypeIsCoveredOrExcluded — gate 1.
func TestEveryCascadedTypeIsCoveredOrExcluded(t *testing.T) {
	model := parseModel(t)
	r := New(nil).WithConditions(stubConditionReader{})

	cascaded, uncovered := 0, []string(nil)
	for name, mt := range model {
		def, ok := mt.relations["super_admin"]
		if !ok {
			continue
		}
		// Only a derivation over a structural pointer is delivery-dependent. A
		// `super_admin` that reads nothing structural is not in this class.
		if !strings.Contains(def, " from ") {
			continue
		}
		cascaded++
		if r.Derivable(name) {
			continue
		}
		if _, excused := notDerivableHere[name]; excused {
			continue
		}
		uncovered = append(uncovered, name+" ("+def+")")
	}
	if cascaded == 0 {
		t.Fatal("premise broken: no type derives super_admin over a structural pointer — " +
			"either the cascade was removed or this gate stopped recognising it")
	}
	t.Logf("%d types derive super_admin over a structural pointer; %d derivable here, %d excluded",
		cascaded, len(DerivableTypes), len(notDerivableHere))
	if len(uncovered) > 0 {
		t.Errorf("these types cascade over a structural pointer but are neither derivable at "+
			"request time nor explicitly excluded, so their cascade silently depends on a queue:\n  %s",
			strings.Join(uncovered, "\n  "))
	}
}

// TestExclusionListHasSomethingLeftToExclude — gate 2. An exclusion that has
// become derivable is a false statement about the tree, and the next slow-moving
// blind spot inherits it.
func TestExclusionListHasSomethingLeftToExclude(t *testing.T) {
	model := parseModel(t)
	r := New(nil).WithConditions(stubConditionReader{})
	for name, reason := range notDerivableHere {
		mt, ok := model[name]
		if !ok {
			t.Errorf("excluded type %q (%s) is not in the model any more — the exclusion has "+
				"nothing left to exclude", name, reason)
			continue
		}
		if _, has := mt.relations["super_admin"]; !has {
			t.Errorf("excluded type %q (%s) no longer derives super_admin — the exclusion has "+
				"nothing left to exclude", name, reason)
		}
		if r.Derivable(name) {
			t.Errorf("excluded type %q is now derivable (%s) — remove the exclusion", name, reason)
		}
	}
}

// TestSuppliedRelationsAreReadOnlyBySuperAdmin — gate 3, the safety argument.
//
// This package hands OpenFGA true facts about a committed row. A contextual tuple
// can only ADD a resolution path, so the whole safety argument is that the model
// reads the supplied relation in exactly one place — `super_admin`. If some other
// relation of the same type started reading it, a true fact would confer something
// the decision never intended, and no diff of this package would show it.
//
// The pairs come from running the real projections (suppliedPairs), not from a
// restated list, and the check is scoped PER OBJECT TYPE: registry types read
// `owner` directly on their verbs, which is theirs and none of this package's
// business, because nothing here ever supplies a fact about a registry object.
func TestSuppliedRelationsAreReadOnlyBySuperAdmin(t *testing.T) {
	model := parseModel(t)
	supplied := suppliedPairs()
	if len(supplied) == 0 {
		t.Fatal("premise broken: the projections emitted nothing, so this gate would examine nothing")
	}

	checked, pairs := 0, 0
	for typeName, relations := range supplied {
		mt, ok := model[typeName]
		if !ok {
			t.Errorf("this package supplies facts about object type %q, which is not in the model",
				typeName)
			continue
		}
		for ptr := range relations {
			pairs++
			if _, declared := mt.relations[ptr]; !declared {
				t.Errorf("%s has no relation %q, yet this package supplies it — OpenFGA would "+
					"reject the contextual tuple and the cascade would silently stay "+
					"delivery-dependent", typeName, ptr)
				continue
			}
			for _, rel := range mt.order {
				def := mt.relations[rel]
				if !readsRelation(def, ptr) {
					continue
				}
				checked++
				switch {
				case rel == "super_admin":
					// The cascade itself — the whole point.
				case typeName == "account" && ptr == "owner" &&
					(rel == "admin" || strings.HasPrefix(rel, "v_")):
					// The recorded owner refinement: `account`'s five verbs and its
					// admin tier read `owner` directly, on purpose, so that tearing an
					// account down is as reliable as creating it.
				default:
					t.Errorf("%s.%s reads the structural relation %q (%q). This package supplies "+
						"%q about %s as a request-scoped fact on the strength of it being read "+
						"ONLY by super_admin there; that is no longer true, so either stop "+
						"supplying it or justify this reader here.",
						typeName, rel, ptr, def, ptr, typeName)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("premise broken: none of the supplied relations is read by anything — the gate " +
			"matched nothing and would pass on an empty model")
	}
	t.Logf("%d supplied (type, relation) pairs; %d readers of them in the model; all accounted for",
		pairs, checked)
}

// readsRelation reports whether a relation definition RESOLVES over `name` —
// either as a tuple-to-userset hop (`<rel> from name`) or as a direct disjunct
// (`or name`). A type-restriction list (`[user, service_account]`) is not a read,
// so it is stripped before the disjunct match.
func readsRelation(def, name string) bool {
	if regexp.MustCompile(`\bfrom\s+` + regexp.QuoteMeta(name) + `\b`).MatchString(def) {
		return true
	}
	bare := strings.TrimSpace(regexp.MustCompile(`\[[^\]]*\]`).ReplaceAllString(def, ""))
	return regexp.MustCompile(`(^|\bor\s+)` + regexp.QuoteMeta(name) + `\b`).MatchString(bare)
}

// stubConditionReader makes iam_condition count as wired for the coverage gates
// without needing a database (they never call StructuralFacts).
type stubConditionReader struct{}

func (stubConditionReader) Get(context.Context, domain.ConditionID) (domain.Condition, error) {
	return domain.Condition{}, nil
}
