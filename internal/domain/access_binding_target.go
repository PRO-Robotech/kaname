// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// access_binding_target.go — the reintroduced AccessBinding.target
// (redesign-2026 F8, least-privilege spine). A binding's target selects WHICH
// objects, under its scope-anchor, the grant applies to:
//
//   - AllInScope — ALL objects under the anchor, including future ones (the
//     broadest grant, reachable ONLY via explicit opt-in — never a default);
//   - Resources  — a closed set of per-object ResourceRef{type,id} (no name;
//     `type` dotted from the closed type-registry, e.g. `compute.instance`).
//
// The two arms are mutually exclusive. The zero value (both empty) is treated as
// the whole-anchor grant for legacy / internal rows that predate F8 (matching the
// historical semantics of a target-less binding); the PUBLIC Create RPC rejects a
// missing target sync (least-priv at the boundary).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"go.uber.org/multierr"
)

// ResourceRef is the closed-table {type,id} per-object pointer (redesign-2026 F8 /
// B1). Unlike a generic Referrer it carries NO name — the iam target is the strict
// {type,id} form. `Type` is the dotted `<module>.<resource>` key.
type ResourceRef struct {
	Type string
	ID   string
}

// AccessTarget is the object-selection of an AccessBinding (F8). Exactly one arm
// is meaningful; the zero value is the whole-anchor grant (AllInScope semantics).
type AccessTarget struct {
	AllInScope bool          // whole-anchor grant (incl. future objects)
	Resources  []ResourceRef // per-object grant (mutually exclusive with AllInScope)
}

// IsEmpty reports whether neither arm is set (no explicit selection). An empty
// target is treated as AllInScope for storage/digest, but the public Create RPC
// rejects it (target REQUIRED).
func (t AccessTarget) IsEmpty() bool {
	return !t.AllInScope && len(t.Resources) == 0
}

// Validate checks the target well-formedness: the two arms are mutually exclusive,
// and every per-object ResourceRef carries a non-empty id and a type drawn from the
// closed dotted type-registry. AllInScope / empty is always well-formed.
func (t AccessTarget) Validate() error {
	if t.AllInScope && len(t.Resources) > 0 {
		return fmt.Errorf("Illegal argument target (allInScope and resources are mutually exclusive)")
	}
	var errs error
	for i, r := range t.Resources {
		if !ValidTargetType(r.Type) {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument target.resources[%d].type %q", i, r.Type))
		}
		if r.ID == "" {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument target.resources[%d].id (empty)", i))
		}
	}
	return errs
}

// Contains reports whether the closed per-object target set lists the object
// (dottedType, id). It is the least-privilege membership test the reconciler applies so
// a role.rules match materializes ONLY an object the target also lists. An
// AllInScope/empty target lists NO explicit object here (its breadth is the whole
// anchor, materialized by the reconciler's all-in-scope path — not this test), so
// Contains returns false for it; callers gate on IsEmpty()/AllInScope before using it.
func (t AccessTarget) Contains(dottedType, id string) bool {
	for _, r := range t.Resources {
		if r.Type == dottedType && r.ID == id {
			return true
		}
	}
	return false
}

// ResourceIDsForTypes returns the ids of the per-object target resources whose dotted
// type is in `types` (order-preserving, de-duplicated). It lets the reconciler resolve a
// per-object target's ARM_ANCHOR candidates by id (MatchByIDs) instead of scanning the
// whole scope (MatchAllInScope) — the least-privilege materialization path (IAM-1-21).
// Empty when no listed resource matches the given types.
func (t AccessTarget) ResourceIDsForTypes(types []string) []string {
	if len(t.Resources) == 0 || len(types) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(types))
	for _, ty := range types {
		want[ty] = struct{}{}
	}
	seen := make(map[string]struct{}, len(t.Resources))
	var out []string
	for _, r := range t.Resources {
		if _, ok := want[r.Type]; !ok {
			continue
		}
		if _, dup := seen[r.ID]; dup {
			continue
		}
		seen[r.ID] = struct{}{}
		out = append(out, r.ID)
	}
	return out
}

// Digest returns a deterministic, set-based canonicalization of the target for the
// active-grant partial UNIQUE. AllInScope / empty → "all"; a resource set → a hash
// of its SORTED "type:id" members (order-independent — the same set in any order
// collides, IAM-1-29).
func (t AccessTarget) Digest() string {
	if t.AllInScope || len(t.Resources) == 0 {
		return "all"
	}
	members := make([]string, 0, len(t.Resources))
	for _, r := range t.Resources {
		members = append(members, r.Type+":"+r.ID)
	}
	sort.Strings(members)
	sum := sha256.Sum256([]byte(strings.Join(members, "\n")))
	return "obj:" + hex.EncodeToString(sum[:])
}

// splitDottedType splits a dotted `<module>.<resource>` type into its parts on the
// first dot. ok=false when the form is not `<nonempty>.<nonempty>`.
func splitDottedType(dotted string) (module, resource string, ok bool) {
	i := strings.IndexByte(dotted, '.')
	if i <= 0 || i >= len(dotted)-1 {
		return "", "", false
	}
	return dotted[:i], dotted[i+1:], true
}

// CoversType reports whether the role's authored rules grant verbs on the dotted
// `<module>.<resource>` type (redesign-2026 F9 gate 3 / IAM-1-24). A rule covers the
// type when its Module matches and its Resources list the resource (or "*"). Empty
// rules cover nothing.
func (rs Rules) CoversType(dottedType string) bool {
	module, resource, ok := splitDottedType(dottedType)
	if !ok {
		return false
	}
	for _, r := range rs {
		if r.Module != module {
			continue
		}
		for _, res := range r.Resources {
			if res == "*" || res == resource {
				return true
			}
		}
	}
	return false
}

// ValidTargetType reports whether a dotted `<module>.<resource>` target type is in
// the closed type-registry. It maps the dotted form to the bare vocabulary
// (`compute.instance` → `compute_instance`) shared with `validResourceTypes`, so the
// target registry stays in sync with the FGA object-type vocabulary by construction.
// The wildcard `*` is NOT a valid per-object target type.
func ValidTargetType(dotted string) bool {
	module, resource, ok := splitDottedType(dotted)
	if !ok {
		return false
	}
	_, known := validResourceTypes[ResourceType(module+"_"+resource)]
	return known
}
