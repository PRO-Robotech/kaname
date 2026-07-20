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

// ValidTargetType reports whether a dotted `<module>.<resource>` target type is in
// the closed type-registry. It maps the dotted form to the bare vocabulary
// (`compute.instance` → `compute_instance`) shared with `validResourceTypes`, so the
// target registry stays in sync with the FGA object-type vocabulary by construction.
// The wildcard `*` is NOT a valid per-object target type.
func ValidTargetType(dotted string) bool {
	i := strings.IndexByte(dotted, '.')
	if i <= 0 || i >= len(dotted)-1 {
		return false
	}
	bare := dotted[:i] + "_" + dotted[i+1:]
	if bare == "*" {
		return false
	}
	_, ok := validResourceTypes[ResourceType(bare)]
	return ok
}
