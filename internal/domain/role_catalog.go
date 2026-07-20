// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// role_catalog.go — redesign-2026 F6 canonical system-role catalog metadata.
//
// The published catalog leads with the canonical four — viewer → editor → admin →
// owner — each carrying a friendly displayName + a one-line purpose. Pre-Phase-0
// these map to the extant cluster-scoped system roles by name (view/edit/admin/
// owner); the hyphen-id form (rol-viewer/…) is B3-gated. displayName/purpose are
// DERIVED on read (no stored columns pre-Phase-0). A non-canonical role's
// displayName defaults to its name and its purpose is empty.

type catalogMeta struct {
	displayName string
	purpose     string
	rank        int // canonical ordering: viewer<editor<admin<owner
}

// canonicalCatalog keys the canonical four by their extant (pre-Phase-0) role
// name. viewer/editor land on the read-only / edit tiers (extant names view/edit).
var canonicalCatalog = map[string]catalogMeta{
	"view":  {displayName: "Viewer", purpose: "Read-only access to resources in scope.", rank: 0},
	"edit":  {displayName: "Editor", purpose: "Create and update access — plus delete of the in-scope leaf objects it edits, never the account/project anchor.", rank: 1},
	"admin": {displayName: "Admin", purpose: "Full control of resources in scope.", rank: 2},
	"owner": {displayName: "Owner", purpose: "Full control plus access-binding management of the scope.", rank: 3},
}

// nonCanonicalRank sorts every non-canonical role after the canonical four.
const nonCanonicalRank = 1 << 30

// DisplayName is the friendly catalog label. For a canonical system role it is the
// curated name (Viewer/Editor/Admin/Owner); otherwise it defaults to the role name.
func (r Role) DisplayName() string {
	if r.IsSystemDerived() {
		if m, ok := canonicalCatalog[string(r.Name)]; ok {
			return m.displayName
		}
	}
	return string(r.Name)
}

// Purpose is the one-line description of a canonical system role; empty otherwise.
func (r Role) Purpose() string {
	if r.IsSystemDerived() {
		if m, ok := canonicalCatalog[string(r.Name)]; ok {
			return m.purpose
		}
	}
	return ""
}

// CanonicalRank returns the ordering rank of a canonical system role (0=viewer …
// 3=owner) so the catalog can present the four first among system roles; a
// non-canonical role sorts after them.
func (r Role) CanonicalRank() int {
	if r.IsSystemDerived() {
		if m, ok := canonicalCatalog[string(r.Name)]; ok {
			return m.rank
		}
	}
	return nonCanonicalRank
}
