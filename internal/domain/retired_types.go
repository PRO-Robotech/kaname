// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// retired_types.go — the closed set of `<module>.<resource>` types the platform
// has RETIRED: resources iam once knew and no longer does, because another
// service became their owner.
//
// # Why a deny-list here and an allow-list on the labels arm
//
// A rule's three arms have three different consumers, so they do not share one
// vocabulary:
//
//   - ARM_LABELS is read only by the reconciler's label-matching, whose feed is a
//     small closed set owned in this package (labelSelectableTypes). An allow-list
//     is exactly right there, and validateFeedGate has always applied it.
//   - ARM_ANCHOR and ARM_NAMES feed TWO consumers with different and much larger
//     vocabularies: the per-object reconciler (AllMaterializableTypes) and the
//     method gate, via CompileRules into the generated permission catalog.
//
// Those vocabularies were measured, not assumed (revision bdafe2c4): 22
// label-selectable types, 23 materializable, 82 `<module>.<resource>` pairs in the
// catalog's permission strings. Checked against the rules that migrations actually
// seed, EVERY one of those sets refuses at least one rule that works today —
// `iam.projects` is in neither reconciler set, `loadbalancer.operations` is in none
// of the three. An allow-list on ARM_ANCHOR/ARM_NAMES would therefore not be a
// stricter version of the feed-gate; it would reject live seeded system roles.
//
// What IS knowable with certainty is the opposite direction. A retired type can
// never be meant, on any arm, by anybody: no resource of that type exists, no
// mirror row will appear, no permission string resolves. Naming one is
// accepted-and-ignored — the call succeeds, the role stores a grant, and the grant
// can never take effect. So the check that belongs on all three arms is membership
// in this closed set, and it asserts nothing about the open part of the vocabulary.
//
// # The entry lives while its subject does
//
// A name leaves this list only when the platform can no longer produce it at all.
// Re-introducing a resource under a retired name must fail loudly rather than
// silently regain a grant path, so the list is asserted in lockstep against iam's
// other vocabularies (services/iam/internal/check/retired_block_storage_test.go).

import "sort"

// retiredTypes — dotted `<module>.<resource>` types iam no longer knows.
//
// Block storage: kacho-storage owns Volume / Snapshot / Image. compute used to
// serve a second, independent copy of the same three resources; that copy is gone,
// and the authorization types outlived it. Their live counterparts are
// storage.volumes / storage.snapshots / storage.images.
var retiredTypes = map[string]struct{}{
	"compute.disk":     {},
	"compute.image":    {},
	"compute.snapshot": {},
}

// IsRetiredType reports whether a dotted `<module>.<resource>` names a resource the
// platform has retired. A retired type is not grantable on any rule arm.
func IsRetiredType(objectType string) bool {
	_, ok := retiredTypes[objectType]
	return ok
}

// RetiredTypes returns the closed, sorted set of retired dotted types. Exported so
// the gates that keep the retirement complete can be driven from ONE list rather
// than from a copy of it.
func RetiredTypes() []string {
	out := make([]string, 0, len(retiredTypes))
	for ty := range retiredTypes {
		out = append(out, ty)
	}
	sort.Strings(out)
	return out
}
