// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// selector_feed.go — T3 feed-source classification (D6/D7). Where the
// reconciler reads candidate objects for a selectable type, and which
// containment rule applies. Pure domain (no authzmap/pgx/grpc): the classifier
// is keyed on the dotted object-type prefix, and the reconciler uses it to pick
// the candidate source + containment predicate per type without importing the
// use-case registry (keeps the dependency graph acyclic).
//
// The closed label-selectable whitelist itself (which exact types are
// selectable) lives in feed_registry.go (labelSelectableTypes / the
// IsLabelSelectableType feed-gate). This classifier only answers "given a type
// that IS selectable, what feeds it?".

import "strings"

// FeedSource — where the reconciler reads candidate objects for a selectable
// type (D7).
type FeedSource int8

const (
	// FeedMirror — candidates read from kacho_iam.resource_mirror (labels @>
	// matchLabels); containment from mirror.parent_* (D7). Mirror-fed types can be
	// PENDING_VERIFICATION (object not yet mirrored). Consumer-owned resources:
	// compute / vpc / loadbalancer.
	FeedMirror FeedSource = iota
	// FeedIAMDirect — candidates read SAME-DB from IAM's own resource table;
	// containment via iam-hierarchy (project ⊑ account ⊑ cluster). Never PENDING
	// (the object is always in its own table the instant it exists). Покрывает ВСЕ
	// iam-native типы (любой `iam.*`): account / project / user / serviceAccount /
	// group / role / accessBinding — все label-selectable под единой моделью.
	FeedIAMDirect
)

// FeedSourceForType classifies a selectable object type by its feed-source
// (D6/D7). An `iam.*` type is IAM-direct (own-table same-DB match, iam-hierarchy
// containment); every other selectable family (compute/vpc/loadbalancer) is
// mirror-fed. The classification is by module-prefix only — the precise selectable
// whitelist is enforced separately in the use-case (a non-selectable type never
// reaches the reconciler).
func FeedSourceForType(objectType string) FeedSource {
	if strings.HasPrefix(objectType, "iam.") {
		return FeedIAMDirect
	}
	return FeedMirror
}
