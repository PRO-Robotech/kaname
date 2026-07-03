// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// feed_registry.go — the closed code-registry of CONFIRMED-fed object types
// eligible for match_labels (ARM_LABELS) selection. Pure domain (stdlib only) so
// the rules compiler / Rule.Validate feed-gate stays self-contained and acyclic.
//
// A match_labels rule is allowed ONLY on a `<module>.<resource>` here:
//   - mirror-fed: what vpc/compute/loadbalancer emit into resource_mirror;
//   - iam-direct: ALL iam-native resource types (project/account + the content
//     types user/serviceAccount/group/role/accessBinding) — they carry a `labels`
//     column on their own table and an iam-hierarchy containment.
//
// Unified visibility model: EVERY iam-native type is label-selectable on par with
// account/project (owner direction — single model for all iam types). This
// supersedes the earlier split where iam content types were materializable ONLY by
// ARM_ANCHOR/ARM_NAMES; they are now ALSO ARM_LABELS-selectable (their own-table
// labels @> matchLabels is matched same-DB by the reconciler — no self-mirror,
// the graph stays acyclic).
//
// This is the source of truth for label-selectability. ARM_NAMES
// (resource_names) is NOT feed-gated — any type may be pinned by id.

import "sort"

var labelSelectableTypes = map[string]struct{}{
	// compute — mirror-fed via compute→iam RegisterResource.
	"compute.instance": {},
	"compute.disk":     {},
	"compute.image":    {},
	"compute.snapshot": {},

	// vpc — mirror-fed via vpc→iam RegisterResource extended payload.
	"vpc.network":          {},
	"vpc.subnet":           {},
	"vpc.securityGroup":    {},
	"vpc.routeTable":       {},
	"vpc.address":          {},
	"vpc.gateway":          {},
	"vpc.networkInterface": {},

	// loadbalancer (kacho-nlb) — mirror-fed via nlb→iam RegisterResource.
	"loadbalancer.networkLoadBalancers": {},
	"loadbalancer.targetGroups":         {},
	"loadbalancer.listeners":            {},

	// registry (kacho-registry) — the namespace `registries` carries own-table
	// labels driving authz label-scope (mirror-fed via registry→iam
	// RegisterResource). Per-repo `repositories` is name-selectable only (repos
	// appear via docker push, without labels) → intentionally ABSENT here.
	"registry.registries": {},

	// iam-direct — labels live on the native table + an iam-hierarchy
	// containment. Unified model: ALL iam-native types are label-selectable,
	// matched SAME-DB from their own table (no self-mirror, acyclic).
	"iam.project":        {},
	"iam.account":        {},
	"iam.user":           {},
	"iam.serviceAccount": {},
	"iam.group":          {},
	"iam.role":           {},
	"iam.accessBinding":  {},
}

// IsLabelSelectableType reports whether a `<module>.<resource>` type may carry a
// match_labels (ARM_LABELS) selector (feed-gate). Unified model: every iam-native
// type is label-selectable (project/account + the content types
// user/serviceAccount/group/role/accessBinding).
func IsLabelSelectableType(objectType string) bool {
	_, ok := labelSelectableTypes[objectType]
	return ok
}

// AllMaterializableTypes returns the closed, sorted, deduped set of
// `<module>.<resource>` types the reconciler can materialize per-object. It is the
// wildcard-expansion set for a BOUNDED-scope `*.*` rule (issue #224 / D-8a): an owner
// role bound at ACCOUNT/PROJECT becomes an explicit per-object admin on EVERY object
// kind inside the scope, instead of relying on the FGA derivation cascade.
//
// Under the unified visibility model this equals labelSelectableTypes — every
// materializable type (mirror-fed vpc/compute/loadbalancer + EVERY iam-native type)
// is also ARM_LABELS-selectable. The iam content types (user/serviceAccount/group/
// role/accessBinding) remain materializable by ARM_ANCHOR/ARM_NAMES (replacing the
// flat model's missing `from account` cascade with per-object materialization) AND
// are now additionally label-selectable.
//
// Sorted so the resulting selector + role_rule_selectors index are deterministic
// (stable fast-path JOIN + migration-seed lockstep, rule_wildcard_scope_test.go).
func AllMaterializableTypes() []string {
	out := make([]string, 0, len(labelSelectableTypes))
	for ty := range labelSelectableTypes {
		out = append(out, ty)
	}
	sort.Strings(out)
	return out
}
