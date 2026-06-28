// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// role_cluster_admin.go — RBAC explicit-model 2026 P5 (A-05 / A-05c / D-9 / D-11a).
//
// Two pure predicates that decide GLOBAL (=cluster scope) + selector-all legality
// at AccessBinding.Create:
//
//   - Rules.HasAnchorRule()    — does the role carry a selector=all (ARM_ANCHOR)
//     rule? GLOBAL + ARM_ANCHOR on a NON cluster-admin role is the rejected case
//     (A-05): per-object materialization cluster-wide for an ordinary role is an
//     anti-pattern (unbounded ledger + churn). GLOBAL + names/labels is legal
//     (A-05b: a finite explicit cluster-wide set).
//   - Role.IsClusterAdminRole() — is the role THE system cluster-admin superuser,
//     identified by its PINNED id (ClusterAdminRoleID `admin` / SystemAdminRoleID
//     `kacho-system.admin`) + is_system + the `*.*.*` shape (defence-in-depth)? It
//     is the SINGLE role for which GLOBAL + all is legal (A-05c / D-11a) — served by
//     the D-9 flat cluster-relation short-circuit, never by per-object
//     materialization. NOTE: the `owner` role carries the SAME `*.*.*` shape but is
//     NOT cluster-admin (matched out by id — #8).

// HasAnchorRule reports whether any rule in the set uses the ARM_ANCHOR selector
// (selector=all: neither resource_names nor match_labels). An ARM_ANCHOR rule
// materializes over ALL instances under scope — on a GLOBAL (cluster) scope that
// is the cluster-wide per-object set Q-2/A-05 forbids for ordinary roles.
func (rs Rules) HasAnchorRule() bool {
	for _, r := range rs {
		if r.Arm() == ArmAnchor {
			return true
		}
	}
	return false
}

// IsClusterAdminRole reports whether r is THE system cluster-admin superuser role.
//
// It is identified by its PINNED deterministic id (ClusterAdminRoleID `admin` or
// SystemAdminRoleID `kacho-system.admin`) AND is_system AND (defence-in-depth) that
// it still carries the full `*.*.*` ARM_ANCHOR rule (module:*, `*` resource, `*`
// verb). Matching by id — NOT by the bare `*.*.*` shape — is load-bearing for #8:
// the `owner` system role (OwnerRoleID, migration 0035) carries the SAME `*.*.*`
// shape, so a shape-only predicate would misclassify owner as cluster-admin and let
// an owner@GLOBAL+all binding slip past the A-05 reject. owner is auto-bound at
// ACCOUNT scope only and is NOT the GLOBAL+all exception.
//
// This is the ONLY role for which a GLOBAL+all binding is legal (A-05c) — its
// binding is materialized as the D-9 cluster-relation, not per-object.
func (r Role) IsClusterAdminRole() bool {
	if !r.IsSystem {
		return false
	}
	if string(r.ID) != ClusterAdminRoleID && string(r.ID) != SystemAdminRoleID {
		return false
	}
	// Defence-in-depth shape belt: a tampered/degraded seed (id matches but the rule
	// is no longer the full superuser) must NOT silently confer the GLOBAL+all
	// exception.
	for _, rule := range r.Rules {
		if rule.Module == wildcard &&
			containsWildcard(rule.Resources) &&
			containsWildcard(rule.Verbs) {
			return true
		}
	}
	return false
}

// containsWildcard reports whether the list contains the `*` element.
func containsWildcard(list []string) bool {
	for _, e := range list {
		if e == wildcard {
			return true
		}
	}
	return false
}
