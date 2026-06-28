// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// access_binding_scope.go — typed Scope enum for the RBAC v2 AccessBinding
// shape. The Scope tier anchors the binding in the
// cluster ▶ account ▶ project hierarchy; per-resourceName grants emit
// direct FGA tuples that respect Scope only as a sanity guard.
package domain

import (
	"errors"
	"strings"
)

// Scope — anchor tier for an AccessBinding.
type Scope int8

const (
	ScopeUnspecified Scope = 0
	ScopeCluster     Scope = 1
	ScopeAccount     Scope = 2
	ScopeProject     Scope = 3
)

// ErrScopeMismatch — Scope does not match (resource_type, resource_id).
// Service-layer maps to gRPC InvalidArgument.
var ErrScopeMismatch = errors.New("scope does not match resource_type / resource_id")

// String — debug-friendly rendering (matches proto enum names).
func (s Scope) String() string {
	switch s {
	case ScopeCluster:
		return "CLUSTER"
	case ScopeAccount:
		return "ACCOUNT"
	case ScopeProject:
		return "PROJECT"
	default:
		return "SCOPE_UNSPECIFIED"
	}
}

// ValidateAgainst checks that the Scope is consistent with the binding's
// (resource_type, resource_id). Returns ErrScopeMismatch if not.
//
// CLUSTER ⇒ resource_type='cluster', resource_id='cluster_kacho_root'
// ACCOUNT ⇒ resource_type='account', resource_id starts with 'acc'
// PROJECT ⇒ resource_type='project', resource_id starts with 'prj'
func (s Scope) ValidateAgainst(resourceType, resourceID string) error {
	switch s {
	case ScopeCluster:
		if resourceType != "cluster" || resourceID != ClusterSingletonID {
			return ErrScopeMismatch
		}
	case ScopeAccount:
		if resourceType != "account" || !strings.HasPrefix(resourceID, PrefixAccount) {
			return ErrScopeMismatch
		}
	case ScopeProject:
		if resourceType != "project" || !strings.HasPrefix(resourceID, PrefixProject) {
			return ErrScopeMismatch
		}
	default:
		return ErrScopeMismatch
	}
	return nil
}

// DeriveFromResourceType — best-effort fallback for code paths that have
// resource_type but no explicit Scope (e.g. legacy callers that pre-date
// the W4 scope plumbing). Mirrors the DB-side BEFORE INSERT trigger in
// migration 0005.
func DeriveFromResourceType(resourceType string) Scope {
	switch resourceType {
	case "cluster":
		return ScopeCluster
	case "account", "cloud":
		return ScopeAccount
	case "project", "folder":
		return ScopeProject
	default:
		return ScopeProject
	}
}
