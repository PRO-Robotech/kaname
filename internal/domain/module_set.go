// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// module_set.go — RBAC rules-model 2026 platform module-set ownership.
//
// The domain OWNS the closed platform module-set. A Rule.module must be a member
// of this set (besides being grammar-valid and non-empty); Rule.Validate consults
// IsKnownModule to reject an unknown module on the request-path (INVALID_ARGUMENT)
// — WITHOUT the domain importing authzmap (clean-arch: pure Go,
// stdlib only).
//
// The set MUST stay in lockstep with the module-prefixes of authzmap.objectTypes
// (the FGA object-type catalog) — authzmap CONSUMES this set (or is held lockstep
// via the authzmap↔domain drift-test). geo is intentionally absent (Geography is
// its own service, not in objectTypes); the load-balancer module token is
// `loadbalancer` (NOT `nlb`).

// knownModules — the closed set of platform modules a rule may grant over. Order
// is the canonical platform order (iam first, then resource domains).
var knownModules = []string{"iam", "vpc", "compute", "loadbalancer", "registry"}

// knownModuleSet — membership index built once from knownModules.
var knownModuleSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(knownModules))
	for _, k := range knownModules {
		m[k] = struct{}{}
	}
	return m
}()

// IsKnownModule reports whether m is a member of the closed platform module-set
// {iam, vpc, compute, loadbalancer, registry}. The wildcard `*` is NOT a known module (it
// is a system-only marker handled separately by Rule.Validate).
func IsKnownModule(m string) bool {
	_, ok := knownModuleSet[m]
	return ok
}

// KnownModules returns a copy of the closed platform module-set in canonical
// order. Used by the authzmap↔domain drift-test to assert lockstep.
func KnownModules() []string {
	return append([]string(nil), knownModules...)
}
