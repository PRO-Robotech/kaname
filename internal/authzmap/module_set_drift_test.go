// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzmap_test

// module_set_drift_test.go — domain/authzmap module-set lockstep drift guard.
//
// The closed platform module-set is OWNED by the domain (domain.IsKnownModule);
// authzmap CONSUMES it. The single review/drift source of truth for the set is
// the module-prefixes of the authzmap.objectTypes keyset (exposed via Catalog()).
// This drift-test asserts the two stay in LOCKSTEP — exactly the same discipline
// as fga_model_drift_test.go for the FGA model. If a new module is added to
// objectTypes without adding it to domain.IsKnownModule (or vice versa), this
// test FAILS, surfacing the divergence before it can let an unknown module slip
// past Rule.Validate or a known module silently lose its FGA object types.

import (
	"sort"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestModuleSetDrift_AuthzmapVsDomain(t *testing.T) {
	// Derive the module-prefix set from the authzmap object-type catalog.
	prefixSet := map[string]struct{}{}
	for _, e := range authzmap.Catalog() {
		prefixSet[e.Module] = struct{}{}
	}
	prefixes := make([]string, 0, len(prefixSet))
	for m := range prefixSet {
		prefixes = append(prefixes, m)
	}
	sort.Strings(prefixes)

	// (1) Every authzmap module-prefix MUST be a domain-known module.
	for _, m := range prefixes {
		if !domain.IsKnownModule(m) {
			t.Errorf("authzmap objectTypes carries module %q but domain.IsKnownModule(%q)=false (drift)", m, m)
		}
	}

	// (2) Every domain-known module MUST appear as an authzmap module-prefix
	// (the domain set must not grow beyond what authzmap can FGA-map).
	for _, m := range domain.KnownModules() {
		if _, ok := prefixSet[m]; !ok {
			t.Errorf("domain.IsKnownModule includes %q but authzmap objectTypes has no %q.* type (drift)", m, m)
		}
	}

	// (3) Pin the exact set for a human-readable failure if either side changes.
	want := []string{"compute", "iam", "loadbalancer", "registry", "vpc"}
	if len(prefixes) != len(want) {
		t.Fatalf("authzmap module-prefix set = %v, want %v", prefixes, want)
	}
	for i := range want {
		if prefixes[i] != want[i] {
			t.Fatalf("authzmap module-prefix set = %v, want %v", prefixes, want)
		}
	}
}
