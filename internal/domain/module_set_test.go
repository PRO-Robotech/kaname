// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain_test

// module_set_test.go — the domain OWNS the closed module-set: IsKnownModule is
// the single source of truth a Rule.Validate consults to reject an unknown
// module on the request-path.

import (
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// TestIsKnownModule_ClosedSet — the closed platform module-set is EXACTLY
// {iam, vpc, compute, loadbalancer, registry}. geo is NOT a module (Geography
// moved to its own service, not in authzmap.objectTypes). `nlb` is NOT the token —
// the load-balancer module is named `loadbalancer`. The wildcard `*` is NOT a
// "known module" (it is a system-only marker handled separately by Rule.Validate,
// not by IsKnownModule).
func TestIsKnownModule_ClosedSet(t *testing.T) {
	known := []string{"iam", "vpc", "compute", "loadbalancer", "registry"}
	for _, m := range known {
		if !domain.IsKnownModule(m) {
			t.Errorf("IsKnownModule(%q) = false, want true (member of closed set)", m)
		}
	}
	unknown := []string{"banana", "geo", "nlb", "loadbalancers", "iAm", "", "*", "vpc "}
	for _, m := range unknown {
		if domain.IsKnownModule(m) {
			t.Errorf("IsKnownModule(%q) = true, want false (NOT in closed set)", m)
		}
	}
}
