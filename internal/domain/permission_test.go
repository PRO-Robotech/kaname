// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// permission_test.go — unit tests for the RBAC v2 4-segment permission
// grammar `module.resource.resourceName.verb` (migration 0005).
//
// permissionElementRe MUST stay in lockstep with the DB validator
// `kacho_iam.iam_permissions_valid()` (internal/migrations/0005_rbac_v2_
// grammar_and_scope.sql). The regex there is:
//
//	^(\*|[a-z][a-z0-9-]*)\.(\*|[a-z][a-zA-Z0-9_-]*)\.(\*|[a-zA-Z0-9_-]+)\.(\*|[a-z][a-zA-Z0-9_-]*)$
//
// These cases pin both the positive 4-segment shapes (incl. wildcards) and
// the negative ones — notably the legacy 3-segment form, which RBAC v2
// rejects.
package domain_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestPermission_Validate(t *testing.T) {
	cases := []struct {
		name string
		in   domain.Permission
		ok   bool
	}{
		// --- valid 4-segment ---
		{"plain 4-seg", "iam.user.*.read", true},
		{"all wildcards", "*.*.*.*", true},
		{"wildcard module", "*.user.*.read", true},
		{"wildcard verb", "iam.user.*.*", true},
		{"camelCase resource", "compute.diskType.*.list", true},
		{"named resource segment", "vpc.subnet.subnet-1.delete", true},
		{"underscore in resourceName", "vpc.subnet.my_subnet.update", true},
		{"dash in module", "load-balancer.nlb.*.create", true},

		// --- invalid ---
		{"legacy 3-seg rejected", "iam.user.read", false},
		{"legacy 3-seg wildcard rejected", "iam.users.*", false},
		{"two segments", "iam.user", false},
		{"five segments", "iam.user.x.read.extra", false},
		{"empty", "", false},
		{"trailing dot", "iam.user.*.read.", false},
		{"module starts with digit", "1iam.user.*.read", false},
		{"verb starts with uppercase", "iam.user.*.Read", false},
		{"verb starts with digit", "iam.user.*.1read", false},
		{"resource starts with uppercase", "iam.User.*.read", false},
		{"empty resourceName segment", "iam.user..read", false},
		{"space inside", "iam.user.*.re ad", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.in.Validate()
			if c.ok && err != nil {
				t.Fatalf("Permission(%q).Validate() = %v, want nil", c.in, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("Permission(%q).Validate() = nil, want error", c.in)
			}
		})
	}
}

func TestPermissions_Validate_Cardinality(t *testing.T) {
	if err := (domain.Permissions{}).Validate(); err == nil {
		t.Fatal("empty Permissions must be rejected (cardinality >=1)")
	}
	if err := (domain.Permissions{"iam.user.*.read"}).Validate(); err != nil {
		t.Fatalf("single valid 4-seg permission rejected: %v", err)
	}
	if err := (domain.Permissions{"iam.user.*.read", "iam.user.read"}).Validate(); err == nil {
		t.Fatal("set containing a legacy 3-seg permission must be rejected")
	}
}

// cap-raise 256→1024 lockstep — domain.Permissions accepts up to
// 1024 valid 4-seg entries and rejects 1025 (parity with the DB CHECK
// iam_permissions_valid and the proto (size) bound).
func TestPermissions_Validate_CapRaise1024(t *testing.T) {
	mk := func(n int) domain.Permissions {
		out := make(domain.Permissions, n)
		for i := range out {
			out[i] = domain.Permission("iam.user." + "id" + itoaPad(i) + ".read")
		}
		return out
	}
	if err := mk(1024).Validate(); err != nil {
		t.Fatalf("1024 permissions rejected (cap-raise not applied): %v", err)
	}
	if err := mk(1025).Validate(); err == nil {
		t.Fatal("1025 permissions must be rejected (cap is 1024)")
	}
}

func itoaPad(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{digits[i%10]}, b...)
		i /= 10
	}
	return string(b)
}
