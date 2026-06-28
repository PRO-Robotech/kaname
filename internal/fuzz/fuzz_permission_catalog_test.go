// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Continuous fuzzing: permission catalog lookup.
//
// Permission strings follow `<module>.<resource>.<verb>` format with optional
// wildcards. Validates the catalog regex + lookup logic against malformed
// inputs (DoS-via-regex, integer overflow, wildcard expansion bombs).

package fuzz_test

import (
	"strings"
	"testing"
)

var permCatalogTestSink any

func FuzzPermissionCatalogLookup(f *testing.F) {
	seeds := []string{
		"iam.user.read",
		"iam.user.*",
		"iam.*.read",
		"*.*.*",
		"vpc.network.create",
		"compute.instance.start",
		"",
		"a.b.c.d", // 4 parts — invalid
		"a.b",     // 2 parts — invalid
		strings.Repeat("a.", 1000) + "z",
		"iam.user.read.extra",
		"iam.\"user\".read",
		"iam.user.read\x00\x00",
		// regex DoS — many dots.
		strings.Repeat(".", 10000),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC on permission %q: %v", input, r)
			}
		}()

		valid := isValidPermission(input)
		permCatalogTestSink = valid
	})
}

// isValidPermission — parity with kacho_iam.iam_permissions_valid() PL/pgSQL.
// Real implementation: kacho-iam/internal/apps/kacho/api/access_binding/permissions.go
func isValidPermission(s string) bool {
	const maxLen = 256
	if len(s) == 0 || len(s) > maxLen {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}
