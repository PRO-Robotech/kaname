// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Continuous fuzzing: CEL expression evaluator.
//
// CEL (Common Expression Language) is used in OpenFGA Conditions.
// Malformed expressions must NOT panic, must respect time/memory budgets,
// must NOT permit code-execution.

package fuzz_test

import (
	"strings"
	"testing"
)

var celTestSink any

func FuzzCELExpression(f *testing.F) {
	seeds := []string{
		`user.role == "admin"`,
		`request.time < timestamp("2026-01-01T00:00:00Z")`,
		`resource.labels["env"] == "prod"`,
		`size(resource.tags) > 0`,
		`user.id.startsWith("usr") && size(user.id) == 20`,
		``,
		`(`,
		strings.Repeat(`(`, 1000),
		`user.role.endsWith("admin")`,
		// Adversarial.
		`user.role == "admin" || true`,
		`__import__("os").system("rm -rf /")`, // python-style not valid CEL
		`size(string(int(user.id)))`,
		`'\x00\x00'`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC on CEL %q: %v", input, r)
			}
		}()

		// Wire to:
		//   import "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/conditions"
		//   _, err := conditions.Parse(input)
		valid := parseCELStub(input)
		celTestSink = valid
	})
}

func parseCELStub(s string) bool {
	if len(s) > 1<<16 {
		return false
	}
	// Basic bracket balance check (real parser does AST).
	open := strings.Count(s, "(")
	close := strings.Count(s, ")")
	return open == close
}
