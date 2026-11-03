// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
)

func TestInstallationDelegationClosedShape(t *testing.T) {
	base, err := os.ReadFile("testdata/registry.delegation-fixture.yaml")
	if err != nil {
		t.Fatal(err)
	}
	declaration := `
seed:
  serviceAccounts:
    - {name: svc-registry, account: system, description: Registry delegated issuer}
  grantDelegations:
    - delegate: {account: system, name: svc-registry}
      roleIds: [registry.puller]
      targetTypes: [registry.registries]
      subjectTypes: [SUBJECT_TYPE_USER]
`
	good := string(base) + declaration
	for _, tc := range []struct {
		name, old, replacement string
		valid                  bool
	}{
		{name: "valid", valid: true},
		{name: "foreign role", old: "roleIds: [registry.puller]", replacement: "roleIds: [iam.admin]"},
		{name: "unseeded delegate", old: "delegate: {account: system, name: svc-registry}", replacement: "delegate: {account: system, name: absent}"},
		{name: "foreign account", old: "delegate: {account: system, name: svc-registry}", replacement: "delegate: {account: tenant, name: svc-registry}"},
		{name: "foreign type", old: "targetTypes: [registry.registries]", replacement: "targetTypes: [iam.accounts]"},
		{name: "unknown enum", old: "subjectTypes: [SUBJECT_TYPE_USER]", replacement: "subjectTypes: [SUBJECT_TYPE_UNSPECIFIED]"},
		{name: "duplicate roles", old: "roleIds: [registry.puller]", replacement: "roleIds: [registry.puller, registry.puller]"},
		{name: "duplicate targets", old: "targetTypes: [registry.registries]", replacement: "targetTypes: [registry.registries, registry.registries]"},
		{name: "duplicate subjects", old: "subjectTypes: [SUBJECT_TYPE_USER]", replacement: "subjectTypes: [SUBJECT_TYPE_USER, SUBJECT_TYPE_USER]"},
		{name: "empty axis", old: "roleIds: [registry.puller]", replacement: "roleIds: []"},
		{name: "unknown field", old: "roleIds: [registry.puller]", replacement: "accountId: fake\n      roleIds: [registry.puller]"},
		{name: "system class", old: "subjectTypes: [SUBJECT_TYPE_USER]", replacement: "subjectTypes: [SUBJECT_TYPE_SYSTEM_CLASS]", valid: true},
		{name: "absent", old: "  grantDelegations:\n    - delegate: {account: system, name: svc-registry}\n      roleIds: [registry.puller]\n      targetTypes: [registry.registries]\n      subjectTypes: [SUBJECT_TYPE_USER]\n", replacement: "", valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := good
			if tc.old != "" {
				if strings.Count(input, tc.old) != 1 {
					t.Fatal("invalid injection")
				}
				input = strings.Replace(input, tc.old, tc.replacement, 1)
			}
			_, err := manifest.Load([]byte(input))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}
