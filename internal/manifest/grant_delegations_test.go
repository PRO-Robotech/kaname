// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

func TestInstallationUnknownFieldCoordinates(t *testing.T) {
	base, err := os.ReadFile("testdata/registry.delegation-fixture.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ body, path string }{
		{"    - delegate: {account: system, name: svc, mystery: secret-value}\n", "seed.grantDelegations[0].delegate.mystery"},
		{"    - delegate: {account: system, name: svc}\n      mystery: secret-value\n", "seed.grantDelegations[0].mystery"},
	} {
		_, err := manifest.Load(append(append([]byte(nil), base...), []byte("\nseed:\n  grantDelegations:\n"+tc.body)...))
		var field interface{ FieldPath() string }
		if !errors.As(err, &field) || field.FieldPath() != tc.path {
			t.Fatalf("coordinate: %v", err)
		}
		if strings.Contains(err.Error(), "secret-value") {
			t.Fatal("input value exposed")
		}
	}
}

// Каждое изменение меняет один узел второго объявления; допустимый близнец
// доказывает, что отказ относится к форме, а не связям или фикстуре.
func TestInstallationDelegationNodeShapeCoordinates(t *testing.T) {
	base, err := os.ReadFile("testdata/registry.delegation-fixture.yaml")
	if err != nil {
		t.Fatal(err)
	}
	const entry = `    - delegate: {account: system, name: svc-registry}
      roleIds: [registry.puller]
      targetTypes: [registry.registries]
      subjectTypes: [SUBJECT_TYPE_USER]
`
	good := string(base) + "\nseed:\n  serviceAccounts:\n    - {name: svc-registry, account: system, description: Registry delegated issuer}\n  grantDelegations:\n" + entry + entry
	// Разрешение псевдонимов должно сохранять формы YAML, уже принятые декодером.
	for _, tc := range []struct{ name, old, anchor, alias string }{
		{"entry", entry, strings.Replace(entry, "- delegate:", "- &entry\n      delegate:", 1), "    - *entry\n"},
		{"delegate", "{account: system, name: svc-registry}", "&delegate {account: system, name: svc-registry}", "*delegate"},
		{"axis", "[registry.puller]", "&roles [registry.puller]", "*roles"},
		{"scalar", "account: system", "account: &account system", "account: *account"},
	} {
		t.Run("valid alias/"+tc.name, func(t *testing.T) {
			input := string(base) + "\nseed:\n  serviceAccounts:\n    - {name: svc-registry, account: system, description: Registry delegated issuer}\n  grantDelegations:\n" +
				strings.Replace(entry, tc.old, tc.anchor, 1) + strings.Replace(entry, tc.old, tc.alias, 1)
			if m, err := manifest.Load([]byte(input)); err != nil || m == nil {
				t.Fatalf("valid alias: %v", err)
			}
		})
	}
	type mutation struct{ name, old, replacement, field string }
	cases := []mutation{}
	for _, bad := range []string{"secret-value", "[secret-value]", "null"} {
		cases = append(cases, mutation{"entry/" + bad, entry, "    - " + bad + "\n", ""})
		cases = append(cases, mutation{"delegate/" + bad, "{account: system, name: svc-registry}", bad, ".delegate"})
	}
	for _, axis := range []struct{ name, value string }{
		{"roleIds", "registry.puller"}, {"targetTypes", "registry.registries"}, {"subjectTypes", "SUBJECT_TYPE_USER"},
	} {
		for _, bad := range []string{"secret-value", "{secret-value: secret-value}", "null"} {
			cases = append(cases, mutation{axis.name + "/" + bad, axis.name + ": [" + axis.value + "]", axis.name + ": " + bad, "." + axis.name})
		}
		for _, bad := range []string{"{secret-value: secret-value}", "[secret-value]"} {
			cases = append(cases, mutation{axis.name + "/item/" + bad, axis.name + ": [" + axis.value + "]", axis.name + ": [" + bad + "]", "." + axis.name + "[0]"})
		}
	}
	for _, field := range []string{"account", "name"} {
		value := "system"
		if field == "name" {
			value = "svc-registry"
		}
		for _, bad := range []string{"{secret-value: secret-value}", "[secret-value]"} {
			cases = append(cases, mutation{"delegate/" + field + "/" + bad, field + ": " + value, field + ": " + bad, ".delegate." + field})
		}
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("%02d/%s", i, tc.name), func(t *testing.T) {
			m, err := manifest.Load([]byte(good))
			if err != nil || m == nil {
				t.Fatalf("valid twin: %v", err)
			}
			// Заменяем лишь второе объявление, чтобы константа [0] не могла пройти.
			first := strings.LastIndex(good, entry)
			bad := good[:first] + strings.Replace(good[first:], tc.old, tc.replacement, 1)
			m, err = manifest.Load([]byte(bad))
			if m != nil || !errors.Is(err, manifest.ErrShape) {
				t.Fatalf("rejected input escaped preflight: %v", err)
			}
			want := "seed.grantDelegations[1]" + tc.field
			var field interface{ FieldPath() string }
			if !errors.As(err, &field) || field.FieldPath() != want {
				t.Fatalf("want %s, got %v", want, err)
			}
			if strings.Contains(err.Error(), "secret-value") {
				t.Fatalf("value exposed: %v", err)
			}
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "manifest.yaml"), []byte(bad), 0600); err != nil {
				t.Fatal(err)
			}
			report := manifest.CheckSyntheticTree(root)
			if report.ExitCode() != manifest.CheckFailed || len(report.Manifests) != 0 || len(report.InputViolations) != 1 || report.InputViolations[0] != "manifests[0]."+want {
				t.Fatalf("whole delivery preflight: %+v", report)
			}
			if strings.Contains(report.Summary(), "secret-value") || strings.Contains(strings.Join(report.Findings, " "), "secret-value") {
				t.Fatal("preflight exposed input value")
			}
		})
	}
}
