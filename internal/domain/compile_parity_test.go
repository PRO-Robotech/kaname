// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain_test

// compile_parity_test.go — compile-parity for the role rules model.
//
// The old Rule.Modules []string codepath is REMOVED post-migration, so
// compile-parity is verified NOT against a live prior codepath (gone) but against
// a GOLDEN SNAPSHOT — the compiled-permission set each representative live-role
// shape produced BEFORE the scalar change, captured as testdata and asserted
// byte-for-byte against the scalar CompileRules output. On live data N=1 (one
// module per rule) so the scalar form is a behavioural equivalent of the prior
// single-element-modules form.
//
// The golden file (testdata/compile_parity_golden.json) maps a role label → its
// expected compiled-permission list (order-preserving). The fixtures mirror the
// live system-role rule shapes re-seeded by migration 0031 (admin/edit/view
// superuser `*.*.*`, plus concrete single-module ANCHOR / NAMES rules).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestCompileParity_ScalarVsGoldenSnapshot(t *testing.T) {
	// Each fixture is a role's scalar rules + the golden compiled set captured
	// pre-migration. The map key is the role label used in the golden JSON.
	fixtures := map[string][]domain.Rule{
		// system admin re-seed form (0031): `*.*.*` (system-context superuser).
		"system_admin": {
			{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}},
		},
		// system view re-seed form (0031): `*.*.{read,list,get}`.
		"system_view": {
			{Module: "*", Resources: []string{"*"}, Verbs: []string{"read", "list", "get"}},
		},
		// concrete single-module ANCHOR (mixed verbs).
		"compute_image_reader": {
			{Module: "compute", Resources: []string{"image", "snapshot"}, Verbs: []string{"get", "list"}},
		},
		// concrete single-module ARM_NAMES.
		"vpc_address_ops": {
			{Module: "vpc", Resources: []string{"address"}, Verbs: []string{"get", "update"},
				ResourceNames: []string{"addr5k", "addr9m"}},
		},
		// mixed-arm role: ANCHOR + LABELS (excluded) + NAMES (H-01 shape).
		"network_ops": {
			{Module: "compute", Resources: []string{"image"}, Verbs: []string{"get"}},
			{Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"create"}, MatchLabels: map[string]string{"env": "prod"}},
			{Module: "vpc", Resources: []string{"address"}, Verbs: []string{"get", "update"}, ResourceNames: []string{"addr5k"}},
		},
	}

	golden := loadGolden(t)

	for label, rules := range fixtures {
		t.Run(label, func(t *testing.T) {
			want, ok := golden[label]
			if !ok {
				t.Fatalf("golden snapshot missing entry %q (regenerate testdata/compile_parity_golden.json)", label)
			}
			perms, err := domain.CompileRules(rules)
			if err != nil {
				t.Fatalf("CompileRules(%q) = %v", label, err)
			}
			got := make([]string, len(perms))
			for i, p := range perms {
				got[i] = string(p)
			}
			if len(got) != len(want) {
				t.Fatalf("compiled count %d != golden %d\n got=%v\nwant=%v", len(got), len(want), got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("compiled[%d] = %q, golden = %q\n got=%v\nwant=%v", i, got[i], want[i], got, want)
				}
			}
		})
	}
}

func loadGolden(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "compile_parity_golden.json"))
	if err != nil {
		t.Fatalf("read golden snapshot: %v", err)
	}
	var m map[string][]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal golden snapshot: %v", err)
	}
	return m
}
