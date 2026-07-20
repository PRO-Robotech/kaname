// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// role_effective_verbs_test.go — redesign-2026 F6 (IAM-1-15). The honest
// effective-verb preview: authoredVerbs is the deduped canonical union of the
// role's rule verbs; effectiveVerbs adds the editor `delete*` qualifier (an editor
// may delete the in-scope leaf objects it edits, NOT the anchor); the verbNote
// spells that out verbatim.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const editorDeleteNote = "co-materialized on in-scope leaf objects, NOT on the account/project anchor itself"

func TestRole_IAM_1_15_EffectiveVerbs(t *testing.T) {
	cases := []struct {
		name           string
		verbs          []string
		wantAuthored   []string
		wantEffective  []string
		wantDeleteNote bool
	}{
		{
			name:          "viewer (read-only) — no delete*",
			verbs:         []string{"get", "list"},
			wantAuthored:  []string{"get", "list"},
			wantEffective: []string{"get", "list"},
		},
		{
			name:           "editor — delete* co-materialized",
			verbs:          []string{"get", "list", "create", "update"},
			wantAuthored:   []string{"get", "list", "create", "update"},
			wantEffective:  []string{"get", "list", "create", "update", "delete*"},
			wantDeleteNote: true,
		},
		{
			name:          "admin (wildcard) — full CRUD, no delete* qualifier",
			verbs:         []string{"*"},
			wantAuthored:  []string{"get", "list", "create", "update", "delete"},
			wantEffective: []string{"get", "list", "create", "update", "delete"},
		},
		{
			name:          "already has delete — not editor-tier, no delete*",
			verbs:         []string{"get", "update", "delete"},
			wantAuthored:  []string{"get", "update", "delete"},
			wantEffective: []string{"get", "update", "delete"},
		},
		{
			name:           "dedupe + canonical order",
			verbs:          []string{"update", "get", "get", "list"},
			wantAuthored:   []string{"get", "list", "update"},
			wantEffective:  []string{"get", "list", "update", "delete*"},
			wantDeleteNote: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Role{Rules: Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: tc.verbs}}}
			assert.Equal(t, tc.wantAuthored, r.AuthoredVerbs(), "authoredVerbs")
			assert.Equal(t, tc.wantEffective, r.EffectiveVerbs(), "effectiveVerbs")
			notes := r.VerbNotes()
			if tc.wantDeleteNote {
				assert.Equal(t, editorDeleteNote, notes["delete*"], "delete* note verbatim")
			} else {
				assert.NotContains(t, notes, "delete*", "no delete* note when not editor-tier")
			}
		})
	}
}

// F6: verbs union across multiple rules.
func TestRole_IAM_1_15_AuthoredVerbs_MultiRule(t *testing.T) {
	r := Role{Rules: Rules{
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "list"}},
		{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"create", "update"}},
	}}
	assert.Equal(t, []string{"get", "list", "create", "update"}, r.AuthoredVerbs())
	assert.Equal(t, []string{"get", "list", "create", "update", "delete*"}, r.EffectiveVerbs())
}
