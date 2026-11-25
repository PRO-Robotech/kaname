// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmodel

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/grantcapability"
)

func TestGrantCapabilityCanonicalPlan(t *testing.T) {
	p, err := New(DSL)
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range [][2]string{{grantcapability.ScopeObjectType, grantcapability.CreateRelation}, {grantcapability.RoleObjectType, grantcapability.BindRelation}, {grantcapability.AccessLabelObjectType, grantcapability.ApplyAccessLabelRelation}} {
		if err := p.GrantCapabilityPlan(slot[0], slot[1]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGrantCapabilityRejectsModelVariants(t *testing.T) {
	original := "define create_binding: [user, service_account, group#member]"
	for _, replacement := range []string{
		"define create_binding: [user]",
		"define create_binding: [user, service_account, group#member, user:*]",
		"define other: [user, service_account, group#member]\n    define create_binding: other",
		"define create_binding: [user with mfa_fresh, service_account, group#member]",
		"define parent: [account]\n    define create_binding: admin from parent",
	} {
		t.Run(replacement, func(t *testing.T) {
			p, err := New(strings.Replace(DSL, original, replacement, 1))
			if err != nil {
				t.Fatal(err)
			}
			if err := p.GrantCapabilityPlan(grantcapability.ScopeObjectType, grantcapability.CreateRelation); err == nil {
				t.Fatal("unsupported model accepted")
			}
		})
	}
}

func TestAccessLabelCapabilityPlanRequiresDirectDeclaredSubjects(t *testing.T) {
	base := "\ntype iam_grant_access_label\n  relations\n"
	original := base + "    define apply: [user, service_account, group#member]\n"
	if strings.Count(DSL, original) != 1 {
		t.Fatal("canonical access label block is absent or ambiguous")
	}
	for _, tt := range []struct {
		relations string
		allowed   bool
	}{
		{"    define apply: [user, service_account, group#member]\n", true},
		{"    define apply: [user]\n", false},
		{"    define apply: [user with mfa_fresh, service_account, group#member]\n", false},
		{"    define other: [user, service_account, group#member]\n    define apply: other\n", false},
		{"    define apply: [user, service_account, group#member, system_class]\n", false},
		{"    define apply: [user, service_account, group#member, user:*]\n", false},
		{"    define parent: [account]\n    define apply: editor from parent\n", false},
	} {
		plans, err := New(strings.Replace(DSL, original, base+tt.relations, 1))
		if err != nil {
			t.Fatal(err)
		}
		err = plans.GrantCapabilityPlan(grantcapability.AccessLabelObjectType, grantcapability.ApplyAccessLabelRelation)
		if (err == nil) != tt.allowed {
			t.Fatalf("форма отношения %q: %v", tt.relations, err)
		}
	}
}

func TestAdmitReservesGrantCoordinates(t *testing.T) {
	for _, suffix := range []string{
		"\ntype iam_grant_scope\n  relations\n    define create_binding: [user]\n",
		"\ntype iam_grant_role\n  relations\n    define bind: [user]\n",
		"\ntype iam_grant_access_label\n  relations\n    define apply: [user, service_account, group#member]\n",
		"\ntype foreign_cap\n  relations\n    define cap: [iam_grant_scope]\n    define v_get: create_binding from cap\n",
		"\ntype foreign_cap\n  relations\n    define v_get: [iam_grant_role#bind]\n",
		"\ntype foreign_cap\n  relations\n    define v_get: [iam_grant_access_label#apply]\n",
		"\ntype foreign_cap\n  relations\n    define cap: [iam_grant_access_label]\n    define v_get: apply from cap\n",
	} {
		report, err := Admit(DSL + suffix)
		if err == nil && len(report.Findings) == 0 {
			t.Fatalf("reserved coordinate admitted: %s", suffix)
		}
	}
	report, err := Admit(DSL + "\ntype foreign_leaf\n  relations\n    define v_get: [user]\n")
	if err != nil || !report.Admitted() {
		t.Fatalf("ordinary extension rejected: %+v %v", report, err)
	}
}
