// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// handler_scope_test.go — kacho-iam#212 handler-mapping unit RED→GREEN: the
// transport must map BOTH account_id and project_id off CreateRoleRequest into
// the domain.Role scope columns. Pre-#212 the handler mapped account_id only
// (project_id dropped), so a project-scoped role could never be authored.

import (
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

func TestRoleHandler_212_MapsProjectID(t *testing.T) {
	req := &iamv1.CreateRoleRequest{
		ProjectId: "prj0000000000000abcd",
		Name:      "prj_role",
		Rules: []*iamv1.Rule{
			{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}},
		},
	}
	r := roleFromCreateReq(req)
	if got := string(r.ProjectID); got != "prj0000000000000abcd" {
		t.Fatalf("ProjectID = %q, want the request project_id", got)
	}
	if got := string(r.AccountID); got != "" {
		t.Fatalf("AccountID = %q, want empty for a project-scoped request", got)
	}
}

func TestRoleHandler_212_MapsAccountID(t *testing.T) {
	req := &iamv1.CreateRoleRequest{
		AccountId: "acc0000000000000abcd",
		Name:      "acc_role",
		Rules: []*iamv1.Rule{
			{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}},
		},
	}
	r := roleFromCreateReq(req)
	if got := string(r.AccountID); got != "acc0000000000000abcd" {
		t.Fatalf("AccountID = %q, want the request account_id", got)
	}
	if got := string(r.ProjectID); got != "" {
		t.Fatalf("ProjectID = %q, want empty for an account-scoped request", got)
	}
}
