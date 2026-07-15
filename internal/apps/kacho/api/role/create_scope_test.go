// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// create_scope_test.go — unit coverage for the
// Role.Create scope XOR: a custom role is EXACTLY ONE of account-scoped XOR
// project-scoped. These cases reject in the sync pre-checks of Execute (BEFORE
// opsRepo/repo are touched), so a use-case with nil deps is safe.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// authnCtx returns a context carrying an authenticated user principal so the
// anti-anonymous guard in Execute passes and the XOR validation is reached.
func authnCtx() context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{
		Type: "user", ID: "usr0000000000000abcd", DisplayName: "tester",
	})
}

// validRules — a minimal well-formed authored rule so the rules[] gate passes
// and the scope XOR is the failing assertion (not a rules error).
func validRules() domain.Rules {
	return domain.Rules{
		{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get", "list"}},
	}
}

// 212-NEG-1: both account_id AND project_id set → InvalidArgument (a custom role
// is exactly one scope). No role created.
func TestCreateRole_212_BothScopesSet_InvalidArgument(t *testing.T) {
	uc := &CreateRoleUseCase{} // nil repo/opsRepo: reject is a sync pre-check
	_, err := uc.Execute(authnCtx(), domain.Role{
		AccountID: "acc0000000000000abcd",
		ProjectID: "prj0000000000000abcd",
		Name:      "both_scopes",
		Rules:     validRules(),
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("Create(both scopes) code = %v, want InvalidArgument; err=%v", st.Code(), err)
	}
}

// 212-NEG-2: neither account_id NOR project_id set → InvalidArgument (custom
// role must carry a scope; system roles are seeded by migration). No role.
func TestCreateRole_212_NoScope_InvalidArgument(t *testing.T) {
	uc := &CreateRoleUseCase{}
	_, err := uc.Execute(authnCtx(), domain.Role{
		Name:  "no_scope",
		Rules: validRules(),
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("Create(no scope) code = %v, want InvalidArgument; err=%v", st.Code(), err)
	}
}

// 212-NEG-3: a malformed project_id (wrong prefix) → InvalidArgument, mirroring
// the account_id id-format guard. No role created.
func TestCreateRole_212_MalformedProjectID_InvalidArgument(t *testing.T) {
	uc := &CreateRoleUseCase{}
	_, err := uc.Execute(authnCtx(), domain.Role{
		ProjectID: "not-a-project-id",
		Name:      "bad_prj",
		Rules:     validRules(),
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("Create(malformed project_id) code = %v, want InvalidArgument; err=%v", st.Code(), err)
	}
}
