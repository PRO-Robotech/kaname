// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_by_account_test.go — unit tests for ListByAccountUseCase.
//
// Covers handler-level authorisation: only account owners (or FGA-admin
// principals) may enumerate all bindings inside an account. Non-owner users
// get PermissionDenied. Anonymous principals get Unauthenticated/403.
//
// Repo-level filtering / pagination is covered by the integration tests in
// pg/access_binding_list_by_account_integration_test.go.
package access_binding

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

func TestListByAccount_AccountOwner_Allowed(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc00000000000ba01ab", "prj_test", "rol_v", "kacho.view", nil)
	uc := NewListByAccountUseCase(repo)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_owner"})

	_, _, err := uc.Execute(ctx, "acc00000000000ba01ab", repoab.AccountPageFilter{PageSize: 100})
	if err != nil {
		t.Fatalf("owner listing must succeed, got %v", err)
	}
}

func TestListByAccount_NonOwner_Denied(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc00000000000ba01ab", "prj_test", "rol_v", "kacho.view", nil)
	uc := NewListByAccountUseCase(repo)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_stranger"})

	_, _, err := uc.Execute(ctx, "acc00000000000ba01ab", repoab.AccountPageFilter{PageSize: 100})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-owner listing must 403, got %v", err)
	}
}

func TestListByAccount_Anonymous_Denied(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc00000000000ba01ab", "prj_test", "rol_v", "kacho.view", nil)
	uc := NewListByAccountUseCase(repo)
	ctx := context.Background()

	_, _, err := uc.Execute(ctx, "acc00000000000ba01ab", repoab.AccountPageFilter{PageSize: 100})
	if status.Code(err) != codes.PermissionDenied && status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous listing must 401/403, got %v", err)
	}
}

func TestListByAccount_InvalidAccountID(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc00000000000ba01ab", "prj_test", "rol_v", "kacho.view", nil)
	uc := NewListByAccountUseCase(repo)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_owner"})

	_, _, err := uc.Execute(ctx, "not-a-valid-id", repoab.AccountPageFilter{PageSize: 100})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid account_id must InvalidArgument, got %v", err)
	}
}

// Sanity: the fake repo returns whatever was stored — exercise the
// owner-allowed path with a recorded binding to confirm the SQL pass-through
// works as expected (one binding seeded → one returned).
func TestListByAccount_OwnerSeesAllBindings(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc00000000000ba01ab", "prj_test", "rol_v", "kacho.view", nil)
	// Pre-seed a fake-account binding so the fake reader returns one row.
	repo.seedABListByAccount([]domain.AccessBinding{
		{
			ID: "acb00000000000ba01ab", SubjectType: domain.SubjectTypeUser,
			SubjectID:    "usr_other",
			RoleID:       "rol_v",
			ResourceType: "account",
			ResourceID:   "acc00000000000ba01ab",
			Status:       domain.AccessBindingStatusActive,
		},
	})

	uc := NewListByAccountUseCase(repo)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_owner"})

	rows, _, err := uc.Execute(ctx, "acc00000000000ba01ab", repoab.AccountPageFilter{PageSize: 100})
	if err != nil {
		t.Fatalf("owner listing must succeed, got %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
}
