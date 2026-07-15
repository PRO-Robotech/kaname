// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_by_subject_w1_6_test.go — ListBySubject self-only enforcement for all
// subject types (user / service_account / group). User and service_account
// subjects require IsSelf. Group subjects are allowed iff the caller is a
// member of the group (via group.IsMember adapter); non-members 403.
// system/bootstrap principals can never be a group member by DB CHECK so
// they 403 unconditionally for group subjects.
package access_binding

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// userCtxAB builds a context with a user principal for AB tests.
func userCtxAB(id string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: id})
}

// service-account subject must be self-only.
func TestListBySubject_ServiceAccountSubject_StrangerDenied(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_test", "prj_test", "rol_v", "kacho.view", nil)
	uc := NewListBySubjectUseCase(repo)
	ctx := userCtxAB("usr_random")

	_, _, err := uc.Execute(ctx, "service_account", "sva_target", repoab.PageFilter{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("stranger listing SA subject's bindings must 403, got %v", err)
	}
}

// group subject: non-member caller denied.
func TestListBySubject_GroupSubject_NonMemberDenied(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_test", "prj_test", "rol_v", "kacho.view", nil)
	uc := NewListBySubjectUseCase(repo)

	// No membership rows seeded → caller is NOT a member → must 403.
	ctx := userCtxAB("usr_not_in_group")
	_, _, err := uc.Execute(ctx, "group", "grp_target", repoab.PageFilter{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-member listing group bindings must 403, got %v", err)
	}
}

// group subject: member caller allowed.
func TestListBySubject_GroupSubject_MemberAllowed(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_test", "prj_test", "rol_v", "kacho.view", nil)
	// Seed: usr_alice is a member of grp_target.
	repo.AddGroupMember("grp_target", "user", "usr_alice")
	uc := NewListBySubjectUseCase(repo)

	ctx := userCtxAB("usr_alice")
	_, _, err := uc.Execute(ctx, "group", "grp_target", repoab.PageFilter{})
	if err != nil {
		t.Fatalf("member listing own group bindings must succeed, got %v", err)
	}
}

// group subject: SA member also allowed.
func TestListBySubject_GroupSubject_SAMemberAllowed(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_test", "prj_test", "rol_v", "kacho.view", nil)
	repo.AddGroupMember("grp_target", "service_account", "sva_bot")
	uc := NewListBySubjectUseCase(repo)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva_bot"})
	_, _, err := uc.Execute(ctx, "group", "grp_target", repoab.PageFilter{})
	if err != nil {
		t.Fatalf("SA member listing group bindings must succeed, got %v", err)
	}
}

// system principal denied even if a name
// collision with the group exists (system/bootstrap can never be a
// group member by DB CHECK).
func TestListBySubject_GroupSubject_SystemPrincipalDenied(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_test", "prj_test", "rol_v", "kacho.view", nil)
	uc := NewListBySubjectUseCase(repo)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "bootstrap"})
	_, _, err := uc.Execute(ctx, "group", "grp_target", repoab.PageFilter{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("system principal must 403 on group ListBySubject, got %v", err)
	}
}

// user subject self-listing still works (regression guard).
func TestListBySubject_UserSubject_SelfAllowed(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_test", "prj_test", "rol_v", "kacho.view", nil)
	uc := NewListBySubjectUseCase(repo)
	ctx := userCtxAB("usr_alice")

	_, _, err := uc.Execute(ctx, "user", "usr_alice", repoab.PageFilter{})
	if err != nil {
		t.Fatalf("self-listing must succeed, got %v", err)
	}
}

// user subject cross-listing still denied.
func TestListBySubject_UserSubject_StrangerDenied(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_test", "prj_test", "rol_v", "kacho.view", nil)
	uc := NewListBySubjectUseCase(repo)
	ctx := userCtxAB("usr_bob")

	_, _, err := uc.Execute(ctx, "user", "usr_alice", repoab.PageFilter{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-user listing must 403, got %v", err)
	}
}

// service-account subject self-listing works.
func TestListBySubject_ServiceAccountSubject_SelfAllowed(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_test", "prj_test", "rol_v", "kacho.view", nil)
	uc := NewListBySubjectUseCase(repo)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva_self"})

	_, _, err := uc.Execute(ctx, "service_account", "sva_self", repoab.PageFilter{})
	if err != nil {
		t.Fatalf("SA listing own bindings must succeed, got %v", err)
	}
}
