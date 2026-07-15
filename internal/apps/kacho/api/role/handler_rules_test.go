// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// handler_rules_test.go — RBAC rules-model handler-boundary unit tests (no DB):
// the transport rejects client-sent permissions (output-only) as a sync
// first-statement, and maps the request rules[] into domain.Rule. These reject
// paths return BEFORE reaching the use-case, so a nil use-case is safe.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// Create with a non-empty permissions field → sync INVALID_ARGUMENT
// "Illegal argument permissions (compiled/output-only)"; no role created.
func TestRoleHandler_A02_CreateRejectsPermissions(t *testing.T) {
	h := &Handler{} // use-case nil — reject must be the first statement
	_, err := h.Create(context.Background(), &iamv1.CreateRoleRequest{
		AccountId:   "acc0000000000000abcd",
		Name:        "net_ops",
		Permissions: []string{"vpc.subnet.*.get"},
		Rules: []*iamv1.Rule{
			{Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"get"}},
		},
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("Create code = %v, want InvalidArgument", st.Code())
	}
	if got := st.Message(); got != "Illegal argument permissions (compiled/output-only)" {
		t.Fatalf("Create message = %q, want the stable text", got)
	}
}

// Update whose update_mask carries permissions → sync
// INVALID_ARGUMENT "permissions is immutable after Role.Create".
func TestRoleHandler_A08_UpdateRejectsPermissionsMask(t *testing.T) {
	h := &Handler{update: &UpdateRoleUseCase{}}
	_, err := h.Update(context.Background(), &iamv1.UpdateRoleRequest{
		RoleId:     "rol0000000000000abcd",
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"permissions"}},
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("Update code = %v, want InvalidArgument", st.Code())
	}
	if got := st.Message(); got != "permissions is immutable after Role.Create" {
		t.Fatalf("Update message = %q, want the stable text", got)
	}
}

// rulesFromProto maps the request Rule list into domain.Rule preserving the arm
// selectors (resource_names / match_labels).
func TestRoleHandler_RulesFromProto(t *testing.T) {
	in := []*iamv1.Rule{
		{Module: "compute", Resources: []string{"image"}, Verbs: []string{"get"}},
		{Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"create"}, MatchLabels: map[string]string{"env": "prod"}},
		{Module: "vpc", Resources: []string{"address"}, Verbs: []string{"get", "update"}, ResourceNames: []string{"addr5k"}},
	}
	rules := rulesFromProto(in)
	if len(rules) != 3 {
		t.Fatalf("rulesFromProto len = %d, want 3", len(rules))
	}
	if rules[1].MatchLabels["env"] != "prod" {
		t.Errorf("matchLabels not mapped: %+v", rules[1])
	}
	if len(rules[2].ResourceNames) != 1 || rules[2].ResourceNames[0] != "addr5k" {
		t.Errorf("resourceNames not mapped: %+v", rules[2])
	}
}

// #184: List with page_size > 1000 → sync INVALID_ARGUMENT (no silent clamp).
// The reject is the first statement (validate.PageSize) so a nil use-case is safe.
func TestRoleHandler_184_ListRejectsPageSizeOverMax(t *testing.T) {
	h := &Handler{} // list use-case nil — reject must precede the use-case
	_, err := h.List(context.Background(), &iamv1.ListRolesRequest{PageSize: 1001})
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("List(page_size=1001) code = %v, want InvalidArgument (#184, no silent clamp)", st.Code())
	}
}

// #184: page_size == 0 is allowed (default applied downstream) and page_size <= 1000
// passes the validate gate (reaching the use-case). With a nil use-case the call
// would panic if it got past the gate, so we only assert that page_size=0 / 1000 do
// NOT produce an InvalidArgument from the page_size validation itself.
func TestRoleHandler_184_ListAcceptsPageSizeAtBoundary(t *testing.T) {
	h := &Handler{list: NewListRolesUseCase(nil).WithRelationStore(nil)}
	// page_size=1000 (max) must pass the validate gate; the downstream nil-FGA path
	// fails closed Unavailable (not InvalidArgument), proving page_size validation OK.
	_, err := h.List(ctxUser("usr-u1"), &iamv1.ListRolesRequest{PageSize: 1000})
	st, _ := status.FromError(err)
	if st.Code() == codes.InvalidArgument {
		t.Fatalf("List(page_size=1000) must NOT be InvalidArgument (#184 boundary); got %v", st.Code())
	}
}

// #185: List handler maps req.AccountId into the use-case filter (scope). We verify
// via a fake use-case repo that the AccountID reaches the repo ListFilter.
func TestRoleHandler_185_ListPassesAccountIdToFilter(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedSystemRole(repo, "rol-sys1")
	seedCustomRole(repo, "rol-cA", "acc0000000000000acca")
	fga := newRoleFGAStub()
	fga.set("user:usr-u1", []string{"rol-cA"})

	h := &Handler{list: NewListRolesUseCase(repo).WithRelationStore(fga)}
	_, err := h.List(ctxUser("usr-u1"), &iamv1.ListRolesRequest{
		PageSize:  100,
		AccountId: "acc0000000000000acca",
	})
	if err != nil {
		t.Fatalf("List err = %v", err)
	}
	if got := string(repo.lastFilter.AccountID); got != "acc0000000000000acca" {
		t.Fatalf("AccountID not passed to filter: got %q want acc...acca (#185)", got)
	}
}
