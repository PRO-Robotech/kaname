// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// get_cluster_test.go — Bug B follow-on: GetAccessBindingUseCase must allow a
// cluster-admin (FGA grant-authority on the binding's scope) to read a
// cluster-scope binding they did not personally receive.
//
// The original get.go scope-filter only had `account` / `project` cases (owner
// lookup) — a cluster-scope binding fell through to PermissionDenied for
// everyone except its own subject, so even the bootstrap cluster-admin got 403
// on Get (newman IAM-ACB-CR-CLUSTER-OK `get-cluster-binding`). The fix routes
// the non-subject path through requireGrantAuthority, which already resolves
// cluster scope via the FGA `admin@cluster` relation.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// seedAB stores a binding the fake repo returns from AccessBindings().Get.
func seedClusterBinding(repo *abFakeRepo, subjectID string) domain.AccessBindingID {
	id := domain.AccessBindingID("acb00000000000clstr1")
	repo.mu.Lock()
	repo.ab = &domain.AccessBinding{
		ID:           id,
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID("rol21232f297a57a5a74"),
		ResourceType: domain.ResourceType("cluster"),
		ResourceID:   domain.ClusterSingletonID,
	}
	repo.mu.Unlock()
	return id
}

func TestGetAccessBinding_ClusterScope_ClusterAdmin_Allowed(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc00000000000ba01ab", "prj_test", "rol_v", "kacho.view", nil)
	id := seedClusterBinding(repo, "usr_grantee") // binding granted to someone else
	fga := newRecordingFGA()                      // Check returns true → FGA admin@cluster
	uc := NewGetAccessBindingUseCase(repo).WithRelationStore(fga, nil)

	// Caller is NOT the subject, but holds cluster grant-authority via FGA.
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_boot"})

	got, err := uc.Execute(ctx, id)
	if err != nil {
		t.Fatalf("cluster-admin must read cluster-scope binding, got %v", err)
	}
	if got.ID != id {
		t.Fatalf("expected binding %s, got %s", id, got.ID)
	}
}

func TestGetAccessBinding_ClusterScope_NonAdmin_Denied(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc00000000000ba01ab", "prj_test", "rol_v", "kacho.view", nil)
	id := seedClusterBinding(repo, "usr_grantee")
	fga := &denyingFGA{} // FGA Check → false (no cluster admin relation)
	uc := NewGetAccessBindingUseCase(repo).WithRelationStore(fga, nil)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_stranger"})

	_, err := uc.Execute(ctx, id)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin stranger must 403 on cluster-scope binding, got %v", err)
	}
}

func TestGetAccessBinding_ClusterScope_Subject_Allowed(t *testing.T) {
	// The binding's own subject can always read it (self-grant visibility),
	// regardless of FGA authority.
	repo := newABFakeRepo("usr_owner", "acc00000000000ba01ab", "prj_test", "rol_v", "kacho.view", nil)
	id := seedClusterBinding(repo, "usr_grantee")
	fga := &denyingFGA{}
	uc := NewGetAccessBindingUseCase(repo).WithRelationStore(fga, nil)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_grantee"})

	if _, err := uc.Execute(ctx, id); err != nil {
		t.Fatalf("subject must read their own cluster-scope binding, got %v", err)
	}
}
