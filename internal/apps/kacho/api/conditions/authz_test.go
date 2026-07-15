// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authz_test.go — server-side authorization for ConditionsService
// Get / List / Create / Update / Delete (SEC / BOLA).
//
// Conditions are project(folder)-scoped CEL policy expressions referenced by
// AccessBindings. Before this hardening the ConditionsService performed NO
// principal-based authorization: Get returned any condition by id, List with an
// empty folder_id enumerated EVERY tenant's conditions, and Create/Update/Delete
// let any authenticated principal tamper with a folder's conditions (which could
// flip an AccessBinding's predicate). These tests pin the secure behaviour:
//
//   - Get: caller must hold `viewer` on the owning project scope (or be a
//     cluster-admin); otherwise NotFound (hide existence, no enumeration leak).
//   - List: anonymous → empty; a non-cluster-admin with an empty folder_id gets
//     an empty page (no cross-tenant enumeration); a scoped list requires
//     `viewer` on that folder.
//   - Create/Update/Delete: caller must hold `editor` on the owning project
//     scope; otherwise PermissionDenied.
//
// The RED batch below builds the service EXACTLY as the composition root did
// before the fix (no RelationStore wired) and asserts the SECURE outcome — it
// fails on the pre-fix code (cross-tenant read/tamper succeeds) and passes once
// the fail-closed in-service authz lands. The allow-path tests use the new
// WithRelationStore option.
package conditions

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// fakeChecker — in-memory authzguard.RelationChecker. `fn` decides each Check;
// nil fn → deny everything (fail-closed default).
type fakeChecker struct {
	fn func(subject, relation, object string) (bool, error)
}

func (f fakeChecker) Check(_ context.Context, subject, relation, object string) (bool, error) {
	if f.fn == nil {
		return false, nil
	}
	return f.fn(subject, relation, object)
}

// allowRel returns a checker that allows exactly `relation` on `object`, denies
// the rest (so a viewer grant never doubles as cluster-admin, etc.).
func allowRel(relation, object string) fakeChecker {
	return fakeChecker{fn: func(_ string, r, o string) (bool, error) {
		return r == relation && o == object, nil
	}}
}

func userCtx(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: id})
}

func sampleCond(id, folder string) domain.Condition {
	return domain.Condition{
		ID:         domain.ConditionID(id),
		FolderID:   folder,
		Name:       "n-" + id,
		Expression: "non_expired",
		Status:     domain.ConditionStatusActive,
	}
}

// newSvc builds a ConditionsCRUDService over the fake repo (no ops repo — the
// CUD authz gate rejects before any Operation is minted on the deny path).
func newSvc(repo *fakeConditionsRepo, checker authzguard.RelationChecker) *service.ConditionsCRUDService {
	svc := service.NewConditionsCRUDService(repo, nil, service.NewBuiltinEvaluator())
	if checker != nil {
		svc.WithRelationStore(checker)
	}
	return svc
}

func repoWith(conds ...domain.Condition) *fakeConditionsRepo {
	r := &fakeConditionsRepo{byID: make(map[domain.ConditionID]domain.Condition, len(conds))}
	for _, c := range conds {
		r.byID[c.ID] = c
		r.listRows = append(r.listRows, c)
	}
	return r
}

// ── Get ──────────────────────────────────────────────────────────────────────

// RED: without a wired RelationStore any principal reads any condition. GREEN:
// fail-closed → NotFound (hide existence).
func TestGetAuthz_Unauthorized_NotFound(t *testing.T) {
	cond := sampleCond("cnd0000000000000auth", "prj_owner")
	h := NewHandler(newSvc(repoWith(cond), nil)) // no relations → fail-closed

	got, err := h.Get(userCtx("usr_intruder"), &iamv1.GetConditionRequest{ConditionId: string(cond.ID)})

	require.Error(t, err)
	assert.Nil(t, got)
	assert.Equal(t, codes.NotFound, status.Code(err), "cross-tenant Get must be NotFound (hide existence)")
}

// A viewer on the owning project scope reads the condition.
func TestGetAuthz_ViewerGranted_Allowed(t *testing.T) {
	cond := sampleCond("cnd0000000000000view", "prj_owner")
	checker := allowRel("viewer", "project:prj_owner")
	h := NewHandler(newSvc(repoWith(cond), checker))

	got, err := h.Get(userCtx("usr_member"), &iamv1.GetConditionRequest{ConditionId: string(cond.ID)})

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, string(cond.ID), got.GetId())
}

// A viewer on a DIFFERENT folder cannot read this condition.
func TestGetAuthz_ViewerOnOtherFolder_NotFound(t *testing.T) {
	cond := sampleCond("cnd0000000000000oth1", "prj_owner")
	checker := allowRel("viewer", "project:prj_other")
	h := NewHandler(newSvc(repoWith(cond), checker))

	got, err := h.Get(userCtx("usr_other"), &iamv1.GetConditionRequest{ConditionId: string(cond.ID)})

	require.Error(t, err)
	assert.Nil(t, got)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ── List ─────────────────────────────────────────────────────────────────────

// RED: List with an empty folder_id returns every tenant's conditions. GREEN: a
// non-cluster-admin gets an empty page (no cross-tenant enumeration).
func TestListAuthz_EmptyFolder_NonAdmin_NoEnumeration(t *testing.T) {
	repo := repoWith(
		sampleCond("cnd000000000000tenaA", "prj_a"),
		sampleCond("cnd000000000000tenaB", "prj_b"),
	)
	h := NewHandler(newSvc(repo, nil)) // no relations → not a cluster-admin

	resp, err := h.List(userCtx("usr_scanner"), &iamv1.ListConditionsRequest{FolderId: ""})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.GetConditions(), "empty folder_id must not enumerate across tenants")
}

// A viewer on the requested folder lists that folder's conditions only.
func TestListAuthz_ScopedFolder_ViewerGranted(t *testing.T) {
	repo := repoWith(
		sampleCond("cnd000000000000scpA1", "prj_a"),
		sampleCond("cnd000000000000scpB1", "prj_b"),
	)
	checker := allowRel("viewer", "project:prj_a")
	h := NewHandler(newSvc(repo, checker))

	resp, err := h.List(userCtx("usr_a"), &iamv1.ListConditionsRequest{FolderId: "prj_a"})

	require.NoError(t, err)
	require.Len(t, resp.GetConditions(), 1)
	assert.Equal(t, "prj_a", resp.GetConditions()[0].GetFolderId())
}

// A caller with no grant on the requested folder gets an empty page (no leak).
func TestListAuthz_ScopedFolder_Unauthorized_Empty(t *testing.T) {
	repo := repoWith(sampleCond("cnd000000000000scpC1", "prj_a"))
	h := NewHandler(newSvc(repo, nil))

	resp, err := h.List(userCtx("usr_x"), &iamv1.ListConditionsRequest{FolderId: "prj_a"})

	require.NoError(t, err)
	assert.Empty(t, resp.GetConditions())
}

// ── Create / Update / Delete ─────────────────────────────────────────────────

// RED: any authenticated principal creates a condition. GREEN: needs `editor`
// on the target folder scope → PermissionDenied otherwise.
func TestCreateAuthz_Unauthorized_PermissionDenied(t *testing.T) {
	h := NewHandler(newSvc(repoWith(), nil))

	op, err := h.Create(userCtx("usr_intruder"), &iamv1.CreateConditionRequest{
		FolderId:   "prj_victim",
		Name:       "evil",
		Expression: "non_expired",
	})

	require.Error(t, err)
	assert.Nil(t, op)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// RED: any authenticated principal updates a condition (can flip a binding's
// predicate). GREEN: needs `editor` on the owning folder → PermissionDenied.
func TestUpdateAuthz_Unauthorized_PermissionDenied(t *testing.T) {
	cond := sampleCond("cnd0000000000000upda", "prj_owner")
	h := NewHandler(newSvc(repoWith(cond), nil))

	newExpr := "always_true"
	op, err := h.Update(userCtx("usr_intruder"), &iamv1.UpdateConditionRequest{
		ConditionId: string(cond.ID),
		Expression:  newExpr,
	})

	require.Error(t, err)
	assert.Nil(t, op)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// RED: any authenticated principal deletes a (restrictive) condition. GREEN:
// needs `editor` on the owning folder → PermissionDenied.
func TestDeleteAuthz_Unauthorized_PermissionDenied(t *testing.T) {
	cond := sampleCond("cnd0000000000000dele", "prj_owner")
	h := NewHandler(newSvc(repoWith(cond), nil))

	op, err := h.Delete(userCtx("usr_intruder"), &iamv1.DeleteConditionRequest{ConditionId: string(cond.ID)})

	require.Error(t, err)
	assert.Nil(t, op)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// Update/Delete of a NON-EXISTENT condition is NotFound (existence check runs
// before the authz gate can leak anything about a folder).
func TestUpdateAuthz_Missing_NotFound(t *testing.T) {
	checker := allowRel("editor", "project:prj_any")
	h := NewHandler(newSvc(repoWith(), checker))

	op, err := h.Update(userCtx("usr_any"), &iamv1.UpdateConditionRequest{
		ConditionId: "cnd0000000000000miss",
		Expression:  "x",
	})

	require.Error(t, err)
	assert.Nil(t, op)
	assert.Equal(t, codes.NotFound, status.Code(err))
}
