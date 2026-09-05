// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list_subject_privileges_test.go — unit tests for ListSubjectPrivilegesUseCase
// (RPC AccessBindingService.ListSubjectPrivileges).
//
// Covered scenarios:
//
//   self-view (caller == subject, no admin role) → allowed
//   malformed subject_id / prefix↔type mismatch → INVALID_ARGUMENT (first stmt)
//   unknown subject_type → INVALID_ARGUMENT
//   well-formed-but-nonexistent subject, caller may read it → NOT_FOUND
//   (a caller who may NOT read it gets the cross-account answer instead —
//    list_subject_privileges_existence_test.go)
//   account-admin (FGA admin on subject's home account) → allowed
//   ServiceAccount subject + admin of its home account → allowed
//   cross-account caller → PERMISSION_DENIED
//   existing subject, 0 bindings → empty list (not error)
//   anonymous caller → fail-closed (PERMISSION_DENIED)
//   role_name resolved server-side (single JOIN, no N+1)
//   dangling role → empty role_name, no panic
//
// The repo JOIN behaviour (LEFT JOIN roles, status<>'REVOKED', keyset
// pagination) is covered by the testcontainers integration test
// (internal/repo/kacho/pg/access_binding_subject_privileges_integration_test.go).

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
)

const (
	spOwnerID  = "usr00000000000owner1"
	spAdminID  = "usr00000000000admin1"
	spMemberID = "usr0000000000member1"
	spOtherID  = "usr00000000000other1"
	spSAID     = "sva0000000000000bot1"
	spGroupID  = "grp00000000000group1" // group in acc-A
	spGroupBID = "grp00000000000group2" // group in acc-B
	spAccA     = "acc00000000000accAaa"
	spAccB     = "acc00000000000accBbb"
)

// spRepo builds a fake repo with a home account acc-A owned by usr-OWNER, and
// seeds the subject (user / SA) with the given home account. relations defaults
// to a denying FGA unless overridden.
func spRepo() *abFakeRepo {
	repo := newABFakeRepo(spOwnerID, spAccA, "prj00000000000proj01", "rol_v", "kacho.view", nil)
	repo.AddUser(spMemberID, spAccA)
	repo.AddUser(spOwnerID, spAccA)
	repo.AddUser(spAdminID, spAccB) // admin lives in another account but holds FGA admin on acc-A
	repo.AddUser(spOtherID, spAccB)
	repo.AddServiceAccount(spSAID, spAccA)
	repo.AddGroup(spGroupID, spAccA)  // group home account = acc-A
	repo.AddGroup(spGroupBID, spAccB) // group home account = acc-B
	return repo
}

func spPriv(bindingID, roleID, roleName, resType, resID string, scope domain.Scope) domain.SubjectPrivilege {
	return domain.SubjectPrivilege{
		BindingID:       domain.AccessBindingID(bindingID),
		RoleID:          domain.RoleID(roleID),
		RoleName:        domain.RoleName(roleName),
		ResourceType:    domain.ResourceType(resType),
		ResourceID:      resID,
		Scope:           scope,
		Status:          domain.AccessBindingStatusActive,
		CreatedAt:       time.Now().UTC(),
		GrantedByUserID: domain.UserID(spOwnerID),
	}
}

// ── self-view ────────────────────────────────────────────────────────────────
func TestListSubjectPrivileges_1_3_03_SelfViewAllowed(t *testing.T) {
	repo := spRepo()
	repo.seedSubjectPrivileges([]domain.SubjectPrivilege{
		spPriv("acb00000000000bind01", "rol_v", "viewer", "account", spAccA, domain.ScopeAccount),
	})
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(&denyingFGA{}, nil)

	ctx := userCtxAB(spMemberID) // caller IS the subject
	out, _, err := uc.Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{})
	if err != nil {
		t.Fatalf("self-view must be allowed, got %v", err)
	}
	if len(out) != 1 || out[0].RoleName != "viewer" {
		t.Fatalf("expected 1 enriched privilege with role_name=viewer, got %+v", out)
	}
}

// ── malformed subject_id (first statement, before repo) ──────────────────────
func TestListSubjectPrivileges_1_3_04_MalformedID_InvalidArgument(t *testing.T) {
	repo := spRepo()
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(newRecordingFGA(), nil)
	ctx := userCtxAB(spOwnerID)

	_, _, err := uc.Execute(ctx, domain.SubjectTypeUser, "not-a-valid-id", repoab.PageFilter{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("malformed subject_id must be InvalidArgument, got %v", err)
	}
}

// ── prefix↔type mismatch (sva-id under subject_type=user) ────────────────────
func TestListSubjectPrivileges_1_3_04_PrefixTypeMismatch_InvalidArgument(t *testing.T) {
	repo := spRepo()
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(newRecordingFGA(), nil)
	ctx := userCtxAB(spOwnerID)

	// valid SA id but subject_type=user → prefix↔type mismatch.
	_, _, err := uc.Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spSAID), repoab.PageFilter{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("prefix↔type mismatch must be InvalidArgument, got %v", err)
	}
}

// ── unknown subject_type (garbage, not in the user|sa|group set) ─────────────
func TestListSubjectPrivileges_1_3_05_UnknownSubjectType_InvalidArgument(t *testing.T) {
	repo := spRepo()
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(newRecordingFGA(), nil)
	ctx := userCtxAB(spOwnerID)

	_, _, err := uc.Execute(ctx, domain.SubjectType("robot"), "rbt00000000000rbt001", repoab.PageFilter{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unknown subject_type must be InvalidArgument, got %v", err)
	}
}

// ── well-formed-but-nonexistent subject, caller MAY read it → NOT_FOUND ──────
// The authority is explicit (cluster-admin): absence is reported only to a
// caller entitled to it, so this case must not be seeded with an all-allowing
// fake — that would make the assertion true for a reason the test does not name.
func TestListSubjectPrivileges_1_3_06_UnknownSubject_NotFound(t *testing.T) {
	repo := spRepo()
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(onlyClusterAdmin(), nil)
	ctx := clusterAdminCtx(spOwnerID)

	ghost := domain.SubjectID("usr0000000000ghost01") // well-formed usr-id, not seeded
	_, _, err := uc.Execute(ctx, domain.SubjectTypeUser, ghost, repoab.PageFilter{})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("nonexistent well-formed subject must be NotFound, got %v", err)
	}
}

// ── nonexistent SA subject, caller MAY read it → NOT_FOUND ───────────────────
func TestListSubjectPrivileges_1_3_06_UnknownServiceAccount_NotFound(t *testing.T) {
	repo := spRepo()
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(onlyClusterAdmin(), nil)
	ctx := clusterAdminCtx(spOwnerID)

	ghost := domain.SubjectID("sva000000000ghost001")
	_, _, err := uc.Execute(ctx, domain.SubjectTypeServiceAccount, ghost, repoab.PageFilter{})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("nonexistent well-formed SA subject must be NotFound, got %v", err)
	}
}

// ── owner sees member's privileges with resolved role names ──────────────────
func TestListSubjectPrivileges_1_3_01_OwnerSeesMemberEnriched(t *testing.T) {
	repo := spRepo()
	repo.seedSubjectPrivileges([]domain.SubjectPrivilege{
		spPriv("acb00000000000bind01", "rol_editor", "editor", "project", "prj00000000000projX1", domain.ScopeProject),
		spPriv("acb00000000000bind02", "rol_viewer", "viewer", "account", spAccA, domain.ScopeAccount),
	})
	// Модель прав: владелец acc-A держит `v_get` на обеих выдачах — он выводится
	// у него через `super_admin from account` / `... from project`. Дублёр не
	// выводит, поэтому предпосылка сужения названа здесь явно (#1354).
	uc := NewListSubjectPrivilegesUseCase(repo).
		WithRelationStore(&denyingFGA{}, nil).
		WithRelationQueries(spVisibleTo(spOwnerID, "acb00000000000bind01", "acb00000000000bind02"))

	ctx := userCtxAB(spOwnerID) // owner of acc-A (home account of usr-MEMBER)
	out, next, err := uc.Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{})
	if err != nil {
		t.Fatalf("owner must see member privileges, got %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 privileges, got %d", len(out))
	}
	if out[0].RoleName != "editor" || out[1].RoleName != "viewer" {
		t.Fatalf("role names must be resolved server-side, got %q / %q", out[0].RoleName, out[1].RoleName)
	}
	if next != "" {
		t.Fatalf("expected empty next_page_token, got %q", next)
	}
}

// ── account-admin (FGA admin on home account) sees member ────────────────────
func TestListSubjectPrivileges_1_3_07_AccountAdminViaFGA_Allowed(t *testing.T) {
	repo := spRepo()
	repo.seedSubjectPrivileges([]domain.SubjectPrivilege{
		spPriv("acb00000000000bind01", "rol_v", "viewer", "account", spAccA, domain.ScopeAccount),
	})
	// usr-ADMIN is NOT the owner of acc-A, but holds FGA admin on account:acc-A.
	//
	// Отношение выдаётся ТОЧЕЧНО, а не дублёром, отвечающим «да» на всё: такой
	// дублёр делает вызывающего ещё и администратором облака, и проба, названная
	// полосой делегированного распорядителя, молча проверяла бы полосу надзора —
	// оставаясь зелёной при полностью сломанной первой (#1354).
	fga := &scopedFGA{allow: map[string]bool{"admin|account:" + spAccA: true}}
	uc := NewListSubjectPrivilegesUseCase(repo).
		WithRelationStore(fga, nil).
		WithRelationQueries(spVisibleTo(spAdminID, "acb00000000000bind01"))

	ctx := userCtxAB(spAdminID)
	out, _, err := uc.Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{})
	if err != nil {
		t.Fatalf("delegated account-admin must see member privileges, got %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 privilege, got %d", len(out))
	}
}

// ── SA subject, admin of its home account ────────────────────────────────────
func TestListSubjectPrivileges_1_3_07a_ServiceAccountSubject_OwnerAllowed(t *testing.T) {
	repo := spRepo()
	repo.seedSubjectPrivileges([]domain.SubjectPrivilege{
		spPriv("acb00000000000bind01", "rol_editor", "editor", "project", "prj00000000000projX1", domain.ScopeProject),
	})
	uc := NewListSubjectPrivilegesUseCase(repo).
		WithRelationStore(&denyingFGA{}, nil).
		WithRelationQueries(spVisibleTo(spOwnerID, "acb00000000000bind01"))

	ctx := userCtxAB(spOwnerID) // owner of acc-A, home account of sva-BOT
	out, _, err := uc.Execute(ctx, domain.SubjectTypeServiceAccount, domain.SubjectID(spSAID), repoab.PageFilter{})
	if err != nil {
		t.Fatalf("owner must see SA-subject privileges, got %v", err)
	}
	if len(out) != 1 || out[0].RoleName != "editor" {
		t.Fatalf("expected 1 privilege role_name=editor, got %+v", out)
	}
}

// ── cross-account caller → PERMISSION_DENIED ─────────────────────────────────
func TestListSubjectPrivileges_1_3_08_CrossAccount_PermissionDenied(t *testing.T) {
	repo := spRepo()
	repo.seedSubjectPrivileges([]domain.SubjectPrivilege{
		spPriv("acb00000000000bind01", "rol_v", "viewer", "account", spAccA, domain.ScopeAccount),
	})
	// usr-OTHER lives in acc-B, no owner/admin on acc-A → FGA denies.
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(&denyingFGA{}, nil)

	ctx := userCtxAB(spOtherID)
	out, _, err := uc.Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-account read must be PermissionDenied, got %v", err)
	}
	if out != nil {
		t.Fatalf("no privileges must leak on cross-account denial, got %+v", out)
	}
}

// ── existing subject, 0 bindings → empty list, no error ──────────────────────
func TestListSubjectPrivileges_1_3_09_ZeroBindings_EmptyList(t *testing.T) {
	repo := spRepo()
	// seed empty.
	repo.seedSubjectPrivileges(nil)
	// Порт сужения провязан и НИЧЕГО не разрешает: пустой ответ здесь — свойство
	// пустого перечня, а не сужения. Непровязанный порт — неполадка посадки, и
	// она отказывает независимо от того, сколько строк на странице.
	uc := NewListSubjectPrivilegesUseCase(repo).
		WithRelationStore(&denyingFGA{}, nil).
		WithRelationQueries(newABQueriesStub())

	ctx := userCtxAB(spOwnerID)
	out, next, err := uc.Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{})
	if err != nil {
		t.Fatalf("existing subject with 0 bindings must NOT error, got %v", err)
	}
	if len(out) != 0 || next != "" {
		t.Fatalf("expected empty list + empty token, got %+v / %q", out, next)
	}
}

// ── anonymous caller → fail-closed ───────────────────────────────────────────
func TestListSubjectPrivileges_1_3_10_Anonymous_FailClosed(t *testing.T) {
	repo := spRepo()
	repo.seedSubjectPrivileges([]domain.SubjectPrivilege{
		spPriv("acb00000000000bind01", "rol_v", "viewer", "account", spAccA, domain.ScopeAccount),
	})
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(&denyingFGA{}, nil)

	// api-gateway injects anonymous as {Type:system, ID:anonymous}.
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "anonymous"})
	_, _, err := uc.Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("anonymous caller must fail-closed (PermissionDenied), got %v", err)
	}
}

// ── dangling role → empty role_name, no panic ────────────────────────────────
func TestListSubjectPrivileges_1_3_13_DanglingRole_EmptyName(t *testing.T) {
	repo := spRepo()
	// role_name empty mimics a LEFT JOIN miss (role deleted).
	repo.seedSubjectPrivileges([]domain.SubjectPrivilege{
		spPriv("acb00000000000bind01", "rol_gone", "", "account", spAccA, domain.ScopeAccount),
	})
	uc := NewListSubjectPrivilegesUseCase(repo).
		WithRelationStore(&denyingFGA{}, nil).
		WithRelationQueries(spVisibleTo(spOwnerID, "acb00000000000bind01"))

	ctx := userCtxAB(spOwnerID)
	out, _, err := uc.Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{})
	if err != nil {
		t.Fatalf("dangling role must not error, got %v", err)
	}
	if len(out) != 1 || out[0].RoleName != "" {
		t.Fatalf("dangling role must yield empty role_name, got %+v", out)
	}
}

// ── subject_type=group is in scope (user-requested extension) ────────────────

// ── owner of group's home account sees the group's direct privileges,
// role names resolved (DIRECT derivation; no via-group resolution).
func TestListSubjectPrivileges_1_3b_01_OwnerSeesGroupEnriched(t *testing.T) {
	repo := spRepo()
	repo.seedSubjectPrivileges([]domain.SubjectPrivilege{
		spPriv("acb00000000000bind01", "rol_editor", "editor", "project", "prj00000000000projX1", domain.ScopeProject),
		spPriv("acb00000000000bind02", "rol_viewer", "viewer", "account", spAccA, domain.ScopeAccount),
	})
	uc := NewListSubjectPrivilegesUseCase(repo).
		WithRelationStore(&denyingFGA{}, nil).
		WithRelationQueries(spVisibleTo(spOwnerID, "acb00000000000bind01", "acb00000000000bind02"))

	ctx := userCtxAB(spOwnerID) // owner of acc-A (home account of grp-1)
	out, next, err := uc.Execute(ctx, domain.SubjectTypeGroup, domain.SubjectID(spGroupID), repoab.PageFilter{})
	if err != nil {
		t.Fatalf("owner must see group privileges (DIRECT), got %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 direct privileges, got %d", len(out))
	}
	if out[0].RoleName != "editor" || out[1].RoleName != "viewer" {
		t.Fatalf("group role names must be resolved server-side, got %q / %q", out[0].RoleName, out[1].RoleName)
	}
	if next != "" {
		t.Fatalf("expected empty next_page_token, got %q", next)
	}
}

// ── delegated account-admin (FGA admin on group's home account) ──────────────
func TestListSubjectPrivileges_1_3b_02_AccountAdminViaFGA_Allowed(t *testing.T) {
	repo := spRepo()
	repo.seedSubjectPrivileges([]domain.SubjectPrivilege{
		spPriv("acb00000000000bind01", "rol_v", "viewer", "account", spAccA, domain.ScopeAccount),
	})
	// Точечное отношение, а не «да» на всё: см. 1_3_07 — иначе проба съезжает на
	// полосу надзора облака и о делегированном распорядителе молчит.
	fga := &scopedFGA{allow: map[string]bool{"admin|account:" + spAccA: true}}
	uc := NewListSubjectPrivilegesUseCase(repo).
		WithRelationStore(fga, nil).
		WithRelationQueries(spVisibleTo(spAdminID, "acb00000000000bind01"))

	ctx := userCtxAB(spAdminID) // not owner of acc-A, holds FGA admin on it
	out, _, err := uc.Execute(ctx, domain.SubjectTypeGroup, domain.SubjectID(spGroupID), repoab.PageFilter{})
	if err != nil {
		t.Fatalf("delegated account-admin must see group privileges, got %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 privilege, got %d", len(out))
	}
}

// ── prefix↔type mismatch — a group id passed as subject_type=user is
// rejected (InvalidArgument, first statement, before any repo touch).
func TestListSubjectPrivileges_1_3b_03_GroupIDAsUser_PrefixMismatch_InvalidArgument(t *testing.T) {
	repo := spRepo()
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(newRecordingFGA(), nil)
	ctx := userCtxAB(spOwnerID)

	// valid grp-id but subject_type=user → prefix↔type mismatch.
	_, _, err := uc.Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spGroupID), repoab.PageFilter{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("group id under subject_type=user must be InvalidArgument, got %v", err)
	}
}

// ── nonexistent group subject, caller MAY read it → NOT_FOUND ────────────────
func TestListSubjectPrivileges_1_3b_04_UnknownGroup_NotFound(t *testing.T) {
	repo := spRepo()
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(onlyClusterAdmin(), nil)
	ctx := clusterAdminCtx(spOwnerID)

	ghost := domain.SubjectID("grp00000000000ghost1") // well-formed grp-id, not seeded
	_, _, err := uc.Execute(ctx, domain.SubjectTypeGroup, ghost, repoab.PageFilter{})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("nonexistent well-formed group subject must be NotFound, got %v", err)
	}
}

// ── cross-account caller (no owner/admin on group's home acc) → DENIED ───────
func TestListSubjectPrivileges_1_3b_05_CrossAccount_PermissionDenied(t *testing.T) {
	repo := spRepo()
	repo.seedSubjectPrivileges([]domain.SubjectPrivilege{
		spPriv("acb00000000000bind01", "rol_v", "viewer", "account", spAccA, domain.ScopeAccount),
	})
	// usr-OTHER lives in acc-B; grp-1's home account is acc-A → FGA denies.
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(&denyingFGA{}, nil)

	ctx := userCtxAB(spOtherID)
	out, _, err := uc.Execute(ctx, domain.SubjectTypeGroup, domain.SubjectID(spGroupID), repoab.PageFilter{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-account group read must be PermissionDenied, got %v", err)
	}
	if out != nil {
		t.Fatalf("no privileges must leak on cross-account denial, got %+v", out)
	}
}
