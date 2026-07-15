// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list_vlist_floor_test.go — unit-тесты D-6 модели видимости AccessBinding:
//
//	visible(iam_access_binding) = viewer ∪ v_list ∪ self/granted-floor
//
// label-селектор материализует v_list на matching-binding'и (T3.3-AB-01), но
// существующие self (ListBySubject) / granted (ListByScope/ListByAccount owner|admin)
// floor'ы НЕ урезаются — они дополняют union. Fail-closed: FGA ListObjects-ошибка
// на v_list-ветке → UNAVAILABLE (никогда unfiltered leak / never owner-only fallback).
//
// Реальный материализационный путь — integration (pg/access_binding_labels_integration_test.go);
// здесь — что use-case применяет union-floor с сохранением self/granted.

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// abQueriesStub — relation-aware ListObjects stub on iam_access_binding (viewer / v_list).
type abQueriesStub struct {
	clients.RelationQueries
	idsBy map[string]map[string][]string // [relation][subject] = ids
	err   error
}

func newABQueriesStub() *abQueriesStub {
	return &abQueriesStub{idsBy: map[string]map[string][]string{}}
}

func (s *abQueriesStub) set(relation, subject string, ids []string) {
	if s.idsBy[relation] == nil {
		s.idsBy[relation] = map[string][]string{}
	}
	s.idsBy[relation][subject] = ids
}

func (s *abQueriesStub) ListObjects(_ context.Context, subject, relation, objType string,
	_ map[string]any, _ int) ([]string, error) {
	if objType != "iam_access_binding" {
		return nil, nil
	}
	if s.err != nil {
		return nil, s.err
	}
	if m := s.idsBy[relation]; m != nil {
		return m[subject], nil
	}
	return nil, nil
}

// seedABListByScope replaces the fixture rows returned by the fake ListByScope.
func seedABListByScope(repo *abFakeRepo, rows []domain.AccessBinding) {
	repo.mu.Lock()
	repo.lbsRows = rows
	repo.mu.Unlock()
}

// ── T3.3-AB-01: a label-grant holder (v_list on the matching binding) sees the
// labeled binding via the union floor; the existing granted-floor (ListByScope
// owner/admin) is NOT dropped. ───────────────────────────────────────────────────

func TestABListByScope_T33AB01_VListUnionFloor(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_ab01", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	acb1 := domain.AccessBinding{ID: "acb000000000000prod1", ResourceType: "account", ResourceID: accountID, SubjectID: "usr_x", Labels: domain.Labels{"stage": "prod"}}
	acb2 := domain.AccessBinding{ID: "acb0000000000000dev2", ResourceType: "account", ResourceID: accountID, SubjectID: "usr_y", Labels: domain.Labels{"stage": "dev"}}
	seedABListByScope(repo, []domain.AccessBinding{acb1, acb2})

	// usr_member is NOT the owner (no granted-floor here) but holds v_list on acb1.
	fga := newABQueriesStub()
	fga.set("v_list", "user:usr_member", []string{"acb000000000000prod1"})

	// Check-stub grants nothing → usr_member is NOT a grant-authority → the union floor
	// (v_list) is the sole visibility path under test.
	uc := NewListByScopeUseCase(repo).
		WithRelationStore(&scopedFGA{allow: map[string]bool{}}, nil).
		WithRelationQueries(fga)

	// usr_member passes the catalog/anti-anon guard but is NOT a grant-authority; the
	// scope-list nonetheless surfaces the v_list-matched binding through the union.
	out, _, err := uc.Execute(newOwnerContext("usr_member"), "account", accountID, repoab.PageFilter{PageSize: 100})
	require.NoError(t, err)
	ids := abIDs(out)
	assert.Contains(t, ids, "acb000000000000prod1", "v_list-matched labeled binding is visible (union floor)")
	assert.NotContains(t, ids, "acb0000000000000dev2", "non-matching binding stays hidden for a v_list-only caller")
}

// owner keeps full granted-floor visibility (ALL bindings on the scope) even without
// any label grant — the union must NOT shrink the existing owner floor (D-6 not-negotiable).
func TestABListByScope_T33AB01_OwnerFloorPreserved(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_ab01o", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	acb1 := domain.AccessBinding{ID: "acb000000000000prod1", ResourceType: "account", ResourceID: accountID, Labels: domain.Labels{"stage": "prod"}}
	acb2 := domain.AccessBinding{ID: "acb0000000000000dev2", ResourceType: "account", ResourceID: accountID, Labels: domain.Labels{"stage": "dev"}}
	seedABListByScope(repo, []domain.AccessBinding{acb1, acb2})

	fga := newABQueriesStub() // owner has NO label grant
	uc := NewListByScopeUseCase(repo).
		WithRelationStore(newRecordingFGA(), nil).
		WithRelationQueries(fga)

	out, _, err := uc.Execute(newOwnerContext(ownerID), "account", accountID, repoab.PageFilter{PageSize: 100})
	require.NoError(t, err)
	ids := abIDs(out)
	assert.ElementsMatch(t, []string{"acb000000000000prod1", "acb0000000000000dev2"}, ids,
		"owner (granted-floor) still sees ALL bindings on the scope — union does not shrink the floor")
}

// T3.3-AB-01 anti-leak: a total stranger — NO grant-authority on the scope AND NO
// label-visibility (empty v_list set) — must get PermissionDenied, NOT an empty 200.
// Forbidden-vs-empty must be indistinguishable to a caller who may not learn the
// scope exists (the union floor collapsing to ∅ falls back to deny, never a leaky
// empty list). RED if the use-case were to return (nil, nil) here instead of deny.
func TestABListByScope_T33AB01_StrangerNoVisibilityDenied(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_ab01s", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	acb1 := domain.AccessBinding{ID: "acb000000000000prod1", ResourceType: "account", ResourceID: accountID, Labels: domain.Labels{"stage": "prod"}}
	seedABListByScope(repo, []domain.AccessBinding{acb1})

	// usr_stranger holds NO v_list on any binding (empty stub) …
	fga := newABQueriesStub()
	uc := NewListByScopeUseCase(repo).
		// … and is NOT a grant-authority (Check grants nothing).
		WithRelationStore(&scopedFGA{allow: map[string]bool{}}, nil).
		WithRelationQueries(fga)

	out, _, err := uc.Execute(newOwnerContext("usr_stranger"), "account", accountID, repoab.PageFilter{PageSize: 100})
	require.Error(t, err, "stranger with no authority and no v_list must NOT get an empty 200")
	assert.Nil(t, out, "no rows leaked to a denied caller")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code(),
		"empty union floor + no authority → PermissionDenied (forbidden indistinguishable from empty)")
}

// T3.3-AUTHZ-02: FGA ListObjects error on the v_list union branch → UNAVAILABLE
// (fail-closed; never unfiltered leak, never owner-only fallback).
func TestABListByScope_T33AUTHZ02_FGAErrorUnavailable(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_ab02", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	seedABListByScope(repo, []domain.AccessBinding{{ID: "acb000000000000prod1", ResourceType: "account", ResourceID: accountID}})

	fga := newABQueriesStub()
	fga.err = stderrors.New("fga down")

	uc := NewListByScopeUseCase(repo).
		WithRelationStore(&scopedFGA{allow: map[string]bool{}}, nil).
		WithRelationQueries(fga)

	// A non-owner caller relies on the v_list branch; an FGA error must fail closed.
	_, _, err := uc.Execute(newOwnerContext("usr_member"), "account", accountID, repoab.PageFilter{PageSize: 100})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code(),
		"FGA ListObjects error on v_list union → UNAVAILABLE (fail-closed)")
}

// abIDs extracts the binding ids from a result slice.
func abIDs(in []domain.AccessBinding) []string {
	out := make([]string, 0, len(in))
	for _, b := range in {
		out = append(out, string(b.ID))
	}
	return out
}
