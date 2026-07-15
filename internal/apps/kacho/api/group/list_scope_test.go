// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

// list_scope_test.go — единая модель видимости GroupService.List (паритет с
// account/project/service_account/role List). Результат фильтруется через UNION
// FGA-отношений на iam_group:
//
//	visible(iam_group) = ListObjects(subj,"viewer","iam_group")
//	                   ∪ ListObjects(subj,"v_list","iam_group")
//
//   - ветка viewer — группы, на которые принципал держит viewer-tier;
//   - ветка v_list — группы, выданные ТОЛЬКО `iam.group.{get,list}` через
//     names/labels-селектор (object-only `iam_group:<id> # v_list @ subj`,
//     see-in-selector-without-content).
//
// Устраняет over-show: прежде List возвращал ВСЕ группы аккаунта любому держателю
// account#v_list (account-tier не каскадит в iam_group viewer/v_list — DIRECT-only).
// Инварианты: anonymous → empty (до FGA); не-forwarded principal (system/bootstrap
// fallback) → тоже empty (fail-closed); FGA-ошибка → Unavailable (fail-closed).

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	repogroup "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
)

const (
	grpScopeAcct = "acc0000000000000aaaa"
	grpScopeUser = "usr0000000000000user"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// scopeGroupRepo — fake Repo; `groups` is what Groups.List returns (the page the
// use-case then intersects with the FGA visible-set).
type scopeGroupRepo struct {
	groups []domain.Group
}

func (f *scopeGroupRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &scopeGroupReader{parent: f}, nil
}
func (f *scopeGroupRepo) Writer(context.Context) (kachorepo.Writer, error) { return nil, nil }
func (f *scopeGroupRepo) Close()                                           {}

type scopeGroupReader struct{ parent *scopeGroupRepo }

func (r *scopeGroupReader) Accounts() account.ReaderIface { return nil }
func (r *scopeGroupReader) Projects() project.ReaderIface { return nil }
func (r *scopeGroupReader) Users() user.ReaderIface       { return nil }
func (r *scopeGroupReader) ServiceAccounts() service_account.ReaderIface {
	return nil
}
func (r *scopeGroupReader) Groups() repogroup.ReaderIface {
	return &scopeGroupRdr{parent: r.parent}
}
func (r *scopeGroupReader) Roles() role.ReaderIface                    { return nil }
func (r *scopeGroupReader) AccessBindings() access_binding.ReaderIface { return nil }
func (r *scopeGroupReader) Commit(context.Context) error               { return nil }
func (r *scopeGroupReader) Rollback(context.Context) error             { return nil }

type scopeGroupRdr struct{ parent *scopeGroupRepo }

func (r *scopeGroupRdr) Get(context.Context, domain.GroupID) (domain.Group, error) {
	return domain.Group{}, nil
}
func (r *scopeGroupRdr) List(context.Context, repogroup.ListFilter) ([]domain.Group, string, error) {
	return r.parent.groups, "", nil
}
func (r *scopeGroupRdr) ListMembers(context.Context, domain.GroupID) ([]domain.GroupMember, error) {
	return nil, nil
}
func (r *scopeGroupRdr) IsMember(context.Context, domain.GroupID, domain.SubjectType, domain.SubjectID) (bool, error) {
	return false, nil
}

// groupUnionFGAStub — relation-aware FGA ListObjects stub (viewer vs v_list).
type groupUnionFGAStub struct {
	clients.RelationQueries
	idsBy map[string]map[string][]string
	err   error
	calls map[string]int
}

func newGroupUnionFGAStub() *groupUnionFGAStub {
	return &groupUnionFGAStub{idsBy: map[string]map[string][]string{}, calls: map[string]int{}}
}

func (s *groupUnionFGAStub) set(relation, subject string, ids []string) {
	if s.idsBy[relation] == nil {
		s.idsBy[relation] = map[string][]string{}
	}
	s.idsBy[relation][subject] = ids
}

func (s *groupUnionFGAStub) ListObjects(_ context.Context, subject, relation, objectType string,
	_ map[string]any, _ int) ([]string, error) {
	s.calls[relation]++
	if objectType != "iam_group" {
		return nil, stderrors.New("unexpected FGA object type: " + objectType)
	}
	if s.err != nil {
		return nil, s.err
	}
	if m := s.idsBy[relation]; m != nil {
		return m[subject], nil
	}
	return nil, nil
}

func grpIDs(in []domain.Group) []string {
	out := make([]string, 0, len(in))
	for _, g := range in {
		out = append(out, string(g.ID))
	}
	return out
}

func ctxGrpUser(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: id})
}

// ── tests ──────────────────────────────────────────────────────────────────

// Exact-set: grant на ПОДМНОЖЕСТВО групп аккаунта → List возвращает РОВНО это
// подмножество (over-show устранен: неграненые группы скрыты). Зеркалит newman
// IAM-SET-GRP-LABEL-EXACT-OK (M+ видимы, M−/baz скрыты).
func TestListGroups_ExactSet_OnlyGrantedSubset(t *testing.T) {
	repo := &scopeGroupRepo{groups: []domain.Group{
		{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
		{ID: "grp0000000000000bbbb", AccountID: grpScopeAcct},
		{ID: "grp0000000000000cccc", AccountID: grpScopeAcct},
	}}
	fga := newGroupUnionFGAStub()
	fga.set("viewer", "user:"+grpScopeUser, []string{"grp0000000000000aaaa"})
	fga.set("v_list", "user:"+grpScopeUser, []string{"grp0000000000000bbbb"})

	uc := NewListGroupsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxGrpUser(grpScopeUser), repogroup.ListFilter{AccountID: grpScopeAcct})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"grp0000000000000aaaa", "grp0000000000000bbbb"}, grpIDs(out),
		"List returns EXACTLY the viewer∪v_list-granted subset; the ungranted group stays hidden")
}

// v_list-only grant (object-only, без viewer) → группа ВИДНА (see-in-selector).
func TestListGroups_VListOnlyGrant_Visible(t *testing.T) {
	repo := &scopeGroupRepo{groups: []domain.Group{
		{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
		{ID: "grp0000000000000bbbb", AccountID: grpScopeAcct},
	}}
	fga := newGroupUnionFGAStub()
	fga.set("v_list", "user:"+grpScopeUser, []string{"grp0000000000000aaaa"})
	fga.set("viewer", "user:"+grpScopeUser, nil)

	uc := NewListGroupsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxGrpUser(grpScopeUser), repogroup.ListFilter{AccountID: grpScopeAcct})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"grp0000000000000aaaa"}, grpIDs(out),
		"v_list-only grant делает группу видимой, вторая остается скрытой")
	require.GreaterOrEqual(t, fga.calls["v_list"], 1, "must query v_list relation")
}

// viewer grant выводит группу (account-admin cascade).
func TestListGroups_ViewerGrant_Visible(t *testing.T) {
	repo := &scopeGroupRepo{groups: []domain.Group{
		{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
	}}
	fga := newGroupUnionFGAStub()
	fga.set("viewer", "user:"+grpScopeUser, []string{"grp0000000000000aaaa"})

	uc := NewListGroupsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxGrpUser(grpScopeUser), repogroup.ListFilter{AccountID: grpScopeAcct})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"grp0000000000000aaaa"}, grpIDs(out))
}

// over-show устранен: член аккаунта БЕЗ per-object гранта НЕ видит группу аккаунта
// (раньше account#v_list-держатель видел все группы).
func TestListGroups_MembershipWithoutGrant_Hidden(t *testing.T) {
	repo := &scopeGroupRepo{groups: []domain.Group{
		{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
	}}
	fga := newGroupUnionFGAStub() // no grants at all
	uc := NewListGroupsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxGrpUser(grpScopeUser), repogroup.ListFilter{AccountID: grpScopeAcct})
	require.NoError(t, err)
	assert.Empty(t, out, "без per-object гранта группа не видна (over-show устранен)")
}

// anonymous → empty ДО любого FGA-вызова (fail-closed).
func TestListGroups_AnonymousEmpty(t *testing.T) {
	repo := &scopeGroupRepo{groups: []domain.Group{
		{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
	}}
	fga := newGroupUnionFGAStub()
	uc := NewListGroupsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(context.Background(), repogroup.ListFilter{AccountID: grpScopeAcct})
	require.NoError(t, err)
	assert.Empty(t, out)
	assert.Zero(t, fga.calls["viewer"], "anonymous short-circuits before FGA")
}

// FGA-ошибка на любой relation → Unavailable (fail-closed, никогда partial).
func TestListGroups_FGAUnavailable_FailClosed(t *testing.T) {
	repo := &scopeGroupRepo{groups: []domain.Group{
		{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
	}}
	fga := newGroupUnionFGAStub()
	fga.err = stderrors.New("openfga listObjects: status 503")
	uc := NewListGroupsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxGrpUser(grpScopeUser), repogroup.ListFilter{AccountID: grpScopeAcct})
	require.Error(t, err)
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code())
}

// non-forwarded principal (api-gateway не передал заголовки → system/bootstrap
// fallback) трактуется authzguard.IsAnonymous как anonymous → empty ДО FGA
// (fail-closed, паритет с account/project/role/SA List — без unfiltered-обхода).
func TestListGroups_SystemBootstrapFallback_FailClosed(t *testing.T) {
	repo := &scopeGroupRepo{groups: []domain.Group{
		{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
		{ID: "grp0000000000000bbbb", AccountID: grpScopeAcct},
	}}
	fga := newGroupUnionFGAStub()
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: domain.PrincipalTypeSystem, ID: domain.PrincipalIDBootstrap})
	uc := NewListGroupsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctx, repogroup.ListFilter{AccountID: grpScopeAcct})
	require.NoError(t, err)
	assert.Empty(t, out, "system/bootstrap fallback → anonymous → empty (fail-closed)")
	assert.Zero(t, fga.calls["viewer"], "short-circuits before FGA")
}
