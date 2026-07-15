// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// list_scope_test.go — единая модель видимости (паритет с
// account/serviceAccount/role List). ListUsersUseCase фильтрует через UNION FGA
// viewer ∪ v_list на iam_user:
//
//	visible(iam_user) = ListObjects(subj,"viewer","iam_user")
//	                  ∪ ListObjects(subj,"v_list","iam_user")
//
// Прежняя membership-over-show модель (любой член аккаунта видел ВСЕХ user'ов
// аккаунта) устранена (T3.3 D-5): видны только user'ы с per-object viewer/v_list
// грантом (включая self через self-tuple → viewer-ветку). Инварианты:
// anonymous → empty (до FGA); FGA-ошибка → Unavailable (fail-closed); cluster-admin/
// operator/owner покрыты веткой viewer (tier-cascade); system bootstrap → unfiltered.

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
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	repouser "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
)

const (
	listAcctA    = "acc0000000000000aaaa"
	listMemberID = "usr0000000000000memb"
	listUser1ID  = "usr0000000000000one0"
	listUser2ID  = "usr0000000000000two0"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// scopeUserRepo — fake Repo; `users` is what Users.List returns (the page the
// use-case then intersects with the FGA visible-set).
type scopeUserRepo struct {
	users []domain.User
}

func (f *scopeUserRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &scopeUserReader{parent: f}, nil
}
func (f *scopeUserRepo) Writer(context.Context) (kachorepo.Writer, error) { return nil, nil }
func (f *scopeUserRepo) Close()                                           {}

type scopeUserReader struct{ parent *scopeUserRepo }

func (r *scopeUserReader) Accounts() account.ReaderIface                { return nil }
func (r *scopeUserReader) Projects() project.ReaderIface                { return nil }
func (r *scopeUserReader) Users() repouser.ReaderIface                  { return &scopeUserRdr{parent: r.parent} }
func (r *scopeUserReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *scopeUserReader) Groups() group.ReaderIface                    { return nil }
func (r *scopeUserReader) Roles() role.ReaderIface                      { return nil }
func (r *scopeUserReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *scopeUserReader) Commit(context.Context) error                 { return nil }
func (r *scopeUserReader) Rollback(context.Context) error               { return nil }

type scopeUserRdr struct{ parent *scopeUserRepo }

func (r *scopeUserRdr) Get(context.Context, domain.UserID) (domain.User, error) {
	return domain.User{}, stderrors.New("not found")
}
func (r *scopeUserRdr) GetByExternalID(context.Context, domain.ExternalSubject) (domain.User, error) {
	return domain.User{}, stderrors.New("not found")
}
func (r *scopeUserRdr) GetByEmail(context.Context, domain.Email) (domain.User, error) {
	return domain.User{}, stderrors.New("not found")
}
func (r *scopeUserRdr) List(context.Context, repouser.ListFilter) ([]domain.User, string, error) {
	return r.parent.users, "", nil
}
func (r *scopeUserRdr) GetByAccountEmail(context.Context, domain.AccountID, domain.Email) (domain.User, error) {
	return domain.User{}, stderrors.New("not found")
}
func (r *scopeUserRdr) FindPendingByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (r *scopeUserRdr) FindActiveByExternalID(context.Context, domain.ExternalSubject) ([]domain.User, error) {
	return nil, nil
}
func (r *scopeUserRdr) FindByExternalIDInStatuses(context.Context, domain.ExternalSubject, []domain.InviteStatus) ([]domain.User, error) {
	return nil, nil
}
func (r *scopeUserRdr) FindActiveByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (r *scopeUserRdr) ListAccountsForUser(context.Context, domain.UserID) ([]domain.AccountID, error) {
	return nil, nil
}

// userUnionFGAStub — relation-aware FGA ListObjects stub (viewer vs v_list).
type userUnionFGAStub struct {
	clients.RelationQueries
	idsBy map[string]map[string][]string
	err   error
	calls map[string]int
}

func newUserUnionFGAStub() *userUnionFGAStub {
	return &userUnionFGAStub{idsBy: map[string]map[string][]string{}, calls: map[string]int{}}
}

func (s *userUnionFGAStub) set(relation, subject string, ids []string) {
	if s.idsBy[relation] == nil {
		s.idsBy[relation] = map[string][]string{}
	}
	s.idsBy[relation][subject] = ids
}

func (s *userUnionFGAStub) ListObjects(_ context.Context, subject, relation, _ string,
	_ map[string]any, _ int) ([]string, error) {
	s.calls[relation]++
	if s.err != nil {
		return nil, s.err
	}
	if m := s.idsBy[relation]; m != nil {
		return m[subject], nil
	}
	return nil, nil
}

func userIDs(in []domain.User) []string {
	out := make([]string, 0, len(in))
	for _, u := range in {
		out = append(out, string(u.ID))
	}
	return out
}

func ctxListUser(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: id})
}

func seedListUsers() []domain.User {
	return []domain.User{
		{ID: domain.UserID(listUser1ID), AccountID: listAcctA},
		{ID: domain.UserID(listUser2ID), AccountID: listAcctA},
	}
}

// ── tests ──────────────────────────────────────────────────────────────────

// T3.3-MAT-01 — v_list-only grant (object-only, no viewer) → user VISIBLE.
func TestListUsers_VListOnlyGrant_Visible(t *testing.T) {
	repo := &scopeUserRepo{users: seedListUsers()}
	fga := newUserUnionFGAStub()
	fga.set("v_list", "user:"+listMemberID, []string{listUser1ID})
	fga.set("viewer", "user:"+listMemberID, nil)

	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxListUser(listMemberID), repouser.ListFilter{AccountID: listAcctA})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{listUser1ID}, userIDs(out),
		"v_list-only grant makes the user visible (see-in-selector); the other stays hidden")
	require.GreaterOrEqual(t, fga.calls["v_list"], 1, "must query v_list relation")
}

// T3.3-MAT-01 — viewer grant surfaces the user (account-admin/owner cascade).
func TestListUsers_ViewerGrant_Visible(t *testing.T) {
	repo := &scopeUserRepo{users: seedListUsers()}
	fga := newUserUnionFGAStub()
	fga.set("viewer", "user:"+listMemberID, []string{listUser1ID, listUser2ID})

	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxListUser(listMemberID), repouser.ListFilter{AccountID: listAcctA})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{listUser1ID, listUser2ID}, userIDs(out),
		"owner/admin sees all via viewer tier-cascade (no admin visibility loss)")
}

// T3.3-MAT-02 — membership-over-show устранен: член аккаунта БЕЗ per-object гранта
// НЕ видит user'ов аккаунта (раньше видел всех).
func TestListUsers_MembershipWithoutGrant_Hidden(t *testing.T) {
	repo := &scopeUserRepo{users: seedListUsers()}
	fga := newUserUnionFGAStub() // no grants at all
	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxListUser(listMemberID), repouser.ListFilter{AccountID: listAcctA})
	require.NoError(t, err)
	assert.Empty(t, out, "membership-over-show устранен: без per-object гранта user не виден")
}

// T3.3-MAT-02 — self-floor: member видит себя (self-tuple резолвит viewer-ветку).
func TestListUsers_SelfVisible(t *testing.T) {
	repo := &scopeUserRepo{users: []domain.User{
		{ID: domain.UserID(listMemberID), AccountID: listAcctA},
		{ID: domain.UserID(listUser1ID), AccountID: listAcctA},
	}}
	fga := newUserUnionFGAStub()
	// self-tuple iam_user:<member>#subject@user:<member> резолвится в viewer-ветку.
	fga.set("viewer", "user:"+listMemberID, []string{listMemberID})
	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxListUser(listMemberID), repouser.ListFilter{AccountID: listAcctA})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{listMemberID}, userIDs(out),
		"member видит себя (self-floor); чужого user'а без гранта — нет")
}

// Self-floor — code-level, НЕ зависит от FGA-материализации: юзер БЕЗ единого
// viewer/v_list-гранта на себя (отсутствует/протух subject self-tuple) все равно
// видит собственную запись. Паритет с GetUser.IsSelf. Гонять с ПУСТЫМ FGA-стабом:
// без code-floor visible пуст → self отфильтровывается → юзер не видит даже себя.
func TestListUsers_SelfFloor_NoFGATuple(t *testing.T) {
	repo := &scopeUserRepo{users: []domain.User{
		{ID: domain.UserID(listMemberID), AccountID: listAcctA},
		{ID: domain.UserID(listUser1ID), AccountID: listAcctA},
	}}
	fga := newUserUnionFGAStub() // пусто: ни viewer, ни v_list, ни self-tuple
	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxListUser(listMemberID), repouser.ListFilter{AccountID: listAcctA})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{listMemberID}, userIDs(out),
		"self-floor: юзер видит себя даже без FGA-гранта; чужого без гранта — нет")
}

// Self-floor НЕ применяется к service-account-принципалу (SA — не iam_user): SA без
// гранта не «видит себя» в списке user'ов.
func TestListUsers_SelfFloor_ServiceAccountPrincipal_NoSelf(t *testing.T) {
	repo := &scopeUserRepo{users: seedListUsers()}
	fga := newUserUnionFGAStub()
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: listUser1ID})
	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctx, repouser.ListFilter{AccountID: listAcctA})
	require.NoError(t, err)
	assert.Empty(t, out, "SA-принципал не получает user-self-floor")
}

// T3.3-AUTHZ-01 — anonymous → empty ДО любого FGA-вызова.
func TestListUsers_AnonymousEmpty(t *testing.T) {
	repo := &scopeUserRepo{users: seedListUsers()}
	fga := newUserUnionFGAStub()
	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(context.Background(), repouser.ListFilter{AccountID: listAcctA})
	require.NoError(t, err)
	assert.Empty(t, out)
	assert.Zero(t, fga.calls["viewer"], "anonymous short-circuits before FGA")
}

// T3.3-AUTHZ-02 — FGA-ошибка на любой relation → Unavailable (fail-closed).
func TestListUsers_FGAUnavailable_FailClosed(t *testing.T) {
	repo := &scopeUserRepo{users: seedListUsers()}
	fga := newUserUnionFGAStub()
	fga.err = stderrors.New("openfga listObjects: status 503")
	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxListUser(listMemberID), repouser.ListFilter{AccountID: listAcctA})
	require.Error(t, err)
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code())
}
