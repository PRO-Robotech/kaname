// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service_account

// list_scope_test.go — единая модель видимости (паритет с account/list_vlist_union).
// ListServiceAccountsUseCase фильтрует через UNION FGA viewer ∪ v_list на
// iam_service_account:
//
//	visible(iam_service_account) = ListObjects(subj,"viewer","iam_service_account")
//	                             ∪ ListObjects(subj,"v_list","iam_service_account")
//
// Прежняя membership-over-show модель (любой член аккаунта видел ВСЕ SA аккаунта)
// устранена: видны только SA с per-object viewer/v_list-грантом. Инварианты:
// anonymous → empty (до FGA); FGA-ошибка → Unavailable (fail-closed); cluster-admin/
// operator покрыты веткой viewer (system_viewer floor).

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
	reposa "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
)

const (
	scopeAcctA  = "acc0000000000000aaaa"
	scopeUserID = "usr0000000000000user"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// scopeSARepo — fake Repo; `sas` is what ServiceAccounts.List returns (the page
// the use-case then intersects with the FGA visible-set).
type scopeSARepo struct {
	sas []domain.ServiceAccount
}

func (f *scopeSARepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &scopeSAReader{parent: f}, nil
}
func (f *scopeSARepo) Writer(context.Context) (kachorepo.Writer, error) { return nil, nil }
func (f *scopeSARepo) Close()                                           {}

type scopeSAReader struct{ parent *scopeSARepo }

func (r *scopeSAReader) Accounts() account.ReaderIface { return nil }
func (r *scopeSAReader) Projects() project.ReaderIface { return nil }
func (r *scopeSAReader) Users() user.ReaderIface       { return nil }
func (r *scopeSAReader) ServiceAccounts() reposa.ReaderIface {
	return &scopeSARdr{parent: r.parent}
}
func (r *scopeSAReader) Groups() group.ReaderIface                  { return nil }
func (r *scopeSAReader) Roles() role.ReaderIface                    { return nil }
func (r *scopeSAReader) AccessBindings() access_binding.ReaderIface { return nil }
func (r *scopeSAReader) Commit(context.Context) error               { return nil }
func (r *scopeSAReader) Rollback(context.Context) error             { return nil }

type scopeSARdr struct{ parent *scopeSARepo }

func (r *scopeSARdr) Get(context.Context, domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return domain.ServiceAccount{}, nil
}
func (r *scopeSARdr) List(context.Context, reposa.ListFilter) ([]domain.ServiceAccount, string, error) {
	return r.parent.sas, "", nil
}

// saUnionFGAStub — relation-aware FGA ListObjects stub (viewer vs v_list).
type saUnionFGAStub struct {
	clients.RelationQueries
	idsBy map[string]map[string][]string
	err   error
	calls map[string]int
}

func newSAUnionFGAStub() *saUnionFGAStub {
	return &saUnionFGAStub{idsBy: map[string]map[string][]string{}, calls: map[string]int{}}
}

func (s *saUnionFGAStub) set(relation, subject string, ids []string) {
	if s.idsBy[relation] == nil {
		s.idsBy[relation] = map[string][]string{}
	}
	s.idsBy[relation][subject] = ids
}

func (s *saUnionFGAStub) ListObjects(_ context.Context, subject, relation, _ string,
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

func saIDs(in []domain.ServiceAccount) []string {
	out := make([]string, 0, len(in))
	for _, sa := range in {
		out = append(out, string(sa.ID))
	}
	return out
}

func ctxUser(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: id})
}

// ── tests ──────────────────────────────────────────────────────────────────

// T3.3 — v_list-only grant (object-only, no viewer) → SA VISIBLE.
func TestListServiceAccounts_VListOnlyGrant_Visible(t *testing.T) {
	repo := &scopeSARepo{sas: []domain.ServiceAccount{
		{ID: "sva0000000000000xxxx", AccountID: scopeAcctA},
		{ID: "sva0000000000000yyyy", AccountID: scopeAcctA},
	}}
	fga := newSAUnionFGAStub()
	fga.set("v_list", "user:"+scopeUserID, []string{"sva0000000000000xxxx"})
	fga.set("viewer", "user:"+scopeUserID, nil)

	uc := NewListServiceAccountsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser(scopeUserID), reposa.ListFilter{AccountID: scopeAcctA})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"sva0000000000000xxxx"}, saIDs(out),
		"v_list-only grant makes the SA visible (see-in-selector), the other stays hidden")
	require.GreaterOrEqual(t, fga.calls["v_list"], 1, "must query v_list relation")
}

// T3.3 — viewer grant surfaces the SA (account-admin cascade).
func TestListServiceAccounts_ViewerGrant_Visible(t *testing.T) {
	repo := &scopeSARepo{sas: []domain.ServiceAccount{
		{ID: "sva0000000000000xxxx", AccountID: scopeAcctA},
	}}
	fga := newSAUnionFGAStub()
	fga.set("viewer", "user:"+scopeUserID, []string{"sva0000000000000xxxx"})

	uc := NewListServiceAccountsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser(scopeUserID), reposa.ListFilter{AccountID: scopeAcctA})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"sva0000000000000xxxx"}, saIDs(out))
}

// T3.3 — membership-over-show устранен: член аккаунта БЕЗ per-object гранта НЕ
// видит SA аккаунта (раньше видел все).
func TestListServiceAccounts_MembershipWithoutGrant_Hidden(t *testing.T) {
	repo := &scopeSARepo{sas: []domain.ServiceAccount{
		{ID: "sva0000000000000xxxx", AccountID: scopeAcctA},
	}}
	fga := newSAUnionFGAStub() // no grants at all
	uc := NewListServiceAccountsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser(scopeUserID), reposa.ListFilter{AccountID: scopeAcctA})
	require.NoError(t, err)
	assert.Empty(t, out, "membership-over-show устранен: без per-object гранта SA не виден")
}

// T3.3 — anonymous → empty ДО любого FGA-вызова.
func TestListServiceAccounts_AnonymousEmpty(t *testing.T) {
	repo := &scopeSARepo{sas: []domain.ServiceAccount{
		{ID: "sva0000000000000xxxx", AccountID: scopeAcctA},
	}}
	fga := newSAUnionFGAStub()
	uc := NewListServiceAccountsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(context.Background(), reposa.ListFilter{AccountID: scopeAcctA})
	require.NoError(t, err)
	assert.Empty(t, out)
	assert.Zero(t, fga.calls["viewer"], "anonymous short-circuits before FGA")
}

// T3.3 — FGA-ошибка на любой relation → Unavailable (fail-closed, INV-7).
func TestListServiceAccounts_FGAUnavailable_FailClosed(t *testing.T) {
	repo := &scopeSARepo{sas: []domain.ServiceAccount{
		{ID: "sva0000000000000xxxx", AccountID: scopeAcctA},
	}}
	fga := newSAUnionFGAStub()
	fga.err = stderrors.New("openfga listObjects: status 503")
	uc := NewListServiceAccountsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser(scopeUserID), reposa.ListFilter{AccountID: scopeAcctA})
	require.Error(t, err)
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code())
}
