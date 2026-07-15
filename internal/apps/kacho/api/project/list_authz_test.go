// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_authz_test.go — RBAC v2 list-filter unit tests for ProjectService.List.
//
// Canonical scenario: a subject with `iam.project.prj-a.read` +
// `iam.project.prj-b.read` grants must see ONLY prj-A and prj-B on
// `GET /projects` — never prj-C. Resource existence must not be disclosed.
package project

import (
	"context"
	stderrors "errors"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	repoaccount "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	repoproject "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
)

// ───────────── fake repo built specifically for list scenarios ───────────

type listFakeRepo struct {
	accounts map[string]domain.Account
	projects map[string]domain.Project
}

func newListFakeRepo() *listFakeRepo {
	return &listFakeRepo{
		accounts: map[string]domain.Account{},
		projects: map[string]domain.Project{},
	}
}

func (f *listFakeRepo) Reader(ctx context.Context) (kachorepo.Reader, error) {
	return &listFakeReader{f}, nil
}
func (f *listFakeRepo) Writer(ctx context.Context) (kachorepo.Writer, error) {
	return nil, stderrors.New("fake.Writer not used in list tests")
}
func (f *listFakeRepo) Close() {}

type listFakeReader struct{ p *listFakeRepo }

func (r *listFakeReader) Accounts() repoaccount.ReaderIface            { return &listFakeAcctReader{r.p} }
func (r *listFakeReader) Projects() repoproject.ReaderIface            { return &listFakeProjReader{r.p} }
func (r *listFakeReader) Users() user.ReaderIface                      { return nil }
func (r *listFakeReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *listFakeReader) Groups() group.ReaderIface                    { return nil }
func (r *listFakeReader) Roles() role.ReaderIface                      { return nil }
func (r *listFakeReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *listFakeReader) Commit(context.Context) error                 { return nil }
func (r *listFakeReader) Rollback(context.Context) error               { return nil }

type listFakeAcctReader struct{ p *listFakeRepo }

func (a *listFakeAcctReader) Get(ctx context.Context, id domain.AccountID) (domain.Account, error) {
	if acc, ok := a.p.accounts[string(id)]; ok {
		return acc, nil
	}
	return domain.Account{}, stderrors.New("not found")
}
func (a *listFakeAcctReader) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (a *listFakeAcctReader) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}
func (a *listFakeAcctReader) List(ctx context.Context, f repoaccount.ListFilter) ([]domain.Account, string, error) {
	out := make([]domain.Account, 0, len(a.p.accounts))
	keys := make([]string, 0, len(a.p.accounts))
	for k := range a.p.accounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, a.p.accounts[k])
	}
	return out, "", nil
}

type listFakeProjReader struct{ p *listFakeRepo }

func (pr *listFakeProjReader) Get(ctx context.Context, id domain.ProjectID) (domain.Project, error) {
	if proj, ok := pr.p.projects[string(id)]; ok {
		return proj, nil
	}
	return domain.Project{}, stderrors.New("not found")
}
func (pr *listFakeProjReader) List(ctx context.Context, f repoproject.ListFilter) ([]domain.Project, string, error) {
	out := make([]domain.Project, 0, len(pr.p.projects))
	keys := make([]string, 0, len(pr.p.projects))
	for k := range pr.p.projects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, pr.p.projects[k])
	}
	return out, "", nil
}
func (pr *listFakeProjReader) CountByAccount(context.Context, domain.AccountID) (int64, error) {
	return 0, nil
}

// outbox is only needed if we exercise writers — but list tests never
// touch the Writer, so just make the iface available.

func seedAccount(r *listFakeRepo, accID, owner string) {
	r.accounts[accID] = domain.Account{
		ID: domain.AccountID(accID), Name: domain.AccountName("n-" + accID),
		OwnerUserID: domain.UserID(owner), CreatedAt: time.Now().UTC(),
	}
}

func seedProject(r *listFakeRepo, prjID, accID string) {
	r.projects[prjID] = domain.Project{
		ID: domain.ProjectID(prjID), Name: domain.ProjectName("n-" + prjID),
		AccountID: domain.AccountID(accID), CreatedAt: time.Now().UTC(),
	}
}

// ───────────── FGA ListObjects stub ─────────────

type relationQueriesStub struct {
	clients.RelationQueries
	allowedIDs []string
	called     struct{ subject, relation, objectType string }
	relations  []string // every relation queried (visibility union viewer ∪ v_list)
}

func (s *relationQueriesStub) ListObjects(ctx context.Context, subject, relation, objectType string,
	condCtx map[string]any, maxResults int) ([]string, error) {
	s.called.subject = subject
	s.called.relation = relation
	s.called.objectType = objectType
	s.relations = append(s.relations, relation)
	return s.allowedIDs, nil
}

// ctxAs — populate caller principal.
func ctxAs(uid string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{
		Type: "user", ID: uid,
	})
}

// ───────────── tests ─────────────

// CanonicalScenarioFromTheTask — the literal user-story. Bob has been granted
// `iam.project.prj-a.read` and `iam.project.prj-b.read` and nothing else.
// `GET /projects` must return ONLY prj-A and prj-B. prj-C must not appear
// (resource-existence disclosure guard).
func TestListProjects_RBACv2_CanonicalScenario_GrantsConcreteIDs(t *testing.T) {
	repo := newListFakeRepo()
	// All three projects live in acc-other; usr-bob does NOT own it, so the
	// pre-RBAC-v2 owner-based filter would return nothing.
	seedAccount(repo, "acc-other", "usr-other")
	seedProject(repo, "prj-a", "acc-other")
	seedProject(repo, "prj-b", "acc-other")
	seedProject(repo, "prj-c", "acc-other") // MUST remain hidden

	fga := &relationQueriesStub{allowedIDs: []string{"prj-a", "prj-b"}}

	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxAs("usr-bob"), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err)

	ids := make([]string, 0, len(out))
	for _, p := range out {
		ids = append(ids, string(p.ID))
	}
	require.ElementsMatch(t, []string{"prj-a", "prj-b"}, ids,
		"list must contain ONLY the granted ids; prj-c must remain hidden (no existence disclosure)")

	require.Equal(t, "user:usr-bob", fga.called.subject)
	require.Equal(t, "project", fga.called.objectType)
	// visibility unions viewer ∪ v_list — both relations queried.
	require.ElementsMatch(t, []string{"viewer", "v_list"}, fga.relations,
		"P7 list-filter must query BOTH viewer and v_list (union)")
}

// NoGrantsReturnsEmpty — resource-existence disclosure guard: a subject
// with neither AccessBindings nor owned accounts gets an empty list, NOT
// PermissionDenied (he must not learn that any project exists at all).
func TestListProjects_RBACv2_NoGrants_ReturnsEmpty(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-other", "usr-other")
	seedProject(repo, "prj-a", "acc-other")
	seedProject(repo, "prj-b", "acc-other")

	fga := &relationQueriesStub{allowedIDs: nil}

	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxAs("usr-nobody"), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.Empty(t, out, "no grants + non-owner → empty list, not 403")
}

// OwnerKeepsBackwardCompatibility — owning the parent Account still
// surfaces every project in that account, even without an AccessBinding.
// RBAC v2 grants are additive on top of owner-based visibility.
func TestListProjects_RBACv2_OwnerSeesUngrantedProjects(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-alice", "usr-alice")
	seedProject(repo, "prj-x", "acc-alice")
	seedProject(repo, "prj-y", "acc-alice")

	fga := &relationQueriesStub{allowedIDs: nil}

	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxAs("usr-alice"), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err)

	ids := make([]string, 0, len(out))
	for _, p := range out {
		ids = append(ids, string(p.ID))
	}
	require.ElementsMatch(t, []string{"prj-x", "prj-y"}, ids)
}

// OwnerPlusGrants — union of owner-visibility and AccessBinding-grants.
func TestListProjects_RBACv2_OwnerPlusGrants(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-alice", "usr-alice")
	seedAccount(repo, "acc-bob", "usr-bob")
	seedProject(repo, "prj-alice-1", "acc-alice")
	seedProject(repo, "prj-bob-1", "acc-bob")
	seedProject(repo, "prj-bob-2", "acc-bob") // hidden — alice has no grant on this one

	fga := &relationQueriesStub{allowedIDs: []string{"prj-bob-1"}}

	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxAs("usr-alice"), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err)

	ids := make([]string, 0, len(out))
	for _, p := range out {
		ids = append(ids, string(p.ID))
	}
	require.ElementsMatch(t, []string{"prj-alice-1", "prj-bob-1"}, ids,
		"alice sees her own project + bob's granted project; bob-2 stays hidden")
}
