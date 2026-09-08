// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// list_authz_test.go — RBAC v2 list-filter unit tests for ProjectService.List.
//
// Canonical scenario: a subject with `iam.project.prj-a.read` +
// `iam.project.prj-b.read` grants must see ONLY prj-A and prj-B on
// `GET /projects` — never prj-C. Resource existence must not be disclosed.
package project

import (
	"context"
	stderrors "errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/authzfilter"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	repoaccount "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	repoproject "github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

// ───────────── fake repo built specifically for list scenarios ───────────

type listFakeRepo struct {
	accounts map[string]domain.Account
	projects map[string]domain.Project
	// acctGets — how many account lookups one listing costs. The number is part of
	// the contract being asserted: it must be bounded by the PAGE, never by the
	// population of the cluster.
	acctGets int
}

func newListFakeRepo() *listFakeRepo {
	return &listFakeRepo{
		accounts: map[string]domain.Account{},
		projects: map[string]domain.Project{},
	}
}

func (f *listFakeRepo) Reader(ctx context.Context) (kanamerepo.Reader, error) {
	return &listFakeReader{f}, nil
}
func (f *listFakeRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
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
	a.p.acctGets++
	if acc, ok := a.p.accounts[string(id)]; ok {
		return acc, nil
	}
	return domain.Account{}, iamerr.Wrapf(iamerr.ErrNotFound, "Account %s not found", id)
}
func (a *listFakeAcctReader) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (a *listFakeAcctReader) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

// List returns a PAGE, capped like the real repository is: the platform maximum is
// 1000 and the listing is ordered oldest-first. A fake that returned everything would
// hide exactly the defect that page cap causes.
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
	const platformMaxPage = 1000
	next := ""
	if len(out) > platformMaxPage {
		out, next = out[:platformMaxPage], "next"
	}
	return out, next, nil
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

// fgaObjectID extracts the bare id from an FGA object string
// ("project:prj-a" → "prj-a"). Shared by the package's per-object Check stubs.
func fgaObjectID(object string) string {
	for i := 0; i < len(object); i++ {
		if object[i] == ':' {
			return object[i+1:]
		}
	}
	return object
}

type relationQueriesStub struct {
	clients.RelationQueries
	mu         sync.Mutex // the per-object Check port is called concurrently
	allowedIDs []string
	called     struct{ subject, relation, objectType string }
	relations  []string // every relation queried (visibility union viewer ∪ v_list)
}

// Метод перечисления объектов снят вместе со своим RPC: порт его больше не
// объявляет, и продукт этим путём не ходит. Дублёр, сохранивший способность,
// которой нет у настоящего, ШИРЕ предмета — он предлагает путь, по которому
// проверяемый код пойти не может, и первое же утверждение о нём стало бы
// утверждением о том, чего не бывает.

// CheckWithContext — the DIRECT per-object oracle the use-case now asks instead
// of enumerating (internal/authzfilter), answering from the SAME allow-set.
func (s *relationQueriesStub) CheckWithContext(_ context.Context, subject, relation, object string,
	_ map[string]any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.called.subject = subject
	s.called.relation = relation
	s.called.objectType = object[:len(object)-len(fgaObjectID(object))-1]
	s.relations = append(s.relations, relation)
	id := fgaObjectID(object)
	for _, got := range s.allowedIDs {
		if got == id {
			return true, nil
		}
	}
	return false, nil
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
	seedAccount(repo, "acc-other", "usr-other00000000000")
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
	// The page is filtered by the relation that gates a single-object read, and by
	// nothing else. Asserted as an exact SET rather than a subset: a stray extra
	// relation is precisely how the page came to be wider than the read. (The filter
	// is per-object, so a relation appears once per row it was needed for.)
	// Вопросы разделены по предмету, потому что их теперь два вида и смешивать их
	// в одно множество значило бы потерять оба утверждения.
	//
	// О СТРОКЕ спрашивается ровно одно отношение — то, которым каталог гейтит
	// ProjectService/Get. Лишнее отношение здесь — ровно то, как страница
	// становилась шире чтения.
	//
	// О СУБЪЕКТЕ спрашивается ровно один раз на запрос («администратор ли он
	// облака»). Это не отношение страницы: у него нет объекта-строки вовсе, и
	// его число обязано быть константой, не растущей ни с населением, ни с
	// размером страницы.
	perObject := map[string]bool{}
	subjectQuestions := 0
	for _, r := range fga.relations {
		if r == "system_admin" {
			subjectQuestions++
			continue
		}
		perObject[r] = true
	}
	require.Equal(t, map[string]bool{"v_get": true}, perObject,
		"the list-filter must ask the relation that gates ProjectService/Get, and only that one")
	require.Equal(t, 1, subjectQuestions,
		"the question about the CALLER is asked once per request, outside any per-row loop")
}

// NoGrantsReturnsEmpty — resource-existence disclosure guard: a subject
// with neither AccessBindings nor owned accounts gets an empty list, NOT
// PermissionDenied (he must not learn that any project exists at all).
func TestListProjects_RBACv2_NoGrants_ReturnsEmpty(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-other", "usr-other00000000000")
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

// ── ownership is resolved for the page, not for the cluster ─────────────────

// An owner whose account is not among the oldest thousand in the cluster still sees
// their own projects.
//
// Ownership used to be resolved by LISTING accounts — one page of them, cluster-wide,
// oldest first — and keeping the ones this principal owns. That page is capped at the
// platform maximum, so past a thousand accounts an owner simply was not recognised as
// one: their own projects disappeared from their own listing while the rows, the
// account and the ownership all existed. Nothing said so; the response was a
// successful, empty list.
func TestListProjects_OwnerBeyondTheAccountPage_StillSeesTheirProjects(t *testing.T) {
	repo := newListFakeRepo()
	// A thousand older accounts fill the account page.
	for i := 0; i < 1000; i++ {
		seedAccount(repo, fmt.Sprintf("acc-%04d", i), "usr-someone-else")
	}
	// The caller's own account sorts after all of them.
	seedAccount(repo, "acc-zzzz-mine", "usr-late")
	seedProject(repo, "prj-mine000000000000", "acc-zzzz-mine")

	// The grant branch denies everything: ownership is the only thing that can make
	// this row visible, which is what the assertion is about.
	fga := &relationQueriesStub{allowedIDs: nil}
	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxAs("usr-late"), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.Len(t, out, 1, "the owner of the account must see the project in it")
	assert.Equal(t, domain.ProjectID("prj-mine000000000000"), out[0].ID)

	// И цена не следует за населением. Прежде она была «один просмотр аккаунта на
	// каждый РАЗЛИЧНЫЙ аккаунт страницы»; теперь владение приходит одним вопросом
	// о СУБЪЕКТЕ, заданным до чтения первой строки, и просмотров аккаунта по
	// строкам страницы не остаётся ни одного.
	//
	// Ноль — утверждение более сильное, чем прежняя единица, и оно продолжает
	// говорить о том же: цена принадлежит запросу, а не облаку.
	assert.Equal(t, 0, repo.acctGets,
		"ownership is resolved once, by asking about the caller — not row by row of the page")
}

// A page naming the same account many times pays for it once.
func TestListProjects_OwnershipLookupsAreDeduplicatedPerPage(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-one", "usr-owner")
	for i := 0; i < 25; i++ {
		seedProject(repo, fmt.Sprintf("prj-%02d", i), "acc-one")
	}
	fga := &relationQueriesStub{allowedIDs: nil}
	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxAs("usr-owner"), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.Len(t, out, 25)
	assert.Equal(t, 0, repo.acctGets,
		"25 rows of one account cost no account lookups at all: ownership is a fact about "+
			"the CALLER, resolved once, not a fact re-read per row")
}

// BatchCheckWithContext — the batched door onto the SAME oracle CheckWithContext
// answers from, so a verdict cannot depend on which door the filter chose.
//
// It is not optional politeness: authzfilter takes its batched path whenever the
// checker offers this method, so a stub that omitted it would leave every test in
// this file exercising a code path production does not take. It refuses an
// over-cap partition the way the relation store refuses one — an error, never a
// trim — so the stub is never more permissive than the thing it stands in for.
func (s *relationQueriesStub) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	if len(objects) > authzfilter.MaxBatchChecksPerRequest {
		return nil, fmt.Errorf("batchCheck received %d checks, the maximum allowed is %d",
			len(objects), authzfilter.MaxBatchChecksPerRequest)
	}
	out := make([]bool, len(objects))
	for i, object := range objects {
		allowed, err := s.CheckWithContext(ctx, subject, relation, object, condCtx)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}

func (r *listFakeReader) Visibility() visibility.ReaderIface { return &listFakeVisibility{r.p} }

// listFakeVisibility — структурные факты о вызывающем, выведенные из данных этой
// фикстуры.
//
// ВЛАДЕНИЕ выводится точно так же, как его выводит настоящий запрос: аккаунты,
// чей столбец владельца называет субъекта. Это существенно — пол владения не
// спрашивает вердикта вовсе, и пробы ниже про него.
//
// ОТБОР КАНДИДАТОВ объявлен НЕСУЖЁННЫМ, и это НАМЕРЕННО снисходительнее
// продукта. Цена названа вслух, а не умолчана: строк выдачи у этой фикстуры нет
// вовсе (её грант живёт только в дублёре стора отношений), поэтому назвать
// объекты, выданные поимённо, она не может — а сузив набор до одного владения,
// она стёрла бы ровно то, о чём эти пробы спрашивают.
//
// Отсюда граница: предмет проб этого пакета — ВЕРДИКТ (каким отношением судится
// строка страницы, как ведёт себя пол владения, что происходит на отказе стора).
// ОТБОР кандидатов они не проверяют и проверять не могут; он проверяется на
// настоящем Postgres и настоящей модели прав —
// services/iam/internal/apps/kaname/api/listvisibility, где снисходительного
// дублёра нет ни с одной стороны именно потому, что предмет там — ПОРЯДОК между
// страницей и сужением.
type listFakeVisibility struct{ p *listFakeRepo }

func (v *listFakeVisibility) ScopeOf(_ context.Context, s visibility.Subject) (visibility.Scope, error) {
	sc := visibility.Scope{Unrestricted: true, GrantedObjects: map[string][]string{}}
	if s.Type != "user" || s.ID == "" {
		return sc, nil
	}
	for id, acc := range v.p.accounts {
		if string(acc.OwnerUserID) == s.ID {
			sc.OwnedAccounts = append(sc.OwnedAccounts, id)
			sc.ScopedAccounts = append(sc.ScopedAccounts, id)
		}
	}
	return sc, nil
}
