// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_authz_test.go — FGA-relation-driven list-filter unit tests for
// AccountService.List.
//
// The list-filter converts ListAccountsUseCase from an owner-only Go post-filter
// to an FGA `ListObjects(principal, "viewer", "account")`-driven filter so the
// kacho-vpc-operator SA (seeded `system_viewer@cluster:cluster_kacho_root`)
// sees every Account while a normal user keeps seeing ONLY their own
// (owner→viewer cascade resolves inside the account).
//
// Scenarios:
//
//	A — user sees ONLY own (INV-1).
//	B — operator SA sees ALL (INV-2) + exact "service_account:<id>" subject.
//	C — anonymous → empty, FGA NOT called (INV-3).
//	D — cross-user isolation: u1 never sees a2 (INV-1, use-case level).
//	F — FGA error → UNAVAILABLE fail-closed, not full list (INV-7); anon still empty.
//	subject-prefix — exact "user:<id>" for user principal.
package account

import (
	"context"
	stderrors "errors"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	repoaccount "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
)

// ───────────── fake repo (Accounts().List only) ─────────────

type acctListFakeRepo struct{ accounts map[string]domain.Account }

func newAcctListFakeRepo() *acctListFakeRepo {
	return &acctListFakeRepo{accounts: map[string]domain.Account{}}
}

func (f *acctListFakeRepo) Reader(ctx context.Context) (kachorepo.Reader, error) {
	return &acctListFakeReader{f}, nil
}
func (f *acctListFakeRepo) Writer(ctx context.Context) (kachorepo.Writer, error) {
	return nil, stderrors.New("fake.Writer not used in list tests")
}
func (f *acctListFakeRepo) Close() {}

type acctListFakeReader struct{ p *acctListFakeRepo }

func (r *acctListFakeReader) Accounts() repoaccount.ReaderIface { return &acctListReader{r.p} }
func (r *acctListFakeReader) Projects() project.ReaderIface     { return nil }
func (r *acctListFakeReader) Users() user.ReaderIface           { return nil }
func (r *acctListFakeReader) ServiceAccounts() service_account.ReaderIface {
	return nil
}
func (r *acctListFakeReader) Groups() group.ReaderIface                  { return nil }
func (r *acctListFakeReader) Roles() role.ReaderIface                    { return nil }
func (r *acctListFakeReader) AccessBindings() access_binding.ReaderIface { return nil }
func (r *acctListFakeReader) Commit(context.Context) error               { return nil }
func (r *acctListFakeReader) Rollback(context.Context) error             { return nil }

type acctListReader struct{ p *acctListFakeRepo }

func (a *acctListReader) Get(ctx context.Context, id domain.AccountID) (domain.Account, error) {
	if acc, ok := a.p.accounts[string(id)]; ok {
		return acc, nil
	}
	return domain.Account{}, stderrors.New("not found")
}
func (a *acctListReader) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (a *acctListReader) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}
func (a *acctListReader) List(ctx context.Context, f repoaccount.ListFilter) ([]domain.Account, string, error) {
	keys := make([]string, 0, len(a.p.accounts))
	for k := range a.p.accounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]domain.Account, 0, len(keys))
	for _, k := range keys {
		out = append(out, a.p.accounts[k])
	}
	return out, "", nil
}

func seedAcct(r *acctListFakeRepo, id, owner string) {
	r.accounts[id] = domain.Account{
		ID: domain.AccountID(id), Name: domain.AccountName("n-" + id),
		OwnerUserID: domain.UserID(owner), CreatedAt: time.Now().UTC(),
	}
}

func ctxUser(uid string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: uid})
}
func ctxSA(said string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "service_account", ID: said})
}

func acctIDs(out []domain.Account) []string {
	ids := make([]string, 0, len(out))
	for _, a := range out {
		ids = append(ids, string(a.ID))
	}
	return ids
}

// ───────────── FGA ListObjects stub (local — the clients-package stub is a
// _test.go type not linked into this package's test binary) ───────────────

type acctFGAStub struct {
	clients.RelationQueries
	idsBySubject map[string][]string
	err          error
	calls        int
	lastSubject  string
}

func newAcctFGAStub() *acctFGAStub {
	return &acctFGAStub{idsBySubject: map[string][]string{}}
}

func (s *acctFGAStub) set(subject string, ids []string) { s.idsBySubject[subject] = ids }

func (s *acctFGAStub) ListObjects(ctx context.Context, subject, relation, objectType string,
	condCtx map[string]any, maxResults int) ([]string, error) {
	s.calls++
	s.lastSubject = subject
	if s.err != nil {
		return nil, s.err
	}
	return s.idsBySubject[subject], nil
}

// ───────────── tests ─────────────

// A — user sees ONLY own (INV-1). FGA viewer-set = {a1}.
func TestListAccounts_SECL_UserSeesOnlyOwn(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")
	seedAcct(repo, "acc-2", "usr-u2")

	fga := newAcctFGAStub()
	fga.set("user:usr-u1", []string{"acc-1"})

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"acc-1"}, acctIDs(out),
		"u1 sees only own account; acc-2 stays hidden (INV-1)")
}

// B — operator SA sees ALL (INV-2); subject reaches FGA as service_account:<id>.
func TestListAccounts_SECL_OperatorSeesAll(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")
	seedAcct(repo, "acc-2", "usr-u2")

	op := "sva-operator"
	fga := newAcctFGAStub()
	fga.set("service_account:"+op, []string{"acc-1", "acc-2"})

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxSA(op), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"acc-1", "acc-2"}, acctIDs(out),
		"operator system-viewer sees ALL accounts (INV-2)")
	require.Equal(t, "service_account:"+op, fga.lastSubject,
		"SA principal must reach FGA as service_account:<id>, not user:<id>")
}

// C — anonymous → empty, FGA NOT called (INV-3).
func TestListAccounts_SECL_AnonymousEmpty_NoFGA(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")

	fga := newAcctFGAStub()
	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(context.Background(), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.Empty(t, out, "anonymous → empty list, OK status (INV-3)")
	require.Equal(t, 0, fga.calls, "anonymous short-circuits BEFORE any FGA call")
}

// D — cross-user isolation: u1 never sees a2 (INV-1, use-case level).
func TestListAccounts_SECL_CrossUserIsolation(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")
	seedAcct(repo, "acc-2", "usr-u2")

	fga := newAcctFGAStub()
	// u1's viewer-set excludes acc-2 (no system_viewer, no grant).
	fga.set("user:usr-u1", []string{"acc-1"})

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.NotContains(t, acctIDs(out), "acc-2",
		"a user CANNOT see another user's account (INV-1 cross-user isolation)")
}

// F — FGA error → UNAVAILABLE fail-closed, not full list (INV-7).
func TestListAccounts_SECL_FGAUnavailable_FailClosed(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")
	seedAcct(repo, "acc-2", "usr-u2")

	fga := newAcctFGAStub()
	fga.err = stderrors.New("openfga listObjects: status 503")

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
	require.Error(t, err, "FGA outage must NOT return a (degraded) list")
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code(),
		"FGA outage → UNAVAILABLE fail-closed; never full-list, never owner-fallback (INV-7)")
}

// F (anon variant) — anon during FGA outage still gets empty/OK (short-circuit).
func TestListAccounts_SECL_AnonDuringOutage_StillEmpty(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")

	fga := newAcctFGAStub()
	fga.err = stderrors.New("openfga listObjects: status 503")

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(context.Background(), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err, "anon path is unaffected by FGA outage (short-circuit before FGA)")
	require.Empty(t, out)
	require.Equal(t, 0, fga.calls)
}

// subject-prefix — exact "user:<id>" for user principal.
func TestListAccounts_SECL_SubjectPrefix_User(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")

	fga := newAcctFGAStub()
	fga.set("user:usr-u1", []string{"acc-1"})

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	_, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.Equal(t, "user:usr-u1", fga.lastSubject,
		"user principal must reach FGA as user:<id>")
}
