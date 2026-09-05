// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// list_authz_test.go — relation-driven list-filter unit tests for
// AccountService.List.
//
// The list-filter converts ListAccountsUseCase from an owner-only Go post-filter
// into one that asks the relation model about the rows ON THE PAGE, so a
// cluster-wide viewer sees every Account while a normal user keeps seeing ONLY
// their own (owner→viewer cascade resolves inside the account).
//
// # What this header used to say, and why that stopped being true
//
// It named the question as `ListObjects(principal, "viewer", "account")` — an
// enumeration of every object of the type the subject may see. That question no
// longer exists in any form: the external relation engine was removed in stage S6
// and clients.RelationQueries carries no method that enumerates objects. What is
// asked instead is a DIRECT per-object question about each row of the page
// (internal/authzfilter), so the cost of a page follows the page.
//
// The reason for the removal is kept because it is still the reason: the
// enumeration was capped server-side with no continuation token, so past that
// population a tenant's own row fell outside the returned prefix and became
// permanently invisible while the row and the grant both existed.
//
// Scenarios:
//
//	A — user sees ONLY own (INV-1).
//	B — operator SA sees ALL (INV-2) + exact "service_account:<id>" subject.
//	C — anonymous → empty, the model is NOT asked at all (INV-3).
//	D — cross-user isolation: u1 never sees a2 (INV-1, use-case level).
//	F — an unanswered question → UNAVAILABLE fail-closed, not a full list (INV-7);
//	    anon still empty.
//	subject-prefix — exact "user:<id>" for user principal.
package account

import (
	"context"
	stderrors "errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/authzfilter"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
	repoaccount "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/visibility"
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

// ───────────── relation-queries stub (local — the clients-package stub is a
// _test.go type not linked into this package's test binary) ───────────────

// fgaObjectID extracts the bare id from an object string ("account:acc-1"
// → "acc-1"). Shared by the package's per-object Check stubs.
func fgaObjectID(object string) string {
	for i := 0; i < len(object); i++ {
		if object[i] == ':' {
			return object[i+1:]
		}
	}
	return object
}

// acctFGAStub — stub clients.RelationQueries.
//
// `calls` counts every question actually asked. It used to be incremented by an
// enumeration door as well; that door is gone, and the counter is kept because the
// question it now counts — the per-object one — is the question production asks.
// A counter with no producer would make "nothing was asked" true by construction
// of this type and unable to go red on anything.
type acctFGAStub struct {
	clients.RelationQueries
	mu           sync.Mutex // the per-object Check port is called concurrently
	idsBySubject map[string][]string
	err          error
	calls        int
	lastSubject  string
}

func newAcctFGAStub() *acctFGAStub {
	return &acctFGAStub{idsBySubject: map[string][]string{}}
}

func (s *acctFGAStub) set(subject string, ids []string) { s.idsBySubject[subject] = ids }

// CheckWithContext — the DIRECT per-object question the use-case asks. It answers
// from the same per-subject id-set the tests seed, so their grant fixtures and
// their intent are unchanged by the removal of the enumeration door.
func (s *acctFGAStub) CheckWithContext(_ context.Context, subject, _, object string,
	_ map[string]any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.lastSubject = subject
	if s.err != nil {
		return false, s.err
	}
	id := fgaObjectID(object)
	for _, got := range s.idsBySubject[subject] {
		if got == id {
			return true, nil
		}
	}
	return false, nil
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
		"SA principal must reach the model as service_account:<id>, not user:<id>")
}

// C — anonymous → empty, the model is NOT asked (INV-3).
func TestListAccounts_SECL_AnonymousEmpty_NoFGA(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")

	fga := newAcctFGAStub()
	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(context.Background(), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.Empty(t, out, "anonymous → empty list, OK status (INV-3)")
	require.Equal(t, 0, fga.calls, "anonymous short-circuits BEFORE a single question is asked")
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

// F — an unanswered question → UNAVAILABLE fail-closed, not a full list (INV-7).
//
// "Could not ask" and "not allowed" are different worlds: returning a page here
// would pass a database that did not answer off as a lawful denial.
func TestListAccounts_SECL_FGAUnavailable_FailClosed(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")
	seedAcct(repo, "acc-2", "usr-u2")

	fga := newAcctFGAStub()
	fga.err = stderrors.New("relation form did not answer: connection closed")

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
	require.Error(t, err, "an unanswered question must NOT return a (degraded) list")
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code(),
		"unanswered → UNAVAILABLE fail-closed; never full-list, never owner-fallback (INV-7)")
}

// F (anon variant) — anon during an outage still gets empty/OK (short-circuit).
func TestListAccounts_SECL_AnonDuringOutage_StillEmpty(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")

	fga := newAcctFGAStub()
	fga.err = stderrors.New("relation form did not answer: connection closed")

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(context.Background(), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err, "anon path is unaffected by the outage (short-circuit before asking)")
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
		"user principal must reach the model as user:<id>")
}

// BatchCheckWithContext — the batched door onto the SAME oracle CheckWithContext
// answers from, so a verdict cannot depend on which door the filter chose.
//
// It is not optional politeness: authzfilter takes its batched path whenever the
// checker offers this method, so a stub that omitted it would leave every test in
// this file exercising a code path production does not take.
//
// The refusal above authzfilter.MaxBatchChecksPerRequest keeps the stub from being
// SLACKER than the declaration it stands behind: that constant is the partition
// size authzfilter itself declares and splits a page against, so a filter that
// stopped honouring its own declaration goes red here instead of quietly changing
// the shape of the request. An error, never a trim — a short answer is
// indistinguishable from a page of denials.
func (s *acctFGAStub) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	if len(objects) > authzfilter.MaxBatchChecksPerRequest {
		return nil, fmt.Errorf("batch of %d objects exceeds the declared partition size %d",
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

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kacho/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
// Visibility — структурные факты о вызывающем, объявленные НЕСУЖЁННЫМИ.
//
// Это НАМЕРЕННО снисходительнее продукта, и цена названа вслух: строк выдачи у
// этой фикстуры нет вовсе (её гранты живут только в дублёре стора отношений),
// поэтому назвать кандидатов она не может — а сузив набор до пустого, вернула бы
// пустую страницу везде и стёрла бы ровно то, о чём эти пробы спрашивают.
//
// Отсюда граница: предмет проб этого пакета — ВЕРДИКТ (каким отношением судится
// строка страницы, как ведут себя полы, что происходит на отказе стора). ОТБОР
// кандидатов они не проверяют и проверять не могут; он проверяется на настоящем
// Postgres и настоящей модели прав —
// services/iam/internal/apps/kacho/api/listvisibility, где снисходительного
// дублёра нет ни с одной стороны именно потому, что предмет там — ПОРЯДОК между
// страницей и сужением.
func (r *acctListFakeReader) Visibility() visibility.ReaderIface { return acctUnrestrictedVisibility{} }

// acctUnrestrictedVisibility — «кандидаты не сужаются»: Candidates(...) вернёт nil,
// и репозиторий не получит ни одного предиката отбора.
type acctUnrestrictedVisibility struct{}

func (acctUnrestrictedVisibility) ScopeOf(_ context.Context, _ visibility.Subject) (visibility.Scope, error) {
	return visibility.Scope{Unrestricted: true, GrantedObjects: map[string][]string{}}, nil
}
