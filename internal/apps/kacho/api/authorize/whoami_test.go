// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// whoami_test.go — unit tests for WhoAmIUseCase.
//
// Coverage:
//   - Anonymous → Unauthenticated (RED first if executed pre-implementation).
//   - User principal → returns identity (email, display_name) + cluster
//     flags (system_admin, cluster_viewer) + per-account memberships.
//   - Owner-implicit `owner` tag is appended even without an explicit
//     ACCESS_BINDING row.
//   - Missing user row tolerated (best-effort identity backfill).
package authorize

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
)

// ── Fake repo plumbing (narrow surface for WhoAmI: Users().Get +
//    Users().ListAccountsForUser + Accounts().Get + AccessBindings()
//    .ListBySubject). Other methods stub out to nil/zero.

type fakeWhoAmIRepo struct {
	users      map[domain.UserID]domain.User
	accountsBy map[domain.UserID][]domain.AccountID
	accounts   map[domain.AccountID]domain.Account
	bindings   []domain.AccessBinding
	listErr    error
}

func (f *fakeWhoAmIRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &fakeWhoAmIReader{parent: f}, nil
}
func (f *fakeWhoAmIRepo) Writer(context.Context) (kachorepo.Writer, error) {
	return nil, errors.New("writer not used")
}
func (f *fakeWhoAmIRepo) Close() {}

type fakeWhoAmIReader struct{ parent *fakeWhoAmIRepo }

func (r *fakeWhoAmIReader) Accounts() account.ReaderIface {
	return &fakeAcctRdr{parent: r.parent}
}
func (r *fakeWhoAmIReader) Projects() project.ReaderIface { return nil }
func (r *fakeWhoAmIReader) Users() user.ReaderIface       { return &fakeUserRdr{parent: r.parent} }
func (r *fakeWhoAmIReader) ServiceAccounts() service_account.ReaderIface {
	return nil
}
func (r *fakeWhoAmIReader) Groups() group.ReaderIface { return nil }
func (r *fakeWhoAmIReader) Roles() role.ReaderIface   { return nil }
func (r *fakeWhoAmIReader) AccessBindings() access_binding.ReaderIface {
	return &fakeABRdr{parent: r.parent}
}
func (r *fakeWhoAmIReader) Commit(context.Context) error   { return nil }
func (r *fakeWhoAmIReader) Rollback(context.Context) error { return nil }

// fakeAcctRdr.
type fakeAcctRdr struct{ parent *fakeWhoAmIRepo }

func (r *fakeAcctRdr) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	a, ok := r.parent.accounts[id]
	if !ok {
		return domain.Account{}, iamerr.Wrapf(iamerr.ErrNotFound, "Account %s not found", id)
	}
	return a, nil
}
func (r *fakeAcctRdr) List(context.Context, account.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (r *fakeAcctRdr) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (r *fakeAcctRdr) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

// fakeUserRdr.
type fakeUserRdr struct{ parent *fakeWhoAmIRepo }

func (r *fakeUserRdr) Get(_ context.Context, id domain.UserID) (domain.User, error) {
	u, ok := r.parent.users[id]
	if !ok {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
	}
	return u, nil
}
func (r *fakeUserRdr) GetByExternalID(context.Context, domain.ExternalSubject) (domain.User, error) {
	return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "not used")
}
func (r *fakeUserRdr) GetByEmail(context.Context, domain.Email) (domain.User, error) {
	return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "not used")
}
func (r *fakeUserRdr) List(context.Context, user.ListFilter) ([]domain.User, string, error) {
	return nil, "", nil
}
func (r *fakeUserRdr) GetByAccountEmail(context.Context, domain.AccountID, domain.Email) (domain.User, error) {
	return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "not used")
}
func (r *fakeUserRdr) FindPendingByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (r *fakeUserRdr) FindActiveByExternalID(context.Context, domain.ExternalSubject) ([]domain.User, error) {
	return nil, nil
}
func (r *fakeUserRdr) FindByExternalIDInStatuses(context.Context, domain.ExternalSubject, []domain.InviteStatus) ([]domain.User, error) {
	return nil, nil
}
func (r *fakeUserRdr) FindActiveByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (r *fakeUserRdr) ListAccountsForUser(_ context.Context, id domain.UserID) ([]domain.AccountID, error) {
	if r.parent.listErr != nil {
		return nil, r.parent.listErr
	}
	return r.parent.accountsBy[id], nil
}

// fakeABRdr.
type fakeABRdr struct{ parent *fakeWhoAmIRepo }

func (r *fakeABRdr) Get(context.Context, domain.AccessBindingID) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "not used")
}
func (r *fakeABRdr) ListByScope(context.Context, domain.ResourceType, string, access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}
func (r *fakeABRdr) ListBySubject(_ context.Context, st domain.SubjectType, sid domain.SubjectID, _ access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
	out := make([]domain.AccessBinding, 0)
	for _, b := range r.parent.bindings {
		if b.SubjectType == st && b.SubjectID == sid {
			out = append(out, b)
		}
	}
	return out, "", nil
}
func (r *fakeABRdr) ListByAccount(context.Context, domain.AccountID, access_binding.AccountPageFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}
func (r *fakeABRdr) ListSubjectPrivileges(context.Context, domain.SubjectType, domain.SubjectID, access_binding.PageFilter) ([]domain.SubjectPrivilege, string, error) {
	return nil, "", nil
}
func (r *fakeABRdr) SelectEmittedTuples(context.Context, domain.AccessBindingID) ([]access_binding.RelationTuple, error) {
	return nil, nil
}
func (r *fakeABRdr) ListActiveByRole(context.Context, domain.RoleID) ([]domain.AccessBinding, error) {
	return nil, nil
}
func (r *fakeABRdr) CountActiveByRole(context.Context, domain.RoleID) (int, error) { return 0, nil }
func (r *fakeABRdr) SelectEmittedTuplesBySource(context.Context, domain.AccessBindingID, string) ([]access_binding.RelationTuple, error) {
	return nil, nil
}
func (r *fakeABRdr) ListByRole(context.Context, domain.RoleID, access_binding.ListByRoleFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}
func (r *fakeABRdr) ListSubjects(context.Context, domain.AccessBindingID) ([]domain.Subject, error) {
	return nil, nil
}
func (r *fakeABRdr) ListSubjectsForBindings(context.Context, []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
	return nil, nil
}

// fakeChecker — stub WhoAmICheckerForAuthz; map (subject,relation,object)→bool.
type fakeChecker struct {
	allow map[string]bool
}

func (f *fakeChecker) CheckWithContext(_ context.Context, subject, relation, object string, _ map[string]any) (bool, error) {
	if f == nil {
		return false, nil
	}
	return f.allow[subject+"|"+relation+"|"+object], nil
}

// outbox compile-time interface assertions (unused but keeps tests honest).

// ── Tests ────────────────────────────────────────────────────────────────

func TestWhoAmI_Anonymous_ReturnsUnauthenticated(t *testing.T) {
	uc := NewWhoAmIUseCase(&fakeWhoAmIRepo{}, nil)
	// no operations.WithPrincipal — ctx is empty.
	_, err := uc.Execute(context.Background())
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated; got %v (%v)", st.Code(), err)
	}
}

func TestWhoAmI_User_FullSnapshot(t *testing.T) {
	const uid = "usr0000000000000abcd"
	const acc1 = "acc0000000000000fst1"
	const acc2 = "acc0000000000000scnd"

	repo := &fakeWhoAmIRepo{
		users: map[domain.UserID]domain.User{
			uid: {
				ID:          uid,
				Email:       "alice@example.com",
				DisplayName: "Alice",
			},
		},
		accountsBy: map[domain.UserID][]domain.AccountID{
			uid: {acc1, acc2},
		},
		accounts: map[domain.AccountID]domain.Account{
			acc1: {ID: acc1, Name: "First", OwnerUserID: uid /* owner */},
			acc2: {ID: acc2, Name: "Second", OwnerUserID: "usr000000000000other"},
		},
		bindings: []domain.AccessBinding{
			// editor binding on acc2 — should produce "editor" tag.
			{
				SubjectType:  "user",
				SubjectID:    uid,
				ResourceType: "account",
				ResourceID:   acc2,
				RoleID:       "iam.editor",
				Status:       domain.AccessBindingStatusActive,
			},
			// REVOKED binding on acc1 — must NOT contribute a tag.
			{
				SubjectType:  "user",
				SubjectID:    uid,
				ResourceType: "account",
				ResourceID:   acc1,
				RoleID:       "iam.admin",
				Status:       domain.AccessBindingStatusRevoked,
			},
		},
	}
	checker := &fakeChecker{allow: map[string]bool{
		"user:" + uid + "|system_admin|cluster:" + domain.ClusterSingletonID: false,
		"user:" + uid + "|viewer|cluster:" + domain.ClusterSingletonID:       true,
	}}
	uc := NewWhoAmIUseCase(repo, checker)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: uid, DisplayName: "Alice"})

	res, err := uc.Execute(ctx)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Subject != "user:"+uid {
		t.Errorf("subject: %q", res.Subject)
	}
	if res.Email != "alice@example.com" {
		t.Errorf("email: %q", res.Email)
	}
	if res.DisplayName != "Alice" {
		t.Errorf("display_name: %q", res.DisplayName)
	}
	if res.SystemAdmin {
		t.Errorf("expected SystemAdmin=false")
	}
	if !res.ClusterViewer {
		t.Errorf("expected ClusterViewer=true (cluster.viewer cascade)")
	}
	if len(res.Accounts) != 2 {
		t.Fatalf("expected 2 accounts; got %d", len(res.Accounts))
	}
	// Stable order: acc1 < acc2.
	if string(res.Accounts[0].AccountID) != acc1 {
		t.Errorf("expected acc1 first; got %s", res.Accounts[0].AccountID)
	}
	if res.Accounts[0].AccountName != "First" {
		t.Errorf("acc1 name: %q", res.Accounts[0].AccountName)
	}
	// acc1: owner-implicit (no explicit ACTIVE binding) → ["owner"].
	if got := res.Accounts[0].Roles; len(got) != 1 || got[0] != "owner" {
		t.Errorf("acc1 roles: %v", got)
	}
	// acc2: editor binding (status=ACTIVE) → ["editor"]; no owner tag (not owner).
	if got := res.Accounts[1].Roles; len(got) != 1 || got[0] != "editor" {
		t.Errorf("acc2 roles: %v", got)
	}
	if res.CheckedAt.IsZero() {
		t.Errorf("expected non-zero CheckedAt")
	}
	if time.Since(res.CheckedAt) > time.Minute {
		t.Errorf("CheckedAt unrealistic: %v", res.CheckedAt)
	}
}

func TestWhoAmI_User_MissingUserRowFallsBack(t *testing.T) {
	const uid = "usr0000000000000xxxx"
	repo := &fakeWhoAmIRepo{
		users:      map[domain.UserID]domain.User{},
		accountsBy: map[domain.UserID][]domain.AccountID{}, // no accounts
		accounts:   map[domain.AccountID]domain.Account{},
	}
	uc := NewWhoAmIUseCase(repo, nil) // nil checker → cluster flags false

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: uid, DisplayName: "X"})

	res, err := uc.Execute(ctx)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Subject != "user:"+uid {
		t.Errorf("subject: %q", res.Subject)
	}
	if res.Email != "" {
		t.Errorf("expected empty email; got %q", res.Email)
	}
	if res.SystemAdmin || res.ClusterViewer {
		t.Errorf("expected cluster flags false when fga nil")
	}
	if len(res.Accounts) != 0 {
		t.Errorf("expected zero accounts; got %d", len(res.Accounts))
	}
}

func TestWhoAmI_User_SystemAdminTrue(t *testing.T) {
	const uid = "usr0000000000000adm1"
	repo := &fakeWhoAmIRepo{
		users:      map[domain.UserID]domain.User{uid: {ID: uid, Email: "ad@m"}},
		accountsBy: map[domain.UserID][]domain.AccountID{},
		accounts:   map[domain.AccountID]domain.Account{},
	}
	checker := &fakeChecker{allow: map[string]bool{
		"user:" + uid + "|system_admin|cluster:" + domain.ClusterSingletonID: true,
		"user:" + uid + "|viewer|cluster:" + domain.ClusterSingletonID:       true,
	}}
	uc := NewWhoAmIUseCase(repo, checker)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: uid})

	res, err := uc.Execute(ctx)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.SystemAdmin || !res.ClusterViewer {
		t.Errorf("expected both flags true; got system_admin=%v viewer=%v",
			res.SystemAdmin, res.ClusterViewer)
	}
}

func TestWhoAmI_ServiceAccount_NoAccountListing(t *testing.T) {
	repo := &fakeWhoAmIRepo{
		users:      map[domain.UserID]domain.User{},
		accountsBy: map[domain.UserID][]domain.AccountID{},
		accounts:   map[domain.AccountID]domain.Account{},
	}
	uc := NewWhoAmIUseCase(repo, nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva00000000000000abc", DisplayName: "ci-bot"})

	res, err := uc.Execute(ctx)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Subject != "service_account:sva00000000000000abc" {
		t.Errorf("subject: %q", res.Subject)
	}
	if res.UserID != "" {
		t.Errorf("expected empty user_id for SA principal; got %q", res.UserID)
	}
	if res.DisplayName != "ci-bot" {
		t.Errorf("expected display_name from principal; got %q", res.DisplayName)
	}
	if len(res.Accounts) != 0 {
		t.Errorf("expected zero accounts; got %d", len(res.Accounts))
	}
}

func TestClassifyRoleID_HappyPath(t *testing.T) {
	cases := []struct {
		id, want string
	}{
		{"iam.admin", "admin"},
		{"iam.editor", "editor"},
		{"iam.viewer", "viewer"},
		{"iam.edit", "editor"},
		{"iam.view", "viewer"},
		{"iam.owner", "owner"},
		{"customRole", "viewer"},   // unknown → viewer (least privilege)
		{"", "viewer"},             // empty → viewer
		{"compute.admin", "admin"}, // dotted ids: last segment classified
	}
	for _, c := range cases {
		if got := classifyRoleID(domain.RoleID(c.id)); got != c.want {
			t.Errorf("classifyRoleID(%q) = %q; want %q", c.id, got, c.want)
		}
	}
}
