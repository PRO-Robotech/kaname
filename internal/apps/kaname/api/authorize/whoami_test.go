// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

// ── Fake repo plumbing (narrow surface for WhoAmI: Users().Get +
//    Users().ListAccountsForUser + Accounts().Get + AccessBindings()
//    .ListBySubject). Other methods stub out to nil/zero.

type fakeWhoAmIRepo struct {
	users      map[domain.UserID]domain.User
	accountsBy map[domain.UserID][]domain.AccountID
	accounts   map[domain.AccountID]domain.Account
	bindings   []domain.AccessBinding
	roles      map[domain.RoleID]domain.Role
	listErr    error
}

func (f *fakeWhoAmIRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	return &fakeWhoAmIReader{parent: f}, nil
}
func (f *fakeWhoAmIRepo) Writer(context.Context) (kanamerepo.Writer, error) {
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
func (r *fakeWhoAmIReader) Roles() role.ReaderIface   { return &fakeRoleRdr{parent: r.parent} }
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

// fakeRoleRdr — дублёр каталога ролей. Отвечает ровно то, что настоящий:
// строку роли по её id, а отсутствующую — тем же ErrNotFound. Роль, которой
// в карте нет, для use-case неотличима от снятой из каталога.
type fakeRoleRdr struct{ parent *fakeWhoAmIRepo }

func (r *fakeRoleRdr) Get(_ context.Context, id domain.RoleID) (domain.Role, error) {
	rl, ok := r.parent.roles[id]
	if !ok {
		return domain.Role{}, iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id)
	}
	return rl, nil
}

// Остальные методы каталога WhoAmI не зовёт: снимок личности читает имя роли и
// ничего больше. Пустой ответ здесь — не «ответить нечем», а отсутствие
// предмета: утверждения, которого никто не делал, дублёр не производит.
func (r *fakeRoleRdr) GetWithVersion(ctx context.Context, id domain.RoleID) (domain.Role, string, error) {
	got, err := r.Get(ctx, id)
	return got, "v1", err
}
func (*fakeRoleRdr) List(context.Context, role.ListFilter) ([]domain.Role, string, error) {
	return nil, "", nil
}
func (*fakeRoleRdr) ListAssignable(context.Context, string, string, role.ListFilter) ([]domain.Role, string, error) {
	return nil, "", nil
}
func (*fakeRoleRdr) UnresolvedSegments(context.Context, []domain.RoleSegment) (map[domain.RoleID][]domain.RoleSegment, error) {
	return nil, nil
}
func (*fakeRoleRdr) WithdrawnGrants(context.Context, []domain.RoleID) (map[domain.RoleID][]domain.WithdrawnGrant, error) {
	return nil, nil
}
func (*fakeRoleRdr) PrunedSelectorTypes(context.Context, []domain.RoleID) (map[domain.RoleID][]domain.PrunedSelectorType, error) {
	return nil, nil
}
func (*fakeRoleRdr) Lifecycles(context.Context, []domain.RoleID) (map[domain.RoleID]domain.RoleLifecycle, error) {
	return nil, nil
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
func (r *fakeABRdr) List(context.Context, access_binding.ListFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
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
func (r *fakeABRdr) SelectTuplesClaimedByOtherActiveBindings(context.Context, domain.AccessBindingID, []access_binding.RelationTuple) ([]access_binding.RelationTuple, error) {
	return nil, nil
}
func (r *fakeABRdr) ListByRole(context.Context, domain.RoleID, access_binding.ListByRoleFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}

// ListActiveHoldingMembership — предмета этой пробы не касается: она не исключает
// человека из аккаунта. Пустой перечень — ЗАКОННЫЙ ответ (мешающих выдач нет), а
// не заглушка «ответить нечем»: дублёр обязан выполнять контракт настоящего, и
// молчаливо шире его не отвечать.
func (r *fakeABRdr) ListActiveHoldingMembership(context.Context, domain.UserID, domain.AccountID, int) ([]string, int, error) {
	return nil, 0, nil
}

func (r *fakeABRdr) ListSubjects(context.Context, domain.AccessBindingID) ([]domain.Subject, error) {
	return nil, nil
}
func (r *fakeABRdr) ListMaterializedAtForBindings(context.Context, []domain.AccessBindingID) (map[domain.AccessBindingID]time.Time, error) {
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
				RoleID:       seededRoleIDEdit,
				Status:       domain.AccessBindingStatusActive,
			},
			// REVOKED binding on acc1 — must NOT contribute a tag.
			{
				SubjectType:  "user",
				SubjectID:    uid,
				ResourceType: "account",
				ResourceID:   acc1,
				RoleID:       seededRoleIDAccountAdmin,
				Status:       domain.AccessBindingStatusRevoked,
			},
		},
		roles: map[domain.RoleID]domain.Role{
			seededRoleIDEdit:         {ID: seededRoleIDEdit, Name: "edit", IsSystem: true},
			seededRoleIDAccountAdmin: {ID: seededRoleIDAccountAdmin, Name: "iam.account.admin", IsSystem: true},
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

// TestClassifyRoleName_HappyPath — словарь тегов читается по ИМЕНИ роли.
// Имена взяты из посева (`internal/migrations/0001_initial.sql`), а не
// сочинены: имя вида `iam.<тег>` в этом дереве не носит ни одна роль, и
// проба на нём закрепляла бы поведение, которого продукт не производит.
func TestClassifyRoleName_HappyPath(t *testing.T) {
	cases := []struct {
		name, want string
	}{
		{"owner", "owner"},             // посев: rol72122ce96bfec66e2
		{"admin", "admin"},             // посев: rol21232f297a57a5a74
		{"edit", "editor"},             // посев: rolde95b43bceeb4b998
		{"view", "viewer"},             // посев: rol1bda80f2be4d3658e
		{"iam.account.admin", "admin"}, // посев: составное имя — тег по хвосту
		{"iam.account.edit", "editor"}, // посев
		{"iam.account.view", "viewer"}, // посев
		{"vpc.gateway.view", "viewer"}, // посев: составное имя другого модуля
		{"billing-ops", "viewer"},      // роль арендатора → наименьшая привилегия
		{"", "viewer"},                 // имени нет → наименьшая привилегия
		{"ADMIN", "admin"},             // регистр имени тега не меняет
	}
	for _, c := range cases {
		if got := classifyRoleName(domain.RoleName(c.name)); got != c.want {
			t.Errorf("classifyRoleName(%q) = %q; want %q", c.name, got, c.want)
		}
	}
}

// TestClassifyRoleName_RoleIDCarriesNoTag — идентификатор роли тега не несёт:
// это ПРИЧИНА дефекта #279, и она закрепляется прямо. Подставленный вместо
// имени id обязан дать откат, а не тег — иначе кто-нибудь снова прочтёт его
// как источник классификации.
func TestClassifyRoleName_RoleIDCarriesNoTag(t *testing.T) {
	for _, id := range []string{
		domain.OwnerRoleID,
		domain.ClusterAdminRoleID,
		seededRoleIDAccountAdmin,
		seededRoleIDEdit,
	} {
		if got := classifyRoleName(domain.RoleName(id)); got != "viewer" {
			t.Errorf("classifyRoleName(%q) = %q; id роли тега не несёт, ожидался откат viewer", id, got)
		}
	}
}

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *fakeWhoAmIReader) Visibility() visibility.ReaderIface { return nil }

// MembershipExists — дублёр не отвечает на вопрос о членстве: предмет этой
// пробы другой, и подставной ответ был бы утверждением, которого никто не
// делал. Единственный прод-вызывающий — разрешение осиротевшей операции
// исключения из аккаунта (#1127).
func (*fakeUserRdr) MembershipExists(context.Context, domain.UserID, domain.AccountID) (bool, error) {
	return false, nil
}

// Membership — дублёр членства ПАРОЙ не читает: предмет этих проб другой, и
// подставная строка была бы утверждением, которого никто не делал (kaname#181).
func (*fakeUserRdr) Membership(context.Context, domain.UserID, domain.AccountID) (domain.Membership, error) {
	return domain.Membership{}, iamerr.ErrNotFound
}

// ── Тег роли берётся у ПОСЕВНОЙ роли, а не у хвоста её id (#279) ─────────

// Посевные id ролей и их имена — дословно из `internal/migrations/0001_initial.sql`
// (строки 3777, 3778, 3780, 3788, 3814). Точки в id нет НИ У ОДНОЙ из 48 посевных
// ролей: id есть `rol` плюс производный суффикс (`internal/domain/derived_id.go`),
// точка живёт только в ИМЕНИ (`iam.account.admin`).
const (
	seededRoleIDAccountAdmin = "rol6307d201bf18e6763" // name: iam.account.admin
	seededRoleIDEdit         = "rolde95b43bceeb4b998" // name: edit
	seededRoleIDView         = "rol1bda80f2be4d3658e" // name: view
	customRoleIDBillingOps   = "rol0000000000custom1" // роль арендатора: тега не имеет
)

// TestWhoAmI_AccountRoles_FollowTheSeededRole — тег привязки уровня аккаунта
// обязан отвечать РОЛИ, которую привязка выдаёт.
//
// Положительные близнецы здесь — два, и оба обязаны остаться зелёными после
// правки: роль `view`, у которой `viewer` законен ПО ИМЕНИ, и роль арендатора
// `billing-ops`, у которой `viewer` законен как откат наименьшей привилегии.
// Без них правка просто перевернула бы ошибку.
func TestWhoAmI_AccountRoles_FollowTheSeededRole(t *testing.T) {
	const uid = "usr0000000000000seed"
	const (
		accOwn    = "acc0000000000000own1"
		accAdmin  = "acc0000000000000adm1"
		accEdit   = "acc0000000000000edt1"
		accView   = "acc0000000000000vew1"
		accCustom = "acc0000000000000cst1"
	)
	binding := func(acc, roleID string) domain.AccessBinding {
		return domain.AccessBinding{
			SubjectType:  "user",
			SubjectID:    uid,
			ResourceType: "account",
			ResourceID:   acc,
			RoleID:       domain.RoleID(roleID),
			Status:       domain.AccessBindingStatusActive,
		}
	}
	repo := &fakeWhoAmIRepo{
		users:      map[domain.UserID]domain.User{uid: {ID: uid, Email: "seed@example.test"}},
		accountsBy: map[domain.UserID][]domain.AccountID{uid: {accOwn, accAdmin, accEdit, accView, accCustom}},
		accounts: map[domain.AccountID]domain.Account{
			// Личный аккаунт: вызывающий — его владелец, и привязка OwnerRoleID
			// уровня аккаунта у него есть (user/mirror_tx.go, account/create.go).
			accOwn:    {ID: accOwn, Name: "Own", OwnerUserID: uid},
			accAdmin:  {ID: accAdmin, Name: "Adm", OwnerUserID: "usr000000000000other"},
			accEdit:   {ID: accEdit, Name: "Edt", OwnerUserID: "usr000000000000other"},
			accView:   {ID: accView, Name: "Vew", OwnerUserID: "usr000000000000other"},
			accCustom: {ID: accCustom, Name: "Cst", OwnerUserID: "usr000000000000other"},
		},
		bindings: []domain.AccessBinding{
			binding(accOwn, domain.OwnerRoleID),
			binding(accAdmin, seededRoleIDAccountAdmin),
			binding(accEdit, seededRoleIDEdit),
			binding(accView, seededRoleIDView),
			binding(accCustom, customRoleIDBillingOps),
		},
		roles: map[domain.RoleID]domain.Role{
			domain.OwnerRoleID:       {ID: domain.OwnerRoleID, Name: "owner", IsSystem: true},
			seededRoleIDAccountAdmin: {ID: seededRoleIDAccountAdmin, Name: "iam.account.admin", IsSystem: true},
			seededRoleIDEdit:         {ID: seededRoleIDEdit, Name: "edit", IsSystem: true},
			seededRoleIDView:         {ID: seededRoleIDView, Name: "view", IsSystem: true},
			customRoleIDBillingOps:   {ID: customRoleIDBillingOps, Name: "billing-ops", AccountID: accCustom},
		},
	}
	uc := NewWhoAmIUseCase(repo, nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: uid})

	res, err := uc.Execute(ctx)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := make(map[domain.AccountID][]string, len(res.Accounts))
	for _, a := range res.Accounts {
		got[a.AccountID] = a.Roles
	}
	for _, c := range []struct {
		account domain.AccountID
		want    []string
		why     string
	}{
		{accOwn, []string{"owner"}, "владелец личного аккаунта держит роль owner и только её"},
		{accAdmin, []string{"admin"}, "участник с ролью iam.account.admin — администратор"},
		{accEdit, []string{"editor"}, "роль edit — редактор"},
		{accView, []string{"viewer"}, "положительный близнец: у роли view тег viewer ЗАКОНЕН"},
		{accCustom, []string{"viewer"}, "положительный близнец: неизвестная роль откатывается в viewer"},
	} {
		have := got[c.account]
		if len(have) != len(c.want) {
			t.Errorf("%s: roles(%s) = %v; want %v", c.why, c.account, have, c.want)
			continue
		}
		for i := range c.want {
			if have[i] != c.want[i] {
				t.Errorf("%s: roles(%s) = %v; want %v", c.why, c.account, have, c.want)
				break
			}
		}
	}
}
