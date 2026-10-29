// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// user_test.go — unit-тесты sync-валидации user use-cases (без БД).
//
// Покрытие:
//   - Get: invalid id format → InvalidArgument.
//   - Delete: invalid id format → InvalidArgument.
//   - BootstrapPersonalResourcesTx: граф заведения со-коммитится в транзакции.

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	gdrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/grant_delegation"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	repouser "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

func TestGetUser_Sync_InvalidID(t *testing.T) {
	uc := NewGetUserUseCase(newFakeUserRepo())
	_, err := uc.Execute(context.Background(), "bad-id-x")
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeleteUser_Sync_InvalidID(t *testing.T) {
	uc := NewDeleteUserUseCase(newFakeUserRepo(), newFakeOpsRepoUser())
	op, err := uc.Execute(context.Background(), "bad-id")
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// ── SEC-L: signup/bootstrap path writes the cluster parent-tuples ───────────

// spyFGA records WriteTuples calls so the test can assert the SEC-L cluster
// parent-pointer tuples are emitted on the bootstrap path. Mirrors the spyFGA
// helper in account/create_test.go and satisfies clients.RelationStore.
// ─────────────────────────────────────────────────────────────────────────────
// ЗДЕСЬ СТОЯЛ ДУБЛЁР ВТОРОЙ ПОЛОВИНЫ УТВЕРЖДЕНИЯ — ОН СНЯТ ВМЕСТЕ С ПРЕДМЕТОМ
//
// Он записывал набор, переданный ПОСТ-КОММИТНОЙ записи кортежей у внешнего
// движка, а проба требовала, чтобы этот набор был ПУСТ: «в транзакции — да, мимо
// неё — нет».
//
// Записи мимо транзакции больше не существует: у use-case'а нет ни поля, ни
// параметра, через которые она шла. Продукт физически не может пройти тем путём,
// значит утверждение о пустоте зеленело бы при любом поведении, а дублёр без
// утверждения — просто тип, который некому подставить.
//
// Отрицание не потеряно — оно переехало с прогона на СБОРКУ: возвращение
// пост-коммитной записи потребует вернуть и порт, и провязку, и это не проходит
// молча. Живая половина (намерение со-коммитится в той же транзакции) осталась
// ниже и по-прежнему падает.

// TestBootstrapPersonalResources_SECL_EmitsClusterParentTuplesInTx — 1.4-10b
// (S2-iam): the bootstrap body (`BootstrapPersonalResourcesTx`, the one that
// serves registration and invite activation) that provisions a NEW account +
// default project must co-commit the WHOLE bootstrap-graph (owner self-grant +
// admin self-grants + hierarchy + SEC-L cluster parent-pointer tuples) as
// fga_outbox INTENTS in the SAME bootstrap-tx — NOT best-effort post-commit
// through RelationStore.WriteTuples (which lost them on any FGA outage). The
// owner self-grant is D-4 non-reconstructible, so the in-tx emit is the only
// guarantee.
func TestBootstrapPersonalResources_SECL_EmitsClusterParentTuplesInTx(t *testing.T) {
	repo := newFakeUserRepo()
	ctx := context.Background()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)

	_, err = BootstrapPersonalResourcesTx(ctx, w, BootstrapInput{
		CandidateUserID: ids.NewID(domain.PrefixUser),
		ExternalID:      "zit-bootstrap-secl",
		Email:           "bootstrap-secl@example.com",
		DisplayName:     "Bootstrap SEC-L",
		Actor:           "system",
		NewIdentity:     true,
	})
	require.NoError(t, err)

	var accountClusterSeen, projectClusterSeen, ownerSeen bool
	for _, tup := range repo.fgaTuples() {
		if tup.Relation == "cluster" && tup.User == "cluster:cluster_root" {
			if strings.HasPrefix(tup.Object, "account:") {
				accountClusterSeen = true
			}
			if strings.HasPrefix(tup.Object, "project:") {
				projectClusterSeen = true
			}
		}
		if tup.Relation == "owner" && strings.HasPrefix(tup.User, "user:") &&
			strings.HasPrefix(tup.Object, "account:") {
			ownerSeen = true
		}
	}
	assert.True(t, ownerSeen,
		"bootstrap owner self-grant intent must be co-committed in-tx (D-4: not reconstructible)")
	assert.True(t, accountClusterSeen,
		"SEC-L: bootstrap must co-commit account:<id>#cluster@cluster:cluster_root in-tx")
	assert.True(t, projectClusterSeen,
		"SEC-L: bootstrap must co-commit project:<id>#cluster@cluster:cluster_root in-tx")
}

// ── fakes ────────────────────────────────────────────────────────────────

type fakeUserRepo struct {
	mu         sync.Mutex
	fgaEmitted []service.RelationTuple
	fgaDeleted []service.RelationTuple
}

func newFakeUserRepo() *fakeUserRepo { return &fakeUserRepo{} }

// fgaTuples — snapshot of the bootstrap FGA owner-tuple intents emitted in-tx.
func (f *fakeUserRepo) fgaTuples() []service.RelationTuple {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]service.RelationTuple, len(f.fgaEmitted))
	copy(cp, f.fgaEmitted)
	return cp
}

func (f *fakeUserRepo) Reader(ctx context.Context) (kanamerepo.Reader, error) {
	return &fakeURdr{parent: f}, nil
}
func (f *fakeUserRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	return &fakeUWtr{fakeURdr: fakeURdr{parent: f}, parent: f}, nil
}
func (f *fakeUserRepo) Close() {}

type fakeURdr struct{ parent *fakeUserRepo }

func (fakeURdr) Accounts() account.ReaderIface                { return fakeUserAccR{} }
func (fakeURdr) Projects() project.ReaderIface                { return nil }
func (r fakeURdr) Users() repouser.ReaderIface                { return fakeUserUR(r) }
func (fakeURdr) ServiceAccounts() service_account.ReaderIface { return nil }
func (fakeURdr) Groups() group.ReaderIface                    { return nil }
func (fakeURdr) Roles() role.ReaderIface                      { return nil }
func (fakeURdr) AccessBindings() access_binding.ReaderIface   { return nil }
func (fakeURdr) Commit(context.Context) error                 { return nil }
func (fakeURdr) Rollback(context.Context) error               { return nil }

// fakeUserAccR — account-reader stub for the RC-5 owns-zero-accounts gate. These
// unit tests drive the genuinely-new-identity bootstrap path, where the resolved
// user owns no account → CountAccountsByOwner returns 0 so bootstrap fires.
type fakeUserAccR struct{}

func (fakeUserAccR) Get(context.Context, domain.AccountID) (domain.Account, error) {
	return domain.Account{}, stderrors.New("not stubbed")
}
func (fakeUserAccR) List(context.Context, account.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (fakeUserAccR) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (fakeUserAccR) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

type fakeUWtr struct {
	fakeURdr
	parent *fakeUserRepo
}

func (w *fakeUWtr) AccountsW() account.WriterIface { return fakeAccW{} }
func (w *fakeUWtr) ProjectsW() project.WriterIface { return fakePrjW{} }
func (w *fakeUWtr) UsersW() repouser.WriterIface {
	return &fakeUserUW{fakeUserUR: fakeUserUR{parent: w.parent}, parent: w.parent}
}
func (w *fakeUWtr) ServiceAccountsW() service_account.WriterIface            { return nil }
func (w *fakeUWtr) GroupsW() group.WriterIface                               { return nil }
func (w *fakeUWtr) RolesW() role.WriterIface                                 { return nil }
func (w *fakeUWtr) AccessBindingsW() access_binding.WriterIface              { return fakeABW{} }
func (w *fakeUWtr) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *fakeUWtr) EmitFGARelationWrite(_ context.Context, tuples []service.RelationTuple) error {
	w.parent.mu.Lock()
	w.parent.fgaEmitted = append(w.parent.fgaEmitted, tuples...)
	w.parent.mu.Unlock()
	return nil
}

// EmitFGARelationDelete записывает снятия так же, как соседний Write записывает
// записи. Прежде он их ГЛОТАЛ — а дублёр, принимающий больше настоящего, делает
// невидимым ровно тот дефект, ради которого его подставляют: путь удаления мог
// не эмитить ничего, и ни один юнит этого не заметил бы.
func (w *fakeUWtr) EmitFGARelationDelete(_ context.Context, tuples []service.RelationTuple) error {
	w.parent.mu.Lock()
	w.parent.fgaDeleted = append(w.parent.fgaDeleted, tuples...)
	w.parent.mu.Unlock()
	return nil
}

func (w *fakeUWtr) AdvisoryXactLock(context.Context, string) error { return nil }

// Stubs нужные для bootstrap-path (InsertActive + Account.Insert +
// Project.Insert + AB.Insert). Возвращают входной argument как success.

type fakeAccW struct{}

func (fakeAccW) Insert(_ context.Context, a domain.Account) (domain.Account, error) {
	a.CreatedAt = time.Now().UTC()
	return a, nil
}
func (fakeAccW) Update(_ context.Context, a domain.Account, _ []string) (domain.Account, error) {
	return a, nil
}
func (fakeAccW) Delete(context.Context, domain.AccountID) error { return nil }
func (fakeAccW) LockForRemoval(context.Context, domain.AccountID) ([]domain.UserID, error) {
	return nil, nil
}
func (fakeAccW) LockOwner(context.Context, domain.UserID) error { return nil }

type fakePrjW struct{}

func (fakePrjW) Insert(_ context.Context, p domain.Project) (domain.Project, error) {
	p.CreatedAt = time.Now().UTC()
	return p, nil
}
func (fakePrjW) Update(_ context.Context, p domain.Project, _ []string) (domain.Project, error) {
	return p, nil
}
func (fakePrjW) Delete(context.Context, domain.ProjectID) error { return nil }

type fakeABW struct{}

// LockLiveTargetTypes — подмножество `types`, живое в каталоге фикстуры: дублёр
// не снисходительнее настоящего писателя.
func (fakeABW) LockLiveTargetTypes(_ context.Context, types []string) ([]string, error) {
	f := catalogfixture.Facts()
	var out []string
	for _, ty := range types {
		if _, ok := f.FGAObjectType(ty); ok {
			out = append(out, ty)
		}
	}
	return out, nil
}

func (fakeABW) Insert(_ context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	b.CreatedAt = time.Now().UTC()
	return b, nil
}
func (fakeABW) Delete(context.Context, domain.AccessBindingID) error        { return nil }
func (fakeABW) DeleteGuarded(context.Context, domain.AccessBindingID) error { return nil }
func (fakeABW) GetForDeactivation(context.Context, domain.AccessBindingID) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, nil
}
func (fakeABW) RevokeGuarded(context.Context, domain.AccessBindingID, domain.UserID) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, nil
}
func (fakeABW) SetDeletionProtection(context.Context, domain.AccessBindingID, bool) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, nil
}
func (fakeABW) UpdateLabels(context.Context, domain.AccessBindingID, domain.Labels) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, nil
}
func (fakeABW) TransitionStatus(
	_ context.Context, _ domain.AccessBindingID, _ []domain.AccessBindingStatus,
	_ domain.AccessBindingStatus, _ *domain.UserID,
) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, nil
}
func (fakeABW) EmitSubjectChangeEvent(context.Context, access_binding.SubjectChangeEvent) error {
	return nil
}
func (fakeABW) EmitRelationWrite(context.Context, []access_binding.RelationTuple) error  { return nil }
func (fakeABW) EmitRelationDelete(context.Context, []access_binding.RelationTuple) error { return nil }
func (fakeABW) EmitRelationJournal(context.Context, []access_binding.RelationTuple, []access_binding.RelationTuple) error {
	return nil
}
func (fakeABW) EmitAuditEvent(context.Context, access_binding.AuditEvent) error { return nil }
func (fakeABW) InsertEmittedTuples(context.Context, domain.AccessBindingID, []access_binding.RelationTuple) error {
	return nil
}
func (fakeABW) ReplaceEmittedTuples(context.Context, domain.AccessBindingID, []access_binding.RelationTuple) error {
	return nil
}
func (fakeABW) InsertSubjects(context.Context, domain.AccessBindingID, []domain.Subject) error {
	return nil
}
func (fakeABW) DeleteSubject(context.Context, domain.AccessBindingID, domain.Subject) (bool, error) {
	return false, nil
}

type fakeUserUR struct{ parent *fakeUserRepo }

func (fakeUserUR) Get(context.Context, domain.UserID) (domain.User, error) {
	return domain.User{}, stderrors.New("not stubbed")
}
func (fakeUserUR) GetByEmail(context.Context, domain.Email) (domain.User, error) {
	return domain.User{}, stderrors.New("not stubbed")
}
func (fakeUserUR) GetByAccountEmail(context.Context, domain.AccountID, domain.Email) (domain.User, error) {
	return domain.User{}, stderrors.New("not stubbed")
}

func (fakeUserUR) FindPendingByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (fakeUserUR) FindByExternalIDInStatuses(context.Context, domain.ExternalSubject, []domain.InviteStatus) ([]domain.User, error) {
	return nil, nil
}
func (fakeUserUR) FindActiveByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (fakeUserUR) ListAccountsForUser(context.Context, domain.UserID) ([]domain.AccountID, error) {
	return nil, nil
}
func (fakeUserUR) List(context.Context, repouser.ListFilter) ([]domain.User, string, error) {
	return nil, "", nil
}

type fakeUserUW struct {
	fakeUserUR
	parent *fakeUserRepo
}

func (w *fakeUserUW) InsertPending(_ context.Context, u domain.User, _ time.Time) (domain.User, bool, error) {
	u.CreatedAt = time.Now().UTC()
	return u, true, nil
}
func (w *fakeUserUW) ActivateInvite(_ context.Context, userID domain.UserID, ext domain.ExternalSubject, dn domain.DisplayName) (domain.User, error) {
	return domain.User{ID: userID, ExternalID: ext, DisplayName: dn, InviteStatus: domain.InviteStatusActive}, nil
}

// InsertActive — ветвь заведения новой личности.
func (w *fakeUserUW) InsertActive(_ context.Context, u domain.User) (domain.User, error) {
	u.CreatedAt = time.Now().UTC()
	return u, nil
}
func (w *fakeUserUW) Delete(context.Context, domain.UserID) error { return nil }
func (*fakeUserUW) LockForRemoval(context.Context, domain.UserID) ([]domain.AccountID, error) {
	return nil, nil
}
func (*fakeUserUW) Now(context.Context) (time.Time, error) { return time.Now().UTC(), nil }
func (*fakeUserUW) CutOffIdentity(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *fakeUserUW) UpdateLabels(_ context.Context, id domain.UserID, _ domain.Labels) (domain.User, error) {
	return domain.User{ID: id}, nil
}

// fake ops
type fakeOpsRepoUser struct {
	mu  sync.Mutex
	ops map[string]*operations.Operation
}

func newFakeOpsRepoUser() *fakeOpsRepoUser {
	return &fakeOpsRepoUser{ops: map[string]*operations.Operation{}}
}

func (r *fakeOpsRepoUser) Create(_ context.Context, op operations.Operation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := op
	r.ops[op.ID] = &cp
	return nil
}
func (r *fakeOpsRepoUser) CreateWithPrincipal(_ context.Context, op operations.Operation, _ operations.Principal) error {
	return r.Create(context.Background(), op)
}
func (r *fakeOpsRepoUser) Get(_ context.Context, id string) (*operations.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	cp := *op
	return &cp, nil
}
func (r *fakeOpsRepoUser) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (r *fakeOpsRepoUser) MarkDone(_ context.Context, id string, resp *anypb.Any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Response = resp
	}
	return nil
}
func (r *fakeOpsRepoUser) MarkError(_ context.Context, id string, st *gstatus.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Error = st
	}
	return nil
}
func (r *fakeOpsRepoUser) Cancel(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
	}
	return nil
}

// EmitReconcileEvent — T3/Q2 no-op stub (fake does not exercise the iam-direct reconcile trigger).
func (w *fakeUWtr) EmitReconcileEvent(context.Context, string, string, string) error {
	return nil
}

// SetInviteStatus — заглушка: bootstrap-пути этот писатель не касается.
func (w *fakeUserUW) SetInviteStatus(context.Context, domain.UserID, domain.InviteStatus) (domain.User, error) {
	return domain.User{}, nil
}

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (fakeURdr) Visibility() visibility.ReaderIface { return nil }

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *fakeUWtr) Visibility() visibility.ReaderIface { return nil }

// MembershipExists — дублёр не отвечает на вопрос о членстве: предмет этих проб
// другой, и подставной ответ был бы утверждением, которого никто не делал.
func (fakeUserUR) MembershipExists(context.Context, domain.UserID, domain.AccountID) (bool, error) {
	return false, nil
}

// Membership — дублёр членства ПАРОЙ не читает: предмет этих проб другой, и
// подставная строка была бы утверждением, которого никто не делал (kaname#181).
func (fakeUserUR) Membership(context.Context, domain.UserID, domain.AccountID) (domain.Membership, error) {
	return domain.Membership{}, iamerr.ErrNotFound
}

// RemoveMembership — дублёр исключения из аккаунта не делает: снятие членства
// проверяется своими пробами (kacho#1127).
func (*fakeUserUW) RemoveMembership(context.Context, domain.UserID, domain.AccountID) (bool, error) {
	return false, nil
}

// EmitInviteMail — порт со-коммита намерения отправить письмо приглашения.
// Дублёр не глотает того, что настоящий отвергает: пустой адресат и пустой ключ
// партиции отвергаются здесь так же, как ограничением миграции, — иначе фикстура
// была бы снисходительнее продукта и скрыла бы ровно тот дефект, ради которого её
// подставляют.
func (w *fakeUWtr) EmitInviteMail(_ context.Context, intent outboxtypes.InviteMailIntent) (bool, error) {
	if intent.To == "" {
		return false, fmt.Errorf("invite mail: recipient required")
	}
	if intent.UserID == "" {
		return false, fmt.Errorf("invite mail: user id required")
	}
	if intent.Limit.MaxPerWindow <= 0 || intent.Limit.Window <= 0 {
		return false, fmt.Errorf("invite mail: rate limit must be positive — there is no «unlimited»")
	}
	return true, nil
}

// GrantDelegationsW — делегирований этот дублёр не несёт (kaname#986): пробы файла
// делегированного пути права выдавать не касаются.
func (fakeABW) GrantDelegationsW() gdrepo.WriterIface { return nil }
