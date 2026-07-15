// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// update_test.go — unit-тесты UpdateUserUseCase (без БД, через in-memory fakes).
//
// Покрывает новый публичный UpdateUser RPC (T3.3 D-1a):
//   - T3.3-UPD-02: identity-поле (external_id) в update_mask → sync
//     INVALID_ARGUMENT "external_id is immutable after User.Create"
//     (первым стейтментом, до writer-tx); unknown-поле в mask → INVALID_ARGUMENT.
//   - T3.3-UPD-01: happy — labels через mask; full-PATCH (пустой mask) применяет
//     labels, immutable identity-поля из тела silently игнорируются.
//   - malformed user id → sync INVALID_ARGUMENT.
//
// Реальный round-trip labels + reconcile-event co-commit — в integration-тестах
// (см. pg/user_labels_integration_test.go).

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

const (
	updAccountID = "acc0000000000000updt"
	updOwnerID   = "usr0000000000000ownr"
	updUserID    = "usr0000000000000targ"
)

// ── fakes ────────────────────────────────────────────────────────────────────

type updUserRepo struct {
	mu       sync.Mutex
	user     domain.User
	owner    domain.UserID
	updated  domain.Labels
	updCalls int
	reconcil []string // objectIDs for which a reconcile-event was emitted
}

func newUpdUserRepo() *updUserRepo {
	return &updUserRepo{
		user: domain.User{
			ID:           domain.UserID(updUserID),
			AccountID:    domain.AccountID(updAccountID),
			ExternalID:   "ext-target",
			Email:        "target@example.com",
			DisplayName:  "Target",
			InviteStatus: domain.InviteStatusActive,
		},
		owner: domain.UserID(updOwnerID),
	}
}

func (f *updUserRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &updUserReader{parent: f}, nil
}
func (f *updUserRepo) Writer(context.Context) (kachorepo.Writer, error) {
	return &updUserWriter{updUserReader: updUserReader{parent: f}}, nil
}
func (f *updUserRepo) Close() {}

func (f *updUserRepo) labelsSnapshot() domain.Labels {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.updated
}
func (f *updUserRepo) reconcileSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.reconcil...)
}

type updUserReader struct{ parent *updUserRepo }

func (r *updUserReader) Accounts() account.ReaderIface                { return &updAccountRdr{parent: r.parent} }
func (r *updUserReader) Projects() project.ReaderIface                { return nil }
func (r *updUserReader) Users() user.ReaderIface                      { return &updUserRdr{parent: r.parent} }
func (r *updUserReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *updUserReader) Groups() group.ReaderIface                    { return nil }
func (r *updUserReader) Roles() role.ReaderIface                      { return nil }
func (r *updUserReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *updUserReader) Commit(context.Context) error                 { return nil }
func (r *updUserReader) Rollback(context.Context) error               { return nil }

type updUserRdr struct{ parent *updUserRepo }

func (r *updUserRdr) Get(_ context.Context, id domain.UserID) (domain.User, error) {
	r.parent.mu.Lock()
	defer r.parent.mu.Unlock()
	if id != r.parent.user.ID {
		return domain.User{}, errNotFound
	}
	return r.parent.user, nil
}
func (r *updUserRdr) GetByExternalID(context.Context, domain.ExternalSubject) (domain.User, error) {
	return domain.User{}, errNotFound
}
func (r *updUserRdr) GetByEmail(context.Context, domain.Email) (domain.User, error) {
	return domain.User{}, errNotFound
}
func (r *updUserRdr) List(context.Context, user.ListFilter) ([]domain.User, string, error) {
	return nil, "", nil
}
func (r *updUserRdr) GetByAccountEmail(context.Context, domain.AccountID, domain.Email) (domain.User, error) {
	return domain.User{}, errNotFound
}
func (r *updUserRdr) FindPendingByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (r *updUserRdr) FindActiveByExternalID(context.Context, domain.ExternalSubject) ([]domain.User, error) {
	return nil, nil
}
func (r *updUserRdr) FindByExternalIDInStatuses(context.Context, domain.ExternalSubject, []domain.InviteStatus) ([]domain.User, error) {
	return nil, nil
}
func (r *updUserRdr) FindActiveByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (r *updUserRdr) ListAccountsForUser(context.Context, domain.UserID) ([]domain.AccountID, error) {
	return nil, nil
}

type updAccountRdr struct{ parent *updUserRepo }

func (r *updAccountRdr) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	if id != r.parent.user.AccountID {
		return domain.Account{}, errNotFound
	}
	return domain.Account{ID: id, Name: "acct", OwnerUserID: r.parent.owner}, nil
}
func (r *updAccountRdr) List(context.Context, account.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (r *updAccountRdr) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}
func (r *updAccountRdr) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}

type updUserWriter struct {
	updUserReader
}

func (w *updUserWriter) AccountsW() account.WriterIface                { return nil }
func (w *updUserWriter) ProjectsW() project.WriterIface                { return nil }
func (w *updUserWriter) UsersW() user.WriterIface                      { return &updUserWtr{parent: w.parent} }
func (w *updUserWriter) ServiceAccountsW() service_account.WriterIface { return nil }
func (w *updUserWriter) GroupsW() group.WriterIface                    { return nil }
func (w *updUserWriter) RolesW() role.WriterIface                      { return nil }
func (w *updUserWriter) AccessBindingsW() access_binding.WriterIface   { return nil }

func (w *updUserWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *updUserWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *updUserWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *updUserWriter) EmitReconcileEvent(_ context.Context, _, _, objectID string) error {
	w.parent.mu.Lock()
	defer w.parent.mu.Unlock()
	w.parent.reconcil = append(w.parent.reconcil, objectID)
	return nil
}
func (w *updUserWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *updUserWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *updUserWriter) Savepoint(context.Context, string) error           { return nil }
func (w *updUserWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *updUserWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *updUserWriter) AdvisoryXactLock(context.Context, string) error    { return nil }
func (w *updUserWriter) Commit(context.Context) error                      { return nil }
func (w *updUserWriter) Rollback(context.Context) error                    { return nil }

type updUserWtr struct{ parent *updUserRepo }

func (w *updUserWtr) Upsert(context.Context, domain.User) (domain.User, bool, error) {
	return domain.User{}, false, nil
}
func (w *updUserWtr) InsertPending(context.Context, domain.User) (domain.User, bool, error) {
	return domain.User{}, false, nil
}
func (w *updUserWtr) ActivateInvite(context.Context, domain.UserID, domain.ExternalSubject, domain.DisplayName) (domain.User, error) {
	return domain.User{}, nil
}
func (w *updUserWtr) InsertActive(context.Context, domain.User) (domain.User, error) {
	return domain.User{}, nil
}
func (w *updUserWtr) ReEnable(context.Context, domain.UserID) (domain.User, bool, error) {
	return domain.User{}, false, nil
}
func (w *updUserWtr) Delete(context.Context, domain.UserID) error { return nil }
func (w *updUserWtr) UpdateLabels(_ context.Context, id domain.UserID, labels domain.Labels) (domain.User, error) {
	w.parent.mu.Lock()
	defer w.parent.mu.Unlock()
	w.parent.updCalls++
	w.parent.updated = labels
	out := w.parent.user
	out.Labels = labels
	w.parent.user = out
	return out, nil
}

var errNotFound = stderrors.New("not found")

// ── opsRepo fake ─────────────────────────────────────────────────────────────

type updOpsRepo struct {
	mu  sync.Mutex
	ops map[string]*operations.Operation
}

func newUpdOpsRepo() *updOpsRepo { return &updOpsRepo{ops: map[string]*operations.Operation{}} }

func (r *updOpsRepo) Create(_ context.Context, op operations.Operation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := op
	r.ops[op.ID] = &cp
	return nil
}
func (r *updOpsRepo) CreateWithPrincipal(ctx context.Context, op operations.Operation, _ operations.Principal) error {
	return r.Create(ctx, op)
}
func (r *updOpsRepo) Get(_ context.Context, id string) (*operations.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	return op, nil
}
func (r *updOpsRepo) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (r *updOpsRepo) MarkDone(_ context.Context, id string, response *anypb.Any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op := r.ops[id]; op != nil {
		op.Done = true
		op.Response = response
	}
	return nil
}
func (r *updOpsRepo) MarkError(_ context.Context, id string, st *gstatus.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op := r.ops[id]; op != nil {
		op.Done = true
		op.Error = st
	}
	return nil
}
func (r *updOpsRepo) Cancel(context.Context, string) error { return nil }

func ownerCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: updOwnerID})
}

// ── tests ──────────────────────────────────────────────────────────────────

// T3.3-UPD-02 — external_id (IdP identity) в update_mask → sync INVALID_ARGUMENT
// первым стейтментом, операция не создается.
func TestUpdateUser_T33UPD02_ExternalIDImmutable(t *testing.T) {
	uc := NewUpdateUserUseCase(newUpdUserRepo(), newUpdOpsRepo())
	op, err := uc.Execute(ownerCtx(), UpdateUserInput{
		ID:         domain.UserID(updUserID),
		Labels:     domain.Labels{"tier": "gold"},
		UpdateMask: []string{"external_id"},
	})
	require.Error(t, err)
	assert.Nil(t, op, "Operation не создается при sync-immutability-ошибке")
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, err.Error(), "external_id is immutable after User.Create")
}

// T3.3-UPD-02 — unknown-поле в update_mask → sync INVALID_ARGUMENT.
func TestUpdateUser_T33UPD02_UnknownMaskField(t *testing.T) {
	uc := NewUpdateUserUseCase(newUpdUserRepo(), newUpdOpsRepo())
	op, err := uc.Execute(ownerCtx(), UpdateUserInput{
		ID:         domain.UserID(updUserID),
		Labels:     domain.Labels{"tier": "gold"},
		UpdateMask: []string{"nonexistent"},
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// malformed user id → sync INVALID_ARGUMENT первым стейтментом.
func TestUpdateUser_MalformedID(t *testing.T) {
	uc := NewUpdateUserUseCase(newUpdUserRepo(), newUpdOpsRepo())
	op, err := uc.Execute(ownerCtx(), UpdateUserInput{
		ID:         "not-a-user-id",
		UpdateMask: []string{"labels"},
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// T3.3-UPD-01 happy — labels через mask: Operation возвращен, async worker пишет
// labels через UpdateLabels + co-commit reconcile-event на own-resource.
func TestUpdateUser_T33UPD01_LabelsViaMask(t *testing.T) {
	repo := newUpdUserRepo()
	uc := NewUpdateUserUseCase(repo, newUpdOpsRepo())
	op, err := uc.Execute(ownerCtx(), UpdateUserInput{
		ID:         domain.UserID(updUserID),
		Labels:     domain.Labels{"tier": "gold"},
		UpdateMask: []string{"labels"},
	})
	require.NoError(t, err)
	require.NotNil(t, op)
	assert.False(t, op.Done, "первый ответ — done=false (async)")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	assert.Equal(t, domain.Labels{"tier": "gold"}, repo.labelsSnapshot(),
		"async worker применяет labels через UpdateLabels")
	assert.Contains(t, repo.reconcileSnapshot(), updUserID,
		"label-change co-commit'ит reconcile-event на own-resource (eager re-materialization)")
}

// T3.3-UPD-01 случай B — full-PATCH (пустой mask): применяются mutable labels;
// immutable identity-поля (external_id и пр.) не затрагиваются — flat-request их
// вообще не несет, изменить можно только через mask (где они reject'атся).
func TestUpdateUser_T33UPD01_FullPatchEmptyMask(t *testing.T) {
	repo := newUpdUserRepo()
	uc := NewUpdateUserUseCase(repo, newUpdOpsRepo())
	op, err := uc.Execute(ownerCtx(), UpdateUserInput{
		ID:         domain.UserID(updUserID),
		Labels:     domain.Labels{"tier": "silver"},
		UpdateMask: nil, // empty mask = full-PATCH
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	assert.Equal(t, domain.Labels{"tier": "silver"}, repo.labelsSnapshot(),
		"full-PATCH применяет mutable labels")
	assert.Equal(t, domain.ExternalSubject("ext-target"), repo.user.ExternalID,
		"immutable external_id при full-PATCH не затрагивается")
}

// Handler-уровень: flat-форма UpdateUserRequest. Проверяем, что транспорт читает
// `labels` с верхнего уровня request'а (а не из вложенного `User`) и протаскивает
// их в use-case → repo. Гард против регресса формы request'а к nested-варианту.
func TestUpdateUserHandler_FlatLabels(t *testing.T) {
	repo := newUpdUserRepo()
	uc := NewUpdateUserUseCase(repo, newUpdOpsRepo())
	h := NewHandler(nil, nil, uc, nil, nil)

	op, err := h.Update(ownerCtx(), &iamv1.UpdateUserRequest{
		UserId:     updUserID,
		Labels:     map[string]string{"tier": "gold"},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
	})
	require.NoError(t, err)
	require.NotNil(t, op)
	assert.False(t, op.GetDone(), "первый ответ — done=false (async)")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	assert.Equal(t, domain.Labels{"tier": "gold"}, repo.labelsSnapshot(),
		"flat request.labels доходят до repo через handler")
}
