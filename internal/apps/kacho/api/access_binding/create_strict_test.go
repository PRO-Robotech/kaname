// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// create_strict_test.go — unit test for CreateAccessBindingUseCase strict
// create contract (migration 0003 — replaced idempotent ON CONFLICT upsert).
//
// Сценарий: 5-tuple уже занят активным grant'ом. doCreate.Insert возвращает
// ErrAlreadyExists (мапится из 23505 в проде); use-case → Operation worker
// сохраняет gRPC status с code AlreadyExists и канонический Kachō text
// «these permissions are already granted to <subject_id> on
// <res_type>:<res_id>».
//
// Тест НАМЕРЕННО не использует testcontainers — in-memory fakes.

import (
	"context"
	stderrors "errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	repoaccount "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	repogroup "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	repoproject "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	reposa "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	repouser "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// TestCreateAccessBinding_DuplicateActive_OperationAlreadyExists.
//
// Insert returns ErrAlreadyExists (verbatim text) → operations worker
// captures gRPC status with code AlreadyExists in op.Error.
func TestCreateAccessBinding_DuplicateActive_OperationAlreadyExists(t *testing.T) {
	const ownerUserID = "usr00000000000000test"
	const accountID = "acc00000000000000test"

	repo := newStrictDupFakeRepo(ownerUserID, accountID)
	opsRepo := newStrictFakeOpsRepo()
	uc := NewCreateAccessBindingUseCase(repo, opsRepo)

	ctx := operations.WithPrincipal(context.Background(), operations.Principal{
		Type: "user",
		ID:   ownerUserID,
	})

	b := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(ownerUserID),
		RoleID:       "rol00000000000000iamvw",
		ResourceType: "account",
		ResourceID:   accountID,
	}

	op, err := uc.Execute(ctx, b)
	require.NoError(t, err, "Execute must enqueue Operation even when worker will fail")
	require.NotNil(t, op)

	waitCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	saved, serr := opsRepo.Get(context.Background(), op.ID)
	require.NoError(t, serr)
	require.True(t, saved.Done, "operation must be done after worker")

	require.NotNil(t, saved.Error, "operation must carry an error (duplicate active grant)")
	assert.Equal(t, int32(codes.AlreadyExists), saved.Error.Code,
		"gRPC code must be AlreadyExists")
	want := "these permissions are already granted to " + ownerUserID + " on account:" + accountID
	assert.True(t, strings.Contains(saved.Error.Message, want),
		"error message must include verbatim text %q (got %q)", want, saved.Error.Message)
}

// ── in-memory fakes (strict-duplicate scenario) ────────────────────────────

type strictDupFakeRepo struct {
	ownerUserID string
	accountID   string
}

func newStrictDupFakeRepo(ownerUserID, accountID string) *strictDupFakeRepo {
	return &strictDupFakeRepo{ownerUserID: ownerUserID, accountID: accountID}
}

func (r *strictDupFakeRepo) Reader(ctx context.Context) (kachorepo.Reader, error) {
	return &strictDupFakeReader{repo: r}, nil
}
func (r *strictDupFakeRepo) Writer(ctx context.Context) (kachorepo.Writer, error) {
	return &strictDupFakeWriter{strictDupFakeReader: strictDupFakeReader{repo: r}}, nil
}
func (r *strictDupFakeRepo) Close() {}

type strictDupFakeReader struct {
	repo *strictDupFakeRepo
}

func (rd *strictDupFakeReader) Accounts() repoaccount.ReaderIface {
	return &strictDupAcctReader{ownerUserID: rd.repo.ownerUserID, accountID: rd.repo.accountID}
}
func (rd *strictDupFakeReader) Projects() repoproject.ReaderIface   { return nil }
func (rd *strictDupFakeReader) Users() repouser.ReaderIface         { return nil }
func (rd *strictDupFakeReader) ServiceAccounts() reposa.ReaderIface { return nil }
func (rd *strictDupFakeReader) Groups() repogroup.ReaderIface       { return nil }
func (rd *strictDupFakeReader) Roles() reporole.ReaderIface         { return &strictDupRoleReader{} }
func (rd *strictDupFakeReader) AccessBindings() repoab.ReaderIface {
	return &strictDupABReader{}
}
func (rd *strictDupFakeReader) Commit(context.Context) error   { return nil }
func (rd *strictDupFakeReader) Rollback(context.Context) error { return nil }

type strictDupFakeWriter struct {
	strictDupFakeReader
}

func (w *strictDupFakeWriter) AccountsW() repoaccount.WriterIface   { return nil }
func (w *strictDupFakeWriter) ProjectsW() repoproject.WriterIface   { return nil }
func (w *strictDupFakeWriter) UsersW() repouser.WriterIface         { return nil }
func (w *strictDupFakeWriter) ServiceAccountsW() reposa.WriterIface { return nil }
func (w *strictDupFakeWriter) GroupsW() repogroup.WriterIface       { return nil }
func (w *strictDupFakeWriter) RolesW() reporole.WriterIface         { return nil }
func (w *strictDupFakeWriter) AccessBindingsW() repoab.WriterIface {
	return &strictDupABWriter{}
}
func (w *strictDupFakeWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *strictDupFakeWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *strictDupFakeWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *strictDupFakeWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *strictDupFakeWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *strictDupFakeWriter) Savepoint(context.Context, string) error           { return nil }
func (w *strictDupFakeWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *strictDupFakeWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *strictDupFakeWriter) AdvisoryXactLock(context.Context, string) error    { return nil }

type strictDupAcctReader struct {
	ownerUserID string
	accountID   string
}

func (r *strictDupAcctReader) Get(ctx context.Context, id domain.AccountID) (domain.Account, error) {
	if string(id) == r.accountID {
		return domain.Account{
			ID:          domain.AccountID(r.accountID),
			OwnerUserID: domain.UserID(r.ownerUserID),
		}, nil
	}
	return domain.Account{}, iamerr.Wrapf(iamerr.ErrNotFound, "Account %s not found", id)
}
func (r *strictDupAcctReader) List(context.Context, repoaccount.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (r *strictDupAcctReader) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (r *strictDupAcctReader) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

type strictDupRoleReader struct{}

func (r *strictDupRoleReader) Get(ctx context.Context, id domain.RoleID) (domain.Role, error) {
	// System role → assignable on any resource (scope-enforcement
	// must pass so this test reaches the strict-duplicate Insert path it asserts).
	return domain.Role{
		ID:        id,
		Name:      "roles/iam.viewer",
		ClusterID: domain.ClusterID(domain.ClusterSingletonID),
		IsSystem:  true,
	}, nil
}
func (r *strictDupRoleReader) GetWithVersion(ctx context.Context, id domain.RoleID) (domain.Role, string, error) {
	role, err := r.Get(ctx, id)
	return role, "v-fake", err
}
func (r *strictDupRoleReader) List(context.Context, reporole.ListFilter) ([]domain.Role, string, error) {
	return nil, "", nil
}
func (r *strictDupRoleReader) ListAssignable(context.Context, string, string, reporole.ListFilter) ([]domain.Role, string, error) {
	return nil, "", nil
}
func (r *strictDupRoleReader) ExistsByName(context.Context, domain.AccountID, domain.RoleName) (bool, error) {
	return false, nil
}

type strictDupABReader struct{}

func (r *strictDupABReader) Get(ctx context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
}
func (r *strictDupABReader) ListByScope(context.Context, domain.ResourceType, string, repoab.PageFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}
func (r *strictDupABReader) ListBySubject(context.Context, domain.SubjectType, domain.SubjectID, repoab.PageFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}
func (r *strictDupABReader) ListByAccount(context.Context, domain.AccountID, repoab.AccountPageFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}
func (r *strictDupABReader) ListSubjectPrivileges(context.Context, domain.SubjectType, domain.SubjectID, repoab.PageFilter) ([]domain.SubjectPrivilege, string, error) {
	return nil, "", nil
}
func (r *strictDupABReader) SelectEmittedTuples(context.Context, domain.AccessBindingID) ([]repoab.RelationTuple, error) {
	return nil, nil
}
func (r *strictDupABReader) ListActiveByRole(context.Context, domain.RoleID) ([]domain.AccessBinding, error) {
	return nil, nil
}
func (r *strictDupABReader) CountActiveByRole(context.Context, domain.RoleID) (int, error) {
	return 0, nil
}
func (r *strictDupABReader) SelectEmittedTuplesBySource(context.Context, domain.AccessBindingID, string) ([]repoab.RelationTuple, error) {
	return nil, nil
}
func (r *strictDupABReader) ListByRole(context.Context, domain.RoleID, repoab.ListByRoleFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}
func (r *strictDupABReader) ListSubjects(context.Context, domain.AccessBindingID) ([]domain.Subject, error) {
	return nil, nil
}
func (r *strictDupABReader) ListSubjectsForBindings(context.Context, []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
	return nil, nil
}

type strictDupABWriter struct{}

func (w *strictDupABWriter) Insert(ctx context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	// Эмулирует Insert после migration 0003: дубль активного 5-tuple → ErrAlreadyExists.
	idHint := string(b.SubjectID) + " on " + string(b.ResourceType) + ":" + b.ResourceID
	return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrAlreadyExists,
		"these permissions are already granted to %s", idHint)
}
func (w *strictDupABWriter) Delete(ctx context.Context, id domain.AccessBindingID) error {
	return stderrors.New("not stubbed")
}
func (w *strictDupABWriter) DeleteGuarded(ctx context.Context, id domain.AccessBindingID) error {
	return stderrors.New("not stubbed")
}
func (w *strictDupABWriter) SetDeletionProtection(ctx context.Context, id domain.AccessBindingID, protected bool) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, stderrors.New("not stubbed")
}
func (w *strictDupABWriter) UpdateLabels(ctx context.Context, id domain.AccessBindingID, labels domain.Labels) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, stderrors.New("not stubbed")
}
func (w *strictDupABWriter) TransitionStatus(ctx context.Context, id domain.AccessBindingID,
	expected []domain.AccessBindingStatus, newStatus domain.AccessBindingStatus,
	revokedByUserID *domain.UserID) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, stderrors.New("not stubbed")
}
func (w *strictDupABWriter) EmitSubjectChangeEvent(_ context.Context, _ repoab.SubjectChangeEvent) error {
	return nil
}
func (w *strictDupABWriter) EmitRelationWrite(_ context.Context, _ []repoab.RelationTuple) error {
	return nil
}
func (w *strictDupABWriter) EmitRelationDelete(_ context.Context, _ []repoab.RelationTuple) error {
	return nil
}
func (w *strictDupABWriter) EmitAuditEvent(_ context.Context, _ repoab.AuditEvent) error {
	return nil
}
func (w *strictDupABWriter) InsertEmittedTuples(context.Context, domain.AccessBindingID, []repoab.RelationTuple) error {
	return nil
}
func (w *strictDupABWriter) ReplaceEmittedTuples(context.Context, domain.AccessBindingID, []repoab.RelationTuple) error {
	return nil
}
func (w *strictDupABWriter) InsertSubjects(context.Context, domain.AccessBindingID, []domain.Subject) error {
	return nil
}
func (w *strictDupABWriter) DeleteSubject(context.Context, domain.AccessBindingID, domain.Subject) (bool, error) {
	return false, nil
}

// ── in-memory operations.Repo ────────────────────────────────────────────

type strictFakeOpsRepo struct {
	mu  sync.Mutex
	ops map[string]*operations.Operation
}

func newStrictFakeOpsRepo() *strictFakeOpsRepo {
	return &strictFakeOpsRepo{ops: map[string]*operations.Operation{}}
}

func (r *strictFakeOpsRepo) Create(_ context.Context, op operations.Operation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := op
	r.ops[op.ID] = &cp
	return nil
}
func (r *strictFakeOpsRepo) CreateWithPrincipal(_ context.Context, op operations.Operation, _ operations.Principal) error {
	return r.Create(context.Background(), op)
}
func (r *strictFakeOpsRepo) Get(_ context.Context, id string) (*operations.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	cp := *op
	return &cp, nil
}
func (r *strictFakeOpsRepo) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (r *strictFakeOpsRepo) MarkDone(_ context.Context, id string, resp *anypb.Any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Response = resp
	}
	return nil
}
func (r *strictFakeOpsRepo) MarkError(_ context.Context, id string, st *gstatus.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Error = st
	}
	return nil
}
func (r *strictFakeOpsRepo) Cancel(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
	}
	return nil
}

var _ operations.Repo = (*strictFakeOpsRepo)(nil)

// EmitReconcileEvent — T3/Q2 no-op stub (fake does not exercise the iam-direct reconcile trigger).
func (w *strictDupFakeWriter) EmitReconcileEvent(context.Context, string, string, string) error {
	return nil
}
