// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// account_id_metadata_test.go — verifies UserService.Delete stamps the owning
// account_id (target.AccountID, loaded
// synchronously for authz) into DeleteUserMetadata so the operation surfaces in
// the account-scoped module list. Account-less users (AccountID=="") leave it
// empty → corelib writes SQL NULL → excluded from the account-scoped list
// (visible per-resource + cluster-wide Internal).

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	repoproject "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	repouser "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

const (
	delUserID = "usr0000000000000self"
	delAccID  = "acc0000000000000abcd"
)

func selfCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: delUserID})
}

func deleteUserMetaAccountID(t *testing.T, opsRepo *fakeUsrOps) string {
	t.Helper()
	opsRepo.mu.Lock()
	defer opsRepo.mu.Unlock()
	require.Len(t, opsRepo.ops, 1, "exactly one operation must be created")
	for _, op := range opsRepo.ops {
		md := &iamv1.DeleteUserMetadata{}
		require.NoError(t, op.Metadata.UnmarshalTo(md))
		return md.GetAccountId()
	}
	return ""
}

func TestDeleteUser_StampsAccountID(t *testing.T) {
	opsRepo := newFakeUsrOps()
	uc := NewDeleteUserUseCase(newFakeUsrRepo(delAccID), opsRepo)
	op, err := uc.Execute(selfCtx(), delUserID)
	require.NoError(t, err)
	require.NotNil(t, op)

	assert.Equal(t, delAccID, deleteUserMetaAccountID(t, opsRepo),
		"DeleteUserMetadata.account_id from target.AccountID")
}

func TestDeleteUser_AccountLess_EmptyAccountID(t *testing.T) {
	// Account-less user (AccountID=="") → empty account_id in the metadata →
	// corelib writes SQL NULL → excluded from the partial-index account list.
	opsRepo := newFakeUsrOps()
	uc := NewDeleteUserUseCase(newFakeUsrRepo(""), opsRepo)
	op, err := uc.Execute(selfCtx(), delUserID)
	require.NoError(t, err)
	require.NotNil(t, op)

	assert.Empty(t, deleteUserMetaAccountID(t, opsRepo),
		"account-less user → empty account_id → SQL NULL")
}

// ── compact fake Repo (Users reader populated for self-delete) ──────────────

type fakeUsrRepo struct{ accID string }

func newFakeUsrRepo(accID string) *fakeUsrRepo { return &fakeUsrRepo{accID: accID} }

func (f *fakeUsrRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &fakeUsrReader{accID: f.accID}, nil
}
func (f *fakeUsrRepo) Writer(context.Context) (kachorepo.Writer, error) {
	return &fakeUsrWriter{fakeUsrReader: fakeUsrReader{accID: f.accID}}, nil
}
func (f *fakeUsrRepo) Close() {}

type fakeUsrReader struct{ accID string }

func (r *fakeUsrReader) Accounts() account.ReaderIface                { return nil }
func (r *fakeUsrReader) Projects() repoproject.ReaderIface            { return nil }
func (r *fakeUsrReader) Users() repouser.ReaderIface                  { return &fakeUsrRdr{accID: r.accID} }
func (r *fakeUsrReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *fakeUsrReader) Groups() group.ReaderIface                    { return nil }
func (r *fakeUsrReader) Roles() role.ReaderIface                      { return nil }
func (r *fakeUsrReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *fakeUsrReader) Commit(context.Context) error                 { return nil }
func (r *fakeUsrReader) Rollback(context.Context) error               { return nil }

type fakeUsrWriter struct{ fakeUsrReader }

func (w *fakeUsrWriter) AccountsW() account.WriterIface                           { return nil }
func (w *fakeUsrWriter) ProjectsW() repoproject.WriterIface                       { return nil }
func (w *fakeUsrWriter) UsersW() repouser.WriterIface                             { return &fakeUsrWtr{} }
func (w *fakeUsrWriter) ServiceAccountsW() service_account.WriterIface            { return nil }
func (w *fakeUsrWriter) GroupsW() group.WriterIface                               { return nil }
func (w *fakeUsrWriter) RolesW() role.WriterIface                                 { return nil }
func (w *fakeUsrWriter) AccessBindingsW() access_binding.WriterIface              { return nil }
func (w *fakeUsrWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *fakeUsrWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *fakeUsrWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *fakeUsrWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *fakeUsrWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *fakeUsrWriter) Savepoint(context.Context, string) error           { return nil }
func (w *fakeUsrWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *fakeUsrWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *fakeUsrWriter) AdvisoryXactLock(context.Context, string) error    { return nil }

type fakeUsrRdr struct{ accID string }

func (r *fakeUsrRdr) Get(_ context.Context, id domain.UserID) (domain.User, error) {
	return domain.User{ID: id, AccountID: domain.AccountID(r.accID), CreatedAt: time.Now().UTC()}, nil
}
func (r *fakeUsrRdr) GetByExternalID(context.Context, domain.ExternalSubject) (domain.User, error) {
	return domain.User{}, iamerr.ErrNotFound
}
func (r *fakeUsrRdr) GetByEmail(context.Context, domain.Email) (domain.User, error) {
	return domain.User{}, iamerr.ErrNotFound
}
func (r *fakeUsrRdr) List(context.Context, repouser.ListFilter) ([]domain.User, string, error) {
	return nil, "", nil
}
func (r *fakeUsrRdr) GetByAccountEmail(context.Context, domain.AccountID, domain.Email) (domain.User, error) {
	return domain.User{}, iamerr.ErrNotFound
}
func (r *fakeUsrRdr) FindPendingByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (r *fakeUsrRdr) FindActiveByExternalID(context.Context, domain.ExternalSubject) ([]domain.User, error) {
	return nil, nil
}
func (r *fakeUsrRdr) FindByExternalIDInStatuses(context.Context, domain.ExternalSubject, []domain.InviteStatus) ([]domain.User, error) {
	return nil, nil
}
func (r *fakeUsrRdr) FindActiveByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (r *fakeUsrRdr) ListAccountsForUser(context.Context, domain.UserID) ([]domain.AccountID, error) {
	return nil, nil
}

type fakeUsrWtr struct{ fakeUsrRdr }

func (w *fakeUsrWtr) Upsert(_ context.Context, u domain.User) (domain.User, bool, error) {
	return u, false, nil
}
func (w *fakeUsrWtr) InsertPending(_ context.Context, u domain.User) (domain.User, bool, error) {
	return u, false, nil
}
func (w *fakeUsrWtr) ActivateInvite(_ context.Context, id domain.UserID, _ domain.ExternalSubject, _ domain.DisplayName) (domain.User, error) {
	return domain.User{ID: id}, nil
}
func (w *fakeUsrWtr) InsertActive(_ context.Context, u domain.User) (domain.User, error) {
	return u, nil
}
func (w *fakeUsrWtr) ReEnable(_ context.Context, id domain.UserID) (domain.User, bool, error) {
	return domain.User{ID: id}, false, nil
}
func (w *fakeUsrWtr) Delete(context.Context, domain.UserID) error { return nil }
func (w *fakeUsrWtr) UpdateLabels(_ context.Context, id domain.UserID, _ domain.Labels) (domain.User, error) {
	return domain.User{ID: id}, nil
}

// ── fake ops repo ───────────────────────────────────────────────────────────

type fakeUsrOps struct {
	mu  sync.Mutex
	ops map[string]*operations.Operation
}

func newFakeUsrOps() *fakeUsrOps { return &fakeUsrOps{ops: map[string]*operations.Operation{}} }

func (r *fakeUsrOps) Create(_ context.Context, op operations.Operation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := op
	r.ops[op.ID] = &cp
	return nil
}
func (r *fakeUsrOps) CreateWithPrincipal(_ context.Context, op operations.Operation, _ operations.Principal) error {
	return r.Create(context.Background(), op)
}
func (r *fakeUsrOps) Get(_ context.Context, id string) (*operations.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	cp := *op
	return &cp, nil
}
func (r *fakeUsrOps) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (r *fakeUsrOps) MarkDone(_ context.Context, id string, resp *anypb.Any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Response = resp
	}
	return nil
}
func (r *fakeUsrOps) MarkError(_ context.Context, id string, st *gstatus.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Error = st
	}
	return nil
}
func (r *fakeUsrOps) Cancel(_ context.Context, id string) error { return nil }

// EmitReconcileEvent — no-op stub (fake does not exercise the iam-direct reconcile trigger).
func (w *fakeUsrWriter) EmitReconcileEvent(context.Context, string, string, string) error {
	return nil
}
