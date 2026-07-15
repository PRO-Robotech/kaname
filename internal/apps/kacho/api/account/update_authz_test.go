// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// update_authz_test.go — verifies UpdateAccountUseCase no longer double-gates
// by owner-equality: an account-editor (FGA `editor` relation, not the
// Account owner) is allowed; a non-member is still denied.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
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
	authzAcctID   = "acc0000000000000abcd"
	authzOwnerID  = "usr0000000000000ownr"
	authzEditorID = "usr0000000000000edit"
	authzOtherID  = "usr0000000000000othr"
)

// stubFGA — minimal in-memory clients.RelationStore for authz tests.
type stubFGA struct {
	mu    sync.Mutex
	store map[string]struct{}
}

func newStubFGA() *stubFGA { return &stubFGA{store: map[string]struct{}{}} }

func (s *stubFGA) allow(subject, relation, object string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[subject+"|"+relation+"|"+object] = struct{}{}
}

func (s *stubFGA) Check(_ context.Context, subject, relation, object string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.store[subject+"|"+relation+"|"+object]
	return ok, nil
}

func (s *stubFGA) WriteTuples(context.Context, []clients.RelationTuple) error  { return nil }
func (s *stubFGA) DeleteTuples(context.Context, []clients.RelationTuple) error { return nil }

var _ clients.RelationStore = (*stubFGA)(nil)

// authzAcctRepo — fake Repo that stubs Accounts().Get with a fixed owner.
type authzAcctRepo struct{ ownerUserID domain.UserID }

func (f *authzAcctRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &authzAcctReader{parent: f}, nil
}
func (f *authzAcctRepo) Writer(context.Context) (kachorepo.Writer, error) {
	return &authzAcctWriter{authzAcctReader: authzAcctReader{parent: f}}, nil
}
func (f *authzAcctRepo) Close() {}

type authzAcctReader struct{ parent *authzAcctRepo }

func (r *authzAcctReader) Accounts() account.ReaderIface {
	return &authzAcctRdr{ownerUserID: r.parent.ownerUserID}
}
func (r *authzAcctReader) Projects() project.ReaderIface { return nil }
func (r *authzAcctReader) Users() user.ReaderIface       { return nil }
func (r *authzAcctReader) ServiceAccounts() service_account.ReaderIface {
	return nil
}
func (r *authzAcctReader) Groups() group.ReaderIface                  { return nil }
func (r *authzAcctReader) Roles() role.ReaderIface                    { return nil }
func (r *authzAcctReader) AccessBindings() access_binding.ReaderIface { return nil }
func (r *authzAcctReader) Commit(context.Context) error               { return nil }
func (r *authzAcctReader) Rollback(context.Context) error             { return nil }

type authzAcctWriter struct{ authzAcctReader }

func (w *authzAcctWriter) AccountsW() account.WriterIface { return &authzAcctWtr{} }
func (w *authzAcctWriter) ProjectsW() project.WriterIface { return nil }
func (w *authzAcctWriter) UsersW() user.WriterIface       { return nil }
func (w *authzAcctWriter) ServiceAccountsW() service_account.WriterIface {
	return nil
}
func (w *authzAcctWriter) GroupsW() group.WriterIface                               { return nil }
func (w *authzAcctWriter) RolesW() role.WriterIface                                 { return nil }
func (w *authzAcctWriter) AccessBindingsW() access_binding.WriterIface              { return nil }
func (w *authzAcctWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *authzAcctWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *authzAcctWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *authzAcctWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *authzAcctWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *authzAcctWriter) Savepoint(context.Context, string) error           { return nil }
func (w *authzAcctWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *authzAcctWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *authzAcctWriter) AdvisoryXactLock(context.Context, string) error    { return nil }

type authzAcctRdr struct{ ownerUserID domain.UserID }

func (r *authzAcctRdr) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	return domain.Account{
		ID:          id,
		Name:        "fake-acct",
		OwnerUserID: r.ownerUserID,
		CreatedAt:   time.Now().UTC(),
	}, nil
}
func (r *authzAcctRdr) List(context.Context, account.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (r *authzAcctRdr) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (r *authzAcctRdr) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

type authzAcctWtr struct{ authzAcctRdr }

func (w *authzAcctWtr) Insert(_ context.Context, a domain.Account) (domain.Account, error) {
	return a, nil
}
func (w *authzAcctWtr) Update(_ context.Context, a domain.Account, _ []string) (domain.Account, error) {
	return a, nil
}
func (w *authzAcctWtr) Delete(context.Context, domain.AccountID) error { return nil }

// ── tests ──────────────────────────────────────────────────────────────────

// account-editor (FGA editor relation, NOT the Account owner) is allowed —
// the legacy owner-equality guard would have wrongly denied this.
func TestUpdateAccount_Authz_EditorAllowed(t *testing.T) {
	repo := &authzAcctRepo{ownerUserID: authzOwnerID}
	fga := newStubFGA()
	fga.allow("user:"+authzEditorID, "editor", "account:"+authzAcctID)

	uc := NewUpdateAccountUseCase(repo, newFakeOpsRepo()).WithRelationStore(fga, nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: authzEditorID})
	newName := domain.AccountName("renamed-acct")
	op, err := uc.Execute(ctx, UpdateAccountInput{
		ID:         authzAcctID,
		Name:       &newName,
		UpdateMask: []string{"name"},
	})
	require.NoError(t, err)
	require.NotNil(t, op)
}

// Account owner (no FGA relation needed) is still allowed — bootstrap path.
func TestUpdateAccount_Authz_OwnerAllowed(t *testing.T) {
	repo := &authzAcctRepo{ownerUserID: authzOwnerID}
	uc := NewUpdateAccountUseCase(repo, newFakeOpsRepo()).WithRelationStore(newStubFGA(), nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: authzOwnerID})
	newName := domain.AccountName("renamed-acct")
	op, err := uc.Execute(ctx, UpdateAccountInput{
		ID:         authzAcctID,
		Name:       &newName,
		UpdateMask: []string{"name"},
	})
	require.NoError(t, err)
	require.NotNil(t, op)
}

// non-member (not owner, no FGA relation) is denied — no security regression.
func TestUpdateAccount_Authz_NonMemberDenied(t *testing.T) {
	repo := &authzAcctRepo{ownerUserID: authzOwnerID}
	uc := NewUpdateAccountUseCase(repo, newFakeOpsRepo()).WithRelationStore(newStubFGA(), nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: authzOtherID})
	newName := domain.AccountName("renamed-acct")
	op, err := uc.Execute(ctx, UpdateAccountInput{
		ID:         authzAcctID,
		Name:       &newName,
		UpdateMask: []string{"name"},
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

// EmitReconcileEvent — T3/Q2 no-op stub (fake does not exercise the iam-direct reconcile trigger).
func (w *authzAcctWriter) EmitReconcileEvent(context.Context, string, string, string) error {
	return nil
}
