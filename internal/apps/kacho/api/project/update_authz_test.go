// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package project

// update_authz_test.go — verifies UpdateProjectUseCase no longer double-gates
// by owner-equality: a project-editor (FGA `editor` relation, not the owning
// Account's owner) is allowed; a non-member is still denied.

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
	repoaccount "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	repoproject "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

const (
	authzProjID   = "prj0000000000000xxxx"
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

// authzProjRepo — fake Repo that stubs Projects().Get + Accounts().Get so the
// Update use-case can reach the authz guard with a real owning Account.
type authzProjRepo struct{ ownerUserID domain.UserID }

func (f *authzProjRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &authzProjReader{parent: f}, nil
}
func (f *authzProjRepo) Writer(context.Context) (kachorepo.Writer, error) {
	return &authzProjWriter{authzProjReader: authzProjReader{parent: f}}, nil
}
func (f *authzProjRepo) Close() {}

type authzProjReader struct{ parent *authzProjRepo }

func (r *authzProjReader) Accounts() repoaccount.ReaderIface {
	return &authzAcctRdr{ownerUserID: r.parent.ownerUserID}
}
func (r *authzProjReader) Projects() repoproject.ReaderIface { return &authzProjPRdr{} }
func (r *authzProjReader) Users() user.ReaderIface           { return nil }
func (r *authzProjReader) ServiceAccounts() service_account.ReaderIface {
	return nil
}
func (r *authzProjReader) Groups() group.ReaderIface                  { return nil }
func (r *authzProjReader) Roles() role.ReaderIface                    { return nil }
func (r *authzProjReader) AccessBindings() access_binding.ReaderIface { return nil }
func (r *authzProjReader) Commit(context.Context) error               { return nil }
func (r *authzProjReader) Rollback(context.Context) error             { return nil }

type authzProjWriter struct{ authzProjReader }

func (w *authzProjWriter) AccountsW() repoaccount.WriterIface { return nil }
func (w *authzProjWriter) ProjectsW() repoproject.WriterIface { return &authzProjPWtr{} }
func (w *authzProjWriter) UsersW() user.WriterIface           { return nil }
func (w *authzProjWriter) ServiceAccountsW() service_account.WriterIface {
	return nil
}
func (w *authzProjWriter) GroupsW() group.WriterIface                               { return nil }
func (w *authzProjWriter) RolesW() role.WriterIface                                 { return nil }
func (w *authzProjWriter) AccessBindingsW() access_binding.WriterIface              { return nil }
func (w *authzProjWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *authzProjWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *authzProjWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *authzProjWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *authzProjWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *authzProjWriter) Savepoint(context.Context, string) error           { return nil }
func (w *authzProjWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *authzProjWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *authzProjWriter) AdvisoryXactLock(context.Context, string) error    { return nil }

type authzAcctRdr struct{ ownerUserID domain.UserID }

func (r *authzAcctRdr) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	return domain.Account{
		ID:          id,
		Name:        "fake-acct",
		OwnerUserID: r.ownerUserID,
		CreatedAt:   time.Now().UTC(),
	}, nil
}
func (r *authzAcctRdr) List(context.Context, repoaccount.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (r *authzAcctRdr) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (r *authzAcctRdr) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

type authzProjPRdr struct{}

func (r *authzProjPRdr) Get(_ context.Context, id domain.ProjectID) (domain.Project, error) {
	return domain.Project{
		ID:        id,
		AccountID: authzAcctID,
		Name:      "fake-proj",
		CreatedAt: time.Now().UTC(),
	}, nil
}
func (r *authzProjPRdr) List(context.Context, repoproject.ListFilter) ([]domain.Project, string, error) {
	return nil, "", nil
}
func (r *authzProjPRdr) CountByAccount(context.Context, domain.AccountID) (int64, error) {
	return 0, nil
}

type authzProjPWtr struct{ authzProjPRdr }

func (w *authzProjPWtr) Insert(_ context.Context, p domain.Project) (domain.Project, error) {
	return p, nil
}
func (w *authzProjPWtr) Update(_ context.Context, p domain.Project, _ []string) (domain.Project, error) {
	return p, nil
}
func (w *authzProjPWtr) Delete(context.Context, domain.ProjectID) error { return nil }

// ── tests ──────────────────────────────────────────────────────────────────

// project-editor (FGA editor relation, NOT the Account owner) is allowed —
// the legacy owner-equality guard would have wrongly denied this.
func TestUpdateProject_Authz_EditorAllowed(t *testing.T) {
	repo := &authzProjRepo{ownerUserID: authzOwnerID}
	fga := newStubFGA()
	fga.allow("user:"+authzEditorID, "editor", "project:"+authzProjID)

	uc := NewUpdateProjectUseCase(repo, newFakeOpsRepoProj()).WithRelationStore(fga, nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: authzEditorID})
	newName := domain.ProjectName("renamed-proj")
	op, err := uc.Execute(ctx, UpdateProjectInput{
		ID:         authzProjID,
		Name:       &newName,
		UpdateMask: []string{"name"},
	})
	require.NoError(t, err)
	require.NotNil(t, op)
}

// Account owner (no FGA relation needed) is still allowed — bootstrap path.
func TestUpdateProject_Authz_OwnerAllowed(t *testing.T) {
	repo := &authzProjRepo{ownerUserID: authzOwnerID}
	uc := NewUpdateProjectUseCase(repo, newFakeOpsRepoProj()).WithRelationStore(newStubFGA(), nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: authzOwnerID})
	newName := domain.ProjectName("renamed-proj")
	op, err := uc.Execute(ctx, UpdateProjectInput{
		ID:         authzProjID,
		Name:       &newName,
		UpdateMask: []string{"name"},
	})
	require.NoError(t, err)
	require.NotNil(t, op)
}

// non-member (not owner, no FGA relation) is denied — no security regression.
func TestUpdateProject_Authz_NonMemberDenied(t *testing.T) {
	repo := &authzProjRepo{ownerUserID: authzOwnerID}
	uc := NewUpdateProjectUseCase(repo, newFakeOpsRepoProj()).WithRelationStore(newStubFGA(), nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: authzOtherID})
	newName := domain.ProjectName("renamed-proj")
	op, err := uc.Execute(ctx, UpdateProjectInput{
		ID:         authzProjID,
		Name:       &newName,
		UpdateMask: []string{"name"},
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

// EmitReconcileEvent — T3/Q2 no-op stub (fake does not exercise the iam-direct reconcile trigger).
func (w *authzProjWriter) EmitReconcileEvent(context.Context, string, string, string) error {
	return nil
}
