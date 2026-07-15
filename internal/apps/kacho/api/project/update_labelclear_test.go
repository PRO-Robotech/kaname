// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package project

// update_labelclear_test.go — очистка labels Project через update_mask=["labels"]
// с пустым телом. proto3-map не несет presence: пустой `labels:{}` и отсутствующий
// labels неотличимы (оба nil), поэтому единственный сигнал «очистить» — labels в
// update_mask. Без фикса очистка была silent no-op: label-scoped грант нельзя было
// отозвать снятием совпадающей метки (admin получал 200, доступ молча сохранялся).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"

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
	lcpProjID  = "prj0000000000000clr1"
	lcpAcctID  = "acc0000000000000clr1"
	lcpOwnerID = "usr0000000000000clr1"
)

func TestUpdateProject_LabelClearViaMask(t *testing.T) {
	repo := newLcpRepo(domain.Labels{"team": "sec"}) // у проекта есть метки
	uc := NewUpdateProjectUseCase(repo, newLcpOps()) // relations nil → owner-path
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: lcpOwnerID})

	op, err := uc.Execute(ctx, UpdateProjectInput{
		ID:         lcpProjID,
		Labels:     nil, // пустое тело labels (proto3-map ⇒ nil)
		UpdateMask: []string{"labels"},
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	assert.Empty(t, repo.writtenLabels(),
		"update_mask=labels + пустое тело очищает labels Project (был silent no-op)")
	assert.Contains(t, repo.reconciled(), lcpProjID,
		"очистка labels co-commit'ит reconcile-event на iam.project (eager re-materialization)")
}

// ── compact fake repo (Projects + Accounts; capture written labels + reconcile) ──

type lcpRepo struct {
	proj     domain.Project
	written  domain.Labels
	gotLabel bool
	reconcil []string
}

func newLcpRepo(initial domain.Labels) *lcpRepo {
	return &lcpRepo{proj: domain.Project{
		ID: lcpProjID, AccountID: lcpAcctID, Name: "clr", Labels: initial,
		CreatedAt: time.Now().UTC(),
	}}
}

func (r *lcpRepo) writtenLabels() domain.Labels { return r.written }
func (r *lcpRepo) reconciled() []string         { return append([]string{}, r.reconcil...) }

func (r *lcpRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &lcpReader{parent: r}, nil
}
func (r *lcpRepo) Writer(context.Context) (kachorepo.Writer, error) {
	return &lcpWriter{lcpReader: lcpReader{parent: r}}, nil
}
func (r *lcpRepo) Close() {}

type lcpReader struct{ parent *lcpRepo }

func (r *lcpReader) Accounts() repoaccount.ReaderIface            { return &lcpAcctRdr{} }
func (r *lcpReader) Projects() repoproject.ReaderIface            { return &lcpProjRdr{parent: r.parent} }
func (r *lcpReader) Users() user.ReaderIface                      { return nil }
func (r *lcpReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *lcpReader) Groups() group.ReaderIface                    { return nil }
func (r *lcpReader) Roles() role.ReaderIface                      { return nil }
func (r *lcpReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *lcpReader) Commit(context.Context) error                 { return nil }
func (r *lcpReader) Rollback(context.Context) error               { return nil }

type lcpProjRdr struct{ parent *lcpRepo }

func (r *lcpProjRdr) Get(_ context.Context, id domain.ProjectID) (domain.Project, error) {
	return r.parent.proj, nil
}
func (r *lcpProjRdr) List(context.Context, repoproject.ListFilter) ([]domain.Project, string, error) {
	return nil, "", nil
}
func (r *lcpProjRdr) CountByAccount(context.Context, domain.AccountID) (int64, error) {
	return 0, nil
}

type lcpAcctRdr struct{}

func (r *lcpAcctRdr) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	return domain.Account{ID: id, Name: "acct", OwnerUserID: lcpOwnerID, CreatedAt: time.Now().UTC()}, nil
}
func (r *lcpAcctRdr) List(context.Context, repoaccount.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (r *lcpAcctRdr) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (r *lcpAcctRdr) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

type lcpWriter struct{ lcpReader }

func (w *lcpWriter) AccountsW() repoaccount.WriterIface                       { return nil }
func (w *lcpWriter) ProjectsW() repoproject.WriterIface                       { return &lcpProjWtr{parent: w.parent} }
func (w *lcpWriter) UsersW() user.WriterIface                                 { return nil }
func (w *lcpWriter) ServiceAccountsW() service_account.WriterIface            { return nil }
func (w *lcpWriter) GroupsW() group.WriterIface                               { return nil }
func (w *lcpWriter) RolesW() role.WriterIface                                 { return nil }
func (w *lcpWriter) AccessBindingsW() access_binding.WriterIface              { return nil }
func (w *lcpWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *lcpWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *lcpWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *lcpWriter) EmitReconcileEvent(_ context.Context, _, objectType, objectID string) error {
	if objectType == "iam.project" {
		w.parent.reconcil = append(w.parent.reconcil, objectID)
	}
	return nil
}
func (w *lcpWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *lcpWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *lcpWriter) Savepoint(context.Context, string) error           { return nil }
func (w *lcpWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *lcpWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *lcpWriter) AdvisoryXactLock(context.Context, string) error    { return nil }
func (w *lcpWriter) Commit(context.Context) error                      { return nil }
func (w *lcpWriter) Rollback(context.Context) error                    { return nil }

type lcpProjWtr struct{ parent *lcpRepo }

func (w *lcpProjWtr) Insert(_ context.Context, p domain.Project) (domain.Project, error) {
	return p, nil
}
func (w *lcpProjWtr) Update(_ context.Context, p domain.Project, mask []string) (domain.Project, error) {
	for _, m := range mask {
		if m == "labels" {
			w.parent.written = p.Labels
			w.parent.gotLabel = true
			w.parent.proj.Labels = p.Labels
		}
	}
	return w.parent.proj, nil
}
func (w *lcpProjWtr) Delete(context.Context, domain.ProjectID) error { return nil }

// ── fake ops repo (no-op; worker runs via operations.Run + Wait) ────────────────

type lcpOps struct{}

func newLcpOps() *lcpOps { return &lcpOps{} }

func (o *lcpOps) Create(context.Context, operations.Operation) error { return nil }
func (o *lcpOps) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	return nil
}
func (o *lcpOps) Get(context.Context, string) (*operations.Operation, error) {
	return &operations.Operation{}, nil
}
func (o *lcpOps) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (o *lcpOps) MarkDone(context.Context, string, *anypb.Any) error       { return nil }
func (o *lcpOps) MarkError(context.Context, string, *gstatus.Status) error { return nil }
func (o *lcpOps) Cancel(context.Context, string) error                     { return nil }
