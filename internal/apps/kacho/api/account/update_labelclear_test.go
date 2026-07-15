// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// update_labelclear_test.go — очистка labels Account через update_mask=["labels"]
// с пустым телом. Единственный сигнал «очистить» — labels в update_mask (proto3-map
// без presence). Без фикса очистка была silent no-op.

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
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

const (
	lcaAcctID  = "acc0000000000000clr2"
	lcaOwnerID = "usr0000000000000clr2"
)

func TestUpdateAccount_LabelClearViaMask(t *testing.T) {
	repo := newLcaRepo(domain.Labels{"tier": "gold"}) // у account'а есть метки
	uc := NewUpdateAccountUseCase(repo, newLcaOps())  // relations nil → owner-path
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: lcaOwnerID})

	op, err := uc.Execute(ctx, UpdateAccountInput{
		ID:         lcaAcctID,
		Labels:     nil, // пустое тело labels (proto3-map ⇒ nil)
		UpdateMask: []string{"labels"},
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	assert.Empty(t, repo.writtenLabels(),
		"update_mask=labels + пустое тело очищает labels Account (был silent no-op)")
	assert.Contains(t, repo.reconciled(), lcaAcctID,
		"очистка labels co-commit'ит reconcile-event на iam.account")
}

// ── compact fake repo (Accounts; capture written labels + reconcile) ────────────

type lcaRepo struct {
	acct     domain.Account
	written  domain.Labels
	gotLabel bool
	reconcil []string
}

func newLcaRepo(initial domain.Labels) *lcaRepo {
	return &lcaRepo{acct: domain.Account{
		ID: lcaAcctID, Name: "clr-acct", OwnerUserID: lcaOwnerID, Labels: initial,
		CreatedAt: time.Now().UTC(),
	}}
}

func (r *lcaRepo) writtenLabels() domain.Labels { return r.written }
func (r *lcaRepo) reconciled() []string         { return append([]string{}, r.reconcil...) }

func (r *lcaRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &lcaReader{parent: r}, nil
}
func (r *lcaRepo) Writer(context.Context) (kachorepo.Writer, error) {
	return &lcaWriter{lcaReader: lcaReader{parent: r}}, nil
}
func (r *lcaRepo) Close() {}

type lcaReader struct{ parent *lcaRepo }

func (r *lcaReader) Accounts() repoaccount.ReaderIface            { return &lcaAcctRdr{parent: r.parent} }
func (r *lcaReader) Projects() project.ReaderIface                { return nil }
func (r *lcaReader) Users() user.ReaderIface                      { return nil }
func (r *lcaReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *lcaReader) Groups() group.ReaderIface                    { return nil }
func (r *lcaReader) Roles() role.ReaderIface                      { return nil }
func (r *lcaReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *lcaReader) Commit(context.Context) error                 { return nil }
func (r *lcaReader) Rollback(context.Context) error               { return nil }

type lcaAcctRdr struct{ parent *lcaRepo }

func (r *lcaAcctRdr) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	return r.parent.acct, nil
}
func (r *lcaAcctRdr) List(context.Context, repoaccount.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (r *lcaAcctRdr) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (r *lcaAcctRdr) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

type lcaWriter struct{ lcaReader }

func (w *lcaWriter) AccountsW() repoaccount.WriterIface                       { return &lcaAcctWtr{parent: w.parent} }
func (w *lcaWriter) ProjectsW() project.WriterIface                           { return nil }
func (w *lcaWriter) UsersW() user.WriterIface                                 { return nil }
func (w *lcaWriter) ServiceAccountsW() service_account.WriterIface            { return nil }
func (w *lcaWriter) GroupsW() group.WriterIface                               { return nil }
func (w *lcaWriter) RolesW() role.WriterIface                                 { return nil }
func (w *lcaWriter) AccessBindingsW() access_binding.WriterIface              { return nil }
func (w *lcaWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *lcaWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *lcaWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *lcaWriter) EmitReconcileEvent(_ context.Context, _, objectType, objectID string) error {
	if objectType == "iam.account" {
		w.parent.reconcil = append(w.parent.reconcil, objectID)
	}
	return nil
}
func (w *lcaWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *lcaWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *lcaWriter) Savepoint(context.Context, string) error           { return nil }
func (w *lcaWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *lcaWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *lcaWriter) AdvisoryXactLock(context.Context, string) error    { return nil }
func (w *lcaWriter) Commit(context.Context) error                      { return nil }
func (w *lcaWriter) Rollback(context.Context) error                    { return nil }

type lcaAcctWtr struct{ parent *lcaRepo }

func (w *lcaAcctWtr) Insert(_ context.Context, a domain.Account) (domain.Account, error) {
	return a, nil
}
func (w *lcaAcctWtr) Update(_ context.Context, a domain.Account, mask []string) (domain.Account, error) {
	for _, m := range mask {
		if m == "labels" {
			w.parent.written = a.Labels
			w.parent.gotLabel = true
			w.parent.acct.Labels = a.Labels
		}
	}
	return w.parent.acct, nil
}
func (w *lcaAcctWtr) Delete(context.Context, domain.AccountID) error { return nil }

// ── fake ops repo (no-op; worker runs via operations.Run + Wait) ────────────────

type lcaOps struct{}

func newLcaOps() *lcaOps { return &lcaOps{} }

func (o *lcaOps) Create(context.Context, operations.Operation) error { return nil }
func (o *lcaOps) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	return nil
}
func (o *lcaOps) Get(context.Context, string) (*operations.Operation, error) {
	return &operations.Operation{}, nil
}
func (o *lcaOps) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (o *lcaOps) MarkDone(context.Context, string, *anypb.Any) error       { return nil }
func (o *lcaOps) MarkError(context.Context, string, *gstatus.Status) error { return nil }
func (o *lcaOps) Cancel(context.Context, string) error                     { return nil }
