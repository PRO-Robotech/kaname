// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

// update_labelclear_test.go — очистка labels Group через update_mask=["labels"] с
// пустым телом. Единственный сигнал «очистить» — labels в update_mask (proto3-map
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
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	repogroup "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	repoproject "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

const (
	lcgGrpID   = "grp0000000000000clr3"
	lcgAcctID  = "acc0000000000000clr3"
	lcgOwnerID = "usr0000000000000clr3"
)

func TestUpdateGroup_LabelClearViaMask(t *testing.T) {
	repo := newLcgRepo(domain.Labels{"squad": "blue"}) // у группы есть метки
	uc := NewUpdateGroupUseCase(repo, newLcgOps())
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: lcgOwnerID})

	op, err := uc.Execute(ctx, UpdateGroupInput{
		ID:         lcgGrpID,
		Labels:     nil, // пустое тело labels (proto3-map ⇒ nil)
		UpdateMask: []string{"labels"},
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	assert.Empty(t, repo.writtenLabels(),
		"update_mask=labels + пустое тело очищает labels Group (был silent no-op)")
}

// ── compact fake repo (Groups + Accounts; capture written labels) ───────────────

type lcgRepo struct {
	grp     domain.Group
	written domain.Labels
	gotLbl  bool
}

func newLcgRepo(initial domain.Labels) *lcgRepo {
	return &lcgRepo{grp: domain.Group{
		ID: lcgGrpID, AccountID: lcgAcctID, Name: "clr-grp", Labels: initial,
		CreatedAt: time.Now().UTC(),
	}}
}

func (r *lcgRepo) writtenLabels() domain.Labels { return r.written }

func (r *lcgRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &lcgReader{parent: r}, nil
}
func (r *lcgRepo) Writer(context.Context) (kachorepo.Writer, error) {
	return &lcgWriter{lcgReader: lcgReader{parent: r}}, nil
}
func (r *lcgRepo) Close() {}

type lcgReader struct{ parent *lcgRepo }

func (r *lcgReader) Accounts() account.ReaderIface                { return &lcgAcctRdr{} }
func (r *lcgReader) Projects() repoproject.ReaderIface            { return nil }
func (r *lcgReader) Users() user.ReaderIface                      { return nil }
func (r *lcgReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *lcgReader) Groups() repogroup.ReaderIface                { return &lcgGrpRdr{parent: r.parent} }
func (r *lcgReader) Roles() role.ReaderIface                      { return nil }
func (r *lcgReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *lcgReader) Commit(context.Context) error                 { return nil }
func (r *lcgReader) Rollback(context.Context) error               { return nil }

type lcgGrpRdr struct{ parent *lcgRepo }

func (r *lcgGrpRdr) Get(_ context.Context, id domain.GroupID) (domain.Group, error) {
	return r.parent.grp, nil
}
func (r *lcgGrpRdr) List(context.Context, repogroup.ListFilter) ([]domain.Group, string, error) {
	return nil, "", nil
}
func (r *lcgGrpRdr) ListMembers(context.Context, domain.GroupID) ([]domain.GroupMember, error) {
	return nil, nil
}
func (r *lcgGrpRdr) IsMember(context.Context, domain.GroupID, domain.SubjectType, domain.SubjectID) (bool, error) {
	return false, nil
}

type lcgAcctRdr struct{}

func (r *lcgAcctRdr) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	return domain.Account{ID: id, Name: "acct", OwnerUserID: lcgOwnerID, CreatedAt: time.Now().UTC()}, nil
}
func (r *lcgAcctRdr) List(context.Context, account.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (r *lcgAcctRdr) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (r *lcgAcctRdr) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

type lcgWriter struct{ lcgReader }

func (w *lcgWriter) AccountsW() account.WriterIface                           { return nil }
func (w *lcgWriter) ProjectsW() repoproject.WriterIface                       { return nil }
func (w *lcgWriter) UsersW() user.WriterIface                                 { return nil }
func (w *lcgWriter) ServiceAccountsW() service_account.WriterIface            { return nil }
func (w *lcgWriter) GroupsW() repogroup.WriterIface                           { return &lcgGrpWtr{parent: w.parent} }
func (w *lcgWriter) RolesW() role.WriterIface                                 { return nil }
func (w *lcgWriter) AccessBindingsW() access_binding.WriterIface              { return nil }
func (w *lcgWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *lcgWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *lcgWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *lcgWriter) EmitReconcileEvent(context.Context, string, string, string) error { return nil }
func (w *lcgWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *lcgWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *lcgWriter) Savepoint(context.Context, string) error           { return nil }
func (w *lcgWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *lcgWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *lcgWriter) AdvisoryXactLock(context.Context, string) error    { return nil }
func (w *lcgWriter) Commit(context.Context) error                      { return nil }
func (w *lcgWriter) Rollback(context.Context) error                    { return nil }

type lcgGrpWtr struct{ parent *lcgRepo }

func (w *lcgGrpWtr) Insert(_ context.Context, g domain.Group) (domain.Group, error) { return g, nil }
func (w *lcgGrpWtr) Update(_ context.Context, g domain.Group, mask []string) (domain.Group, error) {
	for _, m := range mask {
		if m == "labels" {
			w.parent.written = g.Labels
			w.parent.gotLbl = true
			w.parent.grp.Labels = g.Labels
		}
	}
	return w.parent.grp, nil
}
func (w *lcgGrpWtr) Delete(context.Context, domain.GroupID) error        { return nil }
func (w *lcgGrpWtr) AddMember(context.Context, domain.GroupMember) error { return nil }
func (w *lcgGrpWtr) RemoveMember(context.Context, domain.GroupID, domain.SubjectType, domain.SubjectID) error {
	return nil
}

// ── fake ops repo (no-op; worker runs via operations.Run + Wait) ────────────────

type lcgOps struct{}

func newLcgOps() *lcgOps { return &lcgOps{} }

func (o *lcgOps) Create(context.Context, operations.Operation) error { return nil }
func (o *lcgOps) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	return nil
}
func (o *lcgOps) Get(context.Context, string) (*operations.Operation, error) {
	return &operations.Operation{}, nil
}
func (o *lcgOps) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (o *lcgOps) MarkDone(context.Context, string, *anypb.Any) error       { return nil }
func (o *lcgOps) MarkError(context.Context, string, *gstatus.Status) error { return nil }
func (o *lcgOps) Cancel(context.Context, string) error                     { return nil }
