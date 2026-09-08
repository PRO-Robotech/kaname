// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_account

// update_labelclear_test.go — очистка labels ServiceAccount через
// update_mask=["labels"] с пустым телом. Единственный сигнал «очистить» — labels в
// update_mask (proto3-map без presence). Без фикса очистка была silent no-op.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	reposa "github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
	"github.com/PRO-Robotech/kaname/internal/service"
)

const (
	lcsSaID    = "sva0000000000000clr4"
	lcsAcctID  = "acc0000000000000clr4"
	lcsOwnerID = "usr0000000000000clr4"
)

func TestUpdateServiceAccount_LabelClearViaMask(t *testing.T) {
	repo := newLcsRepo(domain.Labels{"role": "ci"}) // у SA есть метки
	uc := NewUpdateServiceAccountUseCase(repo, newLcsOps())
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: lcsOwnerID})

	op, err := uc.Execute(ctx, UpdateServiceAccountInput{
		ID:         lcsSaID,
		Labels:     nil, // пустое тело labels (proto3-map ⇒ nil)
		UpdateMask: []string{"labels"},
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	assert.Empty(t, repo.writtenLabels(),
		"update_mask=labels + пустое тело очищает labels ServiceAccount (был silent no-op)")
	assert.Contains(t, repo.reconciled(), lcsSaID,
		"очистка labels co-commit'ит reconcile-event на iam.serviceAccount")
}

// ── compact fake repo (ServiceAccounts + Accounts; capture written labels) ──────

type lcsRepo struct {
	sa       domain.ServiceAccount
	written  domain.Labels
	gotLbl   bool
	reconcil []string
}

func newLcsRepo(initial domain.Labels) *lcsRepo {
	return &lcsRepo{sa: domain.ServiceAccount{
		ID: lcsSaID, AccountID: lcsAcctID, Name: "clr-sa", Labels: initial,
		CreatedAt: time.Now().UTC(),
	}}
}

func (r *lcsRepo) writtenLabels() domain.Labels { return r.written }
func (r *lcsRepo) reconciled() []string         { return append([]string{}, r.reconcil...) }

func (r *lcsRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	return &lcsReader{parent: r}, nil
}
func (r *lcsRepo) Writer(context.Context) (kanamerepo.Writer, error) {
	return &lcsWriter{lcsReader: lcsReader{parent: r}}, nil
}
func (r *lcsRepo) Close() {}

type lcsReader struct{ parent *lcsRepo }

func (r *lcsReader) Accounts() account.ReaderIface              { return &lcsAcctRdr{} }
func (r *lcsReader) Projects() project.ReaderIface              { return nil }
func (r *lcsReader) Users() user.ReaderIface                    { return nil }
func (r *lcsReader) ServiceAccounts() reposa.ReaderIface        { return &lcsSaRdr{parent: r.parent} }
func (r *lcsReader) Groups() group.ReaderIface                  { return nil }
func (r *lcsReader) Roles() role.ReaderIface                    { return nil }
func (r *lcsReader) AccessBindings() access_binding.ReaderIface { return nil }
func (r *lcsReader) Commit(context.Context) error               { return nil }
func (r *lcsReader) Rollback(context.Context) error             { return nil }

type lcsSaRdr struct{ parent *lcsRepo }

func (r *lcsSaRdr) Get(_ context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return r.parent.sa, nil
}
func (r *lcsSaRdr) List(context.Context, reposa.ListFilter) ([]domain.ServiceAccount, string, error) {
	return nil, "", nil
}

type lcsAcctRdr struct{}

func (r *lcsAcctRdr) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	return domain.Account{ID: id, Name: "acct", OwnerUserID: lcsOwnerID, CreatedAt: time.Now().UTC()}, nil
}
func (r *lcsAcctRdr) List(context.Context, account.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (r *lcsAcctRdr) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (r *lcsAcctRdr) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

type lcsWriter struct{ lcsReader }

func (w *lcsWriter) AccountsW() account.WriterIface                           { return nil }
func (w *lcsWriter) ProjectsW() project.WriterIface                           { return nil }
func (w *lcsWriter) UsersW() user.WriterIface                                 { return nil }
func (w *lcsWriter) ServiceAccountsW() reposa.WriterIface                     { return &lcsSaWtr{parent: w.parent} }
func (w *lcsWriter) GroupsW() group.WriterIface                               { return nil }
func (w *lcsWriter) RolesW() role.WriterIface                                 { return nil }
func (w *lcsWriter) AccessBindingsW() access_binding.WriterIface              { return nil }
func (w *lcsWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *lcsWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *lcsWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *lcsWriter) EmitReconcileEvent(_ context.Context, _, objectType, objectID string) error {
	if objectType == "iam.serviceAccount" {
		w.parent.reconcil = append(w.parent.reconcil, objectID)
	}
	return nil
}
func (w *lcsWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *lcsWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *lcsWriter) Savepoint(context.Context, string) error           { return nil }
func (w *lcsWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *lcsWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *lcsWriter) AdvisoryXactLock(context.Context, string) error    { return nil }
func (w *lcsWriter) Commit(context.Context) error                      { return nil }
func (w *lcsWriter) Rollback(context.Context) error                    { return nil }

type lcsSaWtr struct{ parent *lcsRepo }

func (w *lcsSaWtr) Insert(_ context.Context, sa domain.ServiceAccount) (domain.ServiceAccount, error) {
	return sa, nil
}
func (w *lcsSaWtr) Update(_ context.Context, sa domain.ServiceAccount, mask []string) (domain.ServiceAccount, error) {
	for _, m := range mask {
		if m == "labels" {
			w.parent.written = sa.Labels
			w.parent.gotLbl = true
			w.parent.sa.Labels = sa.Labels
		}
	}
	return w.parent.sa, nil
}
func (w *lcsSaWtr) Delete(context.Context, domain.ServiceAccountID) error { return nil }
func (w *lcsSaWtr) SetEnabled(_ context.Context, _ domain.ServiceAccountID, enabled bool) (domain.ServiceAccount, error) {
	w.parent.sa.Enabled = enabled
	return w.parent.sa, nil
}

// ── fake ops repo (no-op; worker runs via operations.Run + Wait) ────────────────

type lcsOps struct{}

func newLcsOps() *lcsOps { return &lcsOps{} }

func (o *lcsOps) Create(context.Context, operations.Operation) error { return nil }
func (o *lcsOps) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	return nil
}
func (o *lcsOps) Get(context.Context, string) (*operations.Operation, error) {
	return &operations.Operation{}, nil
}
func (o *lcsOps) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (o *lcsOps) MarkDone(context.Context, string, *anypb.Any) error       { return nil }
func (o *lcsOps) MarkError(context.Context, string, *gstatus.Status) error { return nil }
func (o *lcsOps) Cancel(context.Context, string) error                     { return nil }

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *lcsReader) Visibility() visibility.ReaderIface { return nil }

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *lcsWriter) Visibility() visibility.ReaderIface { return nil }

// EmitInviteMail — порт со-коммита намерения отправить письмо приглашения.
// Дублёр не глотает того, что настоящий отвергает: пустой адресат и пустой ключ
// партиции отвергаются здесь так же, как ограничением миграции, — иначе фикстура
// была бы снисходительнее продукта и скрыла бы ровно тот дефект, ради которого её
// подставляют.
func (w *lcsWriter) EmitInviteMail(_ context.Context, userID, _, to, _ string) error {
	if to == "" {
		return fmt.Errorf("invite mail: recipient required")
	}
	if userID == "" {
		return fmt.Errorf("invite mail: user id required")
	}
	return nil
}
