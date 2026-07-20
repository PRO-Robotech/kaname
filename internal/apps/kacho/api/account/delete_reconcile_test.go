// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// delete_reconcile_test.go — Design-B (flat-authz verb-bearing complete)
// acceptance VBC-17 (Account.Delete owner-tuple cleanup, #234). Account.Delete
// MUST symmetrically revoke the owner-binding's emitted-tuple ledger (owner
// self-grant + owner-binding hierarchy pointer, like AccessBinding.Delete) AND
// the SEC-L cluster-pointer (cluster:cluster_kacho_root#cluster@account:<A>),
// otherwise the FGA `define admin: … or owner` derivation leaves a dangling
// owner-tuple → the ex-owner keeps standing admin on a deleted account (VBC-08
// regression).
//
// RED until DeleteAccountUseCase.doDelete reads the owner-binding ledger and
// emits EmitFGARelationDelete on the owner-tuple set + the cluster-pointer.

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

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
	delTestAcct  = "acc0000000000000del1"
	delTestOwner = "usr0000000000000ownr"
	delTestBind  = "acb0000000000000own1"
)

// TestAccountDelete_VBC17_OwnerTuplesRevoked — on Account.Delete the owner-binding
// emitted-tuple ledger (owner self-grant + hierarchy pointer) AND the cluster
// pointer are revoked via EmitFGARelationDelete; the owner-binding row is deleted.
func TestAccountDelete_VBC17_OwnerTuplesRevoked(t *testing.T) {
	repo := newDelFakeRepo()
	repo.seedOwnerBinding()

	uc := NewDeleteAccountUseCase(repo, newFakeOpsRepo())
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: delTestOwner})

	op, err := uc.Execute(ctx, domain.AccountID(delTestAcct))
	require.NoError(t, err)
	require.NotNil(t, op)

	wctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(wctx))

	deleted := repo.fgaDeleted()
	var ownerRevoked, hierRevoked, clusterRevoked bool
	for _, tp := range deleted {
		switch {
		case tp.Relation == "owner" && tp.User == "user:"+delTestOwner &&
			tp.Object == "account:"+delTestAcct:
			ownerRevoked = true
		case tp.Relation == "account" && tp.User == "account:"+delTestAcct &&
			tp.Object == "iam_access_binding:"+delTestBind:
			hierRevoked = true
		case tp.Relation == "cluster" && tp.User == "cluster:cluster_kacho_root" &&
			tp.Object == "account:"+delTestAcct:
			clusterRevoked = true
		}
	}
	assert.True(t, ownerRevoked,
		"VBC-17/#234: owner self-grant (user:<owner>#owner@account:<A>) MUST be revoked on Account.Delete "+
			"(else FGA `admin … or owner` derivation leaves standing admin)")
	assert.True(t, hierRevoked,
		"VBC-17/#234: owner-binding hierarchy pointer MUST be revoked on Account.Delete (symmetric ledger revoke)")
	assert.True(t, clusterRevoked,
		"VBC-17/#234: SEC-L cluster pointer (cluster:…#cluster@account:<A>) MUST be revoked on Account.Delete "+
			"(the account no longer exists)")
	assert.GreaterOrEqual(t, repo.acctDeletes(), 1, "the account row must be deleted")
	assert.GreaterOrEqual(t, repo.bindingDeletes(), 1,
		"the owner-binding row must be deleted so its ledger cascade-drops")
}

// ── focused fake repo for the Delete cleanup path ───────────────────────────

type delFakeRepo struct {
	acct          domain.Account
	ownerBinding  domain.AccessBinding
	ownerLedger   []access_binding.RelationTuple
	fgaDel        []service.RelationTuple
	acctDelCnt    int
	bindingDelCnt int
}

func newDelFakeRepo() *delFakeRepo {
	return &delFakeRepo{
		acct: domain.Account{
			ID:          domain.AccountID(delTestAcct),
			Name:        "acme-del",
			OwnerUserID: domain.UserID(delTestOwner),
			CreatedAt:   time.Now().UTC(),
		},
	}
}

func (f *delFakeRepo) seedOwnerBinding() {
	f.ownerBinding = domain.AccessBinding{
		ID:           domain.AccessBindingID(delTestBind),
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(delTestOwner),
		RoleID:       domain.OwnerRoleID,
		ResourceType: "account",
		ResourceID:   delTestAcct,
		Scope:        domain.ScopeAccount,
		CreatedAt:    time.Now().UTC(),
	}
	// What Account.Create's ownerBindingLedgerTuples recorded (source='binding').
	f.ownerLedger = []access_binding.RelationTuple{
		{User: "user:" + delTestOwner, Relation: "owner", Object: "account:" + delTestAcct},
		{User: "account:" + delTestAcct, Relation: "account", Object: "iam_access_binding:" + delTestBind},
	}
}

func (f *delFakeRepo) fgaDeleted() []service.RelationTuple {
	cp := make([]service.RelationTuple, len(f.fgaDel))
	copy(cp, f.fgaDel)
	return cp
}
func (f *delFakeRepo) acctDeletes() int    { return f.acctDelCnt }
func (f *delFakeRepo) bindingDeletes() int { return f.bindingDelCnt }

func (f *delFakeRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &delFakeReader{repo: f}, nil
}
func (f *delFakeRepo) Writer(context.Context) (kachorepo.Writer, error) {
	return &delFakeWriter{delFakeReader: delFakeReader{repo: f}, repo: f}, nil
}
func (f *delFakeRepo) Close() {}

type delFakeReader struct{ repo *delFakeRepo }

func (r delFakeReader) Accounts() account.ReaderIface { return delAcctReader{r.repo} }
func (r delFakeReader) Projects() project.ReaderIface { return nil }
func (r delFakeReader) Users() user.ReaderIface       { return nil }
func (r delFakeReader) ServiceAccounts() service_account.ReaderIface {
	return nil
}
func (r delFakeReader) Groups() group.ReaderIface { return nil }
func (r delFakeReader) Roles() role.ReaderIface   { return nil }
func (r delFakeReader) AccessBindings() access_binding.ReaderIface {
	return delABReader{r.repo}
}
func (r delFakeReader) Commit(context.Context) error   { return nil }
func (r delFakeReader) Rollback(context.Context) error { return nil }

type delAcctReader struct{ repo *delFakeRepo }

func (r delAcctReader) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	if string(id) == string(r.repo.acct.ID) {
		return r.repo.acct, nil
	}
	return domain.Account{}, stderrors.New("not found")
}
func (delAcctReader) List(context.Context, account.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (delAcctReader) ExistsByName(context.Context, domain.AccountName) (bool, error) {
	return false, nil
}
func (delAcctReader) CountAccountsByOwner(context.Context, domain.UserID) (int, error) {
	return 0, nil
}

type delABReader struct{ repo *delFakeRepo }

func (r delABReader) List(_ context.Context, _ access_binding.ListFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}
func (r delABReader) ListByScope(_ context.Context, rt domain.ResourceType, rid string, _ access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
	if rt == "account" && rid == delTestAcct && r.repo.ownerBinding.ID != "" {
		return []domain.AccessBinding{r.repo.ownerBinding}, "", nil
	}
	return nil, "", nil
}
func (r delABReader) SelectEmittedTuples(_ context.Context, id domain.AccessBindingID) ([]access_binding.RelationTuple, error) {
	if id == r.repo.ownerBinding.ID {
		return r.repo.ownerLedger, nil
	}
	return nil, nil
}
func (delABReader) Get(context.Context, domain.AccessBindingID) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, stderrors.New("not stubbed")
}
func (delABReader) ListBySubject(context.Context, domain.SubjectType, domain.SubjectID, access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}
func (delABReader) ListSubjectPrivileges(context.Context, domain.SubjectType, domain.SubjectID, access_binding.PageFilter) ([]domain.SubjectPrivilege, string, error) {
	return nil, "", nil
}
func (delABReader) ListByAccount(context.Context, domain.AccountID, access_binding.AccountPageFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}
func (delABReader) SelectEmittedTuplesBySource(context.Context, domain.AccessBindingID, string) ([]access_binding.RelationTuple, error) {
	return nil, nil
}
func (delABReader) ListActiveByRole(context.Context, domain.RoleID) ([]domain.AccessBinding, error) {
	return nil, nil
}
func (delABReader) CountActiveByRole(context.Context, domain.RoleID) (int, error) { return 0, nil }
func (delABReader) ListByRole(context.Context, domain.RoleID, access_binding.ListByRoleFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}
func (delABReader) ListSubjects(context.Context, domain.AccessBindingID) ([]domain.Subject, error) {
	return nil, nil
}
func (delABReader) ListSubjectsForBindings(context.Context, []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
	return nil, nil
}

type delFakeWriter struct {
	delFakeReader
	repo *delFakeRepo
}

func (w *delFakeWriter) AccountsW() account.WriterIface { return delAcctWriter{w.repo} }
func (w *delFakeWriter) ProjectsW() project.WriterIface { return nil }
func (w *delFakeWriter) UsersW() user.WriterIface       { return nil }
func (w *delFakeWriter) ServiceAccountsW() service_account.WriterIface {
	return nil
}
func (w *delFakeWriter) GroupsW() group.WriterIface { return nil }
func (w *delFakeWriter) RolesW() role.WriterIface   { return nil }
func (w *delFakeWriter) AccessBindingsW() access_binding.WriterIface {
	return delABWriter{repo: w.repo}
}
func (w *delFakeWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *delFakeWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *delFakeWriter) EmitFGARelationDelete(_ context.Context, tuples []service.RelationTuple) error {
	w.repo.fgaDel = append(w.repo.fgaDel, tuples...)
	return nil
}
func (w *delFakeWriter) EmitReconcileEvent(context.Context, string, string, string) error {
	return nil
}
func (w *delFakeWriter) InsertRecoveryCompletion(context.Context, domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return domain.RecoveryCompletion{}, false, nil
}
func (w *delFakeWriter) UpsertUserTokenRevokeAll(context.Context, domain.UserTokenRevocation, domain.UserID) error {
	return nil
}
func (w *delFakeWriter) Savepoint(context.Context, string) error           { return nil }
func (w *delFakeWriter) RollbackToSavepoint(context.Context, string) error { return nil }
func (w *delFakeWriter) ReleaseSavepoint(context.Context, string) error    { return nil }
func (w *delFakeWriter) AdvisoryXactLock(context.Context, string) error    { return nil }

type delAcctWriter struct{ repo *delFakeRepo }

func (w delAcctWriter) Insert(context.Context, domain.Account) (domain.Account, error) {
	return domain.Account{}, stderrors.New("not stubbed")
}
func (w delAcctWriter) Update(context.Context, domain.Account, []string) (domain.Account, error) {
	return domain.Account{}, stderrors.New("not stubbed")
}
func (w delAcctWriter) Delete(_ context.Context, _ domain.AccountID) error {
	w.repo.acctDelCnt++
	return nil
}

type delABWriter struct {
	access_binding.WriterIface
	repo *delFakeRepo
}

func (w delABWriter) Delete(_ context.Context, _ domain.AccessBindingID) error {
	w.repo.bindingDelCnt++
	return nil
}
func (w delABWriter) EmitRelationDelete(context.Context, []access_binding.RelationTuple) error {
	return nil
}
func (w delABWriter) EmitAuditEvent(context.Context, access_binding.AuditEvent) error { return nil }
