// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/visibility"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
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
	acct         domain.Account
	ownerBinding domain.AccessBinding
	ownerLedger  []access_binding.RelationTuple
	// extra — bindings anchored on the account beyond the owner one. Deleting a
	// binding removes it from this set, which is what the real writer-tx does
	// (a row deleted in the transaction is invisible to the next read in it).
	extra         []domain.AccessBinding
	extraLedger   map[domain.AccessBindingID][]access_binding.RelationTuple
	deleted       map[domain.AccessBindingID]bool
	fgaDel        []service.RelationTuple
	acctDelCnt    int
	bindingDelCnt int
}

// seedExtraBindings adds n further account-scoped bindings, each with one tuple in
// its ledger, so a page-limited revoke can be caught leaving some behind.
func (f *delFakeRepo) seedExtraBindings(n int) {
	if f.extraLedger == nil {
		f.extraLedger = map[domain.AccessBindingID][]access_binding.RelationTuple{}
	}
	for i := 0; i < n; i++ {
		id := domain.AccessBindingID(fmt.Sprintf("acb%017d", i))
		f.extra = append(f.extra, domain.AccessBinding{
			ID: id, SubjectType: domain.SubjectTypeUser,
			SubjectID: domain.SubjectID(delTestOwner), RoleID: domain.OwnerRoleID,
			ResourceType: "account", ResourceID: delTestAcct, Scope: domain.ScopeAccount,
			CreatedAt: time.Now().UTC(),
		})
		f.extraLedger[id] = []access_binding.RelationTuple{
			{User: "user:" + delTestOwner, Relation: "viewer", Object: "account:" + delTestAcct + "#" + string(id)},
		}
	}
}

// liveBindings — the bindings still present, owner first (the real query orders by
// created_at, and the owner binding is co-committed with the account).
func (f *delFakeRepo) liveBindings() []domain.AccessBinding {
	out := make([]domain.AccessBinding, 0, 1+len(f.extra))
	if f.ownerBinding.ID != "" && !f.deleted[f.ownerBinding.ID] {
		out = append(out, f.ownerBinding)
	}
	for _, b := range f.extra {
		if !f.deleted[b.ID] {
			out = append(out, b)
		}
	}
	return out
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
func (r delABReader) ListByScope(_ context.Context, rt domain.ResourceType, rid string, f access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
	if rt != "account" || rid != delTestAcct {
		return nil, "", nil
	}
	live := r.repo.liveBindings()
	size := int(f.PageSize)
	if size <= 0 || size > len(live) {
		return live, "", nil
	}
	// A truncated read hands back a continuation token — the signal the caller used
	// to discard.
	return live[:size], "next", nil
}
func (r delABReader) SelectEmittedTuples(_ context.Context, id domain.AccessBindingID) ([]access_binding.RelationTuple, error) {
	if id == r.repo.ownerBinding.ID {
		return r.repo.ownerLedger, nil
	}
	return r.repo.extraLedger[id], nil
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

// The account teardown fixture holds no sibling binding, so nothing survives a
// per-binding revoke here.
func (delABReader) SelectTuplesClaimedByOtherActiveBindings(context.Context, domain.AccessBindingID, []access_binding.RelationTuple) ([]access_binding.RelationTuple, error) {
	return nil, nil
}
func (delABReader) ListActiveByRole(context.Context, domain.RoleID) ([]domain.AccessBinding, error) {
	return nil, nil
}
func (delABReader) CountActiveByRole(context.Context, domain.RoleID) (int, error) { return 0, nil }
func (delABReader) ListByRole(context.Context, domain.RoleID, access_binding.ListByRoleFilter) ([]domain.AccessBinding, string, error) {
	return nil, "", nil
}

// ListActiveHoldingMembership — предмета этой пробы не касается: она не исключает
// человека из аккаунта. Пустой перечень — ЗАКОННЫЙ ответ (мешающих выдач нет), а
// не заглушка «ответить нечем»: дублёр обязан выполнять контракт настоящего, и
// молчаливо шире его не отвечать.
func (delABReader) ListActiveHoldingMembership(context.Context, domain.UserID, domain.AccountID, int) ([]string, int, error) {
	return nil, 0, nil
}

func (delABReader) ListSubjects(context.Context, domain.AccessBindingID) ([]domain.Subject, error) {
	return nil, nil
}
func (delABReader) ListMaterializedAtForBindings(context.Context, []domain.AccessBindingID) (map[domain.AccessBindingID]time.Time, error) {
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
func (w *delFakeWriter) AdvisoryXactLock(context.Context, string) error { return nil }

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

func (w delABWriter) Delete(_ context.Context, id domain.AccessBindingID) error {
	w.repo.bindingDelCnt++
	if w.repo.deleted == nil {
		w.repo.deleted = map[domain.AccessBindingID]bool{}
	}
	w.repo.deleted[id] = true
	return nil
}
func (w delABWriter) EmitRelationDelete(context.Context, []access_binding.RelationTuple) error {
	return nil
}
func (w delABWriter) EmitAuditEvent(context.Context, access_binding.AuditEvent) error { return nil }

// TestAccountDelete_RevokesEveryBinding_NotJustTheFirstPage — deleting an account
// revokes ALL the bindings anchored on it, and says so.
//
// The revoke read ONE page and discarded the continuation token, then deleted
// exactly what it had read. Everything past that page kept its row AND its emitted
// tuples, while the operation reported complete success — no error, no counter, no
// line. Nothing downstream repairs it: access_bindings carry no foreign key to
// accounts, so no cascade reaches them, and the periodic reconcile keeps
// re-materializing the survivors for ever because their rows are still active.
//
// The page is also not the "handful" the discarded token was assumed to represent:
// the query filters by scope only, so every revoked and expired binding ever
// recorded on the account occupies it, oldest first.
func TestAccountDelete_RevokesEveryBinding_NotJustTheFirstPage(t *testing.T) {
	repo := newDelFakeRepo()
	repo.seedOwnerBinding()
	const beyond = 7
	repo.seedExtraBindings(accountBindingRevokePageSize + beyond) // one full page and then some

	uc := NewDeleteAccountUseCase(repo, newFakeOpsRepo())
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: delTestOwner})

	_, err := uc.Execute(ctx, domain.AccountID(delTestAcct))
	require.NoError(t, err)
	wctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(wctx))

	wantBindings := 1 + accountBindingRevokePageSize + beyond
	assert.Equal(t, wantBindings, repo.bindingDeletes(),
		"every binding anchored on the account must be revoked, not one page of them")
	assert.Empty(t, repo.liveBindings(), "no binding of a deleted account may survive")

	// And their tuples must be revoked too: a surviving tuple is standing access on
	// an account that no longer exists, which the periodic reconcile keeps renewing.
	deleted := repo.fgaDeleted()
	assert.GreaterOrEqual(t, len(deleted), wantBindings,
		"each revoked binding contributes at least its own ledger tuple")
	last := repo.extra[len(repo.extra)-1].ID
	var lastRevoked bool
	for _, tp := range deleted {
		if tp.Object == "account:"+delTestAcct+"#"+string(last) {
			lastRevoked = true
		}
	}
	assert.True(t, lastRevoked, "the binding furthest from the first page must be revoked as well")
}

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kacho/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r delFakeReader) Visibility() visibility.ReaderIface { return nil }

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kacho/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *delFakeWriter) Visibility() visibility.ReaderIface { return nil }

// EmitInviteMail — порт со-коммита намерения отправить письмо приглашения.
// Дублёр не глотает того, что настоящий отвергает: пустой адресат и пустой ключ
// партиции отвергаются здесь так же, как ограничением миграции, — иначе фикстура
// была бы снисходительнее продукта и скрыла бы ровно тот дефект, ради которого её
// подставляют.
func (w *delFakeWriter) EmitInviteMail(_ context.Context, userID, _, to, _ string) error {
	if to == "" {
		return fmt.Errorf("invite mail: recipient required")
	}
	if userID == "" {
		return fmt.Errorf("invite mail: user id required")
	}
	return nil
}
