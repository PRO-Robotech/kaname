// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// role_fanout_offdonepath_test.go — a committed change to a role's rules is
// reported as a SUCCESS, even when the membership pass that follows it fails.
//
// The rules change commits first: the role row, the selector projection and the
// audit row are all durable when the writer-tx returns. The membership pass that
// re-materializes what the role grants runs AFTER that commit, over every active
// binding, each in its own transaction. It used to run on the operation's own path,
// so any failure in it turned the operation into an error — for a change that is
// already committed and already in force.
//
// What the caller then does is the damage: it reads an error, concludes the rules
// were not applied, and repeats the request with the resource version it captured
// before the first attempt. That version is stale (its own committed update moved
// it), so the retry is refused as a concurrent modification — naming a competitor
// that never existed. Meanwhile the privileges ARE changed, and an operator who
// believes otherwise is reasoning about the wrong state.
//
// Operation.done means the SUBJECT of the mutation is durable, never that an
// eventually-consistent downstream effect is visible. The convergence backstops (the
// co-committed reconcile event and the periodic sweep) are unchanged — this is about
// what the caller is told.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	roleapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	repoaccount "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	repogroup "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	repoproject "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	reposa "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	repouser "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/visibility"
)

// failingFanout — a fan-out whose pass always fails, the way a lock wait that
// outruns the statement timeout does under concurrent load.
type failingFanout struct {
	mu     sync.Mutex
	count  int
	calls  int
	failed error
}

func (f *failingFanout) CountActiveBindings(context.Context, domain.RoleID) (int, error) {
	return f.count, nil
}

func (f *failingFanout) ReconcileActiveBindings(context.Context, domain.RoleID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.failed
}

func (f *failingFanout) called() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// A failing membership pass must not turn a committed rules change into a failed
// operation.
func TestRoleUpdate_FailingMembershipPass_StillReportsTheCommittedChangeAsDone(t *testing.T) {
	const ownerID, accountID, resourceID = "usr_owner_offpath", "acc_offpath", "prj_offpath"
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID178b, "viewer",
		domain.Permissions{"compute.instance.*.get"})
	repo.setRoleCustom(accountID)
	opsRepo := newFakeOpsRepo()
	fan := &failingFanout{count: 3, failed: errors.New("canceling statement due to statement timeout")}

	uc := roleapp.NewUpdateRoleUseCase(repo, opsRepo).
		WithTupleReconciler(NewRoleTupleReconciler()).
		WithMembershipFanout(fan)

	op, err := uc.Execute(newOwnerContext(ownerID), roleUpdateInput(roleID178b, domain.Rules{
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"env": "prod"}},
	}))
	require.NoError(t, err)
	awaitOpDone(t, opsRepo, op.ID)

	got, gerr := opsRepo.Get(context.Background(), op.ID)
	require.NoError(t, gerr)
	require.True(t, got.Done)
	assert.Nil(t, got.Error,
		"a committed rules change must not be reported as a failure because a "+
			"post-commit materialization pass failed — the caller would retry with a "+
			"resource version its own committed update has already moved")

	// The pass still runs: moving it off the reported path must not delete it.
	assert.Eventually(t, func() bool { return fan.called() > 0 }, 2*time.Second, 10*time.Millisecond,
		"the membership pass must still be attempted, just not on the reported path")
}

// ── the pass covers EVERY binding, not the ones before the first failure ─────

// multiBindingRepo — a role carrying several active bindings.
type multiBindingRepo struct{ bindings []domain.AccessBinding }

func (r *multiBindingRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &multiBindingReader{parent: r}, nil
}
func (r *multiBindingRepo) Writer(context.Context) (kachorepo.Writer, error) { return nil, nil }
func (r *multiBindingRepo) Close()                                           {}

type multiBindingReader struct{ parent *multiBindingRepo }

func (rd *multiBindingReader) Accounts() repoaccount.ReaderIface   { return nil }
func (rd *multiBindingReader) Projects() repoproject.ReaderIface   { return nil }
func (rd *multiBindingReader) Users() repouser.ReaderIface         { return nil }
func (rd *multiBindingReader) ServiceAccounts() reposa.ReaderIface { return nil }
func (rd *multiBindingReader) Groups() repogroup.ReaderIface       { return nil }
func (rd *multiBindingReader) Roles() reporole.ReaderIface         { return nil }
func (rd *multiBindingReader) Commit(context.Context) error        { return nil }
func (rd *multiBindingReader) Rollback(context.Context) error      { return nil }
func (rd *multiBindingReader) AccessBindings() repoab.ReaderIface {
	return &multiBindingABReader{parent: rd.parent}
}

type multiBindingABReader struct {
	strictDupABReader
	parent *multiBindingRepo
}

// ListActiveHoldingMembership — предмета этой пробы не касается: она не исключает
// человека из аккаунта. Пустой перечень — ЗАКОННЫЙ ответ (мешающих выдач нет), а
// не заглушка «ответить нечем»: дублёр обязан выполнять контракт настоящего, и
// молчаливо шире его не отвечать.
func (r *multiBindingABReader) ListActiveHoldingMembership(context.Context, domain.UserID, domain.AccountID, int) ([]string, int, error) {
	return nil, 0, nil
}

func (r *multiBindingABReader) ListActiveByRole(context.Context, domain.RoleID) ([]domain.AccessBinding, error) {
	return r.parent.bindings, nil
}

// fanoutOrderReconciler — fails on the binding it is told to fail on, records the rest.
type fanoutOrderReconciler struct {
	mu       sync.Mutex
	failOn   domain.AccessBindingID
	attempts []domain.AccessBindingID
}

func (r *fanoutOrderReconciler) ReconcileBinding(_ context.Context, id domain.AccessBindingID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts = append(r.attempts, id)
	if id == r.failOn {
		return errors.New("canceling statement due to statement timeout")
	}
	return nil
}

// One binding failing must not decide the fate of the others. Stopping at the first
// failure made the outcome depend on the ORDER of the list: bindings before it were
// re-materialized against the new rules, bindings after it kept the old ones, so
// which subjects saw the change was settled by creation time.
func TestReconcileActiveBindings_ContinuesPastAFailingBinding(t *testing.T) {
	repo := &multiBindingRepo{bindings: []domain.AccessBinding{
		{ID: "iab_first"}, {ID: "iab_second"}, {ID: "iab_third"},
	}}
	rec := &fanoutOrderReconciler{failOn: "iab_second"}

	err := NewRoleMembershipFanout(repo, rec).ReconcileActiveBindings(context.Background(), "irl_x")
	require.Error(t, err, "the first failure must still be reported")
	assert.Contains(t, err.Error(), "iab_second")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Equal(t,
		[]domain.AccessBindingID{"iab_first", "iab_second", "iab_third"}, rec.attempts,
		"every binding must be attempted — a failure in one is not a reason to leave the rest on the old rules")
}

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kacho/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (rd *multiBindingReader) Visibility() visibility.ReaderIface { return nil }
