// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// role_fanout_offdonepath_test.go — зафиксированная смена правил роли сообщается
// УСПЕХОМ, даже когда следующий за ней проход членства отказывает.
//
// Смена правил фиксируется первой: строка роли, проекция селекторов и запись
// аудита записаны, когда транзакция записи возвращается. Проход членства, заново
// материализующий то, что роль даёт, идёт ПОСЛЕ фиксации по каждой активной
// привязке, каждая — в своей транзакции. Прежде он шёл на пути самой операции, и
// любой его отказ превращал операцию в ошибку — о правке, уже зафиксированной и
// уже действующей.
//
// Вред — в том, что вызывающий делает потом: читает ошибку, решает, что правила не
// применились, и повторяет запрос с версией ресурса, снятой до первой попытки. Та
// устарела (её сдвинула его же зафиксированная правка), и повтор отвергается как
// параллельная правка — с соперником, которого не было. А права при этом ИЗМЕНЕНЫ,
// и оператор, думающий иначе, рассуждает о неверном состоянии.
//
// `Operation.done` значит, что ПРЕДМЕТ мутации записан, а не что виден его
// отложенный последующий эффект. Страховки схождения (событие сверки,
// зафиксированное вместе с правкой, и периодический обход) не меняются — речь о том,
// что сообщают вызывающему.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	repoaccount "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	repogroup "github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	repoproject "github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	reporole "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	reposa "github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	repouser "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// failingFanout — проход, который отказывает всегда, — так, как отказывает ожидание
// замка, переросшее предел оператора под параллельной нагрузкой.
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

// Отказ прохода членства не вправе превратить зафиксированную смену правил в
// отказавшую операцию.
func TestRoleUpdate_FailingMembershipPass_StillReportsTheCommittedChangeAsDone(t *testing.T) {
	const ownerID, accountID, resourceID = "usr_owner_offpath---", "acc_offpath---------", "prj_offpath---------"
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID178b, "viewer",
		domain.Permissions{"compute.instance.*.get"})
	repo.setRoleCustom(accountID)
	repo.answerRoleSegments()
	opsRepo := newFakeOpsRepo()
	fan := &failingFanout{count: 3, failed: errors.New("canceling statement due to statement timeout")}

	uc := roleapp.NewUpdateRoleUseCase(repo, opsRepo, catalogfixture.Source()).
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

	// Проход всё равно идёт: снять его с пути отчёта не значит его удалить.
	assert.Eventually(t, func() bool { return fan.called() > 0 }, 2*time.Second, 10*time.Millisecond,
		"the membership pass must still be attempted, just not on the reported path")
}

// ── проход покрывает КАЖДУЮ привязку, а не стоящие до первого отказа ─────────

// multiBindingRepo — роль, которую несут несколько активных привязок.
type multiBindingRepo struct{ bindings []domain.AccessBinding }

func (r *multiBindingRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	return &multiBindingReader{parent: r}, nil
}
func (r *multiBindingRepo) Writer(context.Context) (kanamerepo.Writer, error) { return nil, nil }
func (r *multiBindingRepo) Close()                                            {}

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

// fanoutOrderReconciler — отказывает на названной привязке, прочие записывает.
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

// Отказ одной привязки не вправе решать судьбу прочих. Остановка на первом отказе
// делала исход зависимым от ПОРЯДКА перечня: привязки до него материализовались
// по новым правилам, после него — сохраняли прежние, так что круг субъектов, увидевших
// смену, решало время создания привязок.
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
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (rd *multiBindingReader) Visibility() visibility.ReaderIface { return nil }

// GrantorLastPresentedAt — системный класс субъекта (kaname#829) этим дублёром не судится.
func (_ *multiBindingABReader) GrantorLastPresentedAt(context.Context, domain.UserID) (time.Time, bool, error) {
	return time.Time{}, false, nil
}

// PublicReadContainer — публичное чтение контейнера (kaname#856) этим дублёром не
// судится: тип цели не объявлен, детей нет.
func (_ *multiBindingABReader) PublicReadContainer(context.Context, string) (domain.PublicReadContainer, error) {
	return domain.PublicReadContainer{}, nil
}

func (_ *multiBindingABReader) ClassGrantsKeyedModules(context.Context) (domain.ClassGrantsKeyedModules, error) {
	return domain.ClassGrantsKeyedModules{}, nil
}
