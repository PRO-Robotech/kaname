// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// role_fanout_bound_test.go — сторож предела для правки правил роли. Правка роли
// со сменой правил отвергается FAILED_PRECONDITION, когда роль несут больше
// активных привязок, чем предел контракта (10000), ДО всякой работы прохода
// (операция даже не заводится). Проба над дублёром репозитория и дублёром
// прохода; без Postgres (зависимость слоя службы от Postgres была бы утечкой
// адаптера).

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// fakeFanout — `role.RulesMembershipFanout`, отдающий заданный счёт активных
// привязок и записывающий, звали ли сверку после фиксации.
//
// Проход идёт в горутине, ОТСОЕДИНЁННОЙ от операции (`shared.GoPostCommit`), так
// что факт, который он записывает, пишет не та горутина, что его утверждает, и
// `awaitOpDone` барьером для него НЕ служит: готовность значит, что строка
// записана, а не что отсоединённый проход наблюдён (запрет #9). Голое поле `bool`
// поэтому — два дефекта сразу: гонка данных и утверждение, вправе прочесть
// `false`, пока проход ещё идёт. Запись — канал, который проход закрывает:
// закрытие публикует всё, что было до него, поэтому ожидание без гонки И
// детерминировано и кончается ровно тогда, когда проход исполнился, — без опроса и
// без паузы.
type fakeFanout struct {
	count int
	err   error

	once sync.Once
	ran  chan struct{} // closed by the first ReconcileActiveBindings
}

func newFakeFanout(count int) *fakeFanout {
	return &fakeFanout{count: count, ran: make(chan struct{})}
}

func (f *fakeFanout) CountActiveBindings(context.Context, domain.RoleID) (int, error) {
	return f.count, f.err
}
func (f *fakeFanout) ReconcileActiveBindings(context.Context, domain.RoleID) error {
	f.once.Do(func() { close(f.ran) })
	return nil
}

// reconciled — исполнился ли проход К ЭТОМУ МОМЕНТУ, без ожидания.
func (f *fakeFanout) reconciled() bool {
	select {
	case <-f.ran:
		return true
	default:
		return false
	}
}

// awaitReconciled ждёт, пока отсоединённый проход исполнится либо истечёт срок,
// и отвечает, что случилось. Истечение — настоящий отказ проверяемого свойства,
// а не случайность, которую замазывают.
func (f *fakeFanout) awaitReconciled(budget time.Duration) bool {
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-f.ran:
		return true
	case <-timer.C:
		return false
	}
}

func TestRoleUpdate_C21_FanoutBoundExceeded_FailedPrecondition(t *testing.T) {
	const ownerID, accountID, resourceID = "usr_owner_c21a------", "acc_c21a------------", "prj_c21a------------"
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID178a, "viewer",
		domain.Permissions{"compute.instance.*.get"})
	repo.setRoleCustom(accountID) // custom role → Role.Update account-owner gate passes
	opsRepo := newFakeOpsRepo()
	fan := newFakeFanout(roleapp.MaxRoleFanoutBindings + 1)

	uc := roleapp.NewUpdateRoleUseCase(repo, opsRepo, catalogfixture.Source()).
		WithTupleReconciler(NewRoleTupleReconciler()).
		WithMembershipFanout(fan)

	_, err := uc.Execute(newOwnerContext(ownerID), roleUpdateInput(roleID178a, domain.Rules{
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"env": "prod"}},
	}))
	require.Error(t, err, "a role over the fan-out limit must be rejected SYNC")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "too many bindings")
	// Отвергнуто синхронно, до заведения операции, так что ждать нечего: проход либо
	// не начинался, либо предел не удержан.
	assert.False(t, fan.reconciled(), "the fan-out must NOT run when the bound is exceeded")
}

func TestRoleUpdate_C21_FanoutWithinBound_Runs(t *testing.T) {
	const ownerID, accountID, resourceID = "usr_owner_c21b------", "acc_c21b------------", "prj_c21b------------"
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID178b, "viewer",
		domain.Permissions{"compute.instance.*.get"})
	repo.setRoleCustom(accountID)
	repo.answerRoleSegments()
	opsRepo := newFakeOpsRepo()
	fan := newFakeFanout(3)

	uc := roleapp.NewUpdateRoleUseCase(repo, opsRepo, catalogfixture.Source()).
		WithTupleReconciler(NewRoleTupleReconciler()).
		WithMembershipFanout(fan)

	op, err := uc.Execute(newOwnerContext(ownerID), roleUpdateInput(roleID178b, domain.Rules{
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"env": "prod"}},
	}))
	require.NoError(t, err)
	awaitOpDone(t, opsRepo, op.ID)
	// Готовность операции — барьер для ЗАФИКСИРОВАННОЙ правки, а не для
	// отсоединённого прохода: у прохода свой барьер.
	assert.True(t, fan.awaitReconciled(5*time.Second),
		"within-bound rules change runs the membership fan-out")
}
