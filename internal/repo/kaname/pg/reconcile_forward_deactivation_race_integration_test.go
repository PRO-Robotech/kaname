// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_forward_deactivation_race_integration_test.go — аддитивный форвард и
// ОТЗЫВ либо УДАЛЕНИЕ одной выдачи, идущие одновременно (kaname#923).
//
// ПРЕДМЕТ — тот же класс, что у истечения срока (kaname#919, шапка
// reconcile_forward_expiry_race_integration_test.go): форвард решает «выдача
// жива» чтением её фактов и пишет члена, запись реестра и строку журнала, из
// которой триггер складывает прямой факт. Отзыв и удаление снимают выдачу по
// РЕЕСТРУ, прочитанному в своей транзакции; запись форварда, легшая после
// этого чтения, в снимаемый набор не попадает, и прямой факт субъекта на
// объекте переживает снятие — доступ без выдачи.
//
// ФОРМА — та же остановка форварда сразу после чтения фактов выдачи
// (runForwardDeactivationRace), в паузу запускается НАСТОЯЩИЙ use-case отзыва
// или удаления через Execute владельцем аккаунта, исход операции читается из
// хранилища операций. Оба порядка проба принимает: снятие прошло, не дожидаясь
// форварда (так было до починки), либо встало на замке строки выдачи (так
// после неё) — утверждается ИСХОД.
//
// ЧТО УТВЕРЖДАЕТСЯ. Удаление: строки выдачи нет, и у неё не осталось ни
// члена, ни записи реестра, ни прямого факта. Отзыв мягкий: строка выдачи,
// её члены и реестр остаются по построению (отзыв удерживает след, как и без
// гонки), поэтому предмет — статус REVOKED и НОЛЬ прямых фактов: именно факт
// и есть доступ.
//
// ЗАКОННЫЕ БЛИЗНЕЦЫ — TestForwardVsExpiry_02 и _04: та же остановка без
// снятия, форвард обязан материализовать объект и дать прямой факт; без них
// ноль здесь был бы неотличим от форварда, не пишущего ничего.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ownerRemovalOnlyRelations — хранилище прав, отвечающее «нет» на любой вопрос,
// кроме ОДНОГО: владелец аккаунта держит отношение удаления на объектах выдач.
// С PRO-Robotech/kaname#986 (Р1а) обработчик отзыва и удаления сам задаёт
// вопрос `v_delete` на объекте выдачи — прежде его задавала дверь слушателя,
// мимо которой идут эти пробы; в продукте отношение владельцу материализует
// авто-выдача роли `owner`. Право выдавать по-прежнему приходит путём ВЛАДЕЛЬЦА
// (строка аккаунта), а не замыканием администратора облака.
type ownerRemovalOnlyRelations struct{ owner string }

func (o ownerRemovalOnlyRelations) Check(_ context.Context, subject, relation, object string) (bool, error) {
	return subject == "user:"+o.owner && relation == accessbindingapp.RemovalRelation &&
		strings.HasPrefix(object, accessbindingapp.RemovalObjectType+":"), nil
}

var _ clients.RelationStore = ownerRemovalOnlyRelations{}

// startUseCaseDeactivation запускает отзыв либо удаление выдачи, либо снос её
// области (проекта, аккаунта) настоящим use-case и возвращает канал исхода его
// операции.
func startUseCaseDeactivation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fx gammaFixture, bid domain.AccessBindingID, deact deactivation) <-chan error {
	t.Helper()
	opsRepo := operations.NewRepo(pool, "kaname")
	asOwner := operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: string(fx.owner)})
	var (
		op  *operations.Operation
		err error
	)
	switch deact {
	case revokeDeactivation:
		op, err = accessbindingapp.NewRevokeAccessBindingUseCase(fx.repo, opsRepo).
			WithRelationStore(ownerRemovalOnlyRelations{owner: string(fx.owner)}, nil).Execute(asOwner, bid)
	case deleteDeactivation:
		op, err = accessbindingapp.NewDeleteAccessBindingUseCase(fx.repo, opsRepo).
			WithRelationStore(ownerRemovalOnlyRelations{owner: string(fx.owner)}, nil).Execute(asOwner, bid)
	case projectDeleteDeactivation:
		op, err = projectapp.NewDeleteProjectUseCase(fx.repo, opsRepo).Execute(asOwner, fx.prj)
	case accountDeleteDeactivation:
		op, err = accountapp.NewDeleteAccountUseCase(fx.repo, opsRepo).Execute(asOwner, fx.accID)
	default:
		t.Fatalf("ПРЕДПОСЫЛКА: %s не запускается через use-case", deact)
	}
	require.NoError(t, err, "синхронный путь %s (право владельца, защита от удаления) обязан пройти", deact)
	done := make(chan error, 1)
	go func() { done <- awaitOperationOutcome(ctx, opsRepo, op.ID) }()
	return done
}

// awaitOperationOutcome — исход операции: nil при успехе, ошибка с её текстом
// при отказе, ошибка бюджета, если операция не завершилась.
func awaitOperationOutcome(ctx context.Context, opsRepo operations.Repo, id string) error {
	deadline := time.NewTimer(2 * expiryRaceBudget)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			return fmt.Errorf("операция %s не завершилась за %s", id, 2*expiryRaceBudget)
		case <-tick.C:
			op, err := opsRepo.Get(ctx, id)
			if err != nil {
				return fmt.Errorf("чтение операции %s: %w", id, err)
			}
			if !op.Done {
				continue
			}
			if op.Error != nil {
				return fmt.Errorf("операция %s завершилась отказом: %v", id, op.Error)
			}
			return nil
		}
	}
}

func bindingRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bid domain.AccessBindingID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_bindings WHERE id = $1`, string(bid)).Scan(&n))
	return n
}

// TestForwardVsRevoke_05_ObjectForwardLeavesNoFactOnRevokedBinding — объектный
// форвард против отзыва: после обоих у субъекта нет прямого факта на объекте.
func TestForwardVsRevoke_05_ObjectForwardLeavesNoFactOnRevokedBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, bid, subj := runForwardDeactivationRace(t, objectForward, "fx923a", revokeDeactivation)
	assert.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatus(t, ctx, pool, bid))
	_, _, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	assert.Zero(t, facts, "у субъекта отозванной выдачи остался прямой факт, записанный форвардом, — доступ без выдачи")
}

// TestForwardVsRevoke_06_BindingForwardLeavesNoFactOnRevokedBinding — тот же
// класс на форварде СОЗДАНИЯ выдачи.
func TestForwardVsRevoke_06_BindingForwardLeavesNoFactOnRevokedBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, bid, subj := runForwardDeactivationRace(t, bindingForward, "fx923b", revokeDeactivation)
	assert.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatus(t, ctx, pool, bid))
	_, _, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	assert.Zero(t, facts, "у субъекта отозванной выдачи остался прямой факт, записанный форвардом создания, — доступ без выдачи")
}

// TestForwardVsDelete_07_ObjectForwardLeavesNothingOnDeletedBinding — объектный
// форвард против удаления: после обоих нет ни выдачи, ни её следа.
func TestForwardVsDelete_07_ObjectForwardLeavesNothingOnDeletedBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, bid, subj := runForwardDeactivationRace(t, objectForward, "fx923c", deleteDeactivation)
	assert.Zero(t, bindingRows(t, ctx, pool, bid), "удаление обязано снять строку выдачи")
	members, ledger, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	assert.Zero(t, members, "у удалённой выдачи остались члены, записанные форвардом")
	assert.Zero(t, ledger, "у удалённой выдачи остались записи реестра, записанные форвардом")
	assert.Zero(t, facts, "у субъекта удалённой выдачи остался прямой факт, записанный форвардом, — доступ без выдачи")
}

// TestForwardVsDelete_08_BindingForwardLeavesNothingOnDeletedBinding — тот же
// класс на форварде СОЗДАНИЯ выдачи.
func TestForwardVsDelete_08_BindingForwardLeavesNothingOnDeletedBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, bid, subj := runForwardDeactivationRace(t, bindingForward, "fx923d", deleteDeactivation)
	assert.Zero(t, bindingRows(t, ctx, pool, bid), "удаление обязано снять строку выдачи")
	members, ledger, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	assert.Zero(t, members, "у удалённой выдачи остались члены, записанные форвардом создания")
	assert.Zero(t, ledger, "у удалённой выдачи остались записи реестра, записанные форвардом создания")
	assert.Zero(t, facts, "у субъекта удалённой выдачи остался прямой факт, записанный форвардом создания, — доступ без выдачи")
}
