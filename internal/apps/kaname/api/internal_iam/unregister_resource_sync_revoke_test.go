// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// unregister_resource_sync_revoke_test.go — половина контракта регистрации,
// отвечающая за снятие.
//
// Register делает три записи в одной транзакции (зеркало, кортеж владельца, событие согласования),
// а после коммита запускает материализацию в процессе, чтобы следующий
// вопрос вызывающего получил новое состояние. Unregister делал симметричные три записи (удаление
// зеркала, постановка удаления кортежа, событие согласования), а затем останавливался: нужная
// материализация — проход, снимающий глаголы объекта после исчезновения его
// проекции, — полностью зависела от случайной глубины очереди согласования.
//
// Асимметрия не косметическая. Выдача ограничена одним проходом в процессе, а
// снятие — очередью: продукт быстро говорит «да» и медленно
// говорит «нет». По замеру на стенде (боевая посадка, один том хранения) глаголы
// появлялись внутри запроса создания и продолжали отвечать ALLOW двенадцать секунд
// после того, как сам ресурс начал отвечать 404.
//
// Вызывать нужно прямую точку входа: объект с УЖЕ материализованными
// участниками она передаёт полному проходу, чья разница с удалением устаревшего — именно
// нужное здесь снятие (см. защиту ReconcileObjectForward). Событие согласования,
// записанное тем же коммитом, остаётся страховкой повторной доставки.

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUnregisterResource_DrivesTheRevokeInTheSameRequest — снятие начинает
// материализацию в процессе точно так же, как регистрация.
//
// До исправления ПРОВАЛ: ноль проходов после коммита; отзыв начинался только когда очередь
// согласования доходила до события того же коммита.
func TestUnregisterResource_DrivesTheRevokeInTheSameRequest(t *testing.T) {
	rec := &smObjectReconciler{}
	uc, txb := newStorageRevokeUC(t, rec)

	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject:  "project:prj_owner",
		relation: "project",
		object:   "storage_volume:vol_gone",
	}))
	require.NotNil(t, txb.tx)
	require.True(t, txb.tx.committed, "unregister must commit the writer-tx")

	calls := rec.snapshot()
	require.Len(t, calls, 1,
		"withdrawal must drive exactly one post-commit pass on the withdrawn object — "+
			"otherwise the revoke waits out the reconcile queue while the grant never did")
	assert.Equal(t, [2]string{"storage.volumes", "vol_gone"}, calls[0],
		"the pass must target the withdrawn object (dotted type)")
}

// TestUnregisterResource_NilReconciler_NonFatal — неподключённый работник оставляет
// снятие только на очереди, как прежде, и никогда не даёт ошибки.
func TestUnregisterResource_NilReconciler_NonFatal(t *testing.T) {
	uc, txb := newStorageRevokeUC(t, nil)
	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject: "project:prj_owner", relation: "project", object: "storage_volume:vol_gone",
	}), "nil reconciler must be a non-fatal no-op")
	require.True(t, txb.tx.committed)
}

// TestUnregisterResource_ReconcileError_NonFatal — к моменту прохода снятие уже надёжно записано:
// строка зеркала удалена, удаление кортежа поставлено, событие закоммичено вместе с ними, поэтому
// отказ прохода не должен превращать завершённое снятие в повторяемую вызывающим ошибку.
func TestUnregisterResource_ReconcileError_NonFatal(t *testing.T) {
	rec := &smObjectReconciler{err: errors.New("reconcile transient")}
	uc, txb := newStorageRevokeUC(t, rec)
	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject: "project:prj_owner", relation: "project", object: "storage_volume:vol_gone",
	}), "a post-commit reconcile error must not fail a committed withdrawal (queue is the backstop)")
	require.True(t, txb.tx.committed)
	require.Len(t, rec.snapshot(), 1)
}

// newStorageRevokeUC задаёт прежнюю иерархию только сцены снятия тома:
// аудит читает стоящий указатель до удаления фактов объекта.
func newStorageRevokeUC(t *testing.T, rec *smObjectReconciler) (*RegisterResourceUseCase, *smTxBeginner) {
	t.Helper()
	uc, txb := newRegUC(t, rec)
	uc.WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "storage"})
	scopes := unitScopes()
	scopes.projects["prj_owner"] = "acc_owner"
	scopes.pointers = map[string][]string{"storage_volume:vol_gone": {"project:prj_owner"}}
	uc.scopes = scopes
	return uc, txb
}

// TestUnregisterResource_PureGrantWithdrawal_LeavesTheObjectAlone — снятие
// публичной выдачи с wildcard ничего не говорит о проекции самого объекта, поэтому не должно
// запускать его проход. Без этого предыдущие тесты проходили бы при
// безусловном согласовании, которое заново вывело бы членство ещё живого
// и нетронутого объекта.
func TestUnregisterResource_PureGrantWithdrawal_LeavesTheObjectAlone(t *testing.T) {
	rec := &smObjectReconciler{}
	uc, _ := newRegUC(t, rec)
	uc.WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "registry"})
	scopes := unitScopes()
	scopes.pointers = map[string][]string{"registry_repository:reg1/public": {"registry_registry:reg1"}}
	uc.scopes = scopes

	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject:  "user:*",
		relation: "v_get",
		object:   "registry_repository:reg1/public",
	}))
	assert.Empty(t, rec.snapshot(),
		"a pure-grant withdrawal touches no projection, so it must drive no object pass")
}
