// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_ce09_hold_integration_test.go — детерминированный держатель
// окна, которое закрывает `FOR SHARE` записи выдачи делегатом (условие CE-09
// разбора классов; находка ревью SD-986-I2).
//
// Соседняя проба CE-09 (`grant_delegation_g_race_integration_test.go`) ставит
// порядок «отзыв ЗАФИКСИРОВАН до записи»: его отвергает и запись без замка —
// перепроверка `ACTIVE` видит зафиксированное. Окно замка — другое: отзыв взял
// строку делегирования и ещё не зафиксирован, а запись выдачи уже идёт. Без
// `FOR SHARE` запись читает прежнюю версию строки (`ACTIVE`), её внешний ключ
// берёт `FOR KEY SHARE`, который с замком отзыва не конфликтует, и выдача по
// отзываемому делегированию записывается действующей. С замком запись ждёт
// фиксации отзыва и отказывает Т-D1.
//
// Расстановка — держателем: транзакция отзыва берёт строку тем же писателем,
// что `GrantDelegationService.Revoke` (`LockForRevoke`, `MarkRevoked`), и не
// фиксируется, пока запись выдачи не встанет на замке (`pg_stat_activity`).
// Запись, не вставшая на замке за срок, — красное: окно не закрыто.

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestGrantDelegation_CE09_GrantWriteWaitsForAnUncommittedRevoke(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("CE-09 замок")
	d1 := w.d1()

	rev, err := w.repo.Writer(w.ctx)
	require.NoError(t, err)
	committed := false
	defer func() {
		if !committed {
			_ = rev.Rollback(w.ctx)
		}
	}()
	gw := rev.AccessBindingsW().GrantDelegationsW()
	_, err = gw.LockForRevoke(w.ctx, domain.GrantDelegationID(d1))
	require.NoError(t, err, "Дано: отзыв взял строку D1")
	_, err = gw.MarkRevoked(w.ctx, domain.GrantDelegationID(d1),
		domain.GrantDelegationActor{Type: "user", ID: string(w.usrA)}, time.Now().UTC())
	require.NoError(t, err, "Дано: отзыв перевёл D1 в REVOKED (не зафиксировано)")

	op, err := w.abx.Create(asSA(w.ctx, w.svaIss), w.v())
	require.NoError(t, err, "синхронное решение видит D1 действующим: отзыв не зафиксирован")

	w.awaitLockWaiter("grant_delegations", 30*time.Second,
		"запись выдачи делегатом не ждала незафиксированного отзыва")
	require.NoError(t, rev.Commit(w.ctx), "фиксация отзыва D1")
	committed = true

	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	require.NotNil(t, done.Error, "выдача по отзываемому D1 записана")
	assert.Equal(t, codes.FailedPrecondition, codes.Code(done.Error.Code), "код (текст %q)", done.Error.Message)
	assert.Equal(t, fmt.Sprintf("grant delegation %s was revoked before the access binding was written", d1),
		done.Error.Message, "текст Т-D1")
	assert.Zero(t, w.countActiveDelegated(d1), "действующих выдач по D1")
}
