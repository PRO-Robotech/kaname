// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// revoke_reads_under_its_writer_test.go — транзакция снятия ключа читает
// «есть ли пароль» СВОИМ соединением, а не портом пула (kaname#669, Ф7-26,
// Ф13-21).
//
// # Что наблюдается
//
// Снятие держит соединение транзакции и замки строки личности и строк ключей.
// Чтение портом пула изнутри неё берёт ВТОРОЕ соединение: при занятом пуле оно
// ждёт свободного, а соединения держат входы ключом, ждущие замка личности,
// который держит само снятие. База цикла не видит (снятие для неё «простаивает
// в транзакции»), и всё стоит до сроков клиентов — так упала конкурентная
// проба Ф13-21 на сборке волны (kaname#679, восемь входов по сроку клиента).
// Здесь — то, что базой не вызвать детерминированно: при открытой транзакции
// дублёра порт пула не читается ни разу, а второе чтение «последнего способа»
// идёт транзакцией.
//
// # Близнецы
//
// Синхронная сверка последнего способа ДО операции (без открытой транзакции)
// читает порт пула — это законно и остаётся; под замком тот же вопрос задаётся
// транзакции, и отказ «последний способ» на полосе операции держится им.

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// TestRevokeReadsThePasswordOverItsOwnTransaction — красная до фикса: снятие с
// паролем у человека не обращается к порту пула при открытой транзакции, и
// вопрос «есть ли пароль» под замком задан транзакции.
func TestRevokeReadsThePasswordOverItsOwnTransaction(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	k := h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgES256))

	op, err := h.revoke(alice, string(k.ID))
	require.NoError(t, err)
	require.Nil(t, op.Error, "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: снятие с паролем у человека исполнено")
	require.Zero(t, h.store.keyCount(alice), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: строка ключа снята")

	require.Zerof(t, h.meth.readsInsideWriter(),
		"kaname#669: транзакция снятия читала способы входа портом пула (вторым соединением) %d раз", h.meth.readsInsideWriter())
	require.Positive(t, h.store.writerPasswordReads,
		"Ф7-26: под замком «есть ли пароль» спрошен у транзакции снятия")
}

// TestRevokeLastMethodUnderTheLockIsJudgedByTheTransaction — близнец: тот же
// вопрос, отказ под замком. Пароль есть на синхронной сверке и снят до
// транзакции снятия — операция отказывает «последним способом» по ответу
// транзакции, ключ на месте.
func TestRevokeLastMethodUnderTheLockIsJudgedByTheTransaction(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	k := h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgES256))
	h.ops.afterCreate = func() {
		h.meth.mu.Lock()
		h.meth.password[alice] = false
		h.meth.mu.Unlock()
	}

	op, err := h.revoke(alice, string(k.ID))
	require.NoError(t, err, "синхронная сверка видела пароль")
	require.NotNil(t, op.Error, "Ф7-26: под замком пароля нет — операция отказывает")
	require.Equal(t, int32(codes.FailedPrecondition), op.Error.GetCode())
	require.Equal(t, 1, h.store.keyCount(alice), "Ф7-26: последний способ входа не снят")
	require.Zero(t, h.meth.readsInsideWriter(), "kaname#669: и на отказе порт пула изнутри транзакции не читается")
	require.Empty(t, h.store.auditOf(access_keys.AuditAccessKeyRevoked))
}
