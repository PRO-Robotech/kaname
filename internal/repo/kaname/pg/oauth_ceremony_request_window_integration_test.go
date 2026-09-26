// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// oauth_ceremony_request_window_integration_test.go — окно транзакции запроса
// обмена второй связи из пула не берёт (задача PRO-Robotech/kaname#423,
// возврат ревью сборки 425). Транзакция запроса держит связь от погашения до
// урегулирования; всякое второе взятие связи внутри окна при пуле, занятом
// такими же обменами, ждёт само себя до срока вызова.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// Окно транзакции запроса второй связи из пула не берёт: чтение подписного
// ключа, которое подписант делает между погашением и урегулированием, идёт в
// транзакции запроса. Пул в одну связь, и её держит транзакция запроса, —
// читатель ключа обязан получить ответ хранилища, а не отказ по сроку. Близнец —
// тот же вызов на пуле в две связи (одно изменённое значение — ширина).
func TestCeremonyVaults_RequestWindowReadsTheSigningKeyWithoutASecondConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	for _, cell := range []struct {
		name  string
		width int
	}{
		{"пул в одну связь", 1},
		{"близнец: пул в две связи", 2},
	} {
		t.Run(cell.name, func(t *testing.T) {
			ctx, pool := narrowPool(t, cell.width)
			sc := ceremonyScene(t, ctx, pool, "vsk1")
			v := kanamepg.NewCeremonyVaults(pool)
			keys := kanamepg.NewSigningKeyRepo(pool)
			sig := ceremonyDigest(0x7d0100 + cell.width)
			storeVaultCode(t, ctx, v, sc, sig)

			reqCtx, settle := v.OpenRequest(ctx)
			defer func() { require.NoError(t, settle(ctx), "урегулирование запроса") }()
			out, err := v.ConsumeAuthorizationCode(reqCtx, sig)
			require.NoError(t, err, "погашение открывает транзакцию запроса")
			require.EqualValues(t, 1, out.Rows())

			readCtx, cancel := context.WithTimeout(reqCtx, 500*time.Millisecond)
			_, err = keys.Active(readCtx)
			cancel()
			require.NotErrorIs(t, err, context.DeadlineExceeded,
				"чтение подписного ключа в окне транзакции запроса ждало вторую связь пула шириной %d", cell.width)
			require.ErrorIs(t, err, iamerr.ErrFailedPrecondition,
				"хранилище не ответило о подписном ключе (в схеме пробы его нет): %v", err)
		})
	}
}
