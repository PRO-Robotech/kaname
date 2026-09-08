// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_outbox_notify_integration_test.go — integration-тест LISTEN/NOTIFY
// триггера на kaname.resource_reconcile_outbox (testcontainers Postgres 16).
//
// Контракт: INSERT строки в очередь reconcile-событий обязан доставить pg_notify
// на канал kaname_resource_reconcile_outbox с payload = id строки. Это переводит
// дренаж reconcile-очереди с poll-only на NOTIFY-driven, чтобы материализация
// label-selector гранта укладывалась в один reconcile-проход, а не ждала тика
// дренажа.
//
// Здесь стояло «byte-mirror триггера fga_outbox_notify» и «паритет с fga_outbox» —
// оба утверждения ПЕРЕЖИЛИ свой предмет: уведомление журнала намерений снято
// вместе со своим дренажом (миграция 20260829123045, kacho#1436), и зеркалить
// теперь нечего. Свойство ЭТОГО канала от того не изменилось: у него есть живой
// слушатель (`reconcile_notify.go`), и потому он остаётся — а заодно служит
// положительным контролем семейству проб «канал без слушателя».
//
// RED до миграции с триггером (NOTIFY не приходит → ожидание истекает), GREEN после.

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/reconcile_outbox"
)

func TestReconcileOutbox_Notify_InsertFiresPgNotify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Выделенный conn под LISTEN: hijack из pool, чтобы idle-reset его не
	// переиспользовал и не сбросил подписку (тот же прием, что в corelib drainer).
	pc, err := pool.Acquire(ctx)
	require.NoError(t, err)
	conn := pc.Hijack()
	defer func() { _ = conn.Close(context.Background()) }()

	_, err = conn.Exec(ctx, "LISTEN kaname_resource_reconcile_outbox")
	require.NoError(t, err, "LISTEN на канал reconcile-очереди")

	// Эмитим событие в очередь в отдельной tx и коммитим: pg_notify доставляется
	// слушателю в момент COMMIT, поэтому без коммита уведомления не будет.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, reconcile_outbox.EmitTx(ctx, tx, reconcile_outbox.EventUpsert, "compute.instance", "cinst-notify-1"))
	require.NoError(t, tx.Commit(ctx))

	// Считываем id вставленной строки, чтобы сверить payload уведомления.
	var rowID int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kaname.resource_reconcile_outbox
		  WHERE object_type='compute.instance' AND object_id='cinst-notify-1'`).Scan(&rowID))

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	notif, err := conn.WaitForNotification(waitCtx)
	require.NoError(t, err, "ожидали NOTIFY от AFTER INSERT триггера в пределах таймаута")
	require.Equal(t, "kaname_resource_reconcile_outbox", notif.Channel)
	require.Equal(t, strconv.FormatInt(rowID, 10), notif.Payload, "payload = id вставленной строки (NEW.id::text)")
}
