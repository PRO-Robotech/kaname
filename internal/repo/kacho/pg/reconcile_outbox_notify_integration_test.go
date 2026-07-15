// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_outbox_notify_integration_test.go — integration-тест LISTEN/NOTIFY
// триггера на kacho_iam.resource_reconcile_outbox (testcontainers Postgres 16).
//
// Контракт: INSERT строки в очередь reconcile-событий обязан доставить pg_notify
// на канал kacho_iam_resource_reconcile_outbox с payload = id строки — byte-mirror
// триггера fga_outbox_notify. Это переводит дренаж reconcile-очереди с poll-only на
// NOTIFY-driven (паритет с fga_outbox), чтобы материализация label-selector гранта
// укладывалась в один reconcile-проход, а не ждала тика дренажа.
//
// RED до миграции с триггером (NOTIFY не приходит → ожидание истекает), GREEN после.

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/reconcile_outbox"
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

	_, err = conn.Exec(ctx, "LISTEN kacho_iam_resource_reconcile_outbox")
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
		`SELECT id FROM kacho_iam.resource_reconcile_outbox
		  WHERE object_type='compute.instance' AND object_id='cinst-notify-1'`).Scan(&rowID))

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	notif, err := conn.WaitForNotification(waitCtx)
	require.NoError(t, err, "ожидали NOTIFY от AFTER INSERT триггера в пределах таймаута")
	require.Equal(t, "kacho_iam_resource_reconcile_outbox", notif.Channel)
	require.Equal(t, strconv.FormatInt(rowID, 10), notif.Payload, "payload = id вставленной строки (NEW.id::text)")
}
