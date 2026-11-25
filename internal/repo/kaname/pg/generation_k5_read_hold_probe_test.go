// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Узкий адаптер должен вызвать установленный private helper через owner port.
// Он не создаёт stash/receipt и не берёт advisory lock вместо продукта.
type generationK5OwnerHold func(pgx.Tx, int, int) (rows int, reads int, err error)

// Вызывается после writerProtocolRig + fullContractActivate и установки
// тестового owner port. Это общий сценарий, а не самостоятельно включённый тест.
func probeGenerationK5ReadHold(t *testing.T, r protocolRig, model, otherModel, id string,
	wantRows, wantReads int, hold generationK5OwnerHold,
) {
	t.Helper()
	require.NotEqual(t, model, otherModel)
	require.Positive(t, wantReads)
	var absent int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.object_project_binding
 WHERE object_id=$1 AND object_type=ANY($2::text[])`, id, []string{model, otherModel}).Scan(&absent))
	require.Zero(t, absent)
	var distinctKeys bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT hashtext(jsonb_build_array($1::text,$3::text)::text)
 <>hashtext(jsonb_build_array($2::text,$3::text)::text)`, model, otherModel, id).Scan(&distinctKeys))
	require.True(t, distinctKeys, "контроль разных типов не должен случайно попасть в hash collision")
	acl := func() string {
		var result string
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_array(
 has_table_privilege($1,'kaname.object_project_binding','SELECT'),
 has_table_privilege($1,'kaname.object_project_binding','INSERT'),
 has_table_privilege($1,'kaname.object_project_binding','UPDATE'),
 has_table_privilege($1,'kaname.object_project_binding','DELETE'))::text`, r.role).Scan(&result))
		return result
	}
	originalACL := acl()
	begin := func() pgx.Tx {
		tx, err := r.runtime.Begin(r.ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = tx.Rollback(context.WithoutCancel(r.ctx)) })
		identity := r.bundle.Identity()
		_, err = tx.Exec(r.ctx, `SELECT kaname.authority_resource_enter_v3('accounts',ARRAY[$1::text],
 jsonb_build_array(jsonb_build_object('kind','account','id',$1::text)),$2,$3,$4)`,
			r.a, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
		require.NoError(t, err)
		return tx
	}
	// Проверяем отклонение до ожидания, в отдельных настоящих signed tx.
	if wantRows > 0 {
		tx := begin()
		_, _, err := hold(tx, wantRows-1, wantReads)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "54000", pgErr.Code)
		require.NoError(t, tx.Rollback(r.ctx))
	}
	tx := begin()
	_, _, err := hold(tx, wantRows, wantReads-1)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "54000", pgErr.Code)
	require.NoError(t, tx.Rollback(r.ctx))

	tx = begin()
	gotRows, gotReads, err := hold(tx, wantRows, wantReads)
	require.NoError(t, err)
	require.Equal(t, wantRows, gotRows)
	require.Equal(t, wantReads, gotReads)
	var holderPID int
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&holderPID))
	// Owner port проверяет состояние до и после удержания. Runtime не читает attestation напрямую.

	// Настоящий owner legacy INSERT проходит установленный BEFORE trigger.
	// Runtime не получает INSERT ни на таблицу, ни через новый definer writer.
	writer, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	defer writer.Rollback(context.WithoutCancel(r.ctx))
	_, err = writer.Exec(r.ctx, `SET LOCAL statement_timeout='5s'`)
	require.NoError(t, err)
	_, err = writer.Exec(r.ctx, `INSERT INTO kaname.object_project_binding(object_type,object_id,project_id)
 VALUES($1,$2,$3)`, otherModel, id, "k5-read-hold-project")
	require.NoError(t, err, "другой тип с тем же id не блокируется")
	var writerPID int
	require.NoError(t, writer.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&writerPID))
	done := make(chan error, 1)
	finished := false
	defer func() {
		// Сначала отпускаем blocker, затем ждём завершения использования writer.
		_ = tx.Rollback(context.WithoutCancel(r.ctx))
		if !finished {
			select {
			case <-done:
			case <-time.After(6 * time.Second):
			}
		}
	}()
	go func() {
		_, insertErr := writer.Exec(r.ctx, `INSERT INTO kaname.object_project_binding(object_type,object_id,project_id)
 VALUES($1,$2,$3)`, model, id, "k5-read-hold-project")
		done <- insertErr
	}()
	// Проверяем именно ожидание правильного advisory key. Это наблюдение теста,
	// не доказательство допуска/происхождения lock внутри production helper.
	require.Eventually(t, func() bool {
		var waiting bool
		err := r.admin.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks l
 WHERE l.pid=$1 AND l.locktype='advisory' AND l.classid=1262569300::oid
 AND l.objid=(hashtext(jsonb_build_array($3::text,$4::text)::text)::bigint & 4294967295)::oid
 AND l.objsubid=2 AND l.mode='ExclusiveLock' AND NOT l.granted
 AND $2::integer=ANY(pg_blocking_pids($1)))`, writerPID, holderPID, model, id).Scan(&waiting)
		return err == nil && waiting
	}, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, tx.Rollback(r.ctx))
	select {
	case err := <-done:
		finished = true
		require.NoError(t, err, "ROLLBACK снимает shared xact lock; реальный INSERT завершается")
	case <-time.After(6 * time.Second):
		t.Fatal("INSERT не освободился после ROLLBACK holder")
	}
	require.NoError(t, writer.Rollback(r.ctx))
	require.Equal(t, originalACL, acl(), "проверка не расширяет runtime privileges")
}
