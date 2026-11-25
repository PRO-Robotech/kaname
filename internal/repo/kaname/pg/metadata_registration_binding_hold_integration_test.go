// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Проверяем установленные миграцией тела. Фикстура не создаёт attestation,
// owner stash или receipt и не добавляет тестовый обход signed entry.
func TestMetadataRegistrationBindingHoldBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("требуется PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	signatures := []string{
		"kaname._authority_metadata_registration_binding_holds_v1(integer)",
		"kaname._authority_metadata_registration_binding_check_v1(text,text)",
	}
	probes := []struct {
		name  string
		query string
		args  []any
	}{
		{"hold", `SELECT kaname._authority_metadata_registration_binding_holds_v1($1)`, []any{16}},
		{"check", `SELECT kaname._authority_metadata_registration_binding_check_v1($1,$2)`, []any{"compute_instance", "registration-lock-absent"}},
		{"held_source", `SELECT kaname._authority_metadata_access_label_held_source_v1(5,$1,$2,16,1)`, []any{"compute_instance", "registration-lock-absent"}},
	}
	denied := func(t *testing.T, err error) {
		t.Helper()
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "42501", pgErr.Code)
	}

	t.Run("private_INVOKER_и_закрытые_default_ACL", func(t *testing.T) {
		for _, signature := range signatures {
			var sealed bool
			require.NoError(t, pool.QueryRow(ctx, `SELECT NOT p.prosecdef AND p.provolatile='v'
 AND p.proowner=(SELECT relowner FROM pg_class WHERE oid='kaname.authority_writer_protocol'::regclass)
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE a.grantee<>p.proowner)
 FROM pg_proc p WHERE p.oid=$1::regprocedure`, signature).Scan(&sealed))
			require.True(t, sealed, signature)
		}
	})

	t.Run("unsigned_owner_не_получает_receipt", func(t *testing.T) {
		for _, probe := range probes {
			t.Run(probe.name, func(t *testing.T) {
				tx, err := pool.Begin(ctx)
				require.NoError(t, err)
				defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
				_, err = tx.Exec(ctx, probe.query, probe.args...)
				denied(t, err)
				require.NoError(t, tx.Rollback(ctx))
			})
		}
	})

	t.Run("non_owner_даже_с_EXECUTE_не_получает_допуск", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
		role := ids.NewID("rbl")
		quoted := pgx.Identifier{role}.Sanitize()
		_, err = tx.Exec(ctx, `CREATE ROLE `+quoted+` NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT`)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `GRANT USAGE ON SCHEMA kaname TO `+quoted)
		require.NoError(t, err)
		for _, signature := range signatures {
			var executable bool
			require.NoError(t, tx.QueryRow(ctx, `SELECT has_function_privilege($1,$2,'EXECUTE')`, role, signature).Scan(&executable))
			require.False(t, executable, signature)
		}
		// Даём только вход в helpers и их owner-проверку. Проверка должна
		// отвергнуть роль внутри тела, а не остановиться на недостающем EXECUTE.
		_, err = tx.Exec(ctx, `GRANT SELECT ON kaname.authority_writer_protocol TO `+quoted)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `GRANT EXECUTE ON FUNCTION
 kaname._authority_metadata_registration_binding_holds_v1(integer),
 kaname._authority_metadata_registration_binding_check_v1(text,text),
 kaname._authority_metadata_access_label_stashed_v1(),
 kaname.authority_protocol_require_owner() TO `+quoted)
		require.NoError(t, err)
		var writeGranted bool
		require.NoError(t, tx.QueryRow(ctx, `SELECT
 has_table_privilege($1,'kaname.object_project_binding','INSERT,UPDATE,DELETE')
 OR has_any_column_privilege($1,'kaname.object_project_binding','INSERT,UPDATE')
 OR has_column_privilege($1,'kaname.resource_mirror','access_labels','UPDATE')`, role).Scan(&writeGranted))
		require.False(t, writeGranted, "EXECUTE helpers не выдаёт ordinary DML privileges")
		for _, probe := range probes[:2] {
			_, err = tx.Exec(ctx, `SAVEPOINT registration_caller_probe`)
			require.NoError(t, err)
			_, err = tx.Exec(ctx, `SET LOCAL ROLE `+quoted)
			require.NoError(t, err)
			_, err = tx.Exec(ctx, probe.query, probe.args...)
			denied(t, err)
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Contains(t, pgErr.Message, "requires migration owner")
			_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT registration_caller_probe`)
			require.NoError(t, err)
		}
		require.NoError(t, tx.Rollback(ctx))
	})

	t.Run("session_lock_не_заменяет_signed_stash", func(t *testing.T) {
		conn, err := pool.Acquire(ctx)
		require.NoError(t, err)
		defer conn.Release()
		const keySQL = `jsonb_build_array('compute_instance'::text,'registration-lock-absent'::text)::text`
		_, err = conn.Exec(ctx, `SELECT pg_advisory_lock_shared(1262569300,hashtext(`+keySQL+`))`)
		require.NoError(t, err)
		locked := true
		defer func() {
			if locked {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				_, _ = conn.Exec(cleanup, `SELECT pg_advisory_unlock_shared(1262569300,hashtext(`+keySQL+`))`)
			}
		}()
		// Старый verifier видит настоящий session lock. Новый boundary всё
		// равно требует signed stash; проверка не полагается на pg_locks fixture.
		_, err = conn.Exec(ctx, `SELECT kaname._authority_resource_preheld_key_v2(1262569300,`+keySQL+`,false)`)
		require.NoError(t, err)
		for _, probe := range probes {
			tx, err := conn.Begin(ctx)
			require.NoError(t, err)
			_, callErr := tx.Exec(ctx, probe.query, probe.args...)
			rollbackErr := tx.Rollback(ctx)
			denied(t, callErr)
			require.NoError(t, rollbackErr)
		}
		var released bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT pg_advisory_unlock_shared(1262569300,hashtext(`+keySQL+`))`).Scan(&released))
		require.True(t, released, "session lock пережил ROLLBACK, но не стал owner receipt")
		locked = false
	})
}
