// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"database/sql"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

func accessLabelStorageMigrationDB(t *testing.T, r protocolRig) (*sql.DB, int64, int64) {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err)
	var own, previous, latest int64
	var versions []int64
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		head, _, ok := strings.Cut(entry.Name(), "_")
		require.True(t, ok)
		version, err := strconv.ParseInt(head, 10, 64)
		require.NoError(t, err)
		versions = append(versions, version)
		if version > latest {
			latest = version
		}
		if strings.HasSuffix(entry.Name(), "_access_label_storage_is_closed_by_default.sql") {
			require.Zero(t, own)
			own = version
		}
	}
	require.NotZero(t, own)
	for _, version := range versions {
		if version < own && version > previous {
			previous = version
		}
	}
	require.NotZero(t, previous)
	db := stdlib.OpenDB(*r.admin.Config().ConnConfig)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.DownTo(db, ".", own))
	t.Cleanup(func() { require.NoError(t, goose.UpTo(db, ".", latest)) })
	return db, own, previous
}

func TestAccessLabelStorageMigrationRoundTripKeepsAuthorityClosure(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	db, own, previous := accessLabelStorageMigrationDB(t, r)
	var before, after string
	const functionState = `SELECT jsonb_agg(jsonb_build_array(p.proname,p.prosrc,p.proowner,p.proacl,p.proconfig) ORDER BY p.proname)::text
	 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
	 WHERE n.nspname='kaname' AND p.proname IN ('access_labels_valid_v1','access_labels_immutable_v1','authority_access_label_storage_valid_v1')`
	require.NoError(t, r.admin.QueryRow(r.ctx, functionState).Scan(&before))
	require.NoError(t, goose.Down(db, "."))
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, previous, version)
	var absent, valid bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
	 JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND a.attname='access_labels' AND NOT a.attisdropped),
	 kaname._authority_full_contract_storage_v3()`).Scan(&absent, &valid))
	require.True(t, absent)
	require.True(t, valid)
	require.NoError(t, goose.UpTo(db, ".", own))
	require.NoError(t, r.admin.QueryRow(r.ctx, functionState).Scan(&after))
	require.JSONEq(t, before, after)
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_access_label_storage_valid_v1()`).Scan(&valid))
	require.True(t, valid)
}

func TestAccessLabelStorageClosureAndDrainCoverExactlyProtectedBases(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_protocol_drain()`)
	require.NoError(t, err)
	var locked int
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FROM unnest(ARRAY[
	 'accounts','projects','users','service_accounts','groups','roles','access_bindings','resource_mirror']) target
	 WHERE EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='relation'
	 AND l.relation=to_regclass('kaname.'||target) AND l.mode='AccessExclusiveLock' AND l.granted)`).Scan(&locked))
	require.Equal(t, 8, locked, "Down проверяет пустоту всех источников под уже удерживаемыми замками")
	_, err = tx.Exec(r.ctx, `ALTER TABLE kaname.groups DISABLE TRIGGER access_labels_immutable`)
	require.NoError(t, err)
	var valid bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_access_label_storage_valid_v1()`).Scan(&valid))
	require.False(t, valid, "потеря собственного guard закрывает storage readiness")
	require.NoError(t, tx.Rollback(r.ctx))
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_access_label_storage_valid_v1()`).Scan(&valid))
	require.True(t, valid, "откат DDL восстанавливает защищённое хранение")
}
