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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

// Номер выводится из фактической embedded цепи, без арифметики timestamp и
// предположения о непрерывной нумерации исторических миграций.
func parentPrelockMigrationDB(t *testing.T, r protocolRig) (*sql.DB, int64, int64) {
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
		if strings.HasSuffix(entry.Name(), "_parent_prelock_admission_before_row_locks.sql") {
			require.Zero(t, own, "должен быть ровно один файл предмета")
			own = version
		}
	}
	require.NotZero(t, own)
	require.GreaterOrEqual(t, latest, own)
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
	// Новые append-миграции снимаются настоящим Goose только в nonfull GIVEN.
	// Сам предмет и прежние exact body/ACL assertions остаются без изменений.
	require.NoError(t, goose.DownTo(db, ".", own))
	t.Cleanup(func() { require.NoError(t, goose.UpTo(db, ".", latest)) })
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version)
	return db, own, previous
}

func parentPrelockFunctionState(t *testing.T, r protocolRig) string {
	t.Helper()
	var state string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_agg(jsonb_build_object(
  'name',p.proname,'definition',pg_get_functiondef(p.oid),'acl',p.proacl,'owner',p.proowner)
  ORDER BY p.proname)::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='kaname' AND p.proname IN ('authority_parent_prelock_admit_v3',
  '_authority_full_contract_storage_v3','authority_protocol_grant_runtime','authority_protocol_attestation')`).Scan(&state))
	return state
}

func parentPrelockMigrationPrivateACL(t *testing.T, r protocolRig) {
	t.Helper()
	var private bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,
  'kaname.authority_protocol_attestation()','EXECUTE')`).Scan(&private))
	require.False(t, private, "Down/Up не выдаёт LOGIN private verifier")
}

func TestParentPrelockMigrationGooseRoundTripRestoresExactPreviousContract(t *testing.T) {
	r, owner := parentPrelockRig(t)
	db, own, previous := parentPrelockMigrationDB(t, r)
	before := parentPrelockFunctionState(t, r)
	parentPrelockMigrationPrivateACL(t, r)
	// Даже при раннем Fatal база возвращается к текущей цепи до cleanup фикстуры.
	t.Cleanup(func() { require.NoError(t, goose.UpTo(db, ".", own)) })
	require.NoError(t, goose.Down(db, "."), "настоящий Goose Down, не ручное исполнение его SQL")
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, previous, version)
	var absent bool
	var readiness, grants string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
  to_regprocedure('kaname.authority_parent_prelock_admit_v3()') IS NULL,
  (SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE oid='kaname._authority_full_contract_storage_v3()'::regprocedure),
  (SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE oid='kaname.authority_protocol_grant_runtime(regrole)'::regprocedure)`).Scan(&absent, &readiness, &grants))
	require.True(t, absent)
	// Точные prosrc предыдущих 27 pins и wrapper из последних SOURCE миграций.
	require.Equal(t, "747122428bee085bc73afb112c9b82522693c6e7c3acc4053523ef818e0dd5b0", readiness)
	require.Equal(t, "51d4e38448aad34dc8e0906e06dbbb53f1f10bdfef7aaa875c896545f3572c3c", grants)
	parentPrelockMigrationPrivateACL(t, r)
	var ready bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
	require.True(t, ready, "предыдущая цепь 27 pins действительно работоспособна")
	require.NoError(t, goose.UpTo(db, ".", own))
	version, err = goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version)
	require.Equal(t, before, parentPrelockFunctionState(t, r), "Up восстановил definition/owner/ACL всех четырёх entry функций")
	parentPrelockMigrationPrivateACL(t, r)
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
	require.True(t, ready, "текущая цепь 28 pins восстановлена")
	for _, method := range []string{"account-removal", "account-owner", "user-removal"} {
		w, err := r.repo.Writer(r.ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = w.Rollback(r.ctx) })
		require.NoError(t, parentPrelockCall(r.ctx, w, method, r, owner), "реальный LOGIN port после Goose Up: %s", method)
		require.NoError(t, w.Rollback(r.ctx))
	}
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	full, _ := fullContractActivateBeforePublication(t, r)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
}

func TestParentPrelockMigrationGooseDownRefusesActiveFullWithoutChanges(t *testing.T) {
	r, _ := parentPrelockRig(t)
	db, own, _ := parentPrelockMigrationDB(t, r)
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	full, _ := fullContractActivateBeforePublication(t, r)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
	var contract int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT required_contract FROM kaname.authority_writer_contract WHERE singleton`).Scan(&contract))
	require.Equal(t, 2, contract)
	before := rolePrelockMigrationSnapshot(t, r)
	err := goose.Down(db, ".")
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "P1036", pe.Code)
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version)
	require.Equal(t, before, rolePrelockMigrationSnapshot(t, r), "отказ не изменяет ledger, schema, ACL, function bodies и authority state")
	parentPrelockMigrationPrivateACL(t, r)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
}
