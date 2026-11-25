// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

func TestServiceAccountMetadataMigrationRoundTrip(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	db := stdlib.OpenDB(*r.admin.Config().ConnConfig)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS,
		goose.WithTableName("public.goose_db_version"))
	require.NoError(t, err)
	const (
		version  int64 = 20261125150000
		previous int64 = 20261125140000
	)
	latest, err := provider.GetDBVersion(r.ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, latest, version)
	t.Cleanup(func() {
		_, err := provider.UpTo(r.ctx, latest)
		require.NoError(t, err)
	})
	_, err = provider.DownTo(r.ctx, version)
	require.NoError(t, err)

	inspect := func() (closure string, bodies string, attached bool) {
		t.Helper()
		var valid, capability bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `WITH installed AS (
 SELECT oid,proowner,proacl,proconfig,prosrc FROM pg_catalog.pg_proc WHERE oid IN (
   'kaname._authority_full_contract_storage_v3()'::regprocedure,
   'kaname.authority_metadata_access_label_ready_v2(text)'::regprocedure,
   'kaname.authority_metadata_access_label_write_v1(text,text)'::regprocedure)
) SELECT
 kaname._authority_full_contract_storage_v3() AND kaname.authority_access_label_storage_valid_v1(),
 EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='kaname.service_accounts'::regclass
   AND tgname='access_labels_000_commit_freshness' AND tgenabled='O'),
 to_regprocedure('kaname.authority_metadata_service_account_access_label_ready_v1()') IS NOT NULL,
 (SELECT jsonb_agg(jsonb_build_array(oid,proowner,proacl,proconfig) ORDER BY oid)::text FROM installed),
 (SELECT jsonb_agg(encode(sha256(convert_to(prosrc,'UTF8')),'hex') ORDER BY oid)::text FROM installed)`).
			Scan(&valid, &attached, &capability, &closure, &bodies))
		require.True(t, valid, "цепочка проверок установки остаётся согласованной")
		require.Equal(t, attached, capability, "готовность и триггер устанавливаются и снимаются вместе")
		return closure, bodies, attached
	}
	installedACL, installedBodies, trigger := inspect()
	require.True(t, trigger)
	removed, err := provider.Down(r.ctx)
	require.NoError(t, err)
	require.Equal(t, version, removed.Source.Version)
	current, err := provider.GetDBVersion(r.ctx)
	require.NoError(t, err)
	require.Equal(t, previous, current)
	oldACL, oldBodies, trigger := inspect()
	require.False(t, trigger)
	require.Equal(t, installedACL, oldACL)
	require.NotEqual(t, installedBodies, oldBodies)

	reinstalled, err := provider.UpTo(r.ctx, version)
	require.NoError(t, err)
	require.Len(t, reinstalled, 1)
	require.Equal(t, version, reinstalled[0].Source.Version)
	newACL, newBodies, trigger := inspect()
	require.True(t, trigger)
	require.Equal(t, installedACL, newACL)
	require.Equal(t, installedBodies, newBodies)
}
