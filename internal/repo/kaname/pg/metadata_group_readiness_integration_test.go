// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

func TestGroupMetadataReadinessRejectsChangedRoutinesAndPartialFacades(t *testing.T) {
	r := writerProtocolRig(t)
	full, _ := fullContractActivate(t, r)
	factory, err := kanamepg.NewMetadataMutationWriters(r.ctx, full, r.bundle)
	require.NoError(t, err)
	ports, err := factory.WithInstalledGroupAccessLabels(r.ctx)
	require.NoError(t, err)
	require.NotNil(t, ports)

	// Если клиент вызовет изменённое тело до проверки pg_proc, PostgreSQL вернёт
	// исключение. Отказ по отпечатку должен происходить до выполнения обеих функций.
	for _, signature := range []string{
		"kaname.authority_metadata_group_access_label_ready_v1()",
		"kaname._authority_metadata_group_exports_v1(oid,boolean)",
	} {
		t.Run(signature, func(t *testing.T) {
			var original, changed string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT pg_get_functiondef(p.oid),
				replace(pg_get_functiondef(p.oid),p.prosrc,$2) FROM pg_catalog.pg_proc p WHERE p.oid=$1::regprocedure`,
				signature, "BEGIN RAISE EXCEPTION 'readiness canary invoked' USING ERRCODE='55000'; END;").Scan(&original, &changed))
			require.NotEqual(t, original, changed)
			_, err := r.admin.Exec(r.ctx, changed)
			require.NoError(t, err)
			t.Cleanup(func() {
				_, err := r.admin.Exec(r.ctx, original)
				require.NoError(t, err)
			})
			ports, err := factory.WithInstalledGroupAccessLabels(r.ctx)
			require.Nil(t, ports)
			require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
			var serverErr *pgconn.PgError
			require.False(t, errors.As(err, &serverErr), "изменённое тело было вызвано до проверки")
		})
	}

	// Настоящий Down возвращает все шесть фасадов к закрытому ABI 07000.
	// Для каждой частичной выдачи проверяем запуск с тем же обычным LOGIN.
	db := stdlib.OpenDB(*r.admin.Config().ConnConfig)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS,
		goose.WithTableName("public.goose_db_version"))
	require.NoError(t, err)
	latest, err := provider.GetDBVersion(r.ctx)
	require.NoError(t, err)
	_, err = provider.DownTo(r.ctx, 20261128007000)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := provider.UpTo(r.ctx, latest)
		require.NoError(t, err)
	})
	ports, err = factory.WithInstalledGroupAccessLabels(r.ctx)
	require.NoError(t, err)
	require.Nil(t, ports)

	role := pgx.Identifier{r.role}.Sanitize()
	for _, signature := range []string{
		"kaname.authority_metadata_group_prepare_v1(text,text,text,jsonb,jsonb,text,text,jsonb,text[],integer,integer,integer)",
		"kaname.authority_metadata_group_retention_inputs_v1(jsonb,boolean,text,text,integer,integer,integer)",
		"kaname.authority_metadata_group_reserve_v1(jsonb,text,text,text,integer,integer,integer)",
		"kaname.authority_metadata_group_ordinary_reserve_v1(text,text,text,jsonb,jsonb,text,text,text,integer,integer,integer)",
		"kaname.authority_metadata_group_accept_v1(text,text,integer,integer,integer)",
		"kaname.authority_metadata_group_write_v1(text)",
	} {
		t.Run(signature, func(t *testing.T) {
			_, err := r.admin.Exec(r.ctx, "GRANT EXECUTE ON FUNCTION "+signature+" TO "+role)
			require.NoError(t, err)
			t.Cleanup(func() {
				_, err := r.admin.Exec(r.ctx, "REVOKE EXECUTE ON FUNCTION "+signature+" FROM "+role)
				require.NoError(t, err)
			})
			ports, err := factory.WithInstalledGroupAccessLabels(r.ctx)
			require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
			require.Nil(t, ports)
		})
	}
}
