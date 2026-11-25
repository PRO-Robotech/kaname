// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type metadataPhysicalRootQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func metadataPhysicalRootState(t *testing.T, ctx context.Context, q metadataPhysicalRootQuerier, typ, id string, hold bool) json.RawMessage {
	t.Helper()
	var state json.RawMessage
	require.NoError(t, q.QueryRow(ctx, `SELECT kaname._authority_metadata_root_state_v1($1,$2,$3)`, typ, id, hold).Scan(&state))
	return state
}

func metadataPhysicalRootParts(t *testing.T, state json.RawMessage) []json.RawMessage {
	t.Helper()
	var parts []json.RawMessage
	require.NoError(t, json.Unmarshal(state, &parts))
	require.Len(t, parts, 3)
	return parts
}

func TestMetadataPhysicalRootWitness(t *testing.T) {
	if testing.Short() {
		t.Skip("требуется PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	tenant := seedVerdictTenant(t, ctx, pool)
	const objectID = "physical-root/shared"
	const firstType = "compute.instance"
	const secondType = "vpc.network"
	var liveTypes int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.catalog_resource
 WHERE dotted=ANY($1::text[]) AND live AND module<>'iam'`, []string{firstType, secondType}).Scan(&liveTypes))
	require.Equal(t, 2, liveTypes)
	// Карта access_labels остаётся штатным DEFAULT '{}': фикстура не обходит immutable guard.
	_, err = pool.Exec(ctx, `INSERT INTO kaname.resource_mirror
 (object_type,object_id,parent_project_id,parent_account_id,labels)
 VALUES ($1,$3,$4,$5,'{"team":"first"}'),($2,$3,$4,$5,'{"team":"second"}')`,
		firstType, secondType, objectID, tenant.projectID, tenant.accountID)
	require.NoError(t, err)

	t.Run("составной_ключ_и_отсутствие", func(t *testing.T) {
		for _, typ := range []string{firstType, secondType} {
			state := metadataPhysicalRootState(t, ctx, pool, typ, objectID, false)
			parts := metadataPhysicalRootParts(t, state)
			var row struct {
				Type         string            `json:"object_type"`
				ID           string            `json:"object_id"`
				Labels       map[string]string `json:"labels"`
				AccessLabels map[string]string `json:"access_labels"`
			}
			require.NoError(t, json.Unmarshal(parts[2], &row))
			require.Equal(t, typ, row.Type)
			require.Equal(t, objectID, row.ID)
			require.Equal(t, map[string]string{firstType: "first", secondType: "second"}[typ], row.Labels["team"])
			require.NotNil(t, row.AccessLabels)
			require.Empty(t, row.AccessLabels)
		}
		require.Nil(t, metadataPhysicalRootState(t, ctx, pool, firstType, "physical-root/absent", false))
		for _, typ := range []string{"unknown.root", "iam.user"} {
			_, err := pool.Exec(ctx, `SELECT kaname._authority_metadata_root_state_v1($1,$2,false)`, typ, objectID)
			var denied *pgconn.PgError
			require.ErrorAs(t, err, &denied)
			require.Equal(t, "42501", denied.Code)
		}
	})

	t.Run("native_совпадает_с_прежним_SELECT", func(t *testing.T) {
		for _, root := range []struct{ typ, id, query string }{
			{"iam.account", tenant.accountID, `SELECT jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o)) FROM ONLY kaname.accounts o WHERE o.id=$1`},
			{"iam.project", tenant.projectID, `SELECT jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o)) FROM ONLY kaname.projects o WHERE o.id=$1`},
			{"iam.serviceAccount", tenant.granted, `SELECT jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o)) FROM ONLY kaname.service_accounts o WHERE o.id=$1`},
		} {
			for _, hold := range []bool{false, true} {
				tx, err := pool.Begin(ctx)
				require.NoError(t, err)
				t.Cleanup(func() { _ = tx.Rollback(context.WithoutCancel(ctx)) })
				defer func() { _ = tx.Rollback(ctx) }()
				var expected json.RawMessage
				require.NoError(t, tx.QueryRow(ctx, root.query, root.id).Scan(&expected))
				actual := metadataPhysicalRootState(t, ctx, tx, root.typ, root.id, hold)
				require.JSONEq(t, string(expected), string(actual), root.typ)
				require.NoError(t, tx.Rollback(ctx))
			}
		}
	})

	t.Run("committed_ABA_меняет_физическое_свидетельство", func(t *testing.T) {
		before := metadataPhysicalRootParts(t, metadataPhysicalRootState(t, ctx, pool, firstType, objectID, false))
		// Два самостоятельных COMMIT: настоящее A→B→A, без подмены xmin/ctid.
		for _, value := range []string{"temporary", "first"} {
			tag, err := pool.Exec(ctx, `UPDATE kaname.resource_mirror SET labels=jsonb_build_object('team',$3::text)
 WHERE object_type=$1 AND object_id=$2`, firstType, objectID, value)
			require.NoError(t, err)
			require.EqualValues(t, 1, tag.RowsAffected())
		}
		after := metadataPhysicalRootParts(t, metadataPhysicalRootState(t, ctx, pool, firstType, objectID, false))
		require.JSONEq(t, string(before[2]), string(after[2]), "полный raw OLD восстановлен, включая producer watermark")
		require.NotEqual(t, string(before[0]), string(after[0]), "коммит создал другую физическую версию")
		// ctid вправе переиспользоваться; смена xmin уже различает полный triple.
	})

	t.Run("rollback_сохраняет_свидетельство", func(t *testing.T) {
		before := metadataPhysicalRootState(t, ctx, pool, firstType, objectID, false)
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, `UPDATE kaname.resource_mirror SET labels='{"team":"rolled-back"}'
 WHERE object_type=$1 AND object_id=$2`, firstType, objectID)
		require.NoError(t, err)
		require.NotEqual(t, string(before), string(metadataPhysicalRootState(t, ctx, tx, firstType, objectID, false)))
		require.NoError(t, tx.Rollback(ctx))
		require.JSONEq(t, string(before), string(metadataPhysicalRootState(t, ctx, pool, firstType, objectID, false)))
	})

	t.Run("hold_удерживает_только_точную_строку", func(t *testing.T) {
		holder, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = holder.Rollback(ctx) }()
		metadataPhysicalRootState(t, ctx, holder, firstType, objectID, true)
		contender, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = contender.Rollback(ctx) }()
		var id string
		require.NoError(t, contender.QueryRow(ctx, `SELECT object_id FROM kaname.resource_mirror
 WHERE object_type=$1 AND object_id=$2 FOR UPDATE NOWAIT`, secondType, objectID).Scan(&id))
		require.Equal(t, objectID, id)
		err = contender.QueryRow(ctx, `SELECT object_id FROM kaname.resource_mirror
 WHERE object_type=$1 AND object_id=$2 FOR UPDATE NOWAIT`, firstType, objectID).Scan(&id)
		var blocked *pgconn.PgError
		require.ErrorAs(t, err, &blocked)
		require.Equal(t, "55P03", blocked.Code)
	})

	t.Run("owner_census_подтверждает_область_без_привязок", func(t *testing.T) {
		const query = `SELECT kaname._authority_metadata_access_label_carrier_census_v1(
			$1,$2::jsonb,'{"team":"new"}'::jsonb,$3,$4,100)`
		before := metadataPhysicalRootParts(t, metadataPhysicalRootState(t, ctx, pool, firstType, objectID, false))
		read := func() map[string]json.RawMessage {
			t.Helper()
			var raw json.RawMessage
			require.NoError(t, pool.QueryRow(ctx, query, firstType, before[2], 100, 10).Scan(&raw))
			var census map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(raw, &census))
			return census
		}
		census := read()
		require.JSONEq(t, `[]`, string(census["binding_ids"]))
		require.JSONEq(t, `2`, string(census["logical_reads"]))
		var sources map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(census["root_scope_states"], &sources))
		for _, key := range []string{"root", "catalog", "account", "project"} {
			metadataPhysicalRootParts(t, sources[key])
		}
		require.JSONEq(t, string(before[2]), string(metadataPhysicalRootParts(t, sources["root"])[2]))

		_, err := pool.Exec(ctx, `UPDATE kaname.projects SET account_id=account_id WHERE id=$1`, tenant.projectID)
		require.NoError(t, err)
		after := read()
		require.JSONEq(t, string(census["binding_ids"]), string(after["binding_ids"]))
		require.NotEqual(t, string(census["root_scope_states"]), string(after["root_scope_states"]))

		for _, check := range []struct {
			typ         string
			rows, reads int
			code        string
		}{
			{secondType, 100, 10, "42501"},
			{firstType, 3, 10, "54000"},
			{firstType, 100, 1, "54000"},
		} {
			_, err := pool.Exec(ctx, query, check.typ, before[2], check.rows, check.reads)
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, check.code, pgErr.Code)
		}
	})

	t.Run("private_ACL_и_нет_допуска_UPDATE", func(t *testing.T) {
		var sealed bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT NOT p.prosecdef AND p.provolatile='v'
 AND p.proowner=(SELECT relowner FROM pg_class WHERE oid='kaname.authority_writer_protocol'::regclass)
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner)
 FROM pg_proc p WHERE p.oid='kaname._authority_metadata_root_state_v1(text,text,boolean)'::regprocedure`).Scan(&sealed))
		require.True(t, sealed, "PUBLIC и любые non-owner default grants закрыты")
		// Роль и даже пробный EXECUTE grant существуют только до ROLLBACK этой TX.
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		role := ids.NewID("mrt")
		quoted := pgx.Identifier{role}.Sanitize()
		_, err = tx.Exec(ctx, `CREATE ROLE `+quoted+` NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT`)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `GRANT USAGE ON SCHEMA kaname TO `+quoted)
		require.NoError(t, err)
		var executable bool
		require.NoError(t, tx.QueryRow(ctx, `SELECT has_function_privilege($1,'kaname._authority_metadata_root_state_v1(text,text,boolean)','EXECUTE')`, role).Scan(&executable))
		require.False(t, executable)
		for _, accidentalGrant := range []bool{false, true} {
			if accidentalGrant {
				_, err = tx.Exec(ctx, `GRANT SELECT ON kaname.authority_writer_protocol TO `+quoted)
				require.NoError(t, err)
				_, err = tx.Exec(ctx, `GRANT EXECUTE ON FUNCTION kaname.authority_protocol_require_owner(),kaname._authority_metadata_root_state_v1(text,text,boolean) TO `+quoted)
				require.NoError(t, err)
			}
			_, err = tx.Exec(ctx, `SAVEPOINT caller_probe`)
			require.NoError(t, err)
			_, err = tx.Exec(ctx, `SET LOCAL ROLE `+quoted)
			require.NoError(t, err)
			_, err = tx.Exec(ctx, `SELECT kaname._authority_metadata_root_state_v1($1,$2,false)`, firstType, objectID)
			var denied *pgconn.PgError
			require.ErrorAs(t, err, &denied)
			require.Equal(t, "42501", denied.Code)
			if accidentalGrant {
				require.Contains(t, denied.Message, "requires migration owner")
			}
			_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT caller_probe`)
			require.NoError(t, err)
		}
		require.NoError(t, tx.Rollback(ctx))

		writer, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = writer.Rollback(ctx) }()
		before := metadataPhysicalRootState(t, ctx, writer, firstType, objectID, true)
		_, err = writer.Exec(ctx, `UPDATE kaname.resource_mirror SET access_labels='{"protected":"forbidden"}'
 WHERE object_type=$1 AND object_id=$2`, firstType, objectID)
		var denied *pgconn.PgError
		require.ErrorAs(t, err, &denied)
		require.Equal(t, "42501", denied.Code)
		require.Contains(t, denied.Message, "requires a protected writer")
		require.NoError(t, writer.Rollback(ctx))
		require.JSONEq(t, string(before), string(metadataPhysicalRootState(t, ctx, pool, firstType, objectID, false)), "owner witness не создаёт write admission")
	})
}
