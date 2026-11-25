// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

func TestRoleSelectorMoveSequenceMigrationRoundTrip(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	db := stdlib.OpenDB(*r.admin.Config().ConnConfig)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	latest, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	const version = int64(20261126210000)
	require.GreaterOrEqual(t, latest, version)
	t.Cleanup(func() { require.NoError(t, goose.UpTo(db, ".", latest)) })
	require.NoError(t, goose.DownTo(db, ".", version))

	changed := []string{
		"authority_role_sequence_prepare_v3(jsonb,integer,integer)", "authority_role_sequence_finalize_v3()",
		"authority_role_sequence_stamp_v3(jsonb)", "_authority_sequence_complete_v3()",
		"_authority_crud_storage_v3()", "_authority_full_contract_storage_v3()",
		"authority_metadata_service_account_access_label_ready_v1()",
	}
	private := []string{
		"_authority_role_move_root_journal_v1(jsonb,integer)",
		"_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)",
		"_authority_role_move_sequence_publish_v1(jsonb,integer,integer)",
		"_authority_role_move_sequence_approve_v1()",
		"_authority_role_move_sequence_prepare_v1(jsonb,jsonb,jsonb,integer,integer)",
		"_authority_role_move_sequence_finalize_v1(jsonb,integer,integer)",
	}
	inspect := func() (string, []string) {
		t.Helper()
		var valid bool
		var metadata string
		var hashes []string
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3(),
			jsonb_agg(jsonb_build_array(p.oid,p.proowner,p.proacl,p.prosecdef,p.proconfig) ORDER BY s.pos)::text,
			array_agg(encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') ORDER BY s.pos)
			FROM unnest($1::text[]) WITH ORDINALITY s(sig,pos)
			JOIN pg_proc p ON p.oid=to_regprocedure('kaname.'||s.sig)`, changed).Scan(&valid, &metadata, &hashes))
		require.True(t, valid)
		require.Len(t, hashes, len(changed))
		return metadata, hashes
	}
	privateCount := func() int {
		t.Helper()
		var count, granted int
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*),count(*) FILTER (WHERE EXISTS (
			SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner))
			FROM unnest($1::text[]) sig JOIN pg_proc p ON p.oid=to_regprocedure('kaname.'||sig)`, private).Scan(&count, &granted))
		require.Zero(t, granted)
		return count
	}
	metadata, installed := inspect()
	require.Equal(t, len(private), privateCount())
	require.NoError(t, goose.Down(db, "."))
	priorVersion, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, int64(20261126200000), priorVersion)
	oldMetadata, prior := inspect()
	require.Equal(t, metadata, oldMetadata)
	require.Zero(t, privateCount())
	for i, sig := range changed {
		require.NotEqual(t, installed[i], prior[i], sig)
	}
	require.Equal(t, "0890abdfa2517000901077218dde1cbe48b465003ce4c8e5e74559a2ebaa167e", prior[0])
	require.Equal(t, "0adfc241154b42e561425452f8ceef42eeefa3e802a21111e9e74d5a434830cd", prior[1])
	require.NoError(t, goose.UpTo(db, ".", version))
	reinstalledMetadata, reinstalled := inspect()
	require.Equal(t, metadata, reinstalledMetadata)
	require.Equal(t, installed, reinstalled)
	require.Equal(t, len(private), privateCount())
}

func TestRoleSelectorMoveSequenceEmptyCopiesAndOrdinaryUpdate(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	id := ids.NewID("rol")
	const oldRules = `[{"module":"iam","resources":["project"],"verbs":["list"],"match_labels":{"team":"blue"},"resource_names":null}]`
	const newRules = `[{"module":"iam","resources":["project"],"verbs":["list"],"match_access_labels":{"team":"blue"}}]`
	var version, user string
	var physical json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.roles AS r
		(id,account_id,name,description,permissions,rules,labels)
		VALUES ($1,$2,'move_sequence_probe','before','[]',$3,'{}') RETURNING xmin::text,
		jsonb_build_array(xmin::text,ctid::text,to_jsonb(r))`, id, r.a, oldRules).Scan(&version, &physical))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&user))
	pool, login, _ := roleActorFiniteLogin(t, r)
	actor := map[string]string{"type": "user", "id": user}
	request := map[string]any{
		"create": false, "rules": true, "retier": false, "version": version, "mask": []string{"rules"},
		"role": map[string]any{"id": id, "rules": json.RawMessage(newRules), "permissions": []string{}},
	}
	stampRequest, err := json.Marshal(request)
	require.NoError(t, err)
	request["_access_label_authority"] = map[string]any{"actor": actor, "questions": []string{}}
	preparation, err := json.Marshal(request)
	require.NoError(t, err)
	move, err := json.Marshal(map[string]any{"role_id": id, "version": version, "physical": physical,
		"proposed_rules": json.RawMessage(newRules), "copy_candidates": []any{},
		"moves": []map[string]int{{"rule_index": 0, "child_index": -1}}})
	require.NoError(t, err)

	// Все полномочия тестового моста привязаны к одному OLD, актору и пустому набору копий.
	// Аргумент LOGIN выбирает фазу. SQL литералы формирует PostgreSQL через format(%L).
	var ddl string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT format($ddl$
		CREATE FUNCTION kaname.test_role_move_sequence_v1(phase text) RETURNS jsonb
		LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $bridge$
		DECLARE p jsonb; chosen jsonb; old_row jsonb:=%2$L::jsonb#>'{physical,2}';
		BEGIN
			IF session_user::text IS DISTINCT FROM %3$L THEN
				RAISE EXCEPTION 'unexpected move probe login' USING ERRCODE='42501';
			END IF;
			IF phase='stage_minimum_budget' THEN
				RETURN kaname._authority_role_move_stage_tuple_census_v1(true,1,5);
			END IF;
			IF phase IN ('prepare','prepare_retier') THEN
				RETURN kaname._authority_role_move_sequence_prepare_v1(
					jsonb_set(%1$L::jsonb,'{retier}',to_jsonb(phase='prepare_retier')),%2$L::jsonb,
					%1$L::jsonb#>'{_access_label_authority,actor}',100000,4096);
			END IF;
			p:=kaname._authority_sequence_store_v3();
			IF p#>'{frozen,selector_move,role,physical}' IS DISTINCT FROM %2$L::jsonb->'physical'
				OR p#>'{frozen,selector_move,actor}' IS DISTINCT FROM %1$L::jsonb#>'{_access_label_authority,actor}'
				OR p#>'{frozen,selector_move,copies,roots}' IS DISTINCT FROM '{}'::jsonb THEN
				RAISE EXCEPTION 'unexpected move probe program';
			END IF;
			IF phase='finalize' THEN
				PERFORM kaname._authority_role_move_sequence_finalize_v1('[]'::jsonb,100000,4096);
				p:=kaname._authority_sequence_store_v3();
				chosen:=p#>'{frozen,selector_move_pending,selected,0}';
				IF p->'selected' IS DISTINCT FROM 'null'::jsonb
					OR p#>'{frozen,selector_move_pending,unselected}' IS DISTINCT FROM '[]'::jsonb
					OR jsonb_array_length(p#>'{frozen,selector_move_pending,selected}') IS DISTINCT FROM 1
					OR EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_effects e
						WHERE e.selected OR e.registered OR e.claimed OR e.consumed)
					OR p#>'{frozen,selector_move_decision,commands}' IS DISTINCT FROM '[]'::jsonb
					OR (p->'frozen') ? 'selector_move_approved'
					OR chosen->'reserved_id' IS DISTINCT FROM p#>'{maximum,0,reserved_id}'
					OR chosen->>'table' IS DISTINCT FROM 'resource_journal'
					OR chosen->'origin' IS DISTINCT FROM jsonb_build_object(
						'table','roles','operation','UPDATE','when','AFTER','old',old_row,
						'new',old_row||jsonb_build_object('rules',%2$L::jsonb->'proposed_rules','updated_at',p#>'{frozen,stamp}')) THEN
					RAISE EXCEPTION 'mixed selection differs from reserved role image';
				END IF;
				RETURN chosen->'reserved_id';
			ELSIF phase='approve' THEN
				chosen:=p#>'{frozen,selector_move_pending,selected}';
				PERFORM kaname._authority_role_move_sequence_approve_v1();
				p:=kaname._authority_sequence_store_v3();
				IF p->'selected' IS DISTINCT FROM chosen OR (p->'frozen') ? 'selector_move_pending'
					OR (SELECT count(*) FROM pg_temp.kaname_authority_sequence_effects e WHERE e.selected)<>1 THEN
					RAISE EXCEPTION 'Нарушена публикация зарезервированного эффекта после одобрения';
				END IF;
				RETURN NULL;
			END IF;
			RAISE EXCEPTION 'unknown move probe phase';
		END;
		$bridge$;
		REVOKE ALL ON FUNCTION kaname.test_role_move_sequence_v1(text) FROM PUBLIC;
		GRANT EXECUTE ON FUNCTION kaname.test_role_move_sequence_v1(text) TO %3$I;
	$ddl$,$1::text,$2::text,$3::text)`, string(preparation), string(move), login).Scan(&ddl))
	_, err = r.admin.Exec(r.ctx, ddl)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_role_move_sequence_v1(text)`)
		require.NoError(t, err)
	})
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	_, _ = fullContractActivate(t, r)
	identity := r.bundle.Identity()
	var epoch json.RawMessage
	conn, err := pool.Acquire(r.ctx)
	require.NoError(t, err)
	t.Cleanup(conn.Release)
	begin := func(t *testing.T) pgx.Tx {
		t.Helper()
		tx, err := conn.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		_, err = tx.Exec(r.ctx, `SELECT kaname.authority_protocol_enter_typed_v3('global',ARRAY[]::text[],'[]'::jsonb,
			'role',$1,$2,$3,'decision')`, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
		require.NoError(t, err)
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_binding_epoch_read(NULL::text[])`).Scan(&epoch))
		_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_stage_epoch_lock(NULL::text[],$1::jsonb)`, epoch)
		require.NoError(t, err)
		return tx
	}
	const phase = `SELECT kaname.test_role_move_sequence_v1($1)`
	t.Run("перепись_кортежей_пустой_роли", func(t *testing.T) {
		// Стадия RR и защищённая подготовка RC используют один backend.
		rr, err := conn.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		require.NoError(t, err)
		lifecycleRollback(t, rr)
		_, err = rr.Exec(r.ctx, `CREATE TEMP TABLE kaname_role_stage_tuples(binding_id text NOT NULL,
			side text NOT NULL,object text NOT NULL,fga_user text NOT NULL,relation text NOT NULL,
			PRIMARY KEY(binding_id,side,object,fga_user,relation)) ON COMMIT PRESERVE ROWS`)
		require.NoError(t, err)
		require.NoError(t, rr.Commit(r.ctx))

		t.Run("прямое_право_владельца_обязательно", func(t *testing.T) {
			missing := begin(t)
			_, err := missing.Exec(r.ctx, phase, "stage_minimum_budget")
			requireAccessDefinitionSQLState(t, err, "42501")
			require.ErrorContains(t, err, "lacks exact owner read grant")
			require.NoError(t, missing.Rollback(r.ctx))
		})
		t.Run("посторонний_LOGIN_отклоняется", func(t *testing.T) {
			extraACL, err := conn.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
			require.NoError(t, err)
			lifecycleRollback(t, extraACL)
			var ordinary bool
			require.NoError(t, extraACL.QueryRow(r.ctx, `SELECT rolcanlogin AND NOT rolsuper
				FROM pg_catalog.pg_roles WHERE rolname=$1`, r.role).Scan(&ordinary))
			require.True(t, ordinary)
			_, err = extraACL.Exec(r.ctx, "GRANT SELECT ON TABLE pg_temp.kaname_role_stage_tuples TO "+pgx.Identifier{r.role}.Sanitize())
			require.NoError(t, err)
			var extraRead bool
			require.NoError(t, extraACL.QueryRow(r.ctx, `SELECT pg_catalog.has_table_privilege(
				$1::name,'pg_temp.kaname_role_stage_tuples'::regclass,'SELECT')`, r.role).Scan(&extraRead))
			require.True(t, extraRead)
			_, err = extraACL.Exec(r.ctx, kanamepg.RoleMoveStageTupleGrantSQL)
			requireAccessDefinitionSQLState(t, err, "42501")
			require.ErrorContains(t, err, "read grant differs")
			require.NoError(t, extraACL.Rollback(r.ctx))
		})
		rr, err = conn.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		require.NoError(t, err)
		lifecycleRollback(t, rr)
		_, err = rr.Exec(r.ctx, kanamepg.RoleMoveStageTupleGrantSQL)
		require.NoError(t, err)
		var directOwnerRead, sharedCanRead bool
		require.NoError(t, rr.QueryRow(r.ctx, `SELECT EXISTS(SELECT FROM pg_catalog.aclexplode(c.relacl) a
			WHERE a.grantee=root.relowner AND a.grantor=c.relowner AND a.privilege_type='SELECT' AND NOT a.is_grantable),
			pg_catalog.has_table_privilege($1::name,c.oid,'SELECT')
			FROM pg_catalog.pg_class c,pg_catalog.pg_class root
			WHERE c.oid='pg_temp.kaname_role_stage_tuples'::regclass
			AND root.oid='kaname.authority_writer_protocol'::regclass`, r.role).Scan(&directOwnerRead, &sharedCanRead))
		require.True(t, directOwnerRead)
		require.False(t, sharedCanRead)
		require.NoError(t, rr.Commit(r.ctx))

		t.Run("пустой_набор_проходит", func(t *testing.T) {
			control := begin(t)
			var receipt json.RawMessage
			require.NoError(t, control.QueryRow(r.ctx, phase, "stage_minimum_budget").Scan(&receipt))
			require.JSONEq(t, `{"rows":1,"reads":5,"counts":{},"tuples":0}`, string(receipt))
			_, err := control.Exec(r.ctx, phase, "prepare_retier")
			require.NoError(t, err)
			require.NoError(t, control.Rollback(r.ctx))
		})

		rr, err = conn.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		require.NoError(t, err)
		lifecycleRollback(t, rr)
		_, err = rr.Exec(r.ctx, `INSERT INTO pg_temp.kaname_role_stage_tuples
			VALUES ('outside-role','old','iam_project:outside','user:outside','viewer')`)
		require.NoError(t, err)
		require.NoError(t, rr.Commit(r.ctx))
		t.Run("лишняя_строка_превышает_бюджет", func(t *testing.T) {
			over := begin(t)
			_, err := over.Exec(r.ctx, phase, "stage_minimum_budget")
			requireAccessDefinitionSQLState(t, err, "54000")
			require.ErrorContains(t, err, "stage exceeds budget")
			require.NoError(t, over.Rollback(r.ctx))
		})
		t.Run("чужая_привязка_отклоняется", func(t *testing.T) {
			extra := begin(t)
			_, err := extra.Exec(r.ctx, phase, "prepare_retier")
			requireAccessDefinitionSQLState(t, err, "P1034")
			require.ErrorContains(t, err, "outside the role compiler")
			require.NoError(t, extra.Rollback(r.ctx))
		})

		_, err = conn.Exec(r.ctx, `ALTER TABLE pg_temp.kaname_role_stage_tuples ADD COLUMN extra text`)
		require.NoError(t, err)
		t.Run("изменённая_таблица_отклоняется", func(t *testing.T) {
			shape := begin(t)
			_, err := shape.Exec(r.ctx, phase, "prepare_retier")
			requireAccessDefinitionSQLState(t, err, "P1034")
			require.ErrorContains(t, err, "stage shape changed")
			require.NoError(t, shape.Rollback(r.ctx))
		})
		_, err = conn.Exec(r.ctx, `DROP TABLE pg_temp.kaname_role_stage_tuples`)
		require.NoError(t, err)
	})
	tx := begin(t)
	_, err = tx.Exec(r.ctx, phase, "prepare")
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_stage_epoch_lock(NULL::text[],$1::jsonb)`, epoch)
	require.NoError(t, err)
	rejected := func(query string, args ...any) {
		t.Helper()
		attempt, err := tx.Begin(r.ctx)
		require.NoError(t, err)
		_, err = attempt.Exec(r.ctx, query, args...)
		requireAccessDefinitionSQLState(t, err, "42501")
		require.NoError(t, attempt.Rollback(r.ctx))
	}
	rejected(`SELECT kaname.authority_role_sequence_finalize_v3()`)
	rejected(phase, "approve")
	var reserved int64
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_role_move_sequence_v1('finalize')::bigint`).Scan(&reserved))
	require.Positive(t, reserved)
	const stampSQL = `SELECT kaname.authority_role_sequence_stamp_v3($1::jsonb)`
	rejected(stampSQL, stampRequest)
	rejected(`SET CONSTRAINTS ALL IMMEDIATE`)
	_, err = tx.Exec(r.ctx, phase, "approve")
	require.NoError(t, err)
	rejected(phase, "approve")
	var stamp time.Time
	require.NoError(t, tx.QueryRow(r.ctx, stampSQL, stampRequest).Scan(&stamp))
	tag, err := tx.Exec(r.ctx, `UPDATE ONLY kaname.roles SET rules=$2::jsonb,updated_at=$3 WHERE id=$1 AND xmin::text=$4`,
		id, newRules, stamp, version)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	require.NoError(t, tx.Commit(r.ctx))
	var exactRole, exactJournal bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(r)=(($2::jsonb->2)||
		jsonb_build_object('rules',$3::jsonb,'updated_at',$4::timestamptz)),
		(SELECT count(*)=1 AND bool_and(sequence_no=$5 AND project_id='' AND
			scope=jsonb_build_array(jsonb_build_object('type','account','id',r.account_id)) AND
			payload=jsonb_build_object('id',r.id)) FROM kaname.resource_journal
			WHERE resource_kind='iam_role' AND resource_id=r.id AND event_type='UPDATED')
		FROM ONLY kaname.roles r WHERE id=$1`, id, physical, newRules, stamp, reserved).Scan(&exactRole, &exactJournal))
	require.True(t, exactRole)
	require.True(t, exactJournal)

	// Та же enrolled LOGIN снова проходит обычный цикл без private approve.
	tx = begin(t)
	ordinary, err := json.Marshal(map[string]any{
		"create": false, "rules": false, "retier": false, "mask": []string{"description"}, "version": "",
		"role": map[string]string{"id": id, "description": "after"},
	})
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_sequence_prepare_v3($1,100000,4096)`, ordinary)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_stage_epoch_lock(NULL::text[],$1::jsonb)`, epoch)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_sequence_finalize_v3()`)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(r.ctx, stampSQL, ordinary).Scan(&stamp))
	tag, err = tx.Exec(r.ctx, `UPDATE ONLY kaname.roles SET description='after',updated_at=$2 WHERE id=$1`, id, stamp)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	require.NoError(t, tx.Commit(r.ctx))
	var ordinaryCommitted bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT description='after' AND rules=$2::jsonb
		AND (SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='iam_role'
			AND resource_id=$1 AND event_type='UPDATED')=2 FROM ONLY kaname.roles WHERE id=$1`,
		id, newRules).Scan(&ordinaryCommitted))
	require.True(t, ordinaryCommitted)
}
