// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestRoleSelectorMovePendingNativeSourceBeforeRoleDML(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, actor)
	require.NoError(t, err)
	definition := seedAccessDefinition(t, r, "account", r.a, "pending_native")
	seedMetadataActualApplySource(t, r, actor, definition.id)

	// У исходной и изменяемой ролей одинаковое право apply. Действующая
	// привязка актору принадлежит только исходной роли.
	applyRules := domain.Rules{accessRoleApply(definition.id)}
	sourceRules, err := domain.EncodeRules(applyRules)
	require.NoError(t, err)
	var sourceID, bindingID, fingerprint string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT r.id,b.id,p.rule_fp FROM kaname.roles r
		JOIN kaname.access_bindings b ON b.role_id=r.id
		JOIN kaname.authority_role_access_label_rule p ON p.role_id=r.id
		WHERE p.definition_id=$1::uuid AND r.account_id=$2 AND b.subject_id=$3`,
		definition.id, r.a, actor).Scan(&sourceID, &bindingID, &fingerprint))
	ordinary, _, err := domain.SplitGrantCapabilityRules(applyRules)
	require.NoError(t, err)
	permissions, err := domain.CompileRules(ordinary)
	require.NoError(t, err)
	projection, err := r.bundle.Projection(domain.Role{ID: domain.RoleID(sourceID), AccountID: domain.AccountID(r.a),
		Rules: applyRules, Permissions: permissions})
	require.NoError(t, err)
	checkpoint, err := json.Marshal(projection.Checkpoint)
	require.NoError(t, err)

	id := ids.NewID("rol")
	seed, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, seed)
	var version string
	var physical, nextRules json.RawMessage
	require.NoError(t, seed.QueryRow(r.ctx, `INSERT INTO kaname.roles AS r(id,account_id,name,permissions,rules,labels)
		VALUES ($1,$2,'pending_native_target','[]',
			'[{"module":"iam","resources":["project"],"verbs":["list"],"match_labels":{"team":"blue"}}]'::jsonb || $3::jsonb,'{}')
		RETURNING xmin::text,jsonb_build_array(xmin::text,ctid::text,to_jsonb(r)),
			'[{"module":"iam","resources":["project"],"verbs":["list"],"match_access_labels":{"team":"blue"}}]'::jsonb || $3::jsonb`,
		id, r.a, sourceRules).Scan(&version, &physical, &nextRules))
	// Та же owner-фикстура, что у источника. Обе проекции существуют до передачи writer.
	_, err = seed.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule DISABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, accessRoleProjectionInsert, id, fingerprint, definition.id)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule ENABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	require.NoError(t, seed.Commit(r.ctx))
	pool, login, _ := roleActorFiniteLogin(t, r)
	request := map[string]any{
		"create": false, "rules": true, "retier": false, "version": version, "mask": []string{"rules"},
		"role": map[string]any{"id": id, "rules": nextRules, "permissions": []string{}},
	}
	stampInput, err := json.Marshal(request)
	require.NoError(t, err)
	request["_access_label_authority"] = map[string]any{"actor": map[string]string{"type": "user", "id": actor},
		"questions": []map[string]string{{"scope_kind": "account", "scope_id": r.a, "definition_id": definition.id}}}
	preparation, err := json.Marshal(request)
	require.NoError(t, err)
	move, err := json.Marshal(map[string]any{"role_id": id, "version": version, "physical": physical,
		"proposed_rules": nextRules, "copy_candidates": []any{}, "moves": []map[string]int{{"rule_index": 0, "child_index": -1}}})
	require.NoError(t, err)

	// Мост передаёт закрытому producer один точный запрос. Native source читает
	// сам LOGIN через штатный export. Мост только наблюдает его приватную квитанцию.
	var ddl string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT format($ddl$
		CREATE FUNCTION kaname.test_move_pending_native_v1(phase text) RETURNS boolean
		LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $bridge$
		DECLARE req jsonb:=%1$L::jsonb; move_input jsonb:=%2$L::jsonb; p jsonb; satisfied_point boolean;
		BEGIN
			IF session_user::text IS DISTINCT FROM %3$L THEN RAISE EXCEPTION 'unexpected login'; END IF;
			IF phase='prepare' THEN
				PERFORM kaname._authority_role_move_sequence_prepare_v1(req,move_input,req#>'{_access_label_authority,actor}',100000,4096);
				RETURN true;
			END IF;
			p:=kaname._authority_sequence_store_v3();
			IF p#>'{frozen,selector_move,role,physical}' IS DISTINCT FROM move_input->'physical'
				OR p#>'{frozen,selector_move,actor}' IS DISTINCT FROM req#>'{_access_label_authority,actor}'
				OR p#>'{frozen,selector_move,copies,roots}' IS DISTINCT FROM '{}'::jsonb THEN
				RAISE EXCEPTION 'unexpected pending selector move';
			END IF;
			IF phase='finalize' THEN
				PERFORM kaname._authority_role_move_sequence_finalize_v1('[]'::jsonb,100000,4096);
				RETURN true;
			END IF;
			SELECT q.satisfied INTO STRICT satisfied_point FROM pg_temp.kaname_authority_access_label_role_source q
			WHERE q.nonce=(p->>'nonce')::uuid AND q.scope_kind='account' AND q.scope_id=%4$L AND q.definition_id=%5$L::uuid;
			IF phase='pending' OR phase='approve' THEN
				IF p->'selected' IS DISTINCT FROM 'null'::jsonb OR p->'decision_at' IS DISTINCT FROM 'null'::jsonb
					OR p#>'{frozen,selector_move_decision,commands}' IS DISTINCT FROM '[]'::jsonb
					OR jsonb_array_length(p#>'{frozen,selector_move_pending,selected}') IS DISTINCT FROM 1
					OR EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_effects e WHERE e.selected OR e.registered OR e.claimed OR e.consumed) THEN
					RAISE EXCEPTION 'pending proof opened DML';
				END IF;
				IF phase='approve' THEN
					IF satisfied_point IS DISTINCT FROM true THEN RAISE EXCEPTION 'required native source missing'; END IF;
					PERFORM kaname._authority_role_move_sequence_approve_v1();
				END IF;
				RETURN satisfied_point;
			END IF;
			RAISE EXCEPTION 'unknown test phase';
		END $bridge$;
		REVOKE ALL ON FUNCTION kaname.test_move_pending_native_v1(text) FROM PUBLIC;
		GRANT EXECUTE ON FUNCTION kaname.test_move_pending_native_v1(text) TO %3$I;
	$ddl$,$1::text,$2::text,$3::text,$4::text,$5::text)`, string(preparation), string(move), login, r.a, definition.id).Scan(&ddl))
	_, err = r.admin.Exec(r.ctx, ddl)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_move_pending_native_v1(text)`)
		require.NoError(t, err)
	})
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	_, _ = fullContractActivate(t, r)
	tx, err := pool.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	identity := r.bundle.Identity()
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_protocol_enter_typed_v3('global',ARRAY[]::text[],'[]'::jsonb,
		'role',$1,$2,$3,'decision')`, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
	require.NoError(t, err)
	var epoch json.RawMessage
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_binding_epoch_read(NULL::text[])`).Scan(&epoch))
	const lock = `SELECT kaname.authority_role_stage_epoch_lock(NULL::text[],$1::jsonb)`
	phase := func(name string) bool {
		t.Helper()
		var result bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_move_pending_native_v1($1)`, name).Scan(&result))
		return result
	}
	_, err = tx.Exec(r.ctx, lock, epoch)
	require.NoError(t, err)
	require.True(t, phase("prepare"))
	_, err = tx.Exec(r.ctx, lock, epoch)
	require.NoError(t, err)
	require.True(t, phase("finalize"))
	require.False(t, phase("pending"))

	var at, expectedStamp time.Time
	var roleXmin, roleCTID, bindingXmin, bindingCTID string
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT (kaname.authority_protocol_attestation()->>'decision_at')::timestamptz,
		greatest(transaction_timestamp(),target.created_at),s.xmin::text,s.ctid::text,b.xmin::text,b.ctid::text
		FROM ONLY kaname.roles target, ONLY kaname.roles s, ONLY kaname.access_bindings b
		WHERE target.id=$1 AND s.id=$2 AND b.id=$3 AND b.role_id=s.id`, id, sourceID, bindingID).
		Scan(&at, &expectedStamp, &roleXmin, &roleCTID, &bindingXmin, &bindingCTID))
	var raw json.RawMessage
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_role_access_label_source_read_v1`+accessLabelRoleNativeSourceArgs,
		id, "user", actor, at, bindingID, bindingXmin, bindingCTID, sourceID, roleXmin, roleCTID,
		"user", actor, "account", r.a, definition.id, fingerprint, checkpoint, 100000, 4096).Scan(&raw))
	var verdict accessLabelSourceResult
	require.NoError(t, json.Unmarshal(raw, &verdict))
	require.True(t, verdict.Allowed)
	require.GreaterOrEqual(t, verdict.Rows, kaname.AccessLabelSourceMinimumRows)
	require.Equal(t, kaname.AccessLabelSourceReads, verdict.Reads)
	require.True(t, phase("pending"))

	attemptWrite := func() error {
		t.Helper()
		attempt, err := tx.Begin(r.ctx)
		require.NoError(t, err)
		_, failure := attempt.Exec(r.ctx, `UPDATE ONLY kaname.roles SET rules=$2::jsonb, updated_at=$3 WHERE id=$1 AND xmin::text=$4`,
			id, nextRules, expectedStamp, version)
		requireAccessDefinitionSQLState(t, failure, "42501")
		require.NoError(t, attempt.Rollback(r.ctx))
		return failure
	}
	attemptWrite()
	require.True(t, phase("approve"))
	var stamp time.Time
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_role_sequence_stamp_v3($1::jsonb)`, stampInput).Scan(&stamp))
	require.True(t, stamp.Equal(expectedStamp))
	// Одна положительная native-точка и move approve не заменяют полный
	// RequireRole. Оставляем его невыполненным и проверяем точную причину отказа.
	require.ErrorContains(t, attemptWrite(), "role access label independent method result is absent")
	requireAccessDefinitionSQLState(t, tx.Commit(r.ctx), "42501")
	var unchanged bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r))=$2::jsonb
		AND NOT EXISTS(SELECT FROM kaname.resource_journal WHERE resource_kind='iam_role' AND resource_id=r.id AND event_type='UPDATED')
		FROM ONLY kaname.roles r WHERE r.id=$1`, id, physical).Scan(&unchanged))
	require.True(t, unchanged)
}
