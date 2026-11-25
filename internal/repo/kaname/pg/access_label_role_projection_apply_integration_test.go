// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Наблюдатели проверяют только подготовленное определение и вопрос.
// Запись проекции проходит через штатный триггер ролей.
func accessLabelRoleQuestionObservers(t *testing.T, r protocolRig) {
	t.Helper()
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_access_label_prepared_definition_v1(p_scope text,p_definition uuid,p_reads integer)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $observer$
 SELECT kaname.authority_access_label_prepared_definition_v1('account',p_scope,p_definition,2,p_reads)
$observer$;
REVOKE ALL ON FUNCTION kaname.test_access_label_prepared_definition_v1(text,uuid,integer) FROM PUBLIC;
CREATE FUNCTION kaname.test_access_label_role_question_v1(p_actor text,p_scope text,p_definition uuid)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $observer$
 SELECT kaname.authority_access_label_role_question_require_v1('user',p_actor,'account',p_scope,p_definition,2,2)
$observer$;
REVOKE ALL ON FUNCTION kaname.test_access_label_role_question_v1(text,text,uuid) FROM PUBLIC`)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_access_label_prepared_definition_v1(text,uuid,integer);
 DROP FUNCTION kaname.test_access_label_role_question_v1(text,text,uuid)`)
		require.NoError(t, err)
	})
	_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.test_access_label_prepared_definition_v1(text,uuid,integer), kaname.test_access_label_role_question_v1(text,text,uuid) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
}

func TestAccessLabelProjectionApplyRefusesWithoutTrustedContent(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	role := seedAccountRole(t, r.ctx, r.admin, domain.AccountID(r.a), "projection_apply_source")
	definition := seedAccessDefinition(t, r, "account", r.a, "projection_apply")
	unreferenced := seedAccessDefinition(t, r, "account", r.a, "projection_apply_unreferenced")
	var actor, otherActor string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&actor))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.b).Scan(&otherActor))
	rules := domain.Rules{accessRoleApply(definition.id)}
	encoded, err := domain.EncodeRules(rules)
	require.NoError(t, err)
	accessLabelRoleQuestionObservers(t, r)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	_, _ = fullContractActivate(t, r)

	var before json.RawMessage
	var journalBefore int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(r),
	 (SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='iam_role' AND resource_id=$1)
	 FROM kaname.roles r WHERE id=$1`, role).Scan(&before, &journalBefore))
	input, err := json.Marshal(map[string]any{
		"create": false, "rules": true, "retier": false, "mask": []string{"rules"}, "version": "",
		"role": map[string]any{"id": string(role), "rules": json.RawMessage(encoded), "permissions": []string{}},
	})
	require.NoError(t, err)
	// Envelope нужен только prepare; original input идёт в exact DML stamp.
	var preparation map[string]any
	require.NoError(t, json.Unmarshal(input, &preparation))
	preparation["_access_label_authority"] = map[string]any{
		"actor": map[string]string{"type": "user", "id": actor},
		"questions": []map[string]string{
			{"scope_kind": "account", "scope_id": r.a, "definition_id": definition.id},
			// Объявленный foreign-scope вопрос не должен стать применимым.
			{"scope_kind": "account", "scope_id": r.b, "definition_id": definition.id},
		},
	}
	prepareInput, err := json.Marshal(preparation)
	require.NoError(t, err)
	for _, completion := range []string{"rollback", "closed-commit"} {
		t.Run(completion, func(t *testing.T) {
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			identity := r.bundle.Identity()
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_protocol_enter_typed_v3('accounts',ARRAY[$1::text],
			 jsonb_build_array(jsonb_build_object('kind','account','id',$1::text)),
			 'role',$2,$3,$4,'decision')`, r.a, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
			require.NoError(t, err)
			var epochs json.RawMessage
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_binding_epoch_read($1::text[])`, []string{r.a}).Scan(&epochs))
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_stage_epoch_lock($1::text[],$2::jsonb)`, []string{r.a}, epochs)
			require.NoError(t, err)
			var census json.RawMessage
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_role_sequence_prepare_v3($1::jsonb,100000,4096)`, prepareInput).Scan(&census))
			const readDefinition = `SELECT kaname.test_access_label_prepared_definition_v1($1,$2::uuid,$3)`
			early, err := tx.Begin(r.ctx)
			require.NoError(t, err)
			var custody json.RawMessage
			err = early.QueryRow(r.ctx, readDefinition, r.a, definition.id, 3).Scan(&custody)
			requireAccessDefinitionSQLState(t, err, "42501")
			require.NoError(t, early.Rollback(r.ctx))
			// Тот же второй recheck, что у prepared writer: final attestation
			// позже подготовки программы, затем штатный выбор exact effects.
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_stage_epoch_lock($1::text[],$2::jsonb)`, []string{r.a}, epochs)
			require.NoError(t, err)
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_sequence_finalize_v3()`)
			require.NoError(t, err)
			const readQuestion = `SELECT kaname.test_access_label_role_question_v1($1,$2,$3::uuid)`
			var questionRaw json.RawMessage
			require.NoError(t, tx.QueryRow(r.ctx, readQuestion, actor, r.a, definition.id).Scan(&questionRaw))
			var questionReceipt struct {
				DecisionAt time.Time `json:"decision_at"`
				Rows       int       `json:"rows"`
				Reads      int       `json:"reads"`
			}
			require.NoError(t, json.Unmarshal(questionRaw, &questionReceipt))
			require.False(t, questionReceipt.DecisionAt.IsZero())
			require.Equal(t, 2, questionReceipt.Rows)
			require.Equal(t, 2, questionReceipt.Reads)
			for _, question := range []struct{ name, actor, scope, definition string }{
				{"wrong-actor", otherActor, r.a, definition.id},
				{"undeclared-definition", actor, r.a, unreferenced.id},
				{"declared-but-inapplicable-scope", actor, r.b, definition.id},
			} {
				attempt, err := tx.Begin(r.ctx)
				require.NoError(t, err)
				err = attempt.QueryRow(r.ctx, readQuestion, question.actor, question.scope, question.definition).Scan(&questionRaw)
				requireAccessDefinitionSQLState(t, err, "42501")
				require.NoError(t, attempt.Rollback(r.ctx), question.name)
			}
			for _, candidate := range []struct {
				name, scope, definition string
				matched                 bool
				rows, reads             int
			}{
				{"точное определение", r.a, definition.id, true, 2, 3},
				{"другая область", r.b, definition.id, false, 1, 2},
				{"отсутствует в правилах", r.a, unreferenced.id, false, 1, 2},
			} {
				require.NoError(t, tx.QueryRow(r.ctx, readDefinition, candidate.scope, candidate.definition, 3).Scan(&custody), candidate.name)
				var got struct {
					Matched    bool       `json:"matched"`
					DecisionAt *time.Time `json:"decision_at"`
					Rows       int        `json:"rows"`
					Reads      int        `json:"reads"`
				}
				require.NoError(t, json.Unmarshal(custody, &got))
				require.Equal(t, candidate.matched, got.Matched, candidate.name)
				require.Equal(t, candidate.matched, got.DecisionAt != nil, candidate.name)
				require.Equal(t, candidate.rows, got.Rows, candidate.name)
				require.Equal(t, candidate.reads, got.Reads, candidate.name)
			}
			shortBudget, err := tx.Begin(r.ctx)
			require.NoError(t, err)
			err = shortBudget.QueryRow(r.ctx, readDefinition, r.a, definition.id, 2).Scan(&custody)
			requireAccessDefinitionSQLState(t, err, "54000")
			require.NoError(t, shortBudget.Rollback(r.ctx))
			var stamp time.Time
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_role_sequence_stamp_v3($1::jsonb)`, input).Scan(&stamp))
			// Без подтверждения доверенным writer штатный триггер
			// отклоняет строку вместе с проекцией и журналом.
			write, err := tx.Begin(r.ctx)
			require.NoError(t, err)
			_, err = write.Exec(r.ctx, `UPDATE kaname.roles SET rules=$2::jsonb,permissions='[]'::jsonb,
			 updated_at=$3 WHERE id=$1`, role, encoded, stamp)
			var refusal *pgconn.PgError
			require.ErrorAs(t, err, &refusal)
			require.Equal(t, "42501", refusal.Code)
			require.Equal(t, "role access label independent method result is absent", refusal.Message)
			require.NoError(t, write.Rollback(r.ctx))
			if completion == "rollback" {
				require.NoError(t, tx.Rollback(r.ctx))
			} else {
				err = tx.Commit(r.ctx)
				var refusal *pgconn.PgError
				require.ErrorAs(t, err, &refusal)
				require.Equal(t, "42501", refusal.Code)
				require.Equal(t, "selected sequence program is incomplete", refusal.Message)
			}
			var after json.RawMessage
			var projectionCount, journalAfter int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(r),
			 (SELECT count(*) FROM kaname.authority_role_access_label_rule WHERE role_id=$1),
			 (SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='iam_role' AND resource_id=$1)
			 FROM kaname.roles r WHERE id=$1`, role).Scan(&after, &projectionCount, &journalAfter))
			require.JSONEq(t, string(before), string(after))
			require.Zero(t, projectionCount)
			require.Equal(t, journalBefore, journalAfter, "роль, private projection и journal откатываются вместе")
		})
	}
}

func TestAccessLabelProjectionApplyAndTableRemainPrivate(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	_, err := r.runtime.Exec(r.ctx, `SELECT kaname.authority_access_label_prepared_definition_v1(
	 'account',$1,'a59a06ea-fe06-4d49-819a-7517e59a182b'::uuid,2,3)`, r.a)
	requireAccessDefinitionSQLState(t, err, "42501")
	_, err = r.runtime.Exec(r.ctx, `SELECT kaname.authority_access_label_role_question_require_v1(
	 'user','usr_absent','account',$1,'a59a06ea-fe06-4d49-819a-7517e59a182b'::uuid,2,2)`, r.a)
	requireAccessDefinitionSQLState(t, err, "42501")
	_, err = r.runtime.Exec(r.ctx, `SELECT kaname.authority_access_label_role_questions_prepare_v1('{}'::jsonb,'{}'::jsonb,2,2)`)
	requireAccessDefinitionSQLState(t, err, "42501")
	const apply = `SELECT kaname.authority_access_label_role_projection_apply_v1('{}'::jsonb,NULL,NULL)`
	_, err = r.runtime.Exec(r.ctx, apply)
	requireAccessDefinitionSQLState(t, err, "42501")
	_, err = r.admin.Exec(r.ctx, apply)
	requireAccessDefinitionSQLState(t, err, "42501")
	const emptyInsert = `INSERT INTO kaname.authority_role_access_label_rule(role_id,rule_fp,definition_id)
	 SELECT 'absent-role',repeat('0',64),'00000000-0000-0000-0000-000000000001'::uuid WHERE false`
	_, err = r.runtime.Exec(r.ctx, emptyInsert)
	requireAccessDefinitionSQLState(t, err, "42501")
	_, err = r.admin.Exec(r.ctx, emptyInsert)
	requireAccessDefinitionSQLState(t, err, "42501")
	var allowed bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_table_privilege(current_user,
	 'kaname.authority_role_access_label_rule','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')`).Scan(&allowed))
	require.False(t, allowed)
}
