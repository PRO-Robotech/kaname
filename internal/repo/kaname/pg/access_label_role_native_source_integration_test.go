// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

const accessLabelRoleNativeSourceSignature = `(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)`
const accessLabelRoleNativeSourceArgs = `($1::text,$2::text,$3::text,$4::timestamptz,
 $5::text,$6::text,$7::text,$8::text,$9::text,$10::text,$11::text,$12::text,
 $13::text,$14::text,$15::uuid,$16::text,$17::jsonb,$18::integer,$19::integer)`

func accessLabelSourceReceiptObserver(t *testing.T, r protocolRig) {
	t.Helper()
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_role_access_label_source_receipt_v1(
 p_scope_id text,p_definition uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $observer$
DECLARE header jsonb;observed boolean;
BEGIN
 header:=kaname._authority_sequence_header_v3();
 SELECT s.satisfied INTO STRICT observed
 FROM pg_temp.kaname_authority_access_label_role_source s
 WHERE s.nonce=(header->>'nonce')::uuid AND s.scope_kind='account'
  AND s.scope_id=p_scope_id AND s.definition_id=p_definition;
 RETURN observed;
END $observer$;
REVOKE ALL ON FUNCTION kaname.test_role_access_label_source_receipt_v1(text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION kaname.test_role_access_label_source_receipt_v1(text,uuid) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_role_access_label_source_receipt_v1(text,uuid)`)
		require.NoError(t, err)
	})
}

func TestRoleAccessLabelNativeSourceUsesExactSignedReceiptAndSourceGeneration(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	definition := seedAccessDefinition(t, r, "account", r.a, "role_native_source")
	undeclared := seedAccessDefinition(t, r, "account", r.a, "role_native_undeclared")
	mutation := seedAccountRole(t, r.ctx, r.admin, domain.AccountID(r.a), "role_native_target")
	var actor, otherActor string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&actor))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.b).Scan(&otherActor))
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, actor)
	require.NoError(t, err)
	rules := domain.Rules{accessRoleApply(definition.id)}
	rawRules, err := domain.EncodeRules(rules)
	require.NoError(t, err)
	_, caps, err := domain.SplitGrantCapabilityRules(rules)
	require.NoError(t, err)
	require.Len(t, caps, 1)
	source := domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)), AccountID: domain.AccountID(r.a), Name: "role_native_source", Rules: rules}
	ordinary, _, err := domain.SplitGrantCapabilityRules(rules)
	require.NoError(t, err)
	source.Permissions, err = domain.CompileRules(ordinary)
	require.NoError(t, err)
	projection, err := r.bundle.Projection(source)
	require.NoError(t, err)
	checkpoint, err := json.Marshal(projection.Checkpoint)
	require.NoError(t, err)
	seed, err := owner.Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = seed.Rollback(context.WithoutCancel(r.ctx)) }()
	_, err = seed.RolesW().Insert(r.ctx, source)
	require.NoError(t, err)
	require.NoError(t, seed.RolesW().ReplaceRuleSelectors(r.ctx, source.ID, projection.Selectors))
	require.NoError(t, seed.RolesW().ReplaceRoleVerbs(r.ctx, source.ID, projection.Verbs))
	binding, err := bindingset.Insert(r.ctx, seed.AccessBindingsW(), domain.AccessBinding{
		ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(actor),
		Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(actor)}},
		RoleID:   source.ID, ResourceType: "account", ResourceID: r.a, Scope: domain.DeriveFromResourceType("account"),
		Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true},
	})
	require.NoError(t, err)
	require.NoError(t, seed.Commit(r.ctx))
	var oldRoleXmin, oldRoleCTID, oldBindingXmin, oldBindingCTID string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT r.xmin::text,r.ctid::text,b.xmin::text,b.ctid::text
 FROM kaname.roles r JOIN kaname.access_bindings b ON b.role_id=r.id WHERE r.id=$1 AND b.id=$2`, source.ID, binding.ID).
		Scan(&oldRoleXmin, &oldRoleCTID, &oldBindingXmin, &oldBindingCTID))
	// Trusted fixture сохраняет complete projection ДО handoff. Старые stamps
	// получены с настоящих строк; metadata update не меняет authored checkpoint.
	privateSeed, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, privateSeed)
	_, err = privateSeed.Exec(r.ctx, `UPDATE kaname.roles SET description='new physical generation' WHERE id=$1`, source.ID)
	require.NoError(t, err)
	_, err = privateSeed.Exec(r.ctx, `UPDATE kaname.access_bindings SET grant_capability_version=1 WHERE id=$1`, binding.ID)
	require.NoError(t, err)
	_, err = privateSeed.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule DISABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	_, err = privateSeed.Exec(r.ctx, accessRoleProjectionInsert, source.ID, caps[0].RuleFP, definition.id)
	require.NoError(t, err)
	_, err = privateSeed.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule ENABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	require.NoError(t, privateSeed.Commit(r.ctx))
	accessLabelRoleQuestionObservers(t, r)
	accessLabelSourceReceiptObserver(t, r)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	_, _ = fullContractActivate(t, r)
	// Повторная штатная выдача открывает только узкий runtime export.
	// Ни owner-only wrapper, ни общий core не становятся вызываемыми LOGIN.
	for attempt := 0; attempt < 2; attempt++ {
		_, err = r.admin.Exec(r.ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, r.role)
		require.NoError(t, err)
		var exported, private bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT
		 has_function_privilege(current_user,$1,'EXECUTE'),
		 has_function_privilege(current_user,$2,'EXECUTE')
		 OR has_function_privilege(current_user,'kaname.authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer)','EXECUTE')
		 OR has_function_privilege(current_user,'kaname._authority_access_label_source_check_v2(text,text,text,text,uuid,text,text,text,text,timestamptz,integer,text,text,text,text,text)','EXECUTE')`,
			"kaname.authority_role_access_label_source_read_v1"+accessLabelRoleNativeSourceSignature,
			"kaname.authority_role_access_label_source_check_v1"+accessLabelRoleNativeSourceSignature).Scan(&exported, &private))
		require.True(t, exported)
		require.False(t, private)
	}
	input, err := json.Marshal(map[string]any{
		"create": false, "rules": true, "retier": false, "mask": []string{"rules"}, "version": "",
		"role": map[string]any{"id": string(mutation), "rules": json.RawMessage(rawRules), "permissions": []string{}},
	})
	require.NoError(t, err)
	var preparation map[string]any
	require.NoError(t, json.Unmarshal(input, &preparation))
	preparation["_access_label_authority"] = map[string]any{
		"actor": map[string]string{"type": "user", "id": actor},
		"questions": []map[string]string{
			{"scope_kind": "account", "scope_id": r.a, "definition_id": definition.id},
			{"scope_kind": "account", "scope_id": r.b, "definition_id": definition.id},
		},
	}
	prepareInput, err := json.Marshal(preparation)
	require.NoError(t, err)
	tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	identity := r.bundle.Identity()
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_protocol_enter_typed_v3('accounts',ARRAY[$1::text],
 jsonb_build_array(jsonb_build_object('kind','account','id',$1::text)), 'role',$2,$3,$4,'decision')`, r.a, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
	require.NoError(t, err)
	var epochs, census json.RawMessage
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_binding_epoch_read($1::text[])`, []string{r.a}).Scan(&epochs))
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_stage_epoch_lock($1::text[],$2::jsonb)`, []string{r.a}, epochs)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_role_sequence_prepare_v3($1::jsonb,100000,4096)`, prepareInput).Scan(&census))
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_stage_epoch_lock($1::text[],$2::jsonb)`, []string{r.a}, epochs)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_sequence_finalize_v3()`)
	require.NoError(t, err)
	var questionRaw json.RawMessage
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_access_label_role_question_v1($1,$2,$3::uuid)`, actor, r.a, definition.id).Scan(&questionRaw))
	var receipt struct {
		DecisionAt time.Time `json:"decision_at"`
	}
	require.NoError(t, json.Unmarshal(questionRaw, &receipt))
	require.False(t, receipt.DecisionAt.IsZero())
	var roleXmin, roleCTID, bindingXmin, bindingCTID string
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT r.xmin::text,r.ctid::text,b.xmin::text,b.ctid::text
 FROM kaname.roles r JOIN kaname.access_bindings b ON b.role_id=r.id WHERE r.id=$1 AND b.id=$2`, source.ID, binding.ID).
		Scan(&roleXmin, &roleCTID, &bindingXmin, &bindingCTID))
	require.NotEqual(t, oldRoleXmin, roleXmin)
	require.NotEqual(t, oldRoleCTID, roleCTID)
	require.NotEqual(t, oldBindingXmin, bindingXmin)
	require.NotEqual(t, oldBindingCTID, bindingCTID)
	args := []any{string(mutation), "user", actor, receipt.DecisionAt, string(binding.ID), bindingXmin, bindingCTID,
		string(source.ID), roleXmin, roleCTID, "user", actor, "account", r.a, definition.id, caps[0].RuleFP, checkpoint, 100000, 4096}
	const read = `SELECT kaname.authority_role_access_label_source_read_v1` + accessLabelRoleNativeSourceArgs
	observed := func(t *testing.T) bool {
		t.Helper()
		var satisfied bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_role_access_label_source_receipt_v1($1,$2::uuid)`,
			r.a, definition.id).Scan(&satisfied))
		return satisfied
	}
	readAllowed := func(t *testing.T, input []any) bool {
		t.Helper()
		var raw json.RawMessage
		require.NoError(t, tx.QueryRow(r.ctx, read, input...).Scan(&raw))
		var result struct {
			Allowed *bool `json:"allowed"`
			Rows    int   `json:"rows"`
			Reads   int   `json:"reads"`
		}
		require.NoError(t, json.Unmarshal(raw, &result))
		require.NotNil(t, result.Allowed)
		require.GreaterOrEqual(t, result.Rows, kaname.AccessLabelSourceMinimumRows)
		require.LessOrEqual(t, result.Rows, 100000)
		require.Equal(t, kaname.AccessLabelSourceReads, result.Reads)
		return *result.Allowed
	}
	t.Run("private-source-receipt-store", func(t *testing.T) {
		var canUse bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT has_table_privilege(current_user,
 'pg_temp.kaname_authority_access_label_role_source','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')`).Scan(&canUse))
		require.False(t, canUse)
		require.False(t, observed(t))
	})
	t.Run("negative-source-leaves-question-open", func(t *testing.T) {
		negative := append([]any(nil), args...)
		negative[15] = strings.Repeat("a", 64)
		require.NotEqual(t, args[15], negative[15])
		require.False(t, readAllowed(t, negative))
		require.False(t, observed(t))
	})
	t.Run("exact-source", func(t *testing.T) {
		require.True(t, readAllowed(t, args))
		require.True(t, observed(t))
		require.True(t, readAllowed(t, args))
		require.True(t, observed(t), "повторная проверка сохраняет ту же точку")
	})
	for _, tc := range []struct {
		name, state string
		index       int
		value       any
	}{
		{"stale-binding-xmin", "40001", 5, oldBindingXmin},
		{"stale-binding-ctid", "40001", 6, oldBindingCTID},
		{"stale-role-xmin", "40001", 8, oldRoleXmin},
		{"stale-role-ctid", "40001", 9, oldRoleCTID},
		{"wrong-actor", "42501", 2, otherActor},
		{"undeclared-definition", "42501", 14, undeclared.id},
		{"declared-inapplicable-scope", "42501", 13, r.b},
		{"wrong-mutation-role", "42501", 0, string(source.ID)},
		{"wrong-final-clock", "42501", 3, receipt.DecisionAt.Add(-time.Second)},
		{"read-budget", "54000", 18, kaname.AccessLabelSourceReads - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempt, err := tx.Begin(r.ctx)
			require.NoError(t, err)
			defer func() { _ = attempt.Rollback(context.WithoutCancel(r.ctx)) }()
			changed := append([]any(nil), args...)
			changed[tc.index] = tc.value
			var raw json.RawMessage
			err = attempt.QueryRow(r.ctx, read, changed...).Scan(&raw)
			requireAccessDefinitionSQLState(t, err, tc.state)
			require.NoError(t, attempt.Rollback(r.ctx))
		})
	}
	t.Run("runtime-private-execute-refused", func(t *testing.T) {
		attempt, err := tx.Begin(r.ctx)
		require.NoError(t, err)
		defer func() { _ = attempt.Rollback(context.WithoutCancel(r.ctx)) }()
		_, err = attempt.Exec(r.ctx, `SELECT kaname.authority_role_access_label_source_check_v1`+accessLabelRoleNativeSourceArgs, args...)
		requireAccessDefinitionSQLState(t, err, "42501")
		require.NoError(t, attempt.Rollback(r.ctx))
	})
	t.Run("positive-source-does-not-authorize-role-write", func(t *testing.T) {
		var stamp time.Time
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_role_sequence_stamp_v3($1::jsonb)`, input).Scan(&stamp))
		attempt, err := tx.Begin(r.ctx)
		require.NoError(t, err)
		_, err = attempt.Exec(r.ctx, `UPDATE kaname.roles SET rules=$2::jsonb,permissions='[]'::jsonb,updated_at=$3 WHERE id=$1`, mutation, rawRules, stamp)
		requireAccessDefinitionSQLState(t, err, "42501")
		require.NoError(t, attempt.Rollback(r.ctx))
		require.True(t, observed(t), "отклонённая запись не подменяет проверку исходного доступа")
	})
	requireAccessDefinitionSQLState(t, tx.Commit(r.ctx), "42501")
	t.Run("unsigned-context", func(t *testing.T) {
		// Те же корректные аргументы после rollback не заменяют signed program.
		// Вызов идёт под настоящим LOGIN через обычный pool без owner-моста.
		var raw json.RawMessage
		err := r.runtime.QueryRow(r.ctx, read, args...).Scan(&raw)
		requireAccessDefinitionSQLState(t, err, "42501")
	})
}
