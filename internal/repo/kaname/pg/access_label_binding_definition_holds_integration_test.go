// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Наблюдатель доступен только тестовому LOGIN и возвращает результаты
// сравнений. Production private helper и frozen rows runtime не раскрываются.
func accessLabelBindingHoldsObserver(t *testing.T, r protocolRig) {
	t.Helper()
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_access_label_binding_holds_v1(
 p_binding text,p_role text,p_definitions text[],p_applicable text[],p_projection jsonb,
 p_rows integer,p_reads integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $observer$
DECLARE header jsonb;frozen jsonb;holds jsonb;actual jsonb;row_xmin text;row_ctid text;
 expected_definitions jsonb;expected_questions jsonb;
BEGIN
 header:=kaname._authority_sequence_header_v3();
 IF header IS NULL OR header->>'family'<>'binding' THEN
  RAISE EXCEPTION 'test observer requires signed binding program';END IF;
 SELECT p.frozen INTO STRICT frozen FROM pg_temp.kaname_authority_sequence_program p WHERE p.singleton;
 IF frozen->>'id' IS DISTINCT FROM p_binding OR frozen->>'mode' IS DISTINCT FROM 'create' THEN
  RAISE EXCEPTION 'test observer requires exact binding create';END IF;
 holds:=frozen->'access_label_definition_holds';
 IF cardinality(p_definitions)=0 THEN
  RETURN jsonb_build_object('ordinary_no_obligation',NOT (frozen ? 'access_label_definition_holds'),
   'ordinary_binding_absent',NOT EXISTS(SELECT 1 FROM kaname.access_bindings WHERE id=p_binding));
 END IF;
 SELECT to_jsonb(r),r.xmin::text,r.ctid::text INTO STRICT actual,row_xmin,row_ctid
  FROM kaname.roles r WHERE r.id=p_role;
 SELECT jsonb_agg(jsonb_build_object('id',d.id,'scope_kind',d.scope_kind,'scope_id',d.scope_id,
  'module',d.module,'resource',d.resource,'label_key',d.label_key,'revision',d.revision,
  'xmin',d.xmin::text,'ctid',d.ctid::text,'applicable',d.id::text=ANY(p_applicable)) ORDER BY d.id),
  coalesce(jsonb_agg(jsonb_build_object('scope_kind',d.scope_kind,'scope_id',d.scope_id,
   'definition_id',d.id) ORDER BY d.id) FILTER(WHERE d.id::text=ANY(p_applicable)),'[]'::jsonb)
 INTO expected_definitions,expected_questions
 FROM kaname.authority_access_label_definition d WHERE d.id=ANY(p_definitions::uuid[]);
 RETURN jsonb_build_object(
  'present',jsonb_typeof(holds)='object',
  'role_exact',holds->>'role_id'=p_role
   AND holds->>'role_digest'=encode(sha256(convert_to(actual::text,'UTF8')),'hex')
   AND holds->>'role_xmin'=row_xmin AND holds->>'role_ctid'=row_ctid,
  'projection_exact',holds->'projection'=p_projection,
  'definitions_exact',holds->'definitions'=expected_definitions,
  'questions_exact',holds->'questions'=expected_questions,
  'cost_exact',holds->>'rows'=p_rows::text AND holds->>'reads'=p_reads::text,
  'binding_absent',NOT EXISTS(SELECT 1 FROM kaname.access_bindings WHERE id=p_binding));
END $observer$;
REVOKE ALL ON FUNCTION kaname.test_access_label_binding_holds_v1(text,text,text[],text[],jsonb,integer,integer) FROM PUBLIC`)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.test_access_label_binding_holds_v1(text,text,text[],text[],jsonb,integer,integer) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_access_label_binding_holds_v1(text,text,text[],text[],jsonb,integer,integer)`)
		require.NoError(t, err)
	})
}

func accessLabelBindingPrepareInput(t *testing.T, r protocolRig, role domain.RoleID, prepaid map[string]int) (string, []byte) {
	t.Helper()
	var user string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&user))
	id := ids.NewID("acb")
	target := domain.AccessTarget{AllInScope: true}
	input := map[string]any{
		"id": id, "role_id": string(role), "subject_type": "user", "subject_id": user,
		"resource_type": "account", "resource_id": r.a, "scope": 2, "status": "ACTIVE",
		"expires_at": nil, "granted_by_user_id": user, "revoked_at": nil, "revoked_by_user_id": "",
		"deletion_protection": false, "labels": map[string]string{},
		"target": map[string]bool{"allInScope": true}, "target_digest": target.Digest(),
		"granted_relation": "", "is_system": false, "delegation_id": "",
		"subjects": []map[string]string{{"type": "user", "id": user}},
	}
	if prepaid != nil {
		input["_access_label_prepaid"] = prepaid
	}
	raw, err := json.Marshal(input)
	require.NoError(t, err)
	return id, raw
}

func accessLabelBindingSignedTx(t *testing.T, r protocolRig) pgx.Tx {
	t.Helper()
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	identity := r.bundle.Identity()
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_protocol_enter_typed_v3('accounts',ARRAY[$1::text],
 jsonb_build_array(jsonb_build_object('kind','account','id',$1::text)),
 'binding',$2,$3,$4,'decision')`, r.a, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
	require.NoError(t, err)
	return tx
}

func TestAccessLabelBindingPrepareFreezesScopedDefinitionHolds(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	local := seedAccessDefinition(t, r, "account", r.a, "binding_local")
	foreign := seedAccessDefinition(t, r, "account", r.b, "binding_foreign")
	type scenario struct {
		name, roleName string
		definitions    []string
		applicable     []string
		role           domain.RoleID
		projection     []byte
	}
	cases := []scenario{
		{name: "exact-scope", roleName: "binding_exact", definitions: []string{local.id}, applicable: []string{local.id}},
		{name: "mixed-scopes-hold-both", roleName: "binding_mixed", definitions: []string{local.id, foreign.id}, applicable: []string{local.id}},
		{name: "foreign-only-no-question", roleName: "binding_foreign", definitions: []string{foreign.id}, applicable: []string{}},
		{name: "ordinary-zero-cap", roleName: "binding_ordinary", definitions: []string{}, applicable: []string{}},
	}
	for i := range cases {
		c := &cases[i]
		c.role = seedAccountRole(t, r.ctx, r.admin, domain.AccountID(r.a), c.roleName)
		pairs := make([][]string, 0)
		if len(c.definitions) > 0 {
			rules := domain.Rules{accessRoleApply(c.definitions...)}
			rawRules, err := domain.EncodeRules(rules)
			require.NoError(t, err)
			_, caps, err := domain.SplitGrantCapabilityRules(rules)
			require.NoError(t, err)
			for _, cap := range caps {
				pairs = append(pairs, []string{cap.RuleFP, string(cap.DefinitionID)})
			}
			_, err = r.admin.Exec(r.ctx, `UPDATE kaname.roles SET rules=$2::jsonb,permissions='[]'::jsonb WHERE id=$1`, c.role, rawRules)
			require.NoError(t, err)
		}
		var err error
		sort.Slice(pairs, func(i, j int) bool {
			return pairs[i][0] < pairs[j][0] || pairs[i][0] == pairs[j][0] && pairs[i][1] < pairs[j][1]
		})
		c.projection, err = json.Marshal(pairs)
		require.NoError(t, err)
	}
	accessLabelBindingHoldsObserver(t, r)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	_, _ = fullContractActivate(t, r)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Точный signed compiler seam. Роль и definitions действительно
			// сохранены; подготовка не изображает успешный authoring policy gate.
			var prepaid map[string]int
			rows, reads := 0, 0
			if len(c.definitions) > 0 {
				rows, reads = 3*len(c.definitions), 2+len(c.definitions)
				prepaid = map[string]int{"rows": rows, "reads": reads}
			}
			id, input := accessLabelBindingPrepareInput(t, r, c.role, prepaid)
			tx := accessLabelBindingSignedTx(t, r)
			_, err := tx.Exec(r.ctx, `SELECT kaname.authority_binding_sequence_prepare_v3('create',$1::jsonb)`, input)
			require.NoError(t, err)
			var raw json.RawMessage
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_access_label_binding_holds_v1($1,$2,$3::text[],$4::text[],$5::jsonb,$6,$7)`,
				id, c.role, c.definitions, c.applicable, c.projection, rows, reads).Scan(&raw))
			var result map[string]bool
			require.NoError(t, json.Unmarshal(raw, &result))
			if len(c.definitions) == 0 {
				require.Len(t, result, 2)
			} else {
				require.Len(t, result, 7)
			}
			for field, valid := range result {
				require.True(t, valid, field)
			}
			// NOWAIT из другой транзакции доказывает удержание каждой строки,
			// включая foreign UUID. Это не ожидание с таймером и не второй runner.
			roleProbe, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, roleProbe)
			_, err = roleProbe.Exec(r.ctx, `SELECT id FROM kaname.roles WHERE id=$1 FOR UPDATE NOWAIT`, c.role)
			requireAccessDefinitionSQLState(t, err, "55P03")
			require.NoError(t, roleProbe.Rollback(r.ctx))
			for _, definition := range c.definitions {
				probe, err := r.admin.Begin(r.ctx)
				require.NoError(t, err)
				lifecycleRollback(t, probe)
				_, err = probe.Exec(r.ctx, `SELECT id FROM kaname.authority_access_label_definition WHERE id=$1::uuid FOR UPDATE NOWAIT`, definition)
				requireAccessDefinitionSQLState(t, err, "55P03")
				require.NoError(t, probe.Rollback(r.ctx))
			}
			require.NoError(t, tx.Rollback(r.ctx))
			var exists bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.access_bindings WHERE id=$1)`, id).Scan(&exists))
			require.False(t, exists)
		})
	}
}

func TestAccessLabelBindingPrepareRequiresPrepaidBudgetAndPrivateSQL(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	definition := seedAccessDefinition(t, r, "account", r.a, "binding_budget")
	role := seedAccountRole(t, r.ctx, r.admin, domain.AccountID(r.a), "binding_budget")
	rules, err := domain.EncodeRules(domain.Rules{accessRoleApply(definition.id)})
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.roles SET rules=$2::jsonb,permissions='[]'::jsonb WHERE id=$1`, role, rules)
	require.NoError(t, err)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	_, _ = fullContractActivate(t, r)
	for _, c := range []struct {
		name    string
		prepaid map[string]int
		state   string
	}{
		{"omitted-cap", nil, "54000"},
		{"zero-cap-cannot-hide-apply", map[string]int{"rows": 0, "reads": 0}, "54000"},
		{"row-budget-too-small", map[string]int{"rows": 2, "reads": 3}, "54000"},
		{"read-budget-too-small", map[string]int{"rows": 3, "reads": 2}, "54000"},
		{"budget-shape-closed", map[string]int{"rows": 3, "reads": 3, "allow": 1}, "23514"},
	} {
		t.Run(c.name, func(t *testing.T) {
			id, input := accessLabelBindingPrepareInput(t, r, role, c.prepaid)
			tx := accessLabelBindingSignedTx(t, r)
			_, err := tx.Exec(r.ctx, `SELECT kaname.authority_binding_sequence_prepare_v3('create',$1::jsonb)`, input)
			requireAccessDefinitionSQLState(t, err, c.state)
			require.NoError(t, tx.Rollback(r.ctx))
			var exists bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.access_bindings WHERE id=$1)`, id).Scan(&exists))
			require.False(t, exists)
		})
	}
	const signature = "kaname.authority_access_label_binding_definitions_prepare_v1(jsonb,text,text,text,text,integer,integer)"
	var allowed bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, signature).Scan(&allowed))
	require.False(t, allowed)
	_, err = r.runtime.Exec(r.ctx, `SELECT kaname.authority_access_label_binding_definitions_prepare_v1('{}'::jsonb,'0','(0,1)','account',$1,100000,4096)`, r.a)
	requireAccessDefinitionSQLState(t, err, "42501")
	_, err = r.runtime.Exec(r.ctx, `SELECT * FROM kaname.authority_access_label_definition LIMIT 1`)
	requireAccessDefinitionSQLState(t, err, "42501")
}
