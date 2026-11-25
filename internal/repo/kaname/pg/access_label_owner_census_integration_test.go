// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Наблюдатель возвращает только сравнения. Не записывает census, не вызывает
// его private compiler и не превращает объявленные вопросы в обязательные.
func accessLabelOwnerCensusObserver(t *testing.T, r protocolRig) {
	t.Helper()
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_access_label_owner_census_v1(p_role text,p_expected jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $observer$
DECLARE header jsonb;frozen jsonb;decision timestamptz;prepared timestamptz;actual jsonb;
BEGIN
 header:=kaname._authority_sequence_header_v3();
 IF header->>'family' IS DISTINCT FROM 'role'
  OR jsonb_typeof(header->'selected') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'test requires finalized role program' USING ERRCODE='42501';END IF;
 SELECT s.frozen,s.decision_at,s.staged_decision_at INTO STRICT frozen,decision,prepared
 FROM pg_temp.kaname_authority_sequence_program s WHERE singleton;
 SELECT to_jsonb(r) INTO STRICT actual FROM kaname.roles r WHERE id=p_role;
 RETURN jsonb_build_object(
  'identity',frozen#>>'{access_label_transition,role_id}'=p_role,
  'required_exact',frozen->'access_label_required_questions'=p_expected,
  'declared_empty',frozen#>'{access_label_authority,questions}'='{}'::jsonb,
  'complete',frozen#>'{access_label_scope_census,complete}'='true'::jsonb,
  'final_clock',decision IS NOT NULL AND prepared IS NOT NULL AND decision>prepared,
  'no_role_write',actual=frozen#>'{access_label_transition,old_row}',
  'no_projection_write',NOT EXISTS(SELECT 1 FROM kaname.authority_role_access_label_rule WHERE role_id=p_role),
  'all_carriers_expired',NOT EXISTS(SELECT 1 FROM jsonb_array_elements(frozen#>'{access_label_scope_census,scopes}') s
   WHERE (s->>'never')::boolean OR (s->>'max_expiry')::timestamptz>decision),
  'carrier_scope_present',jsonb_array_length(frozen#>'{access_label_scope_census,scopes}')=1);
END $observer$;
REVOKE ALL ON FUNCTION kaname.test_access_label_owner_census_v1(text,jsonb) FROM PUBLIC`)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_access_label_owner_census_v1(text,jsonb)`)
		require.NoError(t, err)
	})
	_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.test_access_label_owner_census_v1(text,jsonb) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
}

func TestRoleAccessLabelOwnerCensusIgnoresDeclaredOmissions(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	project := seedProject(t, r.ctx, owner, domain.AccountID(r.a), "owner-census-project")
	var actor string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&actor))
	alternateHolder := seedSAID(t, r.ctx, r.admin, r.a, "owner-census-holder")
	projectA := seedAccessDefinition(t, r, "project", string(project.ID), "census_project_a")
	projectB := seedAccessDefinition(t, r, "project", string(project.ID), "census_project_b")
	accountA := seedAccessDefinition(t, r, "account", r.a, "census_account_a")
	accountB := seedAccessDefinition(t, r, "account", r.a, "census_account_b")
	projectIDs := []string{projectA.id, projectB.id}
	accountIDs := []string{accountA.id, accountB.id}
	slices.Sort(projectIDs)
	slices.Sort(accountIDs)
	type scenario struct {
		name                 string
		statuses             []string
		expired, unsupported bool
		role                 domain.RoleID
	}
	cases := []scenario{
		{name: "active-carrier", statuses: []string{"ACTIVE"}},
		{name: "pending-carrier", statuses: []string{"PENDING"}},
		{name: "active-and-pending-deduplicate-scope", statuses: []string{"ACTIVE", "PENDING"}},
		{name: "expired-carriers-use-role-fallback", statuses: []string{"ACTIVE", "PENDING"}, expired: true},
		{name: "unsupported-live-target-refuses", statuses: []string{"ACTIVE"}, unsupported: true},
	}
	// Все holders созданы до handoff с настоящими typed subject rows. PENDING
	// и expired остаются в owner census; никакой набор не подменяется наблюдателем.
	for i := range cases {
		c := &cases[i]
		c.role = seedAccountRole(t, r.ctx, r.admin, domain.AccountID(r.a), "owner_census_"+strconv.Itoa(i))
		for holder, status := range c.statuses {
			subjectType, subjectID := "user", actor
			if holder > 0 {
				// Уникальность active grant не зависит от ACTIVE/PENDING. Второй
				// carrier принадлежит настоящему другому holder; actor роли прежний.
				subjectType, subjectID = "service_account", alternateHolder
			}
			target := `{"allInScope":true}`
			if c.unsupported {
				raw, err := json.Marshal(map[string]any{"resources": []map[string]string{{"type": "iam.role", "id": string(c.role)}}})
				require.NoError(t, err)
				target = string(raw)
			}
			var expires, created any
			if c.expired {
				created = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
				expires = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
			}
			_, err := r.admin.Exec(r.ctx, bindingset.With(`INSERT INTO kaname.access_bindings
 (id,subject_type,subject_id,role_id,resource_type,resource_id,status,scope,grant_capability_version,target,expires_at,created_at)
 VALUES($1,$2,$3,$4,'project',$5,$6,$7,1,$8::jsonb,$9::timestamptz,COALESCE($10::timestamptz,transaction_timestamp()))`),
				ids.NewID("acb"), subjectType, subjectID, c.role, project.ID, status, domain.DeriveFromResourceType("project"), target, expires, created)
			require.NoError(t, err)
		}
	}
	accessLabelOwnerCensusObserver(t, r)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	_, _ = fullContractActivate(t, r)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			definitionIDs, scopeKind, scopeID := projectIDs, "project", string(project.ID)
			if c.expired {
				definitionIDs, scopeKind, scopeID = accountIDs, "account", r.a
			}
			rules, err := domain.EncodeRules(domain.Rules{accessRoleApply(definitionIDs...)})
			require.NoError(t, err)
			input, err := json.Marshal(map[string]any{
				"create": false, "rules": true, "retier": false, "mask": []string{"rules"}, "version": "",
				"role": map[string]any{"id": string(c.role), "rules": json.RawMessage(rules), "permissions": []string{}},
				"_access_label_authority": map[string]any{
					"actor": map[string]string{"type": "user", "id": actor}, "questions": []any{},
				},
			})
			require.NoError(t, err)
			tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			require.NoError(t, err)
			defer func() { _ = tx.Rollback(context.WithoutCancel(r.ctx)) }()
			identity := r.bundle.Identity()
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_protocol_enter_typed_v3('accounts',ARRAY[$1::text],
 jsonb_build_array(jsonb_build_object('kind','account','id',$1::text)), 'role',$2,$3,$4,'decision')`,
				r.a, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
			require.NoError(t, err)
			var epochs, census json.RawMessage
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_binding_epoch_read($1::text[])`, []string{r.a}).Scan(&epochs))
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_stage_epoch_lock($1::text[],$2::jsonb)`, []string{r.a}, epochs)
			require.NoError(t, err)
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_role_sequence_prepare_v3($1::jsonb,100000,4096)`, input).Scan(&census))
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_stage_epoch_lock($1::text[],$2::jsonb)`, []string{r.a}, epochs)
			require.NoError(t, err)
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_sequence_finalize_v3()`)
			if c.unsupported {
				requireAccessDefinitionSQLState(t, err, "23514")
				require.NoError(t, tx.Rollback(r.ctx))
				return
			}
			require.NoError(t, err)
			expected := make([]map[string]string, 0, len(definitionIDs))
			for _, id := range definitionIDs {
				expected = append(expected, map[string]string{"scope_kind": scopeKind, "scope_id": scopeID, "definition_id": id})
			}
			rawExpected, err := json.Marshal(expected)
			require.NoError(t, err)
			var raw json.RawMessage
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_access_label_owner_census_v1($1,$2::jsonb)`, c.role, rawExpected).Scan(&raw))
			var checks map[string]bool
			require.NoError(t, json.Unmarshal(raw, &checks))
			for _, key := range []string{"identity", "required_exact", "declared_empty", "complete", "final_clock", "no_role_write", "no_projection_write", "carrier_scope_present"} {
				require.True(t, checks[key], key)
			}
			require.Equal(t, c.expired, checks["all_carriers_expired"])
			require.NoError(t, tx.Rollback(r.ctx))
		})
	}
}
