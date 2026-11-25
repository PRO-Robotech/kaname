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
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

const accessLabelRoleSequenceMigration = "20261124060000_role_sequence_freezes_access_label_transition.sql"
const accessLabelRoleProjectionWriteMigration = "20261124070000_role_access_label_projection_write.sql"
const accessLabelNativeSourceMigration = "20261124080000_access_label_native_source_checkpoint.sql"
const accessLabelRoleCheckpointReadMigration = "20261124090000_access_label_role_checkpoint_read.sql"
const accessLabelDefinitionCustodyMigration = "20261124100000_access_label_definition_custody.sql"
const accessLabelBindingDefinitionCustodyMigration = "20261124110000_access_label_binding_definition_custody.sql"
const accessLabelRoleQuestionReceiptMigration = "20261124120000_access_label_role_question_receipt.sql"
const accessLabelRoleNativeSourceMigration = "20261124130000_access_label_role_native_source.sql"
const accessLabelRoleNativeReadMigration = "20261124140000_access_label_role_native_read.sql"
const accessLabelRoleOwnerCensusMigration = "20261124150000_access_label_role_owner_census.sql"
const accessLabelRoleSourceReceiptsMigration = "20261124160000_access_label_role_source_receipts.sql"
const accessLabelRoleAtomicProjectionMigration = "20261124170000_access_label_role_atomic_projection.sql"
const accessLabelSelectorCanonicalMigration = "20261124180000_access_label_selector_canonical.sql"
const accessLabelSelectorSourceMigration = "20261124190000_access_label_selector_sources.sql"
const accessLabelFreshnessMigration = "20261124210000_access_label_fact_freshness.sql"

func accessLabelMigrationParts(t *testing.T, name string) (string, string) {
	t.Helper()
	raw, err := migrations.FS.ReadFile(name)
	require.NoError(t, err)
	up, down, found := strings.Cut(string(raw), "-- +goose Down")
	require.True(t, found)
	return up, down
}

// Каждый шаг смены версии выполняется в своей транзакции, как в Goose.
func accessLabelSuspendMigrations(t *testing.T, r protocolRig, names ...string) func() {
	t.Helper()
	ups := make([]string, 0, len(names))
	for _, name := range names {
		up, down := accessLabelMigrationParts(t, name)
		_, err := r.admin.Exec(r.ctx, down)
		require.NoError(t, err, "Down %s", name)
		ups = append(ups, up)
	}
	return func() {
		for i := len(ups) - 1; i >= 0; i-- {
			_, err := r.admin.Exec(r.ctx, ups[i])
			require.NoError(t, err, "Up %s", names[i])
		}
	}
}

func TestAccessLabelRoleSequenceMigrationRestoresSignedClosure(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	restore := accessLabelSuspendMigrations(t, r, accessLabelFreshnessMigration, accessLabelSelectorSourceMigration, accessLabelSelectorCanonicalMigration, accessLabelRoleAtomicProjectionMigration, accessLabelRoleSourceReceiptsMigration, accessLabelRoleOwnerCensusMigration, accessLabelRoleNativeReadMigration, accessLabelRoleNativeSourceMigration, accessLabelRoleQuestionReceiptMigration, accessLabelBindingDefinitionCustodyMigration, accessLabelDefinitionCustodyMigration, accessLabelRoleCheckpointReadMigration, accessLabelNativeSourceMigration, accessLabelRoleProjectionWriteMigration)
	up, down := accessLabelMigrationParts(t, accessLabelRoleSequenceMigration)
	signatures := []string{
		"authority_role_sequence_prepare_v3(jsonb,integer,integer)",
		"_authority_sequence_complete_v3()",
		"_authority_crud_storage_v3()",
		"_authority_full_contract_storage_v3()",
		"authority_access_label_role_compile_v1(jsonb)",
		"authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer)",
		"authority_access_label_definition_hold_v1(text,text,text,text,text,uuid,bigint,text,text,text)",
	}
	type snapshot struct {
		metadata string
		digests  []string
	}
	inspect := func() snapshot {
		t.Helper()
		var valid bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()
		 AND kaname.authority_access_label_storage_valid_v1()`).Scan(&valid))
		require.True(t, valid)
		var got snapshot
		var count int
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*),
		 jsonb_agg(jsonb_build_array(p.oid,p.proowner,p.proacl,p.prosecdef,p.provolatile,p.proconfig) ORDER BY s.ordinal)::text,
		 array_agg(encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') ORDER BY s.ordinal)
		 FROM unnest($1::text[]) WITH ORDINALITY s(signature,ordinal)
		 JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||s.signature)`, signatures).
			Scan(&count, &got.metadata, &got.digests))
		require.Equal(t, len(signatures), count)
		return got
	}
	installed := inspect()
	_, err := r.admin.Exec(r.ctx, down)
	require.NoError(t, err)
	previous := inspect()
	require.Equal(t, installed.metadata, previous.metadata, "OID, owner, ACL и настройки функций сохраняются")
	for i, signature := range signatures {
		if i < 4 {
			require.NotEqual(t, installed.digests[i], previous.digests[i], signature)
		} else {
			require.Equal(t, installed.digests[i], previous.digests[i], "private dependency остаётся неизменной: %s", signature)
		}
	}
	_, err = r.admin.Exec(r.ctx, up)
	require.NoError(t, err)
	require.Equal(t, installed, inspect(), "Up после Down восстанавливает точные тела и closure")
	restore()
}

// Только тестовый наблюдатель: не меняет private store и возвращает одни
// результаты сравнений. Ни proof, ни frozen программа не выдаются LOGIN.
func accessLabelRoleSequenceObserver(t *testing.T, r protocolRig) {
	t.Helper()
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_access_label_role_sequence_observe_v1(
 p_old jsonb,p_new jsonb,p_fp text,p_definition text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $observer$
DECLARE program jsonb;frozen jsonb;transition jsonb;actual jsonb;actual_xmin text;actual_ctid text;
BEGIN
 program:=kaname._authority_sequence_header_v3();
 IF program IS NULL OR program->>'family'<>'role' THEN RAISE EXCEPTION 'test requires signed role program';END IF;
 SELECT s.frozen INTO STRICT frozen FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton;
 transition:=frozen->'access_label_transition';
 SELECT to_jsonb(r),r.xmin::text,r.ctid::text INTO actual,actual_xmin,actual_ctid
  FROM kaname.roles r WHERE r.id=p_new->>'id';
 RETURN jsonb_build_object(
  'present',jsonb_typeof(transition)='object',
  'header_mode',program#>>'{frozen,mode}'='access_label_transition',
  'identity',transition->>'role_id'=p_new->>'id',
  'old_exact',transition->'old_row'=coalesce(p_old,'null'::jsonb),
  'new_exact',((transition->'new_row')-ARRAY['created_at','updated_at'])=(p_new-ARRAY['created_at','updated_at']),
  'new_stamp',transition#>'{new_row,updated_at}'=frozen->'stamp'
   AND CASE WHEN p_old IS NULL THEN transition#>'{new_row,created_at}'=frozen->'stamp'
    ELSE transition#>'{new_row,created_at}'=p_old->'created_at' END,
  'old_digest',transition->'old_digest'=coalesce(to_jsonb(encode(sha256(convert_to(p_old::text,'UTF8')),'hex')),'null'::jsonb),
  'new_digest',transition->>'new_digest'=encode(sha256(convert_to((transition->'new_row')::text,'UTF8')),'hex'),
  'old_projection',transition->'old_projection'='[]'::jsonb,
  'new_projection',transition->'new_projection'=jsonb_build_array(jsonb_build_array(p_fp,p_definition)),
  'old_witness',transition->'old_xmin'=coalesce(to_jsonb(actual_xmin),'null'::jsonb)
   AND transition->'old_ctid'=coalesce(to_jsonb(actual_ctid),'null'::jsonb),
  'definition_witness',transition->'definition_witnesses'=(
   SELECT jsonb_object_agg(d.id::text,jsonb_build_object('id',d.id,'revision',d.revision,
    'scope_kind',d.scope_kind,'scope_id',d.scope_id,'module',d.module,'resource',d.resource,
    'label_key',d.label_key,'row_xmin',d.xmin::text,'row_ctid',d.ctid::text))
   FROM kaname.authority_access_label_definition d WHERE d.id=p_definition::uuid),
  'bounded_cost',(transition->>'reads')::integer>=6 AND (transition->>'rows')::integer>=4,
  'no_role_write',actual IS NOT DISTINCT FROM p_old,
  'no_projection_write',NOT EXISTS(SELECT 1 FROM kaname.authority_role_access_label_rule WHERE role_id=p_new->>'id'));
END $observer$;
REVOKE ALL ON FUNCTION kaname.test_access_label_role_sequence_observe_v1(jsonb,jsonb,text,text) FROM PUBLIC`)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_access_label_role_sequence_observe_v1(jsonb,jsonb,text,text)`)
		require.NoError(t, err)
	})
	_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.test_access_label_role_sequence_observe_v1(jsonb,jsonb,text,text) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
}

func TestAccessLabelRoleSequenceFreezesOwnerImagesAndRefusesUnconsumedCommit(t *testing.T) {
	// Узкий signed SQL seam проверяет подготовку и обязанность completion.
	// Успешный authoring gate и применение проекции этим тестом не заявляются.
	r, owner := writerProtocolRigBeforePreparation(t)
	role := seedAccountRole(t, r.ctx, r.admin, domain.AccountID(r.a), "access_sequence_source")
	definition := seedAccessDefinition(t, r, "account", r.a, "sequence")
	var actor string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&actor))
	rules := domain.Rules{accessRoleApply(definition.id)}
	encoded, err := domain.EncodeRules(rules)
	require.NoError(t, err)
	_, caps, err := domain.SplitGrantCapabilityRules(rules)
	require.NoError(t, err)
	require.Len(t, caps, 1)
	accessLabelRoleSequenceObserver(t, r)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	_, _ = fullContractActivate(t, r)

	for _, creation := range []bool{false, true} {
		name := "update"
		if creation {
			name = "create"
		}
		t.Run(name, func(t *testing.T) {
			id := string(role)
			if creation {
				id = ids.NewID("rol")
			}
			var old, expectedNew json.RawMessage
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(r),to_jsonb(r)||jsonb_build_object(
			 'id',$2::text,'rules',$3::jsonb,'permissions','[]'::jsonb,
			 'name',CASE WHEN $4::boolean THEN 'access_sequence_creation' ELSE r.name END)
			 FROM kaname.roles r WHERE id=$1`, role, id, encoded, creation).
				Scan(&old, &expectedNew))
			var proposed map[string]any
			require.NoError(t, json.Unmarshal(expectedNew, &proposed))
			requestRole := map[string]any{}
			for _, key := range []string{"id", "account_id", "project_id", "name", "description", "rules", "permissions", "labels"} {
				requestRole[key] = proposed[key]
			}
			if !creation {
				// Поля вне маски не должны заменить фактический образ OLD/NEW.
				requestRole["name"] = "caller_name_outside_mask"
				requestRole["description"] = "caller description outside mask"
				requestRole["account_id"] = r.b
			}
			input, err := json.Marshal(map[string]any{
				"create": creation, "rules": true, "retier": false,
				"role": requestRole, "mask": []string{"rules"}, "version": "",
				"_access_label_authority": map[string]any{
					"actor":     map[string]string{"type": "user", "id": actor},
					"questions": []map[string]string{{"scope_kind": "account", "scope_id": r.a, "definition_id": definition.id}},
				},
			})
			require.NoError(t, err)
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			identity := r.bundle.Identity()
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_protocol_enter_typed_v3('accounts',ARRAY[$1::text],
			 jsonb_build_array(jsonb_build_object('kind','account','id',$1::text)),
			 'role',$2,$3,$4,'decision')`, r.a, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
			require.NoError(t, err)
			var cost struct {
				Rows  int `json:"rows"`
				Reads int `json:"reads"`
			}
			var raw json.RawMessage
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_role_sequence_prepare_v3($1,100000,4096)`, input).Scan(&raw))
			require.NoError(t, json.Unmarshal(raw, &cost))
			require.GreaterOrEqual(t, cost.Rows, 4)
			require.Greater(t, cost.Reads, 6, "общий census включает helper и sequence reserve")
			var expectedOld any = old
			if creation {
				expectedOld = nil
			}
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_access_label_role_sequence_observe_v1($1,$2,$3,$4)`,
				expectedOld, expectedNew, caps[0].RuleFP, definition.id).Scan(&raw))
			var checks map[string]bool
			require.NoError(t, json.Unmarshal(raw, &checks))
			require.Len(t, checks, 15)
			for invariant, ok := range checks {
				require.True(t, ok, invariant)
			}
			// Проверяем реальный deferred completion на COMMIT, а не ручной
			// вызов guard. Конкретное сообщение отличает новую обязанность от
			// прежнего отказа по незавершённым journal/outbox effects.
			err = tx.Commit(r.ctx)
			var refusal *pgconn.PgError
			require.ErrorAs(t, err, &refusal)
			require.Equal(t, "42501", refusal.Code)
			require.Equal(t, "sequence program never finalized", refusal.Message)
			var after json.RawMessage
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT (SELECT to_jsonb(r) FROM kaname.roles r WHERE id=$1)`, id).Scan(&after))
			if creation {
				require.Empty(t, after)
			} else {
				require.JSONEq(t, string(old), string(after))
			}
		})
	}
}

func TestAccessLabelRoleSequencePreservesOrdinaryCreateAndMetadataCommit(t *testing.T) {
	w := delegationUCFixture(t)
	full, _ := fullContractActivate(t, w.r)
	factory, err := kanamepg.NewGrantPolicyWriters(w.r.ctx, full, w.r.bundle)
	require.NoError(t, err)
	role := roleFinalCreate(t, w, factory, "access_sequence_ordinary")
	rd, err := full.Reader(w.r.ctx)
	roleFinalCleanup(t, rd)
	require.NoError(t, err)
	current, version, err := rd.Roles().GetWithVersion(w.r.ctx, role.ID)
	require.NoError(t, err)
	require.NoError(t, rd.Rollback(w.r.ctx))
	proposed := current
	proposed.Description = "обычная правка после подготовки accessLabels"
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.owner)}
	writer, err := factory.RoleMutationWriter(w.r.ctx, kaname.RoleMutationRequest{
		Role: proposed, Update: true, UpdateMask: []string{"description"}, ExpectedVersion: version,
	}, actor)
	require.NoError(t, err)
	roleFinalCleanup(t, writer)
	require.NoError(t, grantpolicy.RequireRoleMethod(w.r.ctx, writer, actor, proposed, false))
	_, err = writer.RolesW().UpdateCAS(w.r.ctx, proposed, []string{"description"}, version)
	require.NoError(t, err)
	require.NoError(t, writer.Commit(w.r.ctx))
	var description string
	var projectionCount int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT description,
	 (SELECT count(*) FROM kaname.authority_role_access_label_rule WHERE role_id=$1)
	 FROM kaname.roles WHERE id=$1`, role.ID).Scan(&description, &projectionCount))
	require.Equal(t, string(proposed.Description), description)
	require.Zero(t, projectionCount)
}
