// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

func TestMetadataRetainedRRAddsForeignProjectToSignedAdmission(t *testing.T) {
	testMetadataRetainedRRAdmission(t, false)
}

func TestMetadataRetainedOwnerHeldReplayAfterPolicyProtection(t *testing.T) {
	testMetadataRetainedRRAdmission(t, true)
}

func testMetadataRetainedRRAdmission(t *testing.T, heldReplay bool) {
	for _, withHistory := range []bool{false, true} {
		name := "empty_control"
		if withHistory {
			name = "historical_member_differs_from_output_retained_A_current_B"
		}
		t.Run(name, func(t *testing.T) {
			const outputID = "rr-retained-foreign-output"
			const ancestorID = "rr-retained-projection-only-parent"
			var historical domain.AccessBindingID
			var memberID, foreignProject, ancestorAccount string
			// Штатная fixture создаёт настоящего LOGIN и metadata factory. Исторические
			// строки — storage premise до activation; они не являются allow evidence.
			w := metadataFixtureMode(t, false, "prepared", func(r protocolRig) {
				foreign := seedProject(t, r.ctx, lifecycleOwner(r), domain.AccountID(r.b), "rr-foreign-project")
				foreignProject = string(foreign.ID)
				_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id,parent_project_id)
 VALUES('vpc.network',$1,$2,$3)`, outputID, r.a, foreignProject)
				require.NoError(t, err)
				_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_registration_scope(object_type,object_id,project_id,account_id)
 VALUES('vpc_network',$1,$2,$3)`, outputID, foreignProject, r.a)
				require.NoError(t, err)
				// Нет parent edge/relation fact, которые независимо подсказали бы B.
				var edges int
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT (SELECT count(*) FROM kaname.resource_parent_edge WHERE object_type='vpc_network' AND object_id=$1)+(SELECT count(*) FROM kaname.relation_fact WHERE object_type='vpc_network' AND object_id=$1)`, outputID).Scan(&edges))
				require.Zero(t, edges)
				if !withHistory {
					return
				}
				// Удалённый member отсутствует среди editor outputs. Только настоящий
				// historical census ведёт от root к этому retained carrier.
				memberID = "prj-rr-stale-member"
				var memberPresent bool
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.projects WHERE id=$1)`, memberID).Scan(&memberPresent))
				require.False(t, memberPresent)
				recipient := seedMemberUser(t, r.ctx, r.admin, r.a, "rr-historical-recipient")
				rule := domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, MatchAccessLabels: map[string]string{"team": "after"}}
				historical = groupLifecycleBinding(t, r, r.a, recipient, "rr_historical_role", rule)
				_, err = r.admin.Exec(r.ctx, `UPDATE kaname.access_bindings SET status='REVOKED',revoked_at=clock_timestamp() WHERE id=$1`, string(historical))
				require.NoError(t, err)
				// Member не является корнем account:A. Поэтому root holder scan сам по
				// себе не заменит пропущенный historical census.
				_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.access_binding_target_members(binding_id,role_id,rule_fp,object_type,object_id,verification_status)
 SELECT id,role_id,$2,'iam.project',$3,'ACTIVE' FROM kaname.access_bindings WHERE id=$1`, string(historical), rule.Fingerprint(), memberID)
				require.NoError(t, err)
				_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.access_binding_emitted_tuples(binding_id,member_object_type,member_object_id,fga_user,relation,object,source)
 VALUES($1,'','',$2,'v_get',$3,'binding')`, string(historical), "user:"+recipient, "vpc_network:"+outputID)
				require.NoError(t, err)
				var retainedRows int
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT (SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=$1)+(SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1)`, string(historical)).Scan(&retainedRows))
				require.Equal(t, 2, retainedRows)
				if heldReplay {
					// Отдельный аккаунт находится только через mirror предка.
					_, ancestorAccount = kac127SeedUserAndAccount(t, r.ctx, r.admin, "rr-ancestor-owner")
					require.NotContains(t, []string{r.a, r.b}, ancestorAccount)
					_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id)
 VALUES('vpc.network',$1,$2)`, ancestorID, ancestorAccount)
					require.NoError(t, err)
					_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth)
 VALUES('vpc_network',$1,'vpc_network',$2,1)`, outputID, ancestorID)
					require.NoError(t, err)
				}
			})
			if heldReplay {
				installMetadataOwnerHeldChainProbe(t, w.r)
			} else {
				installMetadataOwnerPrefinalProbe(t, w.r)
			}
			var ancestorState, ancestorRow json.RawMessage
			if heldReplay && withHistory {
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT
 jsonb_build_array(jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m))),to_jsonb(m)
 FROM kaname.resource_mirror m WHERE m.object_type='vpc.network' AND m.object_id=$1`, ancestorID).
					Scan(&ancestorState, &ancestorRow))
			}
			root := w.account
			root.AccessLabels = domain.Labels{"team": "after"}
			probe := kanamepg.ProbeMetadataRetainedRRAdmission
			if heldReplay {
				probe = kanamepg.ProbeMetadataRetainedOwnerHeldReplay
			}
			trace, err := probe(w.r.ctx, w.factory, root, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.actor)})
			require.NoError(t, err)
			require.True(t, trace.RRClosed)
			require.NotNil(t, trace.OwnerPrefinal, "отсутствующий/null owner result не является пустым census")
			require.Equal(t, "observed", trace.OwnerPrefinal.Status)
			require.Equal(t, w.r.role, trace.OwnerPrefinal.Invoker)
			require.NotNil(t, trace.OwnerPrefinal.ConsumerFinalized)
			require.False(t, *trace.OwnerPrefinal.ConsumerFinalized, "owner discovery выполнен до protectPolicyPlan")
			require.True(t, trace.OwnerPrefinal.FenceChecked)
			require.Greater(t, trace.OwnerPrefinal.Rows, 0)
			require.Greater(t, trace.OwnerPrefinal.Reads, 0)
			require.Greater(t, trace.OwnerPrefinal.Work, 0)
			if heldReplay {
				require.NotNil(t, trace.OwnerHeldReplay)
				held := trace.OwnerHeldReplay
				require.Equal(t, "replayed", held.Status)
				require.Equal(t, w.r.role, held.Invoker)
				require.NotNil(t, held.ConsumerFinalized)
				require.True(t, *held.ConsumerFinalized)
				require.True(t, held.StashPrivate)
				require.True(t, held.ScalarUnselected, "no final scalar command or writer activation")
				require.True(t, held.CensusMatched)
				require.Positive(t, held.Sources)
				require.Positive(t, held.HeldRows)
				require.Positive(t, held.EmptyPredicates, "empty predicates are replayed, not skipped")
				require.Positive(t, held.Rows)
				require.Positive(t, held.Reads)
				require.Positive(t, held.Work)
				if withHistory {
					for _, kind := range []int{4, 21, 22, 23, 26, 27, 28, 35} {
						require.Contains(t, held.Kinds, kind)
					}
					require.Positive(t, held.Frontiers)
					require.NotEmpty(t, held.AncestorCapture)
					require.JSONEq(t, string(ancestorState), string(held.AncestorCapture), "held replay preserves exact parent xmin/ctid/row witness")
					require.NotEmpty(t, held.AncestorProjection)
					require.JSONEq(t, string(ancestorRow), string(held.AncestorProjection), "ancestor compiler resolves the parent from replay index")
					parent := domain.ResourceRef{Type: "vpc.network", ID: ancestorID}
					require.NotContains(t, trace.OwnerPrefinal.Outputs, parent, "ancestor projection remains a SOURCE dependency")
					require.NotContains(t, trace.Outputs, parent, "fixture parent is outside original retained outputs")
				}
			}

			require.Equal(t, kaname.AuthorityFenceAccounts, trace.Intent.Plan.Mode, "ни пустой census, ни retained история не заменяются GLOBAL")
			require.Equal(t, kaname.AuthorityFenceAccounts, trace.SignedMode)
			expected := []domain.AccountID{domain.AccountID(w.r.a)}
			if withHistory {
				expected = append(expected, domain.AccountID(w.r.b))
				if heldReplay {
					expected = append(expected, domain.AccountID(ancestorAccount))
					require.Contains(t, trace.Intent.Owners, kaname.AuthorityOwnerRef{Kind: "account", ID: ancestorAccount})
				}
				require.Equal(t, []string{string(historical)}, trace.HistoricalBindings)
				require.Contains(t, trace.RetainedBindings, string(historical))
				require.Equal(t, []string{string(historical)}, trace.OwnerPrefinal.HistoricalBindings)
				require.Contains(t, trace.OwnerPrefinal.Outputs, domain.ResourceRef{Type: "iam.project", ID: memberID})
				require.Contains(t, trace.OwnerPrefinal.Outputs, domain.ResourceRef{Type: "vpc.network", ID: outputID})
				require.Equal(t, "share", trace.OwnerPrefinal.SourceGuards["binding:"+string(historical)])
				require.Contains(t, trace.Outputs, domain.ResourceRef{Type: "iam.project", ID: memberID})
				require.Contains(t, trace.Outputs, domain.ResourceRef{Type: "vpc.network", ID: outputID})
				require.Contains(t, trace.Intent.Owners, kaname.AuthorityOwnerRef{Kind: "account", ID: w.r.b}, "foreign scope входит в настоящий SQL discover(refs) == Plan.Accounts")
			} else {
				require.Empty(t, trace.HistoricalBindings)
				require.Empty(t, trace.OwnerPrefinal.HistoricalBindings)
				require.NotContains(t, trace.OwnerPrefinal.Outputs, domain.ResourceRef{Type: "vpc.network", ID: outputID})
				require.NotContains(t, trace.Outputs, domain.ResourceRef{Type: "vpc.network", ID: outputID})
				require.NotContains(t, trace.Intent.Owners, kaname.AuthorityOwnerRef{Kind: "account", ID: w.r.b})
			}
			require.ElementsMatch(t, expected, trace.OwnerPrefinal.Accounts, "независимый owner RC вывел тот же admission footprint")
			require.ElementsMatch(t, expected, trace.RetainedAccounts)
			require.ElementsMatch(t, expected, trace.Intent.Plan.Accounts)
			require.ElementsMatch(t, expected, trace.SignedAccounts, "успешен настоящий signed entry, не только частный footprint")
		})
	}
}

// Обёртка существует только в отдельной test DB. Установленные private helpers
// не заменяются и не получают runtime grants; runtime исполняет только эту пробу.
func installMetadataOwnerPrefinalProbe(t *testing.T, r protocolRig) {
	t.Helper()
	signatures := []string{
		"kaname._authority_metadata_access_label_prefinal_carriers_v1(text,text,text,jsonb,jsonb,integer,integer,integer)",
		"kaname._authority_metadata_access_label_early_closure_v1(jsonb,jsonb,integer,integer,integer)",
		"kaname._authority_metadata_access_label_discovery_fence_v1(jsonb)",
	}
	for _, signature := range signatures {
		var installed, owned bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_regprocedure($1) IS NOT NULL,
   coalesce((SELECT p.proowner=c.relowner FROM pg_catalog.pg_proc p CROSS JOIN pg_catalog.pg_class c
    WHERE p.oid=to_regprocedure($1) AND c.oid='kaname.authority_writer_protocol'::regclass),false)`, signature).Scan(&installed, &owned))
		require.True(t, installed, "отсутствует установленный owner helper %s", signature)
		require.True(t, owned, "helper принадлежит другому owner: %s", signature)
		var permitted bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, signature).Scan(&permitted))
		require.False(t, permitted, "private API остаётся закрытым: %s", signature)
	}
	// Прямой вызов LOGIN обязан отказать именно по ACL, не вернуть null/empty.
	_, err := r.runtime.Exec(r.ctx, `SELECT kaname._authority_metadata_access_label_discovery_fence_v1('{}'::jsonb)`)
	var denied *pgconn.PgError
	require.ErrorAs(t, err, &denied)
	require.Equal(t, "42501", denied.Code)
	require.Equal(t, "permission denied for function _authority_metadata_access_label_discovery_fence_v1", denied.Message)

	_, err = r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_metadata_owner_prefinal(
 p_kind text,p_id text,p_old_xmin text,p_old jsonb,p_new_access jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $probe$
DECLARE proof jsonb;invoker oid;bundle record;catalog jsonb;packet jsonb;closure jsonb;
 accounts jsonb;outputs jsonb;finalized boolean;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 invoker:=session_user::regrole::oid;
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
  OR (proof->>'invoker_oid')::oid IS DISTINCT FROM invoker
  OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN
  RAISE EXCEPTION 'metadata fixture requires original signed runtime invoker' USING ERRCODE='42501';END IF;
 -- Это тот же доступ к bundle, который имел исходный LOGIN; каталог не
 -- передаётся из Go и не заменяется caller-provided map.
 IF NOT has_function_privilege(invoker,'kaname.authority_protocol_read_bundle()','EXECUTE')
  OR NOT has_table_privilege(invoker,'kaname.authority_semantic_identity','SELECT') THEN
  RAISE EXCEPTION 'metadata fixture canonical bundle ACL missing' USING ERRCODE='42501';END IF;
 SELECT * INTO bundle FROM kaname.authority_protocol_read_bundle();
 IF NOT FOUND THEN
  RAISE EXCEPTION 'metadata fixture canonical bundle unavailable' USING ERRCODE='P1034';END IF;
 IF bundle.model_id IS DISTINCT FROM proof->>'model_id'
  OR bundle.catalog_id IS DISTINCT FROM proof->>'catalog_id'
  OR bundle.projector_version IS DISTINCT FROM proof->>'projector_version'
  OR octet_length(bundle.catalog_json) NOT BETWEEN 1 AND 8388608
  OR encode(sha256(bundle.catalog_json),'hex') IS DISTINCT FROM bundle.catalog_id
  OR encode(sha256(convert_to(bundle.model_source,'UTF8')),'hex') IS DISTINCT FROM bundle.model_id THEN
  RAISE EXCEPTION 'metadata fixture canonical bundle differs from admission' USING ERRCODE='P1034';END IF;
 catalog:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
 IF jsonb_typeof(catalog) IS DISTINCT FROM 'object'
  OR jsonb_typeof(catalog->'Live') IS DISTINCT FROM 'object'
  OR jsonb_typeof(catalog->'Retired') IS DISTINCT FROM 'object'
  OR jsonb_typeof(catalog#>'{Live,Resources}') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'metadata fixture canonical catalog malformed' USING ERRCODE='42501';END IF;
 packet:=kaname._authority_metadata_access_label_prefinal_carriers_v1(
  p_kind,p_id,p_old_xmin,p_old,p_new_access,99999,4095,399999);
 IF packet IS NULL OR jsonb_typeof(packet->'census') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'metadata fixture owner census result missing' USING ERRCODE='42501';END IF;
 closure:=kaname._authority_metadata_access_label_early_closure_v1(packet,catalog,
  99999-(packet->>'rows')::integer,4095-(packet->>'reads')::integer,399999-(packet->>'work')::integer);
 IF closure IS NULL OR jsonb_typeof(closure->'source_index') IS DISTINCT FROM 'object'
  OR jsonb_typeof(closure->'outputs') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'metadata fixture owner closure result missing' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_metadata_access_label_discovery_fence_v1(closure);
 SELECT c.finalized INTO STRICT finalized FROM pg_temp.kaname_authority_consumer c;
 IF finalized IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'metadata fixture discovery unexpectedly finalized consumer' USING ERRCODE='42501';END IF;
 SELECT coalesce(jsonb_agg(a.id ORDER BY a.id COLLATE "C"),'[]'::jsonb) INTO accounts
 FROM (SELECT DISTINCT e.value#>>'{source,id}' AS id FROM jsonb_each(closure->'source_index') e
  WHERE e.value#>>'{source,kind}'='23') a;
 SELECT coalesce(jsonb_agg(jsonb_build_object('Type',e.value->>'object_type','ID',e.value->>'object_id')
  ORDER BY e.key COLLATE "C"),'[]'::jsonb) INTO outputs FROM jsonb_each(closure->'outputs') e;
 RETURN jsonb_build_object('status','observed','invoker',session_user,
  'consumer_finalized',finalized,'fence_checked',true,'accounts',accounts,
  'historical_bindings',packet#>'{census,binding_ids}','outputs',outputs,
  'source_guards',closure->'carrier_source_guards',
  'rows',1+(packet->>'rows')::integer+(closure->>'rows')::integer,
  'reads',1+(packet->>'reads')::integer+(closure->>'reads')::integer,
  'work',1+(packet->>'work')::integer+(closure->>'work')::integer);
END;
$probe$;
DO $acl$
DECLARE recipient record;
BEGIN
 REVOKE ALL ON FUNCTION kaname.test_metadata_owner_prefinal(text,text,text,jsonb,jsonb) FROM PUBLIC;
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname.test_metadata_owner_prefinal(text,text,text,jsonb,jsonb)'::regprocedure AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.test_metadata_owner_prefinal(text,text,text,jsonb,jsonb) FROM %I',recipient.rolname);
 END LOOP;
END;
$acl$;
GRANT EXECUTE ON FUNCTION kaname.test_metadata_owner_prefinal(text,text,text,jsonb,jsonb) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	// Отдельный fixture grant не изменил ACL production функций.
	for _, signature := range signatures {
		var permitted bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, signature).Scan(&permitted))
		require.False(t, permitted)
	}
}
