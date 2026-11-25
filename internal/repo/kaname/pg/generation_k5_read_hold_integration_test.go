// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestGenerationBindingReadHoldSignedAbsentPredicate(t *testing.T) {
	if testing.Short() {
		t.Skip("требуется PostgreSQL")
	}
	r := writerProtocolRig(t)
	_, _ = fullContractActivate(t, r)
	const dotted, model, otherModel = "vpc.network", "vpc_network", "compute_instance"
	const id = "generation-k5/absent"
	const signature = "kaname._authority_access_label_generation_binding_read_hold_v1(jsonb,jsonb,jsonb,integer,integer,integer)"
	var private bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT NOT p.prosecdef
 AND p.proowner=(SELECT relowner FROM pg_class WHERE oid='kaname.authority_writer_protocol'::regclass)
 AND NOT has_function_privilege($1,p.oid,'EXECUTE')
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner)
 FROM pg_proc p WHERE p.oid=$2::regprocedure`, r.role, signature).Scan(&private))
	require.True(t, private, "новый helper остаётся приватным INVOKER владельца")
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_root
 (root_type,root_id,generation,new_labels) VALUES($1,$2,gen_random_uuid(),'{}')`, dotted, id)
	require.NoError(t, err)

	// Порт снимает настоящие физические входы фикстуры. Он не подменяет
	// attestation, не создаёт receipt и не берёт advisory lock вместо helper.
	// Эти SELECT подготовки данных не входят в измеряемую стоимость helper.
	_, err = r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_generation_binding_read_hold(
 p_rows integer,p_reads integer) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $port$
 DECLARE proof jsonb;root_state jsonb;k5_states jsonb;source_key text;graph_key text;capture jsonb;certificate jsonb;idx jsonb;model text;held jsonb;
 BEGIN
  proof:=kaname.authority_protocol_attestation();
  IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
   OR proof->>'purpose' IS DISTINCT FROM 'participant'
   OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_pending'
   OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
   OR (proof->>'invoker_oid')::oid IS DISTINCT FROM session_user::regrole::oid
   OR current_setting('transaction_isolation')<>'read committed' THEN
   RAISE EXCEPTION 'fixture requires original signed pending runtime' USING ERRCODE='42501';END IF;
  SELECT c.object_type INTO STRICT model FROM kaname.catalog_resource c
   WHERE c.dotted='vpc.network' AND c.live;
  IF model IS DISTINCT FROM 'vpc_network' THEN
   RAISE EXCEPTION 'fixture catalog model changed' USING ERRCODE='42501';END IF;
  SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) INTO STRICT root_state
   FROM kaname.authority_access_label_dirty_root r
   WHERE r.root_type='vpc.network' AND r.root_id='generation-k5/absent';
  IF EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_fact f
   WHERE f.root_type='vpc.network' AND f.root_id='generation-k5/absent') THEN
   RAISE EXCEPTION 'fixture root unexpectedly has dirty facts' USING ERRCODE='42501';END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_array(b.xmin::text,b.ctid::text,to_jsonb(b))), '[]'::jsonb)
   INTO k5_states FROM kaname.object_project_binding b
   WHERE b.object_type=model AND b.object_id='generation-k5/absent';
  IF k5_states<>'[]'::jsonb THEN
   RAISE EXCEPTION 'fixture requires actual absent K5 predicate' USING ERRCODE='42501';END IF;
  graph_key:=jsonb_build_array('vpc.network','generation-k5/absent')::text;
  source_key:=jsonb_build_array(5,model,'generation-k5/absent','')::text;
  capture:=jsonb_build_object('roots',jsonb_build_array(jsonb_build_object(
   'state',root_state,'facts','[]'::jsonb,'fact_states','[]'::jsonb)));
  certificate:=jsonb_build_object('graphs',jsonb_build_object(graph_key,jsonb_build_object(
   'object_type','vpc.network','object_id','generation-k5/absent','model_type',model)),
   'required',jsonb_build_object(source_key,true));
  idx:=jsonb_build_object(source_key,jsonb_build_object('source',jsonb_build_object(
   'kind',5,'type',model,'id','generation-k5/absent'),'states',k5_states));
  held:=kaname._authority_access_label_generation_binding_read_hold_v1(capture,certificate,idx,p_rows,p_reads,1);
  proof:=kaname.authority_protocol_attestation();
  IF proof->>'consumer_finalized' IS DISTINCT FROM 'false' THEN
   RAISE EXCEPTION 'fixture requires consumer pending after K5 hold' USING ERRCODE='42501';END IF;
  RETURN held;
 END;
 $port$;
 DO $seal$
 DECLARE recipient record;
 BEGIN
  REVOKE ALL ON FUNCTION kaname.test_generation_binding_read_hold(integer,integer) FROM PUBLIC;
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_proc p
   CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   JOIN pg_roles r ON r.oid=a.grantee
   WHERE p.oid='kaname.test_generation_binding_read_hold(integer,integer)'::regprocedure AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.test_generation_binding_read_hold(integer,integer) FROM %I',recipient.rolname);
  END LOOP;
 END; $seal$;
 GRANT EXECUTE ON FUNCTION kaname.test_generation_binding_read_hold(integer,integer) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	probeGenerationK5ReadHold(t, r, model, otherModel, id, 0, 4,
		func(tx pgx.Tx, rows, reads int) (int, int, error) {
			var raw []byte
			err := tx.QueryRow(r.ctx, `SELECT kaname.test_generation_binding_read_hold($1,$2)`, rows, reads).Scan(&raw)
			if err != nil {
				return 0, 0, err
			}
			var result struct {
				Rows  int `json:"rows"`
				Reads int `json:"reads"`
			}
			if err = json.Unmarshal(raw, &result); err != nil {
				return 0, 0, err
			}
			var shared bool
			err = tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks l
 WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.classid=1262569300::oid
 AND l.objid=(hashtext(jsonb_build_array($1::text,$2::text)::text)::bigint & 4294967295)::oid
 AND l.objsubid=2 AND l.mode='ShareLock' AND l.granted)`, model, id).Scan(&shared)
			if err == nil {
				require.True(t, shared, "read hold должен быть shared, не exclusive")
			}
			return result.Rows, result.Reads, err
		})
}
