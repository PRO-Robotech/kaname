-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Scope membership only. The named-object predicate belongs to the direct
-- compiler. Role/subject provenance, expiration, Apply and Grant still need
-- their own held proof before protected labels can be written.
CREATE FUNCTION kaname._authority_resource_first_registration_scope_bindings_v1(
 p_index jsonb,p_receipt jsonb,p_scopes jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $census$
DECLARE
 manifest jsonb; absence jsonb; account_id text; project_id text;
 coord record; expected jsonb; actual jsonb; ids jsonb; valid boolean;
 candidates jsonb:='[]'; counts jsonb:='[]'; used_rows integer;
BEGIN
 PERFORM kaname._authority_access_label_generation_latch_require_v1(false);
 IF p_rows IS NULL OR p_rows NOT BETWEEN 1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 21 AND 4096
  OR octet_length(p_scopes::text)::bigint+octet_length(p_index::text)::bigint>67108864 THEN
  RAISE EXCEPTION 'first registration census budget exceeded' USING ERRCODE='54000';
 END IF;
 IF jsonb_typeof(p_scopes) IS DISTINCT FROM 'array' OR jsonb_array_length(p_scopes) IS DISTINCT FROM 4 THEN
  RAISE EXCEPTION 'first registration scope inventory incomplete' USING ERRCODE='42501';
 END IF;
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'prepared' THEN
  RAISE EXCEPTION 'first registration census requires prepared manifest' USING ERRCODE='42501';
 END IF;
 absence:=kaname._authority_resource_first_registration_absence_v1(
  manifest->'registration_certificate',p_index,p_receipt,p_rows-1,p_reads-5);
 project_id:=absence->>'project_id'; account_id:=absence->>'account_id';
 -- The direct compiler took the physical root SHARE and owner UPDATE before
 -- constructing this transaction's manifest. Its getter verifies the locks.
 -- An access_bindings change on these axes bumps the owner or root epoch.
 IF NOT coalesce(manifest->'binding_epoch_share_scopes' ? '',false)
  OR NOT coalesce(manifest->'binding_epoch_write_scopes' ? account_id,false)
  OR jsonb_typeof((manifest#>'{epoch_lock_witness,binding_after}')->'') IS DISTINCT FROM 'array'
  OR jsonb_typeof((manifest#>'{epoch_lock_witness,binding_after}')->account_id) IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'first registration binding epochs missing' USING ERRCODE='42501';
 END IF;
 PERFORM kaname._authority_resource_preheld_key_v2(1262569297,'',false);
 PERFORM kaname._authority_resource_preheld_key_v2(1262569297,account_id,true);
 used_rows:=1+(absence->>'logical_rows')::integer;
 FOR coord IN SELECT * FROM (VALUES
  (0,49,'project',project_id,3),(1,49,'account',account_id,2),
  (2,49,'cluster','cluster_root',1),(3,50,'cluster','cluster_root',1)
 ) AS c(pos,kind,typ,id,tier) LOOP
  expected:=p_scopes->coord.pos;
  IF jsonb_typeof(expected->'states') IS DISTINCT FROM 'array'
   OR expected-'states' IS DISTINCT FROM jsonb_build_object('kind',coord.kind,'type',coord.typ,'id',coord.id,'projection','') THEN
   RAISE EXCEPTION 'first registration scope predicate differs' USING ERRCODE='42501';
  END IF;
  IF jsonb_array_length(expected->'states')>p_rows-used_rows THEN
   RAISE EXCEPTION 'first registration scope rows exceeded' USING ERRCODE='54000';
  END IF;
  -- Same witnesses and byte ordering as the Go RR source. Limit the scan
  -- before sorting. Revoked rows remain part of equality, including on the
  -- noncanonical cluster axis. Only unrevoked role carriers are candidates.
  SELECT coalesce(jsonb_agg(s.state ORDER BY s.state COLLATE "C"),'[]'),
   coalesce(jsonb_agg(s.id ORDER BY s.id COLLATE "C") FILTER (WHERE s.status<>'REVOKED'),'[]'),
   coalesce(bool_and(s.id<>'' AND octet_length(s.id)<=16384 AND s.id !~ '[[:space:][:cntrl:]:#*]'
    AND (s.status='REVOKED' OR (s.status IN ('ACTIVE','PENDING') AND s.revoked_at IS NULL
     AND coord.kind=49 AND s.scope=coord.tier AND s.role_id<>'' AND s.granted_relation=''))),true)
  INTO actual,ids,valid FROM (
   SELECT jsonb_build_array(b.xmin::text,b.ctid::text,to_jsonb(b))::text state,
    b.id,b.status,b.revoked_at,b.scope,b.role_id,b.granted_relation
   FROM ONLY kaname.access_bindings b WHERE b.resource_type=coord.typ AND b.role_id IS NOT NULL
    AND ((coord.kind=49 AND b.resource_id=coord.id) OR (coord.kind=50 AND b.resource_id IS DISTINCT FROM coord.id))
   LIMIT (jsonb_array_length(expected->'states')+1)
  ) s;
  used_rows:=used_rows+jsonb_array_length(actual);
  IF used_rows>p_rows THEN RAISE EXCEPTION 'first registration scope rows exceeded' USING ERRCODE='54000'; END IF;
  IF actual IS DISTINCT FROM expected->'states' THEN
   RAISE EXCEPTION 'first registration scope bindings changed' USING ERRCODE='P1034';
  END IF;
  IF valid IS DISTINCT FROM true THEN
   RAISE EXCEPTION 'first registration role carrier scope unconfirmed' USING ERRCODE='42501';
  END IF;
  candidates:=candidates||ids; counts:=counts||jsonb_build_array(jsonb_array_length(actual));
 END LOOP;
 RETURN absence||jsonb_build_object('absence_reads',absence->'logical_reads','logical_rows',used_rows,
  'logical_reads',5+(absence->>'logical_reads')::integer,'scope_counts',counts,'scope_binding_ids',candidates);
END;
$census$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure:='kaname._authority_resource_first_registration_scope_bindings_v1(jsonb,jsonb,jsonb,integer,integer)'::regprocedure; recipient record;
BEGIN
 EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',fn);
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',fn,recipient.rolname);
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_resource_first_registration_scope_bindings_v1(jsonb,jsonb,jsonb,integer,integer);
