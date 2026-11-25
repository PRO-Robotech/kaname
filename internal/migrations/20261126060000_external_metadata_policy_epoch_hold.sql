-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Внутренняя часть будущего резерва, между удержанием OLD/NEW и созданием
-- sequence-программы. Вход и режим берутся из текущей подписанной попытки.
-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_mirror_epoch_hold_v1()
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $hold$
DECLARE
 prepared jsonb; retained jsonb; old_row jsonb; new_row jsonb;
 dotted text; object_id text; account_id text; mode text;
 old_keys text[]; new_keys text[]; epoch_key text;
BEGIN
 prepared:=kaname._authority_metadata_access_label_stashed_v1();
 retained:=prepared->'retention';
 dotted:=retained->>'root_type';
 object_id:=retained->>'root_id';
 account_id:=prepared#>>'{root,census,root_scope_states,account,2,id}';
 mode:=prepared#>>'{plan,mode}';
 old_row:=retained->'old_row'; new_row:=retained->'new_row';
 IF coalesce(mode,'') NOT IN ('global','accounts')
  OR coalesce(account_id,'')='' OR coalesce(dotted,'')='' OR coalesce(object_id,'')=''
  OR split_part(dotted,'.',1)='iam'
  OR prepared#>'{root,root_coordinate}' IS DISTINCT FROM jsonb_build_array(dotted,object_id)
  OR retained#>>'{root_physical,table}' IS DISTINCT FROM 'resource_mirror'
  OR retained#>>'{root_physical,object_type}' IS DISTINCT FROM dotted
  OR retained#>>'{root_physical,id}' IS DISTINCT FROM object_id
  OR old_row->>'object_type' IS DISTINCT FROM dotted OR old_row->>'object_id' IS DISTINCT FROM object_id
  OR (old_row-ARRAY['labels','access_labels']) IS DISTINCT FROM (new_row-ARRAY['labels','access_labels'])
  OR old_row->'access_labels' IS NOT DISTINCT FROM new_row->'access_labels'
  OR (mode='accounts' AND NOT coalesce((prepared#>'{plan,accounts}') ? account_id,false))
  OR kaname._authority_sequence_store_v3() IS NOT NULL THEN
  RAISE EXCEPTION 'external metadata prefinal epoch reservation lacks held root' USING ERRCODE='42501';
 END IF;
 -- Изменение producer_source_receipt берёт запись '*'. Удержание корня
 -- в уже выбранном режиме стабилизирует классификацию до конца транзакции.
 IF mode='global' THEN
  PERFORM e.key FROM ONLY kaname.authority_policy_epoch e WHERE e.key='*' FOR UPDATE NOWAIT;
 ELSE
  PERFORM e.key FROM ONLY kaname.authority_policy_epoch e WHERE e.key='*' FOR SHARE NOWAIT;
 END IF;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'external metadata root policy epoch disappeared' USING ERRCODE='40001';
 END IF;
 old_keys:=kaname.authority_policy_keys('resource_mirror',old_row);
 new_keys:=kaname.authority_policy_keys('resource_mirror',new_row);
 IF old_keys IS DISTINCT FROM new_keys OR cardinality(old_keys) IS DISTINCT FROM 1
  OR old_keys[1] IS NULL OR old_keys[1] NOT IN ('*','scope:'||account_id) THEN
  RAISE EXCEPTION 'external metadata write epoch disagrees with held ownership' USING ERRCODE='42501';
 END IF;
 epoch_key:=old_keys[1];
 IF epoch_key='*' THEN
  IF mode<>'global' THEN
   RAISE EXCEPTION 'external metadata now requires global entry' USING ERRCODE='40001';
  END IF;
 ELSE
  -- Нужна и при GLOBAL из-за другой зависимости: statement trigger меняет
  -- саму типизированную строку, даже если корень уже эксклюзивно удержан.
  PERFORM e.key FROM ONLY kaname.authority_policy_epoch e WHERE e.key=epoch_key FOR UPDATE NOWAIT;
  IF NOT FOUND THEN
   RAISE EXCEPTION 'external metadata scoped policy epoch disappeared' USING ERRCODE='40001';
  END IF;
 END IF;
 RETURN epoch_key;
EXCEPTION WHEN lock_not_available THEN
 RAISE EXCEPTION 'external metadata policy epoch changed during reservation' USING ERRCODE='40001';
END;
$hold$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE recipient record;
BEGIN
 REVOKE ALL ON FUNCTION kaname._authority_metadata_mirror_epoch_hold_v1() FROM PUBLIC;
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_metadata_mirror_epoch_hold_v1()'::regprocedure AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_metadata_mirror_epoch_hold_v1() FROM %I',recipient.rolname);
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_mirror_epoch_hold_v1();
