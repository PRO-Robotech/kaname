-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Один прямой project/get, одна действующая выдача, уже одинаковые метки.
-- Получаем исходные строки только из удержанной программы этого backend.
-- Возвращаем точный OLD для будущей замены fingerprint; слот записи здесь не выбирается.
CREATE FUNCTION kaname._authority_role_move_active_project_witness_v1(p_coordinates jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $witness$
DECLARE
    program jsonb; prepared jsonb; decision jsonb; census jsonb; carrier jsonb; member_image jsonb; subject_row jsonb;
    old_rule jsonb; new_rule jsonb; project_coord jsonb; old_contribution jsonb; new_contribution jsonb;
    rid text; bid text; project_id text; account_id text; old_fp text; new_fp text;
    project_row jsonb; certified jsonb; claims jsonb; claim jsonb; ledger_rows jsonb;
    empty_delta constant jsonb := '{"upsert_members":{},"remove_members":{},"add_ledger":[],"remove_ledger":[]}';
    -- Не более двух координат, одного члена и девяти строк журнала.
    fixed_rows constant integer := 64;
    fixed_reads constant integer := 1;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN fixed_rows+1 AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN fixed_reads+1 AND 4096
        OR octet_length(p_coordinates::text)>65536 THEN
        RAISE EXCEPTION 'active project witness budget exceeded' USING ERRCODE='54000';
    END IF;
    IF jsonb_typeof(p_coordinates) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'active project coordinates must be an array' USING ERRCODE='42501';
    END IF;
    program:=kaname._authority_sequence_store_v3();
    prepared:=program#>'{frozen,selector_move}'; decision:=program#>'{frozen,selector_move_decision}';
    census:=prepared->'binding_census'; carrier:=census#>'{bindings,0,2}'; member_image:=census#>'{members,0}';
    subject_row:=census#>'{subjects,0,2}'; bid:=carrier->>'id'; rid:=prepared->>'role_id';
    project_id:=carrier#>>'{target,resources,0,id}'; account_id:=carrier->>'resource_id';
    old_rule:=prepared#>'{role,physical,2,rules,0}'; new_rule:=prepared#>'{role,new_role,rules,0}';
    IF program#>>'{frozen,mode}' IS DISTINCT FROM 'selector_move' OR program->'selected' IS DISTINCT FROM 'null'::jsonb
        OR prepared#>'{copies,roots}' IS DISTINCT FROM '{}'::jsonb OR decision->'commands' IS DISTINCT FROM '[]'::jsonb
        OR jsonb_array_length(census->'bindings') IS DISTINCT FROM 1 OR jsonb_array_length(census->'subjects') IS DISTINCT FROM 1
        OR jsonb_array_length(census->'members') IS DISTINCT FROM 1 OR coalesce(jsonb_array_length(census->'ledger'),0) NOT BETWEEN 2 AND 9
        OR coalesce(bid,'')='' OR coalesce(project_id,'')='' OR coalesce(account_id,'')='' OR coalesce(rid,'')=''
        OR carrier->>'role_id' IS DISTINCT FROM rid OR carrier->>'status' IS DISTINCT FROM 'ACTIVE'
        OR decision->'binding_status' IS DISTINCT FROM jsonb_build_object(bid,'ACTIVE')
        OR carrier->>'revoked_at' IS NOT NULL OR carrier->>'expires_at' IS NOT NULL OR carrier->>'resource_type' IS DISTINCT FROM 'account'
        OR carrier->'target' IS DISTINCT FROM jsonb_build_object('resources',jsonb_build_array(jsonb_build_object('type','iam.project','id',project_id)))
        OR subject_row->>'binding_id' IS DISTINCT FROM bid OR subject_row->>'subject_type' IS DISTINCT FROM 'user'
        OR jsonb_array_length(prepared#>'{role,physical,2,rules}') IS DISTINCT FROM 1
        OR jsonb_array_length(prepared#>'{role,new_role,rules}') IS DISTINCT FROM 1
        OR old_rule-'match_labels' IS DISTINCT FROM '{"module":"iam","resources":["project"],"verbs":["get"]}'::jsonb
        OR new_rule-'match_access_labels' IS DISTINCT FROM old_rule-'match_labels'
        OR jsonb_typeof(old_rule->'match_labels') IS DISTINCT FROM 'object' OR old_rule->'match_labels'='{}'::jsonb
        OR old_rule->'match_labels' IS DISTINCT FROM new_rule->'match_access_labels'
        OR jsonb_array_length(p_coordinates) IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'active project source outside direct no-copy form' USING ERRCODE='42501';
    END IF;
    project_row:=prepared#>ARRAY['member_projects','projects',project_id,'native','2'];
    IF project_row->>'id' IS DISTINCT FROM project_id OR project_row->>'account_id' IS DISTINCT FROM account_id
        OR project_row->'labels' IS DISTINCT FROM project_row->'access_labels'
        OR (project_row->'labels' @> (old_rule->'match_labels')) IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'active project labels do not agree' USING ERRCODE='42501';
    END IF;
    -- Сертификат пересчитывает OLD и NEW из каталога, сверяет весь физический census
    -- (xmin, ctid и содержимое), удерживает предикаты и возвращает точный diff по каждой координате.
    certified:=kaname._authority_role_move_binding_member_set_v1(bid,p_coordinates,p_rows-fixed_rows,p_reads-fixed_reads);
    SELECT x INTO STRICT project_coord FROM jsonb_array_elements(p_coordinates) x
        WHERE x->'Resource'=jsonb_build_object('Type','iam.project','ID',project_id);
    old_contribution:=project_coord#>'{Before,0}'; new_contribution:=project_coord#>'{Proposed,0}';
    old_fp:=old_contribution->>'RuleFP'; new_fp:=new_contribution->>'RuleFP'; claims:=certified->'before_claims';
    IF jsonb_array_length(project_coord->'Before') IS DISTINCT FROM 1 OR jsonb_array_length(project_coord->'Proposed') IS DISTINCT FROM 1
        OR old_contribution->>'Status' IS DISTINCT FROM 'ACTIVE' OR new_contribution->>'Status' IS DISTINCT FROM 'ACTIVE'
        OR coalesce(old_fp,'') !~ '^[0-9a-f]{64}$' OR coalesce(new_fp,'') !~ '^[0-9a-f]{64}$' OR old_fp=new_fp
        OR member_image#>>'{2,role_id}' IS DISTINCT FROM rid OR member_image#>>'{2,binding_id}' IS DISTINCT FROM bid
        OR member_image#>>'{2,object_type}' IS DISTINCT FROM 'iam.project' OR member_image#>>'{2,object_id}' IS DISTINCT FROM project_id
        OR member_image#>>'{2,verification_status}' IS DISTINCT FROM 'ACTIVE' OR member_image#>>'{2,rule_fp}' IS DISTINCT FROM old_fp
        OR member_image#>'{2,live}' IS DISTINCT FROM 'true'::jsonb
        OR certified->'effects' IS DISTINCT FROM jsonb_build_object('iam.account:'||account_id,empty_delta,
            'iam.project:'||project_id,empty_delta||jsonb_build_object('upsert_members',jsonb_build_object(new_fp,'ACTIVE'),
            'remove_members',jsonb_build_object(old_fp,'ACTIVE')))
        OR jsonb_typeof(claims) IS DISTINCT FROM 'object' OR claims='{}'::jsonb
        OR certified->'proposed_claims' IS DISTINCT FROM claims OR certified->'lost_claims' IS DISTINCT FROM '[]'::jsonb
        OR certified->'unclaimed_ledger' IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'active project member replacement changes rights or provenance' USING ERRCODE='42501';
    END IF;
    claim:=jsonb_build_object('User','user:'||(subject_row->>'subject_id'),'Object','project:'||project_id,'Relation','v_get');
    IF claims->(claim::text) IS DISTINCT FROM claim OR NOT EXISTS(SELECT FROM jsonb_array_elements(census->'ledger') l
        WHERE l#>>'{2,source}'='binding' AND l#>>'{2,binding_id}'=bid AND l#>>'{2,fga_user}'='account:'||account_id
        AND l#>>'{2,relation}'='account' AND l#>>'{2,object}'='iam_access_binding:'||bid
        AND coalesce(l#>>'{2,member_object_type}','')='' AND coalesce(l#>>'{2,member_object_id}','')='') THEN
        RAISE EXCEPTION 'active project read or binding anchor missing' USING ERRCODE='42501';
    END IF;
    SELECT coalesce(jsonb_object_agg(t::text,t),'{}'::jsonb) INTO ledger_rows FROM (
        SELECT jsonb_build_object('User',l#>'{2,fga_user}','Object',l#>'{2,object}','Relation',l#>'{2,relation}') t
        FROM jsonb_array_elements(census->'ledger') l WHERE l#>>'{2,binding_id}'=bid AND l#>>'{2,source}'='member'
        AND l#>>'{2,member_object_type}'='iam.project' AND l#>>'{2,member_object_id}'=project_id
        AND l#>>'{2,fga_user}'='user:'||(subject_row->>'subject_id') AND l#>>'{2,object}'='project:'||project_id
    ) member_tuples;
    IF ledger_rows IS DISTINCT FROM claims OR jsonb_array_length(census->'ledger')<>(SELECT 1+count(*) FROM jsonb_object_keys(claims)) THEN
        RAISE EXCEPTION 'active project physical ledger differs from effective grants' USING ERRCODE='42501';
    END IF;
    RETURN jsonb_build_object('role_id',rid,'binding_id',bid,'project_id',project_id,'member_old',member_image,
        'new_rule_fp',new_fp,'ledger_sha256',encode(sha256(convert_to((census->'ledger')::text,'UTF8')),'hex'),
        'nonce',program->'nonce','decision_at',decision->'decision_at','xid',program->'transaction_id',
        'rows',fixed_rows+(certified->>'rows')::integer,'reads',fixed_reads+(certified->>'reads')::integer);
END;
$witness$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure:='kaname._authority_role_move_active_project_witness_v1(jsonb,integer,integer)'::regprocedure; grantee record;
BEGIN
    FOR grantee IN SELECT a.grantee,r.rolname FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a LEFT JOIN pg_roles r ON r.oid=a.grantee
        WHERE p.oid=fn AND a.grantee<>p.proowner GROUP BY a.grantee,r.rolname LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_role_move_active_project_witness_v1(jsonb,integer,integer);
