-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- Оба триггера сверяют действительные OLD/NEW с одной ожидающей командой.
-- AFTER устанавливает поколение раньше регистрации и расходования номера журнала.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_trigger_v1(
    p_rel oid,p_name text,p_timing text,p_old jsonb,p_new jsonb,p_xmin text,p_ctid text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $trigger$
DECLARE
    command jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF pg_trigger_depth()<>1 OR p_rel IS DISTINCT FROM 'kaname.groups'::regclass::oid
        OR (p_timing,p_name) IS DISTINCT FROM ('BEFORE'::text,'access_labels_immutable'::text)
        AND (p_timing,p_name) IS DISTINCT FROM ('AFTER'::text,'access_labels_000_commit_freshness'::text) THEN
        RAISE EXCEPTION 'group metadata trigger context differs' USING ERRCODE='42501';
    END IF;
    command:=kaname._authority_metadata_group_command_v1();
    IF command->>'phase' IS DISTINCT FROM 'pending' OR command->'journal_consumed' IS DISTINCT FROM 'false'::jsonb
        OR command->'freshness_installed' IS DISTINCT FROM 'false'::jsonb
        OR command->'old' IS DISTINCT FROM p_old OR command->'new' IS DISTINCT FROM p_new
        OR command#>>'{physical,xmin}' IS DISTINCT FROM p_xmin OR command#>>'{physical,ctid}' IS DISTINCT FROM p_ctid THEN
        RAISE EXCEPTION 'group metadata trigger differs from exact pending update' USING ERRCODE='42501';
    END IF;
    RETURN command;
END;
$trigger$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure:='kaname._authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)'::regprocedure; recipient record;
BEGIN
    FOR recipient IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
        WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
            CASE WHEN recipient.grantee=0 THEN 'PUBLIC' ELSE quote_ident(recipient.rolname) END);
    END LOOP;
END;
$private$;
-- +goose StatementEnd

CREATE TRIGGER access_labels_000_commit_freshness AFTER UPDATE ON kaname.groups
FOR EACH ROW WHEN (OLD.access_labels IS DISTINCT FROM NEW.access_labels)
EXECUTE FUNCTION kaname._authority_metadata_access_label_freshness_v1();

-- +goose StatementBegin
DO $storage_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
    ('access_labels_immutable_v1()','acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036','16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a',
    $changes$[
  [
    "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror')",
    "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror','groups')"
  ],
  [
    " IF kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text) IS NOT NULL THEN RETURN NEW;END IF;",
    " IF TG_TABLE_NAME='groups' THEN\n  PERFORM kaname._authority_metadata_group_trigger_v1(TG_RELID,TG_NAME,TG_WHEN,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n  RETURN NEW;\n END IF;\n IF kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text) IS NOT NULL THEN RETURN NEW;END IF;"
  ]
]$changes$::jsonb),
    ('_authority_metadata_access_label_freshness_v1()','0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e','63c255a81eb0a63397307671b06f1279a493899018ce54bc924fc19bbf35c5c6',
    $changes$[
  [
    "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror')",
    "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror','groups')"
  ],
  [
    " move_root:=kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n IF move_root IS NOT NULL THEN",
    " IF TG_TABLE_NAME<>'groups' THEN\n  move_root:=kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n END IF;\n IF TG_TABLE_NAME='groups' THEN\n  command:=kaname._authority_metadata_group_trigger_v1(TG_RELID,TG_NAME,TG_WHEN,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n ELSIF move_root IS NOT NULL THEN"
  ]
]$changes$::jsonb),
    ('_authority_sequence_complete_v3()','4d590ae391a2bff05a7c8346055fa364b342ac290a58079372a661dffffb28e5','8e151549f6e4ee12f3dc51003e59ecd3b0464fafaee7f484fde45b3cd4874850',
    $changes$[
  [
    " IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='external_access_labels' THEN",
    " IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='group_access_labels' THEN\n  PERFORM kaname._authority_metadata_group_complete_v1();\n END IF;\n IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='external_access_labels' THEN"
  ]
]$changes$::jsonb),
    ('authority_access_label_storage_valid_v1()','a64e35aa7a1e913aef34260331117978538d81740fcdbe24fd413344f95f7b74','386496cce2788809e1e66715a31b93285c2533e411a72b606e5c6e9063d9d7c2',
    $changes$[
  [
    "acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036",
    "16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a"
  ]
]$changes$::jsonb),
    ('authority_metadata_access_label_ready_v2(text)','bdb897e826d43c2a1c9c2f9ead3f7192c80dc1ef8bc2dd64931ca330b852c39e','c3e85a3fddbb3b68e9ae040afc09a2242aca1f54f017a3c447ea4c5b6911fced',
    $changes$[
  [
    "0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e",
    "63c255a81eb0a63397307671b06f1279a493899018ce54bc924fc19bbf35c5c6"
  ],
  [
    " FOREACH target IN ARRAY ARRAY['accounts','projects','resource_mirror'] LOOP",
    " FOREACH target IN ARRAY ARRAY['accounts','projects','resource_mirror','groups'] LOOP"
  ]
]$changes$::jsonb),
    ('_authority_crud_storage_v3()','713fda666ed49ca5d9858740a8093a6fa13476a056a6a7a87a868682950266fa','340900a3ba449ae39faab747b0dbdb844fd528c319c90899e8682fdc5db78d91',
    $changes$[
  [
    "acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036",
    "16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a"
  ],
  [
    "0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e",
    "63c255a81eb0a63397307671b06f1279a493899018ce54bc924fc19bbf35c5c6"
  ],
  [
    "4d590ae391a2bff05a7c8346055fa364b342ac290a58079372a661dffffb28e5",
    "8e151549f6e4ee12f3dc51003e59ecd3b0464fafaee7f484fde45b3cd4874850"
  ],
  [
    " ('_authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text)','347ce6b789b9a8334216f7a202949fd833ead9154bf0178371536078ccf9f523',false,'v',true,'private'),",
    " ('_authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text)','347ce6b789b9a8334216f7a202949fd833ead9154bf0178371536078ccf9f523',false,'v',true,'private'),\n ('_authority_metadata_group_command_v1()','3104067d898986dfd59143b0442236c26ee258fa8fa28e5783b299449b52e208',false,'v',true,'private'),\n ('_authority_metadata_group_output_versions_v1(jsonb)','105d39221c8d2ca14978d7db368c7bfe5a43854f6baac4d7f60735dfbbc4223b',false,'v',true,'private'),\n ('_authority_metadata_group_consume_v1(jsonb)','59844b861dfef890a90e92affb80ed1b1b458053b67a8a1e51511f573b0f8b46',false,'v',true,'private'),\n ('_authority_metadata_group_complete_v1()','30147ad90d393299f557c9a9c85e15d214da9e8798315a078a07d25553c15e02',false,'v',true,'private'),\n ('_authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','d93726479a48982fdc6fd435d5c00ac997eea17bf59183a79a5ab594745227aa',false,'v',true,'private'),"
  ],
  [
    "  ('_authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text)','jsonb',5,ARRAY['p_rel','p_old','p_new','p_xmin','p_ctid']),",
    "  ('_authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text)','jsonb',5,ARRAY['p_rel','p_old','p_new','p_xmin','p_ctid']),\n  ('_authority_metadata_group_command_v1()','jsonb',0,NULL::text[]),\n  ('_authority_metadata_group_output_versions_v1(jsonb)','jsonb',1,ARRAY['p_command']),\n  ('_authority_metadata_group_consume_v1(jsonb)','void',1,ARRAY['p_root_version']),\n  ('_authority_metadata_group_complete_v1()','void',0,NULL::text[]),\n  ('_authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','jsonb',7,ARRAY['p_rel','p_name','p_timing','p_old','p_new','p_xmin','p_ctid']),"
  ]
]$changes$::jsonb),
    ('_authority_full_contract_storage_v3()','a220bd43eeed2accacb9c7b02f4abcdc14cf53f9ec75bac242921eccd8016722','f608fe1d4c44496bc9392176c3f687a960ab0eb4145563c8fbbc10a76d7d7e71',
    $changes$[
  [
    "713fda666ed49ca5d9858740a8093a6fa13476a056a6a7a87a868682950266fa",
    "340900a3ba449ae39faab747b0dbdb844fd528c319c90899e8682fdc5db78d91"
  ]
]$changes$::jsonb),
    ('authority_metadata_service_account_access_label_ready_v1()','cf60acefa0bb27eaf5a0ae35fd43d317b9de387e56df31b1023b4f01ce9a41c4','f0f70bf324e747620a4f97059720a7e6eb9920a81e1ed0df4d56a8d8c8fe0efc',
    $changes$[
  [
    "acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036",
    "16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a"
  ],
  [
    "0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e",
    "63c255a81eb0a63397307671b06f1279a493899018ce54bc924fc19bbf35c5c6"
  ],
  [
    "a64e35aa7a1e913aef34260331117978538d81740fcdbe24fd413344f95f7b74",
    "386496cce2788809e1e66715a31b93285c2533e411a72b606e5c6e9063d9d7c2"
  ],
  [
    "bdb897e826d43c2a1c9c2f9ead3f7192c80dc1ef8bc2dd64931ca330b852c39e",
    "c3e85a3fddbb3b68e9ae040afc09a2242aca1f54f017a3c447ea4c5b6911fced"
  ],
  [
    "713fda666ed49ca5d9858740a8093a6fa13476a056a6a7a87a868682950266fa",
    "340900a3ba449ae39faab747b0dbdb844fd528c319c90899e8682fdc5db78d91"
  ],
  [
    "a220bd43eeed2accacb9c7b02f4abcdc14cf53f9ec75bac242921eccd8016722",
    "f608fe1d4c44496bc9392176c3f687a960ab0eb4145563c8fbbc10a76d7d7e71"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'group metadata trigger contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'group metadata trigger contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group metadata trigger contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group metadata trigger contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true
        OR kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'group metadata trigger contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage_contract$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP TRIGGER access_labels_000_commit_freshness ON kaname.groups;

-- +goose StatementBegin
DO $storage_contract$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
    ('authority_metadata_service_account_access_label_ready_v1()','f0f70bf324e747620a4f97059720a7e6eb9920a81e1ed0df4d56a8d8c8fe0efc','cf60acefa0bb27eaf5a0ae35fd43d317b9de387e56df31b1023b4f01ce9a41c4',
    $changes$[
  [
    "f608fe1d4c44496bc9392176c3f687a960ab0eb4145563c8fbbc10a76d7d7e71",
    "a220bd43eeed2accacb9c7b02f4abcdc14cf53f9ec75bac242921eccd8016722"
  ],
  [
    "340900a3ba449ae39faab747b0dbdb844fd528c319c90899e8682fdc5db78d91",
    "713fda666ed49ca5d9858740a8093a6fa13476a056a6a7a87a868682950266fa"
  ],
  [
    "c3e85a3fddbb3b68e9ae040afc09a2242aca1f54f017a3c447ea4c5b6911fced",
    "bdb897e826d43c2a1c9c2f9ead3f7192c80dc1ef8bc2dd64931ca330b852c39e"
  ],
  [
    "386496cce2788809e1e66715a31b93285c2533e411a72b606e5c6e9063d9d7c2",
    "a64e35aa7a1e913aef34260331117978538d81740fcdbe24fd413344f95f7b74"
  ],
  [
    "63c255a81eb0a63397307671b06f1279a493899018ce54bc924fc19bbf35c5c6",
    "0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e"
  ],
  [
    "16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a",
    "acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036"
  ]
]$changes$::jsonb),
    ('_authority_full_contract_storage_v3()','f608fe1d4c44496bc9392176c3f687a960ab0eb4145563c8fbbc10a76d7d7e71','a220bd43eeed2accacb9c7b02f4abcdc14cf53f9ec75bac242921eccd8016722',
    $changes$[
  [
    "340900a3ba449ae39faab747b0dbdb844fd528c319c90899e8682fdc5db78d91",
    "713fda666ed49ca5d9858740a8093a6fa13476a056a6a7a87a868682950266fa"
  ]
]$changes$::jsonb),
    ('_authority_crud_storage_v3()','340900a3ba449ae39faab747b0dbdb844fd528c319c90899e8682fdc5db78d91','713fda666ed49ca5d9858740a8093a6fa13476a056a6a7a87a868682950266fa',
    $changes$[
  [
    "  ('_authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text)','jsonb',5,ARRAY['p_rel','p_old','p_new','p_xmin','p_ctid']),\n  ('_authority_metadata_group_command_v1()','jsonb',0,NULL::text[]),\n  ('_authority_metadata_group_output_versions_v1(jsonb)','jsonb',1,ARRAY['p_command']),\n  ('_authority_metadata_group_consume_v1(jsonb)','void',1,ARRAY['p_root_version']),\n  ('_authority_metadata_group_complete_v1()','void',0,NULL::text[]),\n  ('_authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','jsonb',7,ARRAY['p_rel','p_name','p_timing','p_old','p_new','p_xmin','p_ctid']),",
    "  ('_authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text)','jsonb',5,ARRAY['p_rel','p_old','p_new','p_xmin','p_ctid']),"
  ],
  [
    " ('_authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text)','347ce6b789b9a8334216f7a202949fd833ead9154bf0178371536078ccf9f523',false,'v',true,'private'),\n ('_authority_metadata_group_command_v1()','3104067d898986dfd59143b0442236c26ee258fa8fa28e5783b299449b52e208',false,'v',true,'private'),\n ('_authority_metadata_group_output_versions_v1(jsonb)','105d39221c8d2ca14978d7db368c7bfe5a43854f6baac4d7f60735dfbbc4223b',false,'v',true,'private'),\n ('_authority_metadata_group_consume_v1(jsonb)','59844b861dfef890a90e92affb80ed1b1b458053b67a8a1e51511f573b0f8b46',false,'v',true,'private'),\n ('_authority_metadata_group_complete_v1()','30147ad90d393299f557c9a9c85e15d214da9e8798315a078a07d25553c15e02',false,'v',true,'private'),\n ('_authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text)','d93726479a48982fdc6fd435d5c00ac997eea17bf59183a79a5ab594745227aa',false,'v',true,'private'),",
    " ('_authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text)','347ce6b789b9a8334216f7a202949fd833ead9154bf0178371536078ccf9f523',false,'v',true,'private'),"
  ],
  [
    "8e151549f6e4ee12f3dc51003e59ecd3b0464fafaee7f484fde45b3cd4874850",
    "4d590ae391a2bff05a7c8346055fa364b342ac290a58079372a661dffffb28e5"
  ],
  [
    "63c255a81eb0a63397307671b06f1279a493899018ce54bc924fc19bbf35c5c6",
    "0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e"
  ],
  [
    "16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a",
    "acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036"
  ]
]$changes$::jsonb),
    ('authority_metadata_access_label_ready_v2(text)','c3e85a3fddbb3b68e9ae040afc09a2242aca1f54f017a3c447ea4c5b6911fced','bdb897e826d43c2a1c9c2f9ead3f7192c80dc1ef8bc2dd64931ca330b852c39e',
    $changes$[
  [
    " FOREACH target IN ARRAY ARRAY['accounts','projects','resource_mirror','groups'] LOOP",
    " FOREACH target IN ARRAY ARRAY['accounts','projects','resource_mirror'] LOOP"
  ],
  [
    "63c255a81eb0a63397307671b06f1279a493899018ce54bc924fc19bbf35c5c6",
    "0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e"
  ]
]$changes$::jsonb),
    ('authority_access_label_storage_valid_v1()','386496cce2788809e1e66715a31b93285c2533e411a72b606e5c6e9063d9d7c2','a64e35aa7a1e913aef34260331117978538d81740fcdbe24fd413344f95f7b74',
    $changes$[
  [
    "16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a",
    "acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036"
  ]
]$changes$::jsonb),
    ('_authority_sequence_complete_v3()','8e151549f6e4ee12f3dc51003e59ecd3b0464fafaee7f484fde45b3cd4874850','4d590ae391a2bff05a7c8346055fa364b342ac290a58079372a661dffffb28e5',
    $changes$[
  [
    " IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='group_access_labels' THEN\n  PERFORM kaname._authority_metadata_group_complete_v1();\n END IF;\n IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='external_access_labels' THEN",
    " IF program->>'family'='metadata' AND program#>>'{frozen,mode}'='external_access_labels' THEN"
  ]
]$changes$::jsonb),
    ('_authority_metadata_access_label_freshness_v1()','63c255a81eb0a63397307671b06f1279a493899018ce54bc924fc19bbf35c5c6','0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e',
    $changes$[
  [
    " IF TG_TABLE_NAME<>'groups' THEN\n  move_root:=kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n END IF;\n IF TG_TABLE_NAME='groups' THEN\n  command:=kaname._authority_metadata_group_trigger_v1(TG_RELID,TG_NAME,TG_WHEN,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n ELSIF move_root IS NOT NULL THEN",
    " move_root:=kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n IF move_root IS NOT NULL THEN"
  ],
  [
    "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror','groups')",
    "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror')"
  ]
]$changes$::jsonb),
    ('access_labels_immutable_v1()','16b35a4968271c58e6eaadcee5f1f181e682abdbe21a31ea434cea268f3f153a','acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036',
    $changes$[
  [
    " IF TG_TABLE_NAME='groups' THEN\n  PERFORM kaname._authority_metadata_group_trigger_v1(TG_RELID,TG_NAME,TG_WHEN,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n  RETURN NEW;\n END IF;\n IF kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text) IS NOT NULL THEN RETURN NEW;END IF;",
    " IF kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text) IS NOT NULL THEN RETURN NEW;END IF;"
  ],
  [
    "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror','groups')",
    "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror')"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'group metadata trigger contract predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'group metadata trigger contract replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group metadata trigger contract body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'group metadata trigger contract installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_access_label_freshness_storage_v1() IS DISTINCT FROM true
        OR kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'group metadata trigger contract storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage_contract$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_metadata_group_trigger_v1(oid,text,text,jsonb,jsonb,text,text);
