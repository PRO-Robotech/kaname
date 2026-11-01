-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- САНКЦИЯ: docs/engineering/acceptance/kaname-derives-the-parent-of-a-registered-object.md
-- САНКЦИЯ: docs/engineering/acceptance/service-account-creation-is-its-own-right.md
-- kaname#1020: explicit reconciliation of the two historical 20261026090000
-- lineages (#982 and #1003). Main 90000 remains byte-identical. The other SQL
-- is archived verbatim under historical/ (sha256 bd9449a671136b68ae82ce38edabbe2801a056fd4f7919fde769406be7bced29).
-- No goose history is rewritten. Product migrator uses WithAllowMissing(), so
-- feature installations already at 120000 execute this missing 90001 too.
-- Recognize COMPLETE definitions, never infer deployment from a missing record.
-- All recognition precedes persistent mutation; unexpected partial state fails.
-- +goose Up

-- Отказ до первого DDL, в том числе создания вспомогательных функций.
-- +goose StatementBegin
DO $isolation$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'registration lineage migration requires READ COMMITTED'
            USING ERRCODE='25001';
    END IF;
END
$isolation$;
-- +goose StatementEnd

-- The same guard protects our inverse and the original archived 90000 body.
-- It runs inside that Goose transaction, after excluding concurrent writers.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.registration_lineage_assert_unused(side text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, kaname AS $unused$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'registration lineage migration requires READ COMMITTED'
            USING ERRCODE='25001';
    END IF;
    LOCK TABLE kaname.catalog_resource, kaname.catalog_verb,
               kaname.service_accounts, kaname.role_rule_selectors,
               kaname.roles, kaname.relation_fact IN ACCESS EXCLUSIVE MODE;
    IF side='writer' THEN
        -- Exact harmless values installed by this migration. New declarations
        -- are meaningful policy and cannot be discarded by schema rollback.
        IF EXISTS (SELECT 1 FROM kaname.catalog_resource c
                    WHERE c.writes <> '{}'::text[] OR c.parent_names IS DISTINCT FROM
                      CASE WHEN c.module='registry' AND c.resource='repositories'
                           THEN ARRAY['parent']::text[] ELSE c.parent_types END) THEN
            RAISE EXCEPTION '90000 lineage rollback would discard writer policy'
                USING ERRCODE='23514', CONSTRAINT='registration_lineage_lossless_down';
        END IF;
    ELSIF side='creator' THEN
        IF EXISTS (SELECT 1 FROM kaname.service_accounts WHERE created_by_type IS NOT NULL OR created_by_id IS NOT NULL)
           OR EXISTS (SELECT 1 FROM kaname.role_rule_selectors WHERE created_by_subject)
           OR EXISTS (SELECT 1 FROM kaname.roles WHERE name='iam.service_account.creator'
                       OR jsonb_path_exists(rules,'$.**.created_by_subject'))
           OR EXISTS (SELECT 1 FROM kaname.relation_fact WHERE relation='service_account_creator')
           OR EXISTS (SELECT 1 FROM kaname.catalog_verb
                       WHERE (module='iam' AND resource='serviceAccount' AND verb='create' AND live
                              AND ROW(container_parent,container_relation) IS DISTINCT FROM ROW('account'::text,'service_account_creator'::text))
                          OR (NOT (module='iam' AND resource='serviceAccount' AND verb='create' AND live)
                              AND (container_parent IS NOT NULL OR container_relation IS NOT NULL))) THEN
            RAISE EXCEPTION '90000 lineage rollback would discard creator facts or rights'
                USING ERRCODE='23514', CONSTRAINT='registration_lineage_lossless_down';
        END IF;
    ELSE
        RAISE EXCEPTION 'unknown registration lineage side';
    END IF;
END
$unused$;
-- +goose StatementEnd

-- A bounded schema identity: only objects belonging to the two 90000 sides.
-- Later independent migrations are not provenance for these definitions.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.registration_lineage_shape() RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, kaname AS $shape$
WITH columns_of_interest(table_name, column_name) AS (VALUES
 ('catalog_resource','parent_names'), ('catalog_resource','writes'),
 ('catalog_verb','container_parent'), ('catalog_verb','container_relation'),
 ('service_accounts','created_by_type'), ('service_accounts','created_by_id'),
 ('role_rule_selectors','created_by_subject')),
parts AS (
 SELECT 'column/'||i.table_name||'/'||i.column_name AS key,
        jsonb_build_array(a.atttypid,a.atttypmod,a.attnotnull,a.attcollation,
          a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) AS value
 FROM columns_of_interest i
 JOIN pg_attribute a ON a.attrelid=('kaname.'||i.table_name)::regclass
  AND a.attname=i.column_name AND NOT a.attisdropped
 LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 UNION ALL
 SELECT 'constraint/'||c.conrelid::regclass::text||'/'||c.conname,
        jsonb_build_array(c.contype,c.convalidated,c.condeferrable,c.condeferred,pg_get_constraintdef(c.oid))
 FROM pg_constraint c WHERE c.connamespace='kaname'::regnamespace AND c.conname IN
 ('catalog_resource_parent_names_form','catalog_resource_writes_form',
  'catalog_verb_container_pair_ck','catalog_verb_container_is_tier_ck','catalog_verb_container_relation_form_ck',
  'service_accounts_creator_pair_ck','service_accounts_creator_type_ck','service_accounts_creator_id_nonempty_ck',
  'role_rule_selectors_creator_is_top_anchor_ck')
 UNION ALL
 SELECT 'function/'||p.proname, to_jsonb(pg_get_functiondef(p.oid))
 FROM pg_proc p WHERE p.pronamespace='kaname'::regnamespace
  AND p.proname IN ('iam_rules_valid','service_account_creator_is_immutable')
 UNION ALL
 SELECT 'index/service_accounts_creator_idx',
        jsonb_build_array(pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready,i.indislive)
 FROM pg_index i WHERE i.indexrelid=to_regclass('kaname.service_accounts_creator_idx')
 UNION ALL
 SELECT 'trigger/service_account_creator_is_immutable',
        jsonb_build_array(pg_get_triggerdef(t.oid),t.tgenabled)
 FROM pg_trigger t WHERE t.tgrelid='kaname.service_accounts'::regclass
  AND t.tgname='service_account_creator_is_immutable')
SELECT jsonb_object_agg(key,value) FROM parts;
$shape$;
-- +goose StatementEnd
-- Исходные тела сверяются и при распознавании, и при проверке происхождения.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.registration_lineage_rules_source(creator boolean) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $sources$
SELECT CASE WHEN creator THEN $new_rules$
DECLARE
    rule       jsonb;
    child      jsonb;
    arr        jsonb;
    has_names  boolean;
    has_labels boolean;
BEGIN
    IF rules IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(rules) <> 'array' THEN RETURN false; END IF;
    -- Empty array is valid (legacy permissions-only role; back-compat).
    IF jsonb_array_length(rules) = 0 THEN RETURN true; END IF;
    IF jsonb_array_length(rules) > 64 THEN RETURN false; END IF;

    FOR rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(rule) <> 'object' THEN RETURN false; END IF;

        -- module: required, non-empty string scalar. The array `modules` key is
        -- NO LONGER valid.
        IF NOT (rule ? 'module') THEN RETURN false; END IF;
        IF jsonb_typeof(rule -> 'module') <> 'string' THEN RETURN false; END IF;
        IF length(rule ->> 'module') < 1 THEN RETURN false; END IF;

        -- resources / verbs: required non-empty string arrays, 1..16.
        FOR arr IN SELECT rule -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
            IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END LOOP;

        has_names  := (rule ? 'resource_names') AND jsonb_typeof(rule -> 'resource_names') <> 'null';
        has_labels := (rule ? 'match_labels')   AND jsonb_typeof(rule -> 'match_labels')   <> 'null';

        -- resource_names XOR match_labels (both → reject).
        IF has_names AND has_labels THEN RETURN false; END IF;

        IF has_names THEN
            IF jsonb_typeof(rule -> 'resource_names') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resource_names') > 256 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(rule -> 'resource_names') e
                       WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END IF;

        IF has_labels THEN
            IF jsonb_typeof(rule -> 'match_labels') <> 'object' THEN RETURN false; END IF;
            IF (SELECT count(*) FROM jsonb_object_keys(rule -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                RETURN false;
            END IF;
        END IF;

        -- Селектор создателя (kaname#1003, Р2а). Ключа нет — селектора нет; ключ
        -- пишется только значением true (второго способа сказать «нет» хранимая
        -- форма не несёт). Селектор у правила один: не с resource_names и не с
        -- match_labels. Вид объекта назван поимённо: ни модуль, ни ресурс не
        -- подстановка. Вложенных правил у правила с селектором нет.
        IF rule ? 'created_by_subject' THEN
            IF jsonb_typeof(rule -> 'created_by_subject') <> 'boolean' THEN RETURN false; END IF;
            IF NOT (rule -> 'created_by_subject')::boolean THEN RETURN false; END IF;
            IF has_names OR has_labels THEN RETURN false; END IF;
            IF rule ->> 'module' = '*' THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(rule -> 'resources') e WHERE e = '*') THEN
                RETURN false;
            END IF;
            IF rule ? 'children' THEN RETURN false; END IF;
        END IF;

        -- Вложенные правила (kaname#874). Ключа нет — правило без вложенных.
        IF rule ? 'children' THEN
            IF jsonb_typeof(rule -> 'children') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'children') NOT BETWEEN 1 AND 16 THEN RETURN false; END IF;
            -- Владелец — ровно один ресурс, не подстановка, модуль не подстановка.
            IF rule ->> 'module' = '*' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resources') <> 1 THEN RETURN false; END IF;
            IF rule -> 'resources' ->> 0 = '*' THEN RETURN false; END IF;

            FOR child IN SELECT value FROM jsonb_array_elements(rule -> 'children') LOOP
                IF jsonb_typeof(child) <> 'object' THEN RETURN false; END IF;
                -- Модуль — владельца; глубину выражает тип, а не структура роли.
                IF child ? 'module' OR child ? 'children' THEN RETURN false; END IF;
                FOR arr IN SELECT child -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
                    IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END LOOP;
                -- Вложенное называет тип: не подстановку и не тип владельца.
                IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(child -> 'resources') e
                            WHERE e = '*' OR e = rule -> 'resources' ->> 0) THEN
                    RETURN false;
                END IF;

                has_names  := (child ? 'resource_names') AND jsonb_typeof(child -> 'resource_names') <> 'null';
                has_labels := (child ? 'match_labels')   AND jsonb_typeof(child -> 'match_labels')   <> 'null';
                IF has_names AND has_labels THEN RETURN false; END IF;
                IF has_names THEN
                    IF jsonb_typeof(child -> 'resource_names') <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(child -> 'resource_names') > 256 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(child -> 'resource_names') e
                               WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END IF;
                IF has_labels THEN
                    IF jsonb_typeof(child -> 'match_labels') <> 'object' THEN RETURN false; END IF;
                    IF (SELECT count(*) FROM jsonb_object_keys(child -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                        RETURN false;
                    END IF;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    RETURN true;
END;
$new_rules$ ELSE $old_rules$
DECLARE
    rule       jsonb;
    child      jsonb;
    arr        jsonb;
    has_names  boolean;
    has_labels boolean;
BEGIN
    IF rules IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(rules) <> 'array' THEN RETURN false; END IF;
    -- Empty array is valid (legacy permissions-only role; back-compat).
    IF jsonb_array_length(rules) = 0 THEN RETURN true; END IF;
    IF jsonb_array_length(rules) > 64 THEN RETURN false; END IF;

    FOR rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(rule) <> 'object' THEN RETURN false; END IF;

        -- module: required, non-empty string scalar. The array `modules` key is
        -- NO LONGER valid.
        IF NOT (rule ? 'module') THEN RETURN false; END IF;
        IF jsonb_typeof(rule -> 'module') <> 'string' THEN RETURN false; END IF;
        IF length(rule ->> 'module') < 1 THEN RETURN false; END IF;

        -- resources / verbs: required non-empty string arrays, 1..16.
        FOR arr IN SELECT rule -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
            IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END LOOP;

        has_names  := (rule ? 'resource_names') AND jsonb_typeof(rule -> 'resource_names') <> 'null';
        has_labels := (rule ? 'match_labels')   AND jsonb_typeof(rule -> 'match_labels')   <> 'null';

        -- resource_names XOR match_labels (both → reject).
        IF has_names AND has_labels THEN RETURN false; END IF;

        IF has_names THEN
            IF jsonb_typeof(rule -> 'resource_names') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resource_names') > 256 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(rule -> 'resource_names') e
                       WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END IF;

        IF has_labels THEN
            IF jsonb_typeof(rule -> 'match_labels') <> 'object' THEN RETURN false; END IF;
            IF (SELECT count(*) FROM jsonb_object_keys(rule -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                RETURN false;
            END IF;
        END IF;

        -- Вложенные правила (kaname#874). Ключа нет — правило без вложенных.
        IF rule ? 'children' THEN
            IF jsonb_typeof(rule -> 'children') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'children') NOT BETWEEN 1 AND 16 THEN RETURN false; END IF;
            -- Владелец — ровно один ресурс, не подстановка, модуль не подстановка.
            IF rule ->> 'module' = '*' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resources') <> 1 THEN RETURN false; END IF;
            IF rule -> 'resources' ->> 0 = '*' THEN RETURN false; END IF;

            FOR child IN SELECT value FROM jsonb_array_elements(rule -> 'children') LOOP
                IF jsonb_typeof(child) <> 'object' THEN RETURN false; END IF;
                -- Модуль — владельца; глубину выражает тип, а не структура роли.
                IF child ? 'module' OR child ? 'children' THEN RETURN false; END IF;
                FOR arr IN SELECT child -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
                    IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END LOOP;
                -- Вложенное называет тип: не подстановку и не тип владельца.
                IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(child -> 'resources') e
                            WHERE e = '*' OR e = rule -> 'resources' ->> 0) THEN
                    RETURN false;
                END IF;

                has_names  := (child ? 'resource_names') AND jsonb_typeof(child -> 'resource_names') <> 'null';
                has_labels := (child ? 'match_labels')   AND jsonb_typeof(child -> 'match_labels')   <> 'null';
                IF has_names AND has_labels THEN RETURN false; END IF;
                IF has_names THEN
                    IF jsonb_typeof(child -> 'resource_names') <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(child -> 'resource_names') > 256 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(child -> 'resource_names') e
                               WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END IF;
                IF has_labels THEN
                    IF jsonb_typeof(child -> 'match_labels') <> 'object' THEN RETURN false; END IF;
                    IF (SELECT count(*) FROM jsonb_object_keys(child -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                        RETURN false;
                    END IF;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    RETURN true;
END;
$old_rules$ END;
$sources$;
-- +goose StatementEnd

-- Формат 2 связывает флаги с ПОЛНЫМ исходным набором определений.
-- Ни один SQL-оператор из marker не исполняется.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.registration_lineage_origin_matches(
    original jsonb, complete jsonb, creator boolean, writer boolean) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, kaname AS $origin$
WITH keys(key,side) AS (VALUES
 ('function/iam_rules_valid','common'),
 ('column/catalog_resource/parent_names','writer'), ('column/catalog_resource/writes','writer'),
 ('constraint/catalog_resource/catalog_resource_parent_names_form','writer'),
 ('constraint/catalog_resource/catalog_resource_writes_form','writer'),
 ('column/catalog_verb/container_parent','creator'), ('column/catalog_verb/container_relation','creator'),
 ('column/service_accounts/created_by_type','creator'), ('column/service_accounts/created_by_id','creator'),
 ('column/role_rule_selectors/created_by_subject','creator'),
 ('constraint/catalog_verb/catalog_verb_container_pair_ck','creator'),
 ('constraint/catalog_verb/catalog_verb_container_is_tier_ck','creator'),
 ('constraint/catalog_verb/catalog_verb_container_relation_form_ck','creator'),
 ('constraint/service_accounts/service_accounts_creator_pair_ck','creator'),
 ('constraint/service_accounts/service_accounts_creator_type_ck','creator'),
 ('constraint/service_accounts/service_accounts_creator_id_nonempty_ck','creator'),
 ('constraint/role_rule_selectors/role_rule_selectors_creator_is_top_anchor_ck','creator'),
 ('function/service_account_creator_is_immutable','creator'),
 ('index/service_accounts_creator_idx','creator'), ('trigger/service_account_creator_is_immutable','creator')),
expected AS (
 SELECT jsonb_object_agg(key, CASE WHEN key='function/iam_rules_valid' AND NOT creator
    THEN to_jsonb(replace(complete->>key,kaname.registration_lineage_rules_source(true),
                         kaname.registration_lineage_rules_source(false)))
    ELSE complete->key END) AS shape
 FROM keys WHERE side='common' OR (side='creator' AND creator) OR (side='writer' AND writer))
SELECT coalesce((creator OR writer)
 AND jsonb_typeof(original)='object' AND jsonb_typeof(complete)='object'
 AND (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(complete) k)
     = (SELECT array_agg(key ORDER BY key) FROM keys)
 AND NOT EXISTS (SELECT 1 FROM jsonb_each(complete) WHERE value='null'::jsonb)
 AND strpos(complete->>'function/iam_rules_valid',kaname.registration_lineage_rules_source(true))>0
 AND original=(SELECT shape FROM expected),false);
$origin$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $reconcile$
DECLARE
    v_main_count integer;
    v_feature_count integer;
    v_main boolean;
    v_feature boolean;
    v_pair record;
    v_actual oid;
    v_expected oid;
    v_function oid;
    v_rules_source text;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'registration lineage migration requires READ COMMITTED'
            USING ERRCODE='25001';
    END IF;
    LOCK TABLE kaname.catalog_resource, kaname.catalog_verb,
               kaname.service_accounts, kaname.role_rule_selectors,
               kaname.roles, kaname.relation_fact IN ACCESS EXCLUSIVE MODE;
    -- Expected definitions are parsed by this server, avoiding version-sensitive
    -- hand-written pg_get_constraintdef/default pretty-print comparisons.
    CREATE TEMP TABLE registration_expected_resource (
        parent_types text[],
        parent_names text[] NOT NULL DEFAULT '{}'::text[],
        writes text[] NOT NULL DEFAULT '{}'::text[],
        CONSTRAINT catalog_resource_parent_names_form CHECK (
            array_position(parent_names, NULL) IS NULL
            AND cardinality(parent_names) = cardinality(parent_types)
            AND (cardinality(parent_names) = 0 OR array_to_string(parent_names, ',') ~ '^[a-z][a-z0-9_]*(,[a-z][a-z0-9_]*)*$')),
        CONSTRAINT catalog_resource_writes_form CHECK (
            array_position(writes, NULL) IS NULL AND (cardinality(writes) = 0
            OR array_to_string(writes, ',') ~ '^[a-z][a-z0-9_]*:(user|service_account)(,[a-z][a-z0-9_]*:(user|service_account))*$'))
    ) ON COMMIT DROP;
    CREATE TEMP TABLE registration_expected_verb (
        per_object boolean, container_parent text, container_relation text,
        CONSTRAINT catalog_verb_container_pair_ck CHECK ((container_parent IS NULL) = (container_relation IS NULL)),
        CONSTRAINT catalog_verb_container_is_tier_ck CHECK (container_relation IS NULL OR NOT per_object),
        CONSTRAINT catalog_verb_container_relation_form_ck CHECK (container_relation IS NULL OR (container_relation ~ '^[a-z][a-z0-9_]*$' AND container_relation !~ '^v_'))
    ) ON COMMIT DROP;
    CREATE TEMP TABLE registration_expected_account (
        account_id text, created_by_type text, created_by_id text,
        CONSTRAINT service_accounts_creator_pair_ck CHECK ((created_by_type IS NULL) = (created_by_id IS NULL)),
        CONSTRAINT service_accounts_creator_type_ck CHECK (created_by_type IS NULL OR created_by_type IN ('user', 'service_account')),
        CONSTRAINT service_accounts_creator_id_nonempty_ck CHECK (created_by_id IS NULL OR created_by_id <> '')
    ) ON COMMIT DROP;
    CREATE INDEX registration_expected_creator_idx ON registration_expected_account(account_id,created_by_id)
        WHERE created_by_type = 'service_account';
    CREATE TEMP TABLE registration_expected_selector (
        arm text, container_type text, created_by_subject boolean NOT NULL DEFAULT false,
        CONSTRAINT role_rule_selectors_creator_is_top_anchor_ck CHECK (NOT created_by_subject OR (arm = 'anchor' AND container_type IS NULL))
    ) ON COMMIT DROP;

    SELECT count(*) INTO v_feature_count FROM pg_attribute
     WHERE attrelid='kaname.catalog_resource'::regclass AND NOT attisdropped
       AND attname IN ('parent_names','writes');
    SELECT count(*) INTO v_main_count FROM pg_attribute
     WHERE NOT attisdropped AND ((attrelid='kaname.catalog_verb'::regclass AND attname IN ('container_parent','container_relation'))
        OR (attrelid='kaname.service_accounts'::regclass AND attname IN ('created_by_type','created_by_id'))
        OR (attrelid='kaname.role_rule_selectors'::regclass AND attname='created_by_subject'));
    IF v_feature_count NOT IN (0,2) OR v_main_count NOT IN (0,5) THEN
        RAISE EXCEPTION '90000 lineage reconciliation: partial columns; no changes applied';
    END IF;
    v_feature := v_feature_count=2;
    v_main := v_main_count=5;
    IF (SELECT count(*) FROM pg_proc WHERE pronamespace='kaname'::regnamespace
         AND proname IN ('iam_rules_valid','service_account_creator_is_immutable'))
       <> (CASE WHEN v_main THEN 2 ELSE 1 END) THEN
        RAISE EXCEPTION '90000 lineage reconciliation: unexpected function overload';
    END IF;

    FOR v_pair IN SELECT * FROM (VALUES
        ('kaname.catalog_resource','registration_expected_resource',ARRAY['parent_names','writes']::text[],v_feature),
        ('kaname.catalog_verb','registration_expected_verb',ARRAY['container_parent','container_relation']::text[],v_main),
        ('kaname.service_accounts','registration_expected_account',ARRAY['created_by_type','created_by_id']::text[],v_main),
        ('kaname.role_rule_selectors','registration_expected_selector',ARRAY['created_by_subject']::text[],v_main)
    ) AS t(actual,expected,columns,present) LOOP
        v_actual := v_pair.actual::regclass;
        v_expected := ('pg_temp.'||v_pair.expected)::regclass;
        IF v_pair.present THEN
            IF EXISTS (
                SELECT 1 FROM pg_attribute e
                LEFT JOIN pg_attribute a ON a.attrelid=v_actual AND a.attname=e.attname AND NOT a.attisdropped
                LEFT JOIN pg_attrdef ed ON ed.adrelid=e.attrelid AND ed.adnum=e.attnum
                LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum
                WHERE e.attrelid=v_expected AND e.attname=ANY(v_pair.columns)
                  AND (a.attnum IS NULL OR
                       ROW(a.atttypid,a.atttypmod,a.attnotnull,a.attcollation,a.attidentity,a.attgenerated,pg_get_expr(ad.adbin,ad.adrelid))
                       IS DISTINCT FROM
                       ROW(e.atttypid,e.atttypmod,e.attnotnull,e.attcollation,e.attidentity,e.attgenerated,pg_get_expr(ed.adbin,ed.adrelid)))
            ) OR EXISTS (
                SELECT 1 FROM pg_constraint e
                LEFT JOIN pg_constraint a ON a.conrelid=v_actual AND a.conname=e.conname
                WHERE e.conrelid=v_expected AND
                    (a.oid IS NULL OR ROW(a.contype,a.convalidated,a.condeferrable,a.condeferred,pg_get_constraintdef(a.oid))
                     IS DISTINCT FROM ROW(e.contype,e.convalidated,e.condeferrable,e.condeferred,pg_get_constraintdef(e.oid)))
            ) THEN
                RAISE EXCEPTION '90000 lineage reconciliation: unexpected definition in %, no changes applied',v_pair.actual;
            END IF;
        ELSIF EXISTS (SELECT 1 FROM pg_constraint a JOIN pg_constraint e ON e.conrelid=v_expected AND e.conname=a.conname WHERE a.conrelid=v_actual) THEN
            RAISE EXCEPTION '90000 lineage reconciliation: constraints without complete columns in %',v_pair.actual;
        END IF;
    END LOOP;

    v_function := to_regprocedure('kaname.service_account_creator_is_immutable()');
    IF v_main THEN
        IF v_function IS NULL OR NOT EXISTS (
            SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
             WHERE p.oid=v_function AND p.prosrc=$creator_source$
BEGIN
    IF NEW.created_by_type IS DISTINCT FROM OLD.created_by_type
       OR NEW.created_by_id IS DISTINCT FROM OLD.created_by_id THEN
        RAISE EXCEPTION 'service account % creator is immutable', OLD.id
            USING ERRCODE = '23514', CONSTRAINT = 'service_accounts_creator_immutable';
    END IF;
    RETURN NEW;
END;
$creator_source$
               AND l.lanname='plpgsql' AND p.provolatile='v' AND NOT p.prosecdef
               AND p.proconfig IS NULL AND p.prorettype='trigger'::regtype
        ) OR NOT EXISTS (
            SELECT 1 FROM pg_trigger t WHERE t.tgrelid='kaname.service_accounts'::regclass
             AND t.tgname='service_account_creator_is_immutable' AND t.tgfoid=v_function
             AND t.tgtype=19 AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgnargs=0
             AND t.tgqual IS NULL AND t.tgconstraint=0
             AND ARRAY(SELECT a.attname::text FROM unnest(t.tgattr::smallint[]) WITH ORDINALITY n(attnum,ord)
                       JOIN pg_attribute a ON a.attrelid=t.tgrelid AND a.attnum=n.attnum ORDER BY n.ord)
                 =ARRAY['created_by_type','created_by_id']::text[]
        ) THEN
            RAISE EXCEPTION '90000 lineage reconciliation: creator guard differs; no changes applied';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM pg_index a JOIN pg_class ac ON ac.oid=a.indexrelid JOIN pg_am am ON am.oid=ac.relam,
                          pg_index e
             WHERE a.indexrelid=to_regclass('kaname.service_accounts_creator_idx')
               AND a.indrelid='kaname.service_accounts'::regclass
               AND e.indexrelid='pg_temp.registration_expected_creator_idx'::regclass
               AND am.amname='btree' AND a.indisvalid AND a.indisready AND a.indislive
               AND NOT a.indisunique AND NOT a.indisprimary AND NOT a.indisexclusion
               AND a.indnkeyatts=2 AND a.indnatts=2
               AND pg_get_indexdef(a.indexrelid,1,false)=pg_get_indexdef(e.indexrelid,1,false)
               AND pg_get_indexdef(a.indexrelid,2,false)=pg_get_indexdef(e.indexrelid,2,false)
               AND pg_get_expr(a.indpred,a.indrelid)=pg_get_expr(e.indpred,e.indrelid)
        ) THEN
            RAISE EXCEPTION '90000 lineage reconciliation: creator index differs; no changes applied';
        END IF;
        v_rules_source := kaname.registration_lineage_rules_source(true);
    ELSE
        IF v_function IS NOT NULL OR to_regclass('kaname.service_accounts_creator_idx') IS NOT NULL
           OR EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='kaname.service_accounts'::regclass AND tgname='service_account_creator_is_immutable') THEN
            RAISE EXCEPTION '90000 lineage reconciliation: creator objects without columns; no changes applied';
        END IF;
        v_rules_source := kaname.registration_lineage_rules_source(false);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
         WHERE p.oid='kaname.iam_rules_valid(jsonb)'::regprocedure AND p.prosrc=v_rules_source
           AND l.lanname='plpgsql' AND p.provolatile='i' AND NOT p.prosecdef
           AND p.proconfig IS NULL AND p.prorettype='boolean'::regtype
    ) THEN
        RAISE EXCEPTION '90000 lineage reconciliation: rule validator differs; no changes applied';
    END IF;

    IF NOT v_main AND NOT v_feature THEN
        RAISE EXCEPTION '90000 lineage reconciliation: neither original lineage exists';
    END IF;
    IF to_regclass('kaname.registration_lineage_origin') IS NOT NULL THEN
        -- Only our completed inverse can be upgraded again. A preexisting
        -- unmarked/converged installation is never assigned invented history.
        IF (SELECT count(*) FROM kaname.registration_lineage_origin) <> 1 OR NOT EXISTS (
            SELECT 1 FROM kaname.registration_lineage_origin
             WHERE singleton AND format_version=2 AND state='down'
               AND had_creator=v_main AND had_writer=v_feature
               AND original_shape=kaname.registration_lineage_shape()
               AND kaname.registration_lineage_origin_matches(original_shape,complete_shape,had_creator,had_writer)) THEN
            RAISE EXCEPTION '90000 lineage reconciliation: invalid retained provenance';
        END IF;
    ELSE
        CREATE TABLE kaname.registration_lineage_origin (
            singleton boolean PRIMARY KEY CHECK (singleton),
            format_version integer NOT NULL CHECK (format_version=2),
            had_creator boolean NOT NULL,
            had_writer boolean NOT NULL,
            state text NOT NULL CHECK (state IN ('up','down')),
            complete_shape jsonb NOT NULL,
            original_shape jsonb NOT NULL,
            CHECK (had_creator OR had_writer)
        );
        REVOKE ALL ON kaname.registration_lineage_origin FROM PUBLIC;
        INSERT INTO kaname.registration_lineage_origin
            VALUES (true,2,v_main,v_feature,'up','{}',kaname.registration_lineage_shape());
    END IF;

    -- Existing data, including post-deployment catalog changes, is never replayed.
    -- Only a completely absent lineage runs its exact original Up body.
    IF NOT v_main THEN
        EXECUTE $main_ddl$

-- 1. Контейнерное действие в каталоге.
ALTER TABLE kaname.catalog_verb
    ADD COLUMN container_parent text,
    ADD COLUMN container_relation text,
    ADD CONSTRAINT catalog_verb_container_pair_ck
        CHECK ((container_parent IS NULL) = (container_relation IS NULL)),
    ADD CONSTRAINT catalog_verb_container_is_tier_ck
        CHECK (container_relation IS NULL OR NOT per_object),
    ADD CONSTRAINT catalog_verb_container_relation_form_ck
        CHECK (container_relation IS NULL OR (container_relation ~ '^[a-z][a-z0-9_]*$' AND container_relation !~ '^v_'));

COMMENT ON COLUMN kaname.catalog_verb.container_relation IS
    'Контейнерное действие (kaname#1003, Р2а): отношение на родителе типа container_parent, которое даёт поимённо названное действие. NULL — действие не контейнерное.';

UPDATE kaname.catalog_verb
   SET container_parent = 'account', container_relation = 'service_account_creator'
 WHERE module = 'iam' AND resource = 'serviceAccount' AND verb = 'create' AND live;

-- 2. Факт создателя учётки.
ALTER TABLE kaname.service_accounts
    ADD COLUMN created_by_type text,
    ADD COLUMN created_by_id text,
    ADD CONSTRAINT service_accounts_creator_pair_ck
        CHECK ((created_by_type IS NULL) = (created_by_id IS NULL)),
    ADD CONSTRAINT service_accounts_creator_type_ck
        CHECK (created_by_type IS NULL OR created_by_type IN ('user', 'service_account')),
    ADD CONSTRAINT service_accounts_creator_id_nonempty_ck
        CHECK (created_by_id IS NULL OR created_by_id <> '');

COMMENT ON COLUMN kaname.service_accounts.created_by_id IS
    'Факт создателя (kaname#1003, Р4): принципал, вызвавший ServiceAccountService.Create. Неизменяем (service_account_creator_is_immutable); наружу не выдаётся.';

CREATE INDEX service_accounts_creator_idx
    ON kaname.service_accounts (account_id, created_by_id)
 WHERE created_by_type = 'service_account';

CREATE FUNCTION kaname.service_account_creator_is_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.created_by_type IS DISTINCT FROM OLD.created_by_type
       OR NEW.created_by_id IS DISTINCT FROM OLD.created_by_id THEN
        RAISE EXCEPTION 'service account % creator is immutable', OLD.id
            USING ERRCODE = '23514', CONSTRAINT = 'service_accounts_creator_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER service_account_creator_is_immutable
    BEFORE UPDATE OF created_by_type, created_by_id ON kaname.service_accounts
    FOR EACH ROW EXECUTE FUNCTION kaname.service_account_creator_is_immutable();

-- 3. Селектор создателя у строки селектора правила роли.
ALTER TABLE kaname.role_rule_selectors
    ADD COLUMN created_by_subject boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT role_rule_selectors_creator_is_top_anchor_ck
        CHECK (NOT created_by_subject OR (arm = 'anchor' AND container_type IS NULL));

COMMENT ON COLUMN kaname.role_rule_selectors.created_by_subject IS
    'Селектор создателя (kaname#1003, Р2а): глагол правила действует только на объекте, создатель которого — субъект выдачи.';

-- 4. Хранимая форма правила роли.
CREATE OR REPLACE FUNCTION kaname.iam_rules_valid(rules jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    rule       jsonb;
    child      jsonb;
    arr        jsonb;
    has_names  boolean;
    has_labels boolean;
BEGIN
    IF rules IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(rules) <> 'array' THEN RETURN false; END IF;
    -- Empty array is valid (legacy permissions-only role; back-compat).
    IF jsonb_array_length(rules) = 0 THEN RETURN true; END IF;
    IF jsonb_array_length(rules) > 64 THEN RETURN false; END IF;

    FOR rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(rule) <> 'object' THEN RETURN false; END IF;

        -- module: required, non-empty string scalar. The array `modules` key is
        -- NO LONGER valid.
        IF NOT (rule ? 'module') THEN RETURN false; END IF;
        IF jsonb_typeof(rule -> 'module') <> 'string' THEN RETURN false; END IF;
        IF length(rule ->> 'module') < 1 THEN RETURN false; END IF;

        -- resources / verbs: required non-empty string arrays, 1..16.
        FOR arr IN SELECT rule -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
            IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END LOOP;

        has_names  := (rule ? 'resource_names') AND jsonb_typeof(rule -> 'resource_names') <> 'null';
        has_labels := (rule ? 'match_labels')   AND jsonb_typeof(rule -> 'match_labels')   <> 'null';

        -- resource_names XOR match_labels (both → reject).
        IF has_names AND has_labels THEN RETURN false; END IF;

        IF has_names THEN
            IF jsonb_typeof(rule -> 'resource_names') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resource_names') > 256 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(rule -> 'resource_names') e
                       WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END IF;

        IF has_labels THEN
            IF jsonb_typeof(rule -> 'match_labels') <> 'object' THEN RETURN false; END IF;
            IF (SELECT count(*) FROM jsonb_object_keys(rule -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                RETURN false;
            END IF;
        END IF;

        -- Селектор создателя (kaname#1003, Р2а). Ключа нет — селектора нет; ключ
        -- пишется только значением true (второго способа сказать «нет» хранимая
        -- форма не несёт). Селектор у правила один: не с resource_names и не с
        -- match_labels. Вид объекта назван поимённо: ни модуль, ни ресурс не
        -- подстановка. Вложенных правил у правила с селектором нет.
        IF rule ? 'created_by_subject' THEN
            IF jsonb_typeof(rule -> 'created_by_subject') <> 'boolean' THEN RETURN false; END IF;
            IF NOT (rule -> 'created_by_subject')::boolean THEN RETURN false; END IF;
            IF has_names OR has_labels THEN RETURN false; END IF;
            IF rule ->> 'module' = '*' THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(rule -> 'resources') e WHERE e = '*') THEN
                RETURN false;
            END IF;
            IF rule ? 'children' THEN RETURN false; END IF;
        END IF;

        -- Вложенные правила (kaname#874). Ключа нет — правило без вложенных.
        IF rule ? 'children' THEN
            IF jsonb_typeof(rule -> 'children') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'children') NOT BETWEEN 1 AND 16 THEN RETURN false; END IF;
            -- Владелец — ровно один ресурс, не подстановка, модуль не подстановка.
            IF rule ->> 'module' = '*' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resources') <> 1 THEN RETURN false; END IF;
            IF rule -> 'resources' ->> 0 = '*' THEN RETURN false; END IF;

            FOR child IN SELECT value FROM jsonb_array_elements(rule -> 'children') LOOP
                IF jsonb_typeof(child) <> 'object' THEN RETURN false; END IF;
                -- Модуль — владельца; глубину выражает тип, а не структура роли.
                IF child ? 'module' OR child ? 'children' THEN RETURN false; END IF;
                FOR arr IN SELECT child -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
                    IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END LOOP;
                -- Вложенное называет тип: не подстановку и не тип владельца.
                IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(child -> 'resources') e
                            WHERE e = '*' OR e = rule -> 'resources' ->> 0) THEN
                    RETURN false;
                END IF;

                has_names  := (child ? 'resource_names') AND jsonb_typeof(child -> 'resource_names') <> 'null';
                has_labels := (child ? 'match_labels')   AND jsonb_typeof(child -> 'match_labels')   <> 'null';
                IF has_names AND has_labels THEN RETURN false; END IF;
                IF has_names THEN
                    IF jsonb_typeof(child -> 'resource_names') <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(child -> 'resource_names') > 256 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(child -> 'resource_names') e
                               WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END IF;
                IF has_labels THEN
                    IF jsonb_typeof(child -> 'match_labels') <> 'object' THEN RETURN false; END IF;
                    IF (SELECT count(*) FROM jsonb_object_keys(child -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                        RETURN false;
                    END IF;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    RETURN true;
END;
$$;


$main_ddl$;
    END IF;
    IF NOT v_feature THEN
        EXECUTE $feature_ddl$
ALTER TABLE kaname.catalog_resource
    ADD COLUMN parent_names text[] NOT NULL DEFAULT '{}'::text[],
    ADD COLUMN writes text[] NOT NULL DEFAULT '{}'::text[];

UPDATE kaname.catalog_resource c
   SET parent_names = c.parent_types
 WHERE cardinality(c.parent_types) > 0;

UPDATE kaname.catalog_resource c
   SET parent_names = v.names
  FROM (VALUES
        ('registry', 'repositories', ARRAY['parent']::text[])
       ) AS v(module, resource, names)
 WHERE c.module = v.module AND c.resource = v.resource;

ALTER TABLE kaname.catalog_resource
    ADD CONSTRAINT catalog_resource_parent_names_form
        CHECK (array_position(parent_names, NULL) IS NULL
               AND cardinality(parent_names) = cardinality(parent_types)
               AND (cardinality(parent_names) = 0
                    OR array_to_string(parent_names, ',') ~ '^[a-z][a-z0-9_]*(,[a-z][a-z0-9_]*)*$')),
    ADD CONSTRAINT catalog_resource_writes_form
        CHECK (array_position(writes, NULL) IS NULL
               AND (cardinality(writes) = 0
                    OR array_to_string(writes, ',')
                       ~ '^[a-z][a-z0-9_]*:(user|service_account)(,[a-z][a-z0-9_]*:(user|service_account))*$'));

COMMENT ON COLUMN kaname.catalog_resource.parent_names IS 'Имена указателей ресурса (parents манифеста), позиционно парные parent_types: политика записи модуля адресует указатель именем отношения. Пусто — у строки нет указателей. kaname#982.';
COMMENT ON COLUMN kaname.catalog_resource.writes IS 'Отношения сверх указателя, которые модуль пишет сам (writes манифеста), парами «отношение:тип субъекта». Вместе с указателями — закрытая политика записи модуля; регистрация вне неё отвергается. Пусто — модуль пишет только указатель. kaname#982.';

$feature_ddl$;
    END IF;
    UPDATE kaname.registration_lineage_origin
       SET state='up', complete_shape=kaname.registration_lineage_shape();
    IF NOT EXISTS (SELECT 1 FROM kaname.registration_lineage_origin
                    WHERE kaname.registration_lineage_origin_matches(
                        original_shape,complete_shape,had_creator,had_writer)) THEN
        RAISE EXCEPTION '90000 lineage reconciliation: original definitions differ';
    END IF;
END
$reconcile$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $inverse$
DECLARE
    v_creator boolean;
    v_writer boolean;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'registration lineage migration requires READ COMMITTED'
            USING ERRCODE='25001';
    END IF;
    LOCK TABLE kaname.catalog_resource, kaname.catalog_verb,
               kaname.service_accounts, kaname.role_rule_selectors,
               kaname.roles, kaname.relation_fact IN ACCESS EXCLUSIVE MODE;
    IF to_regclass('kaname.registration_lineage_origin') IS NULL THEN
        RAISE EXCEPTION '90000 lineage rollback: provenance is missing';
    END IF;
    LOCK TABLE kaname.registration_lineage_origin IN ACCESS EXCLUSIVE MODE;
    IF (SELECT count(*) FROM kaname.registration_lineage_origin) <> 1 OR NOT EXISTS (
        SELECT 1 FROM kaname.registration_lineage_origin
         WHERE singleton AND format_version=2 AND state='up'
           AND kaname.registration_lineage_origin_matches(original_shape,complete_shape,had_creator,had_writer)
           AND complete_shape=kaname.registration_lineage_shape()) THEN
        RAISE EXCEPTION '90000 lineage rollback: provenance or schema differs';
    END IF;
    SELECT had_creator,had_writer INTO STRICT v_creator,v_writer
      FROM kaname.registration_lineage_origin WHERE singleton;
    IF NOT v_writer THEN
        PERFORM kaname.registration_lineage_assert_unused('writer');
        ALTER TABLE kaname.catalog_resource
            DROP CONSTRAINT catalog_resource_parent_names_form,
            DROP CONSTRAINT catalog_resource_writes_form,
            DROP COLUMN parent_names, DROP COLUMN writes;
    END IF;
    IF NOT v_creator THEN
        PERFORM kaname.registration_lineage_assert_unused('creator');
        -- The previous validator was validated byte-for-byte before Up.
        -- Its inverse is static SQL, never executable text read from a marker.
        EXECUTE $restore_validator$
CREATE OR REPLACE FUNCTION kaname.iam_rules_valid(rules jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $validator$
DECLARE
    rule       jsonb;
    child      jsonb;
    arr        jsonb;
    has_names  boolean;
    has_labels boolean;
BEGIN
    IF rules IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(rules) <> 'array' THEN RETURN false; END IF;
    -- Empty array is valid (legacy permissions-only role; back-compat).
    IF jsonb_array_length(rules) = 0 THEN RETURN true; END IF;
    IF jsonb_array_length(rules) > 64 THEN RETURN false; END IF;

    FOR rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(rule) <> 'object' THEN RETURN false; END IF;

        -- module: required, non-empty string scalar. The array `modules` key is
        -- NO LONGER valid.
        IF NOT (rule ? 'module') THEN RETURN false; END IF;
        IF jsonb_typeof(rule -> 'module') <> 'string' THEN RETURN false; END IF;
        IF length(rule ->> 'module') < 1 THEN RETURN false; END IF;

        -- resources / verbs: required non-empty string arrays, 1..16.
        FOR arr IN SELECT rule -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
            IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END LOOP;

        has_names  := (rule ? 'resource_names') AND jsonb_typeof(rule -> 'resource_names') <> 'null';
        has_labels := (rule ? 'match_labels')   AND jsonb_typeof(rule -> 'match_labels')   <> 'null';

        -- resource_names XOR match_labels (both → reject).
        IF has_names AND has_labels THEN RETURN false; END IF;

        IF has_names THEN
            IF jsonb_typeof(rule -> 'resource_names') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resource_names') > 256 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(rule -> 'resource_names') e
                       WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END IF;

        IF has_labels THEN
            IF jsonb_typeof(rule -> 'match_labels') <> 'object' THEN RETURN false; END IF;
            IF (SELECT count(*) FROM jsonb_object_keys(rule -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                RETURN false;
            END IF;
        END IF;

        -- Вложенные правила (kaname#874). Ключа нет — правило без вложенных.
        IF rule ? 'children' THEN
            IF jsonb_typeof(rule -> 'children') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'children') NOT BETWEEN 1 AND 16 THEN RETURN false; END IF;
            -- Владелец — ровно один ресурс, не подстановка, модуль не подстановка.
            IF rule ->> 'module' = '*' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resources') <> 1 THEN RETURN false; END IF;
            IF rule -> 'resources' ->> 0 = '*' THEN RETURN false; END IF;

            FOR child IN SELECT value FROM jsonb_array_elements(rule -> 'children') LOOP
                IF jsonb_typeof(child) <> 'object' THEN RETURN false; END IF;
                -- Модуль — владельца; глубину выражает тип, а не структура роли.
                IF child ? 'module' OR child ? 'children' THEN RETURN false; END IF;
                FOR arr IN SELECT child -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
                    IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END LOOP;
                -- Вложенное называет тип: не подстановку и не тип владельца.
                IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(child -> 'resources') e
                            WHERE e = '*' OR e = rule -> 'resources' ->> 0) THEN
                    RETURN false;
                END IF;

                has_names  := (child ? 'resource_names') AND jsonb_typeof(child -> 'resource_names') <> 'null';
                has_labels := (child ? 'match_labels')   AND jsonb_typeof(child -> 'match_labels')   <> 'null';
                IF has_names AND has_labels THEN RETURN false; END IF;
                IF has_names THEN
                    IF jsonb_typeof(child -> 'resource_names') <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(child -> 'resource_names') > 256 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(child -> 'resource_names') e
                               WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END IF;
                IF has_labels THEN
                    IF jsonb_typeof(child -> 'match_labels') <> 'object' THEN RETURN false; END IF;
                    IF (SELECT count(*) FROM jsonb_object_keys(child -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                        RETURN false;
                    END IF;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    RETURN true;
END;
$validator$;
$restore_validator$;
        ALTER TABLE kaname.role_rule_selectors
            DROP CONSTRAINT role_rule_selectors_creator_is_top_anchor_ck,
            DROP COLUMN created_by_subject;
        DROP TRIGGER service_account_creator_is_immutable ON kaname.service_accounts;
        DROP FUNCTION kaname.service_account_creator_is_immutable();
        DROP INDEX kaname.service_accounts_creator_idx;
        ALTER TABLE kaname.service_accounts
            DROP CONSTRAINT service_accounts_creator_id_nonempty_ck,
            DROP CONSTRAINT service_accounts_creator_type_ck,
            DROP CONSTRAINT service_accounts_creator_pair_ck,
            DROP COLUMN created_by_id, DROP COLUMN created_by_type;
        ALTER TABLE kaname.catalog_verb
            DROP CONSTRAINT catalog_verb_container_relation_form_ck,
            DROP CONSTRAINT catalog_verb_container_is_tier_ck,
            DROP CONSTRAINT catalog_verb_container_pair_ck,
            DROP COLUMN container_relation, DROP COLUMN container_parent;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM kaname.registration_lineage_origin
                    WHERE original_shape=kaname.registration_lineage_shape()) THEN
        RAISE EXCEPTION '90000 lineage rollback: inverse differs from original schema';
    END IF;
    UPDATE kaname.registration_lineage_origin SET state='down';
    -- Retain origin across the colliding 90000 boundary. The product runner
    -- selects the exact archived writer for feature origin and refuses both.
END
$inverse$;
-- +goose StatementEnd
