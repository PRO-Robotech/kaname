-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1020: explicit reconciliation of the two historical 20261026090000
-- lineages (#982 and #1003). Main 90000 remains byte-identical. The other SQL
-- is archived verbatim under historical/ (sha256 bd9449a671136b68ae82ce38edabbe2801a056fd4f7919fde769406be7bced29).
-- No goose history is rewritten. Product migrator uses WithAllowMissing(), so
-- feature installations already at 120000 execute this missing 90001 too.
-- Recognize COMPLETE definitions, never infer deployment from a missing record.
-- All recognition precedes persistent mutation; unexpected partial state fails.
-- +goose Up
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
        v_rules_source := $new_rules$
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
$new_rules$;
    ELSE
        IF v_function IS NOT NULL OR to_regclass('kaname.service_accounts_creator_idx') IS NOT NULL
           OR EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='kaname.service_accounts'::regclass AND tgname='service_account_creator_is_immutable') THEN
            RAISE EXCEPTION '90000 lineage reconciliation: creator objects without columns; no changes applied';
        END IF;
        v_rules_source := $old_rules$
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
$old_rules$;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
         WHERE p.oid='kaname.iam_rules_valid(jsonb)'::regprocedure AND p.prosrc=v_rules_source
           AND l.lanname='plpgsql' AND p.provolatile='i' AND NOT p.prosecdef
           AND p.proconfig IS NULL AND p.prorettype='boolean'::regtype
    ) THEN
        RAISE EXCEPTION '90000 lineage reconciliation: rule validator differs; no changes applied';
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
END
$reconcile$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION '90000 lineages were reconciled without rewriting history; automatic down cannot determine which original lineage to remove';
END $$;
-- +goose StatementEnd
