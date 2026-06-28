-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- RBAC Design-B flat-authz verb-bearing — edit tier-roles must carry READ verbs.
--
-- Под Design-B (flat-authz verb-bearing complete) enforcement резолвит каждый
-- CRUD-action на свой verb-bearing relation: get→v_get, list→v_list,
-- update→v_update, delete→v_delete (catalog/permission_map). tier-relations
-- (viewer/editor/admin) РАЗВЯЗАНЫ с v_* в FGA-модели (анти-over-grant guard): editor
-- БОЛЬШЕ НЕ implies viewer, поэтому грант, материализующий только v_update, не дает
-- v_get/v_list — субъект не может прочитать то, что редактирует.
--
-- Системные «edit»-роли (`edit` глобальная + per-resource `*.edit`) были засеяны
-- (миграция 0031) с verbs `["update"]` — под старой tier-каскадной моделью editor⊇
-- viewer этого хватало на чтение. После развязки v_*↔tier такой editor падает на
-- GET/LIST своего же ресурса (403 «lacks v_get/v_list») — наблюдалось в authz-deny
-- (PRJ-GT-A1) и authz-sa-apitoken (SA-NET-GT-A1). Корректная Design-B семантика:
-- «edit»-роль — это CRUD-editor, который ОБЯЗАН читать то, что меняет.
--
-- WHAT: расширить verbs каждой edit-роли с `["update"]` до `["get","list","update"]`
-- (reconciler материализует v_get + v_list + v_update; tier остается editor).
-- НЕ трогаем: admin (`["*"]` → уже разворачивается во все CRUD, включая get/list),
-- view (`["read","list","get"]` — read-only, уже несет v_get/v_list), owner (`*.*`
-- `["*"]`). Это НЕ возврат к tier-каскаду и НЕ union v_*↔tier — только верный
-- verb-набор роли.
--
-- IDEMPOTENT: матчим строго старый набор `["update"]` (jsonb-равенство per-rule), так
-- что повторный прогон / роль уже в целевой форме — no-op. Аддитивно — новая миграция,
-- примененные не редактируются (ban #5). Следующая миграция — 0041.
--
-- ROLE_RULE_SELECTORS: verbs НЕ хранятся в role_rule_selectors (только arm/
-- object_types/resource_names/match_labels для fast-path матчинга) — reconciler
-- читает verbs напрямую из roles.rules. rule_fp в селекторе — это хэш ПРАВИЛА
-- (включая verbs), поэтому смена verbs меняет fingerprint; но системные edit-роли
-- материализуются на Create через ReconcileBinding (полный пересчет из roles.rules),
-- а fast-path object-change для них (anchor/per-resource) пересходится периодическим
-- sweep'ом. Мы пере-сеем затронутые role_rule_selectors строки под новый fingerprint
-- ниже, чтобы fast-path не отставал и lockstep-guard не дрейфил.

-- +goose StatementBegin
DO $$
DECLARE
    r          record;
    rule       jsonb;
    new_rules  jsonb;
BEGIN
    FOR r IN SELECT id, rules FROM kacho_iam.roles
              WHERE is_system = true
                AND rules IS NOT NULL
                AND jsonb_typeof(rules) = 'array'
    LOOP
        new_rules := '[]'::jsonb;
        FOR rule IN SELECT value FROM jsonb_array_elements(r.rules) LOOP
            -- edit-rule signature: verbs == ["update"] exactly. Replace with the
            -- read+update set; every other rule passes through unchanged.
            IF (rule -> 'verbs') = '["update"]'::jsonb THEN
                new_rules := new_rules
                    || jsonb_build_array(rule || jsonb_build_object('verbs', '["get","list","update"]'::jsonb));
            ELSE
                new_rules := new_rules || jsonb_build_array(rule);
            END IF;
        END LOOP;
        IF new_rules <> r.rules THEN
            UPDATE kacho_iam.roles SET rules = new_rules WHERE id = r.id;
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- Re-seed role_rule_selectors for the edit roles whose rule fingerprint changed.
-- The selector spec (arm/object_types/match_labels/resource_names) is verb-independent,
-- so the row CONTENT is unchanged — only the rule_fp key moves. We cannot recompute the
-- Go fingerprint in SQL, so we drop the stale selector rows of changed system edit roles;
-- the application self-heals them (ReplaceRuleSelectors on next Role write / sweep) and
-- the Create-path materialization reads roles.rules directly (fast-path is a latency
-- optimization, not a correctness dependency). System edit roles are `*.*` anchor or
-- `<module>.<resource>` anchor — periodic sweep re-materializes regardless.
-- +goose StatementBegin
DO $$
BEGIN
    DELETE FROM kacho_iam.role_rule_selectors rrs
     USING kacho_iam.roles ro
     WHERE rrs.role_id = ro.id
       AND ro.is_system = true
       AND EXISTS (
         SELECT 1 FROM jsonb_array_elements(ro.rules) e
          WHERE (e -> 'verbs') = '["get","list","update"]'::jsonb
       );
END;
$$;
-- +goose StatementEnd

-- +goose Down

-- Reverse: edit roles back to verbs ["update"] (drop the read verbs). Symmetric and
-- idempotent — matches the ["get","list","update"] signature this migration produced.
-- +goose StatementBegin
DO $$
DECLARE
    r          record;
    rule       jsonb;
    new_rules  jsonb;
BEGIN
    FOR r IN SELECT id, rules FROM kacho_iam.roles
              WHERE is_system = true
                AND rules IS NOT NULL
                AND jsonb_typeof(rules) = 'array'
    LOOP
        new_rules := '[]'::jsonb;
        FOR rule IN SELECT value FROM jsonb_array_elements(r.rules) LOOP
            IF (rule -> 'verbs') = '["get","list","update"]'::jsonb THEN
                new_rules := new_rules
                    || jsonb_build_array(rule || jsonb_build_object('verbs', '["update"]'::jsonb));
            ELSE
                new_rules := new_rules || jsonb_build_array(rule);
            END IF;
        END LOOP;
        IF new_rules <> r.rules THEN
            UPDATE kacho_iam.roles SET rules = new_rules WHERE id = r.id;
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd
