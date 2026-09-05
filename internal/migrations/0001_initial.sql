-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- ─────────────────────────────────────────────────────────────────────────────
-- kacho-iam — сведённая первичная схема (squashed baseline).
--
-- Регенерирована 2026-09-04: чистая база → goose up по цепочке из
-- 171 миграции → pg_dump --column-inserts → снятие мета-команд psql и шапки
-- инструмента → метки времени прогона заменены на now().
--
-- Это ВТОРОЙ свод, а не первый. Предыдущий собран 2026-05-25 из 24 миграций
-- (0001…0025) и лежал в этом же файле; поверх него наросло 170.
--
-- ── Чем доказано равенство ─────────────────────────────────────────────────
--
-- Слепок схемы берётся ЗАПРОСОМ к каталогу, а не дампом: дамп зависит от
-- порядка вывода и версии инструмента, структура — нет. Сравнивается РЕЗУЛЬТАТ
-- применения, а не текст, которым его записали.
--
--   go test ./services/iam/internal/repo/kacho/pg/schemasnapshot/ \
--     -run TestSchemaSnapshot -count=1
--
-- Прибор лежит ОТДЕЛЬНЫМ пакетом, а не рядом с этим файлом, и признака сборки
-- у него нет: обоснование обеих сторон — в шапке
-- services/iam/internal/repo/kacho/pg/schemasnapshot/snapshot_test.go. Здесь оно не
-- пересказывается, чтобы два места об одном предмете не разошлись.
--
-- с переменными KACHO_SCHEMA_SNAPSHOT_OUT (слепок: колонки с типами и
-- умолчаниями · ограничения с выражениями · индексы · триггеры · отпечатки тел
-- функций), KACHO_SCHEMA_ROWS_OUT (перепись строк по таблицам) и
-- KACHO_SCHEMA_FULL_OUT (исходник этого файла).
--
-- ── Порядок разделов НЕСУЩИЙ, а не косметический ────────────────────────────
--
-- Данные стоят МЕЖДУ созданием таблиц и созданием ограничений, индексов и
-- триггеров. Переставив их после триггеров, получишь производные строки дважды:
-- один раз из дампа, второй — от сработавшего триггера. Расхождение переписи
-- придёт не оттуда, где его станут искать.
--
-- ── Метки времени ──────────────────────────────────────────────────────────
--
-- Посевные строки получают now(), а не час, в который снят дамп. now() —
-- время начала транзакции, миграция идёт одной транзакцией, поэтому весь посев
-- разделяет ОДИН момент.
--
-- ── ПОСЕВ КАТАЛОГА ПРАВ ОСТАЁТСЯ, И ЭТО РЕШЕНИЕ, А НЕ НЕДОСМОТР ────────────
--
-- Каталог прав (6 модулей · 30 ресурсов · 135 глаголов) сеют строки ниже, и
-- заманчиво было снять их как второе место об одном предмете: с задачи #1034
-- те же строки умеет заводить ПРИМЕНЕНИЕ МАНИФЕСТА модуля, и оно стоит на пути
-- старта. Снятие рассмотрено и ОТВЕРГНУТО замером.
--
-- Применитель на пустой доставке возвращает «применять нечего», не написав ни
-- строки, а доставка манифестов НЕОБЯЗАТЕЛЬНА по посадке: умолчание чарта iam
-- не монтирует том вовсе, и пару объявляют 2 наложения из 9 (предикат, единица
-- счёта — файл наложения, базовый values.yaml не в счёте:
--   grep -l 'configMapName: kacho-module-manifests' deploy/helm/umbrella/values*.yaml
-- даёт values.dev.yaml и values.prod.yaml). Следом за
-- применителем идёт страж паритета каталога, и на пустом каталоге он ОТКАЗЫВАЕТ
-- В ПУСКЕ («каталог модуля пуст, 0/0/0»). То есть на семи посадках из девяти
-- единственный производитель этих строк — посев, и его снятие превращает
-- «поднимается ровно как прежде» в «не поднимается никогда».
--
-- Второй, более грубый отказ пришёл бы раньше первого: 92 строки проекции
-- системных ролей ссылаются на каталог внешними ключами, которые этот же файл
-- ставит ниже. Сняв посев и не сняв проекцию, роняешь САМУ миграцию на
-- `ADD CONSTRAINT role_rule_ref_res_fk`.
--
-- Расхождения между посевом и манифестом сегодня НЕТ: литерал образа
-- порождается из тех же `services/*/manifest.yaml`, а применение поверх
-- посеянного идемпотентно by construction (`ON CONFLICT … WHERE … IS DISTINCT
-- FROM`). Держит это не эта фраза, а проба последовательности старта, которая
-- требует, чтобы применение доставленных манифестов НЕ СДВИНУЛО каталог.
--
-- Предикат снятия — три условия, и первое обязательное: доставка манифестов
-- становится обязательной на всякой посадке; опорная сторона стража переезжает
-- с литерала на применённые манифесты (задача продукта #1861); гейт паритета
-- посева получает новый предмет либо снимается с объявленной причиной.
--
-- ── Запреты (non-negotiables) ──────────────────────────────────────────────
--   #4  cross-service cascade — нет (FK только внутри kacho_iam).
--   #5  не редактировать применённую миграцию — свод разрешён владельцем
--       (2026-09-04, дословно: «прода нет и мы такие деструктивные операции
--       можем выполнять»).
--
--       СВОД ПРИМЕНИМ ТОЛЬКО К ЧИСТОЙ БАЗЕ, и существующий стенд надо
--       пересоздать. Молчаливым это не будет: страж версии схемы
--       (`pkg/schemaguard`) выводит ожидаемую вершину из САМОГО встроенного
--       набора, поэтому у образа со сводом она равна 1. База, несущая версию
--       цепочки, окажется ВПЕРЕДИ образа, и под останется неготовым с
--       названной причиной в теле `/readyz` — «схема ушла вперёд образа»,
--       а не упадёт без объяснения.
--   #8  database-per-service — да (схема kacho_iam в собственной БД).
--   #10 within-service инварианты — FK / UNIQUE / partial UNIQUE / CHECK /
--       EXCLUDE / триггеры, здесь же.
--
-- ── Трасса приёмок, перенесённая из снятой цепочки ─────────────────────────
--
-- Цитаты ниже выписаны из 171 миграции перед сведением. Дамп их не несёт:
-- он переносит структуру и данные, а не комментарии. Схема осталась — значит
-- и санкция на неё осталась, и её след обязан пережить сведение.
--
-- Приёмки воркспейса (3):
--
--   sub-phase-IAM-ID-2-membership-read-acceptance.md
--   sub-phase-ID-MAIL-1-mail-delivery-acceptance.md
--   sub-phase-quota-v2-materialised-usage-acceptance.md
--
-- Сценарии приёмок дерева продукта и воркспейса (43):
--
--   BAT-1-08  IAM-1-10  IAM-1-21  IAM-1-29  IAM-CT-1-01  IAM-CT-1-04
--   IAM-CT-1-09  IAM-CT-1-10  IAM-CT-1-16  IAM-CT-2-06  IAM-CT-2-14  IAM-ID-1-04
--   IAM-ID-1-08  IAM-ID-1-13  IAM-ID-1-50  IAM-ID-1-51  IAM-ID-1-52  IAM-ID-1-72
--   IAM-ID-2-05  IAM-MW-1-07  IAM-MW-1-08  IAM-MW-1-09  IAM-OM-1-06  IAM-RM-1-08
--   IAM-RW-1-01  IAM-RW-1-02  IAM-RW-1-03  IAM-RW-1-04  IAM-RW-1-12  IAM-RW-1-16
--   IAM-RW-1-26  IAM-RW-1-28  IAM-RW-1-29  IAM-RW-1-30  IAM-RW-1-31  IAM-SV-1-01
--   IAM-SV-1-02  IAM-SV-1-04  IAM-SV-1-05  IAM-SV-1-12  IAM-SV-1-13  IAM-SV-1-14
--   IAM-SV-1-16
--
-- ─────────────────────────────────────────────────────────────────────────────

-- +goose Up
-- +goose StatementBegin
--
-- PostgreSQL database dump
--



SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET search_path TO kacho_iam, public;
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: kacho_iam; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA kacho_iam;


--
-- Name: access_binding_role_assignable(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.access_binding_role_assignable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    r_is_system  boolean;
    r_account_id text;
    r_project_id text;
    scope_account text;
BEGIN
    -- Форма отношения роли не несёт — судить нечего.
    IF NEW.role_id IS NULL THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE'
       AND NEW.role_id       = OLD.role_id
       AND NEW.resource_type = OLD.resource_type
       AND NEW.resource_id   = OLD.resource_id THEN
        RETURN NEW;
    END IF;

    SELECT is_system, coalesce(account_id, ''), coalesce(project_id, '')
      INTO r_is_system, r_account_id, r_project_id
      FROM kacho_iam.roles
     WHERE id = NEW.role_id
     FOR KEY SHARE;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF r_is_system THEN
        RETURN NEW;
    END IF;

    IF NEW.resource_type = 'account' THEN
        IF r_account_id = NEW.resource_id THEN
            RETURN NEW;
        END IF;
    ELSIF NEW.resource_type = 'project' THEN
        IF r_project_id = NEW.resource_id THEN
            RETURN NEW;
        END IF;
        IF r_project_id = '' AND r_account_id <> '' THEN
            SELECT account_id INTO scope_account
              FROM kacho_iam.projects
             WHERE id = NEW.resource_id;
            IF FOUND AND scope_account = r_account_id THEN
                RETURN NEW;
            END IF;
        END IF;
    ELSE
        IF NEW.resource_type <> 'cluster' THEN
            RETURN NEW;
        END IF;
    END IF;

    RAISE EXCEPTION USING ERRCODE = '23514',
        MESSAGE = format(
            'role %s is not assignable on %s:%s',
            NEW.role_id, NEW.resource_type, NEW.resource_id);
END;
$$;


--
-- Name: access_binding_subject_carries_scope(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.access_binding_subject_carries_scope() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  rt text;
  ri text;
BEGIN
  -- Названа вызывающим — берём как есть: солгать не даст внешний ключ.
  IF NEW.resource_type IS NOT NULL AND NEW.resource_id IS NOT NULL THEN
    RETURN NEW;
  END IF;

  SELECT b.resource_type, b.resource_id
    INTO rt, ri
    FROM kacho_iam.access_bindings b
   WHERE b.id = NEW.binding_id;

  IF NOT FOUND THEN
    -- Отказ, а не тихий пропуск: строка без области выпала бы из вердикта
    -- молча, и право перестало бы действовать без единого признака.
    RAISE EXCEPTION
      'access_binding_subjects: выдача % не существует, область субъекта взять неоткуда',
      NEW.binding_id
      USING ERRCODE = 'foreign_key_violation',
            CONSTRAINT = 'access_binding_subjects_scope_fk';
  END IF;

  NEW.resource_type := rt;
  NEW.resource_id   := ri;
  RETURN NEW;
END;
$$;


--
-- Name: access_bindings_role_is_live(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.access_bindings_role_is_live() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    role_live boolean;
BEGIN
    -- РАННИЙ ВЫХОД. Правка, не меняющая ссылку, новой ссылки не создаёт, и
    -- судить её нечем: пережившая выдача обязана оставаться отзываемой и
    -- перемечаемой.
    IF TG_OP = 'UPDATE' AND NEW.role_id IS NOT DISTINCT FROM OLD.role_id THEN
        RETURN NEW;
    END IF;

    -- Замок `FOR SHARE`, а не `FOR KEY SHARE`. На сегодняшней схеме конфликтуют
    -- оба (живость ключевая из-за `roles_id_live_uk`), и различает их только
    -- будущее: `FOR SHARE` останется верным, если референт когда-нибудь снимут.
    -- Разбор и замер — шапка файла.
    SELECT r.live INTO role_live
      FROM kacho_iam.roles r
     WHERE r.id = NEW.role_id
       FOR SHARE;

    -- Строки нет вовсе — это предмет ключа `access_bindings_role_fk`, а не
    -- стража: сказать здесь своё значило бы завести второе место об одном
    -- предмете, и разошлись бы они молча.
    IF role_live IS NULL THEN
        RETURN NEW;
    END IF;

    IF NOT role_live THEN
        RAISE EXCEPTION
            'role % is retired and cannot receive a new access binding', NEW.role_id
            USING ERRCODE = '23000',
                  CONSTRAINT = 'access_bindings_role_is_live';
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: FUNCTION access_bindings_role_is_live(); Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON FUNCTION kacho_iam.access_bindings_role_is_live() IS 'Новая ССЫЛКА на снятую роль отвергается 23000 с именем связи access_bindings_role_is_live. Судится ПОЯВЛЕНИЕ ссылки, а не существование строки: UPDATE, не меняющий role_id, выходит рано — иначе пережившая выдача перестала бы приниматься к отзыву и переметке. Ключом это невыразимо: ключ судит обе стороны сразу, а снятие роли обязано выдачи ПЕРЕЖИВАТЬ (kacho#1913).';


--
-- Name: access_bindings_scope_default(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.access_bindings_scope_default() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.scope IS NULL THEN
        NEW.scope := CASE NEW.resource_type
            WHEN 'cluster'      THEN 1::smallint
            WHEN 'organization' THEN 1::smallint
            WHEN 'account'      THEN 2::smallint
            WHEN 'cloud'        THEN 2::smallint
            WHEN 'project'      THEN 3::smallint
            WHEN 'folder'       THEN 3::smallint
            ELSE 3::smallint
        END;
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: group_members_member_exists(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.group_members_member_exists() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.member_type = OLD.member_type
       AND NEW.member_id   = OLD.member_id THEN
        RETURN NEW;
    END IF;

    IF NEW.member_type = 'user' THEN
        PERFORM 1 FROM kacho_iam.users
            WHERE id = NEW.member_id FOR KEY SHARE;
    ELSIF NEW.member_type = 'service_account' THEN
        PERFORM 1 FROM kacho_iam.service_accounts
            WHERE id = NEW.member_id FOR KEY SHARE;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = format('Illegal argument member_type %s', NEW.member_type);
    END IF;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503',
            MESSAGE = format('%s %s not found', NEW.member_type, NEW.member_id);
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: iam_permissions_valid(jsonb); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.iam_permissions_valid(perms jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $_$
DECLARE
    v text;
    -- module.resource.resourceName.verb (4-segment RBAC v2 grammar, unchanged).
    re text := '^(\*|[a-z][a-z0-9-]*)\.(\*|[a-z][a-zA-Z0-9_-]*)\.(\*|[a-zA-Z0-9_-]+)\.(\*|[a-z][a-zA-Z0-9_-]*)$';
BEGIN
    IF perms IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(perms) <> 'array' THEN RETURN false; END IF;
    IF jsonb_array_length(perms) = 0 THEN RETURN false; END IF;
    IF jsonb_array_length(perms) > 1024 THEN RETURN false; END IF;
    FOR v IN SELECT value::text FROM jsonb_array_elements_text(perms) LOOP
        IF v !~ re THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END;
$_$;


--
-- Name: iam_rule_wildcards_confined(jsonb, text); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.iam_rule_wildcards_confined(rules jsonb, owner_module text) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    rule jsonb;
BEGIN
    -- Платформенная роль: политика не менялась ни на йоту, послабление полное.
    IF owner_module IS NULL THEN RETURN true; END IF;

    -- Форму правил судит iam_rules_valid (0033) — второго кодека здесь не
    -- заводится. Негодная форма до этой функции доезжает только у строки,
    -- которую та проверка уже отвергла бы; поэтому неизвестное читается
    -- защитно, а не додумывается.
    IF rules IS NULL THEN RETURN true; END IF;
    IF jsonb_typeof(rules) <> 'array' THEN RETURN true; END IF;

    FOR rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(rule) <> 'object' THEN CONTINUE; END IF;

        -- module: "*" не находится НИ В ОДНОМ модуле — отвергается всегда.
        IF rule ->> 'module' = '*' THEN RETURN false; END IF;

        -- ресурс "*" находится в модуле СВОЕГО правила: законен ровно тогда,
        -- когда этот модуль и есть владелец роли.
        IF jsonb_typeof(rule -> 'resources') = 'array'
           AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(rule -> 'resources') e WHERE e = '*')
           AND rule ->> 'module' IS DISTINCT FROM owner_module
        THEN
            RETURN false;
        END IF;
    END LOOP;

    RETURN true;
END;
$$;


--
-- Name: FUNCTION iam_rule_wildcards_confined(rules jsonb, owner_module text); Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON FUNCTION kacho_iam.iam_rule_wildcards_confined(rules jsonb, owner_module text) IS 'Подстановка роли с владельцем не выходит за её модуль. Глагол * не судится намеренно: он разрешён и в арендаторской роли безусловно, потому что он не сегмент пространства имён, а «все действия названного типа». Задача продукта #1032.';


--
-- Name: iam_rules_valid(jsonb); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.iam_rules_valid(rules jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    rule       jsonb;
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
    END LOOP;

    RETURN true;
END;
$$;


--
-- Name: identity_journal_note(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.identity_journal_note() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO kacho_iam.identity_journal (identity, first_seen_at)
    VALUES (NEW.external_id, now())
    ON CONFLICT (identity) DO NOTHING;
    RETURN NULL;
END;
$$;


--
-- Name: FUNCTION identity_journal_note(); Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON FUNCTION kacho_iam.identity_journal_note() IS 'notes an identity the first time it appears, on insert and on the update that activates an invitation. Never refuses and never removes: observability is not a gate, and the ledger is accumulating on purpose';


--
-- Name: interactive_client_uris_wellformed(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.interactive_client_uris_wellformed() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    u TEXT;
BEGIN
    FOREACH u IN ARRAY (NEW.redirect_uris || NEW.post_logout_redirect_uris) LOOP
        IF u !~ '^https://[^/?#]+' OR position('#' in u) > 0 OR length(u) > 512 THEN
            RAISE EXCEPTION
                'Illegal argument redirect_uris: entry must be an absolute https:// URL without a fragment'
                USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;


--
-- Name: invite_mail_outbox_notify(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.invite_mail_outbox_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('kacho_iam_invite_mail_outbox', NEW.id::text);
    RETURN NEW;
END;
$$;


--
-- Name: kacho_admission_rate_count(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.kacho_admission_rate_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_kind     text := TG_ARGV[0];
    v_identity text;
    v_max      bigint;
    v_window   bigint;
BEGIN
    SELECT u.external_id INTO v_identity
      FROM kacho_iam.users u
     WHERE u.id = NEW.owner_user_id;

    -- Владелец БЕЗ личности — законное состояние схемы (строка в состоянии
    -- приглашения внешнего идентификатора не несёт), и такой аккаунт не считается
    -- ни объёмом, ни темпом. Решение здесь то же и по той же причине: счётчик не
    -- вправе запрещать состояния, которых схема не запрещает. Молчаливым оно не
    -- является — предупреждение об этом уже производит триггер объёма, и второе
    -- на то же событие было бы шумом.
    IF v_identity IS NULL OR v_identity = '' THEN
        RETURN NULL;
    END IF;

    -- Авторитет читается ПЕРВЫМ: его отсутствие — отдельный исход, а не «сколько
    -- угодно». Не названная величина означает отказ, как и у объёма: «не сказано»
    -- на пути безопасности читается закрыто.
    SELECT max_events, window_seconds INTO v_max, v_window
      FROM kacho_iam.account_admission_rate_limits
     WHERE withdrawn_at IS NULL AND kind = v_kind;

    IF NOT FOUND THEN
        PERFORM kacho_iam.kacho_rate_refuse(v_identity, v_kind);
        RETURN NULL;
    END IF;

    -- ЕДИНСТВЕННЫЙ оператор, принимающий решение.
    --
    -- Ветвь ВСТАВКИ — первое заведение этой личности: проходит безусловно, до
    -- всякого сравнения с величиной. Это и есть «первый вход не ломается».
    --
    -- Ветвь ПРАВКИ берёт блокировку строки, поэтому второй писатель ждёт коммита
    -- первого и видит его результат: гонку разрешает база, а не порядок. Переход
    -- в следующее окно и списание считаются ОДНИМ выражением — посчитать «истекло
    -- ли окно» отдельно значило бы вернуть check-then-act через границу оператора.
    INSERT INTO kacho_iam.identity_admission_windows AS w
        (carrier_id, kind, window_started_at, admitted)
    VALUES (v_identity, v_kind, now(), 1)
    ON CONFLICT (carrier_id, kind) DO UPDATE
       SET window_started_at = CASE
               WHEN now() >= w.window_started_at + make_interval(secs => v_window)
               THEN now() ELSE w.window_started_at END,
           admitted = CASE
               WHEN now() >= w.window_started_at + make_interval(secs => v_window)
               THEN 1 ELSE w.admitted + 1 END,
           updated_at = now()
     WHERE CASE
               WHEN now() >= w.window_started_at + make_interval(secs => v_window)
               THEN 1 ELSE w.admitted + 1 END <= v_max;

    -- `FOUND` после INSERT истинно, когда затронута хотя бы одна строка: и на
    -- ветви вставки, и на ветви правки, чьё условие выполнилось. Ноль строк
    -- означает ровно одно — правка отвергнута условием, то есть окно полно.
    IF FOUND THEN
        RETURN NULL;
    END IF;

    -- Ноль строк означает ровно одно: окно полно. Это не check-then-act —
    -- решение уже принято атомарным оператором выше, а производитель отказа лишь
    -- облекает случившееся в контракт.
    PERFORM kacho_iam.kacho_rate_refuse(v_identity, v_kind);
    RETURN NULL;
END;
$$;


--
-- Name: FUNCTION kacho_admission_rate_count(); Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON FUNCTION kacho_iam.kacho_admission_rate_count() IS 'charges one admission of the current window, in the same transaction as the account row. The first ever admission of an identity goes through the INSERT branch and is therefore unconditional: a rate refusal on first login would be a refusal to log in. Refusals come from kacho_rate_refuse';


--
-- Name: kacho_labels_valid(jsonb); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.kacho_labels_valid(labels jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $_$
DECLARE
    k text;
    v text;
    cnt int;
BEGIN
    IF labels IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(labels) <> 'object' THEN RETURN false; END IF;
    cnt := 0;
    FOR k, v IN SELECT key, value FROM jsonb_each_text(labels) LOOP
        cnt := cnt + 1;
        IF cnt > 64 THEN RETURN false; END IF;
        IF length(k) = 0 OR length(k) > 63 THEN RETURN false; END IF;
        IF k !~ '^[a-z][-_./@a-z0-9]{0,62}$' THEN RETURN false; END IF;
        IF length(v) > 63 THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END;
$_$;


--
-- Name: kacho_quota_admit(text, text, text); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.kacho_quota_admit(v_carrier_type text, v_carrier_id text, v_kind text) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_ok boolean;
BEGIN
    SELECT used < limit_value INTO v_ok
      FROM kacho_iam.project_resource_quotas
     WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier_id AND kind = v_kind;

    IF COALESCE(v_ok, false) THEN
        RETURN;
    END IF;

    PERFORM kacho_iam.kacho_quota_refuse(v_carrier_type, v_carrier_id, v_kind);
END;
$$;


--
-- Name: FUNCTION kacho_quota_admit(v_carrier_type text, v_carrier_id text, v_kind text); Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON FUNCTION kacho_iam.kacho_quota_admit(v_carrier_type text, v_carrier_id text, v_kind text) IS 'advisory band: says whether a slot is available WITHOUT taking it. Never a decision — the decision is the conditional UPDATE of the charging trigger; this exists so the tenant is refused early and in the same words';


--
-- Name: kacho_quota_carrier_lifecycle(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.kacho_quota_carrier_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_kind         text := TG_ARGV[0];
    -- Носитель выводится из вида по тому же правилу, что и в списании: у
    -- вложенного вида он ЕСТЬ его родительская часть. Два места об одном
    -- предмете здесь разошлись бы молча — строка учёта завелась бы под одним
    -- носителем, а списание искало бы её под другим.
    v_carrier_type text := substring(TG_ARGV[0] from '^(.*)\.[^.]+$');
    v_account      text := '';
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Ноль затронутых строк здесь НЕ отказ: строки учёта могло не быть
        -- (величина отозвана), и удаление принципала не вправе от этого зависеть.
        DELETE FROM kacho_iam.project_resource_quotas
         WHERE carrier_type = v_carrier_type AND carrier_id = OLD.id AND kind = v_kind;
        RETURN NULL;
    END IF;

    -- Зеркало аккаунта — только у носителя, принадлежащего ровно одному.
    IF v_carrier_type = 'iam.serviceAccount' THEN
        v_account := COALESCE(NEW.account_id, '');
    END IF;

    -- Строка заводится с НУЛЁМ, и это верно: у нового принципала удостоверений
    -- нет by construction. Уже лежащие покрыты затравкой ниже.
    INSERT INTO kacho_iam.project_resource_quotas
        (carrier_type, carrier_id, kind, used, limit_value,
         source_scope, source_scope_id, limit_revision, synced_at, account_id)
    SELECT v_carrier_type, NEW.id, v_kind, 0,
           l.limit_value, l.scope, l.scope_id, l.revision, now(), v_account
      FROM kacho_iam.limits l
     WHERE l.withdrawn_at IS NULL AND l.kind = v_kind AND l.scope = 'DEFAULT'
    ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

    RETURN NULL;
END;
$_$;


--
-- Name: FUNCTION kacho_quota_carrier_lifecycle(); Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON FUNCTION kacho_iam.kacho_quota_carrier_lifecycle() IS 'creates and removes the accounting row of a PRINCIPAL carrier in the same transaction as the principal itself, so the row always has a producer. Neither arm can refuse: a missing row is zero affected rows, not an error — otherwise a person holding credentials would become undeletable';


--
-- Name: kacho_quota_count(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.kacho_quota_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_kind         text := TG_ARGV[0];
    -- Носитель ВЫВОДИТСЯ из вида, а не передаётся отдельным аргументом.
    --
    -- У вложенного вида носитель ЕСТЬ его родительская часть — этого требует
    -- гейт каталога от КАЖДОЙ записи, поэтому вывод здесь не догадка, а чтение
    -- того же правила. Отдельный аргумент был бы вторым местом об одном
    -- предмете и разошёлся бы с каталогом молча.
    --
    -- Плюс цена, замеренная сразу: носитель, стоящий в объявлении триггера
    -- строкой в кавычках, неотличим от ВИДА для гейтов дерева, которые читают
    -- аргументы списания. Два таких гейта объявили `iam.user` и
    -- `iam.serviceAccount` «получившими производителя списания» — то есть форма
    -- записи начала подменять факт.
    v_carrier_type text := CASE
        WHEN array_length(string_to_array(TG_ARGV[0], '.'), 1) = 3
        THEN substring(TG_ARGV[0] from '^(.*)\.[^.]+$')
        ELSE ''
    END;
    v_carrier_col  text := COALESCE(TG_ARGV[1], '');
    v_row          jsonb;
    v_owner        text;
    v_identity     text;
    v_carrier      text;
    v_account      text := '';
    v_existing     bigint;
    v_limit        bigint;
    v_scope        text;
    v_scope_id     text;
    v_revision     bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_row := to_jsonb(OLD);
    ELSE
        v_row := to_jsonb(NEW);
    END IF;

    -- ─── Полоса носителя-ПРИНЦИПАЛА (задача #1191) ───────────────────────────
    IF v_carrier_type <> '' THEN
        v_carrier := v_row ->> v_carrier_col;
        IF v_carrier IS NULL OR v_carrier = '' THEN
            RAISE EXCEPTION 'quota: row of % carries no %', TG_TABLE_NAME, v_carrier_col
                USING ERRCODE = 'KQ003';
        END IF;

        IF TG_OP = 'DELETE' THEN
            -- Возврат — в той же транзакции, что отзыв. GREATEST не даёт уйти
            -- ниже нуля; ноль затронутых строк не отказ (см. lifecycle выше).
            UPDATE kacho_iam.project_resource_quotas
               SET used = GREATEST(used - 1, 0), updated_at = now()
             WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind;
            RETURN NULL;
        END IF;

        IF v_carrier_type = 'iam.serviceAccount' THEN
            SELECT COALESCE(sa.account_id, '') INTO v_account
              FROM kacho_iam.service_accounts sa WHERE sa.id = v_carrier;
            v_account := COALESCE(v_account, '');
        END IF;

        -- Авторитет читается ПЕРВЫМ: его отсутствие — отдельный исход, а не
        -- «полно». Область аккаунта применима ТОЛЬКО к видам, объявленным
        -- област-ными (`domain.accountScopedKinds`; согласие держит гейт G7):
        -- удостоверение человека действует во всех его аккаунтах, и величина
        -- одного из них управляла бы доступом в чужих.
        SELECT l.limit_value, l.scope, l.scope_id, l.revision
          INTO v_limit, v_scope, v_scope_id, v_revision
          FROM kacho_iam.limits l
         WHERE l.withdrawn_at IS NULL
           AND l.kind = v_kind
           AND (l.scope = 'DEFAULT'
                OR (l.scope = 'ACCOUNT'
                    AND v_account <> ''
                    AND l.scope_id = v_account
                    AND v_kind IN ('iam.serviceAccount.credential')))
         ORDER BY CASE l.scope WHEN 'ACCOUNT' THEN 2 ELSE 1 END DESC
         LIMIT 1;

        IF NOT FOUND THEN
            -- Строка учёта не вправе пережить авторитет: иначе отказ назвал бы
            -- величину, которой больше нет. Снятие до фиксации не доживёт —
            -- следующий оператор возбуждает исключение.
            DELETE FROM kacho_iam.project_resource_quotas
             WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind;
            PERFORM kacho_iam.kacho_quota_refuse(v_carrier_type, v_carrier, v_kind);
            RETURN NULL;
        END IF;

        -- Строка могла быть СНЯТА отзывом величины и заводится теперь заново.
        -- Считать её с нуля нельзя: у принципала уже лежат удостоверения, и
        -- возврат величины подарил бы ему полный потолок сверх имеющегося.
        -- Своя строка исключается — она уже вставлена и будет списана ниже.
        EXECUTE format(
            'SELECT count(*) FROM %I.%I WHERE %I = $1 AND id <> $2',
            TG_TABLE_SCHEMA, TG_TABLE_NAME, v_carrier_col)
           INTO v_existing
          USING v_carrier, v_row ->> 'id';

        INSERT INTO kacho_iam.project_resource_quotas
            (carrier_type, carrier_id, kind, used, limit_value,
             source_scope, source_scope_id, limit_revision, synced_at, account_id)
        VALUES (v_carrier_type, v_carrier, v_kind, v_existing,
                v_limit, v_scope, v_scope_id, v_revision, now(), v_account)
        ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

        -- Снимок величины обновляется БЕЗУСЛОВНО и ДО списания, а не вместе с
        -- ним. Иначе понижение предела администратором доезжало бы до строки
        -- учёта только при УСПЕШНОМ списании, и отказ называл бы арендатору
        -- прежнее число: «предел 12» там, где предел уже 10. Текст отказа —
        -- часть контракта, и величина в нём обязана быть действующей.
        --
        -- Блокировку строки берёт этот оператор; второй писатель ждёт фиксации
        -- первого и видит его результат — гонку по-прежнему разрешает база.
        UPDATE kacho_iam.project_resource_quotas
           SET limit_value     = v_limit,
               source_scope    = v_scope,
               source_scope_id = v_scope_id,
               limit_revision  = v_revision,
               synced_at       = now(),
               updated_at      = now()
         WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind;

        -- Списание. Условие читает УЖЕ ОБНОВЛЁННЫЙ снимок той же строки.
        UPDATE kacho_iam.project_resource_quotas
           SET used = used + 1, updated_at = now()
         WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind
           AND used < limit_value;

        IF FOUND THEN
            RETURN NULL;
        END IF;

        PERFORM kacho_iam.kacho_quota_refuse(v_carrier_type, v_carrier, v_kind);
        RETURN NULL;
    END IF;

    -- ─── Полоса носителя-ЛИЧНОСТИ (потолок числа аккаунтов, #484) ────────────
    -- Сохранена ДОСЛОВНО: смена её поведения здесь была бы правкой чужого
    -- предмета под видом расширения.
    v_owner := v_row ->> 'owner_user_id';

    SELECT u.external_id INTO v_identity
      FROM kacho_iam.users u
     WHERE u.id = v_owner;

    IF v_identity IS NULL OR v_identity = '' THEN
        IF TG_OP = 'INSERT' THEN
            RAISE WARNING 'quota: account % is not counted — its owner % carries no login identity',
                          COALESCE(v_row ->> 'id', '?'), COALESCE(v_owner, '?')
                USING ERRCODE = 'KQ003';
        END IF;
        RETURN NULL;
    END IF;

    IF TG_OP = 'DELETE' THEN
        UPDATE kacho_iam.project_resource_quotas
           SET used = GREATEST(used - 1, 0), updated_at = now()
         WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind;
        RETURN NULL;
    END IF;

    SELECT l.limit_value, l.scope, l.scope_id, l.revision
      INTO v_limit, v_scope, v_scope_id, v_revision
      FROM kacho_iam.limits l
     WHERE l.withdrawn_at IS NULL AND l.kind = v_kind AND l.scope = 'DEFAULT';

    IF NOT FOUND THEN
        DELETE FROM kacho_iam.project_resource_quotas
         WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind;
        PERFORM kacho_iam.kacho_quota_refuse('identity', v_identity, v_kind);
        RETURN NULL;
    END IF;

    INSERT INTO kacho_iam.project_resource_quotas
        (carrier_type, carrier_id, kind, used, limit_value,
         source_scope, source_scope_id, limit_revision, synced_at, account_id)
    VALUES ('identity', v_identity, v_kind, 0,
            v_limit, v_scope, v_scope_id, v_revision, now(), '')
    ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

    UPDATE kacho_iam.project_resource_quotas
       SET used            = used + 1,
           limit_value     = v_limit,
           source_scope    = v_scope,
           source_scope_id = v_scope_id,
           limit_revision  = v_revision,
           synced_at       = now(),
           updated_at      = now()
     WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind
       AND used < v_limit;

    IF FOUND THEN
        RETURN NULL;
    END IF;

    PERFORM kacho_iam.kacho_quota_refuse('identity', v_identity, v_kind);
    RETURN NULL;
END;
$_$;


--
-- Name: FUNCTION kacho_quota_count(); Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON FUNCTION kacho_iam.kacho_quota_count() IS 'charges one slot on insert and returns it on delete, in the same transaction as the account row. Deferred to commit because the identity is resolved through the owner row, whose foreign key is itself deferred — the schema allows the account to be inserted first. The snapshot of the ceiling is refreshed from the local authority in the charging statement: the limit owner has no delta to catch up with. Refusals come from kacho_quota_refuse: KQ001 = full, KQ002 = no ceiling stated. An account whose owner carries no login identity is NOT counted and says so with a KQ003 warning: refusing it would change what the platform accepts under the guise of counting';


--
-- Name: kacho_quota_refuse(text, text, text); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.kacho_quota_refuse(v_carrier_type text, v_carrier_id text, v_kind text) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_limit bigint;
    v_used  bigint;
BEGIN
    SELECT limit_value, used INTO v_limit, v_used
      FROM kacho_iam.project_resource_quotas
     WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier_id AND kind = v_kind;

    IF FOUND THEN
        RAISE EXCEPTION '% % has reached its limit of % %',
                        v_carrier_type, v_carrier_id, v_limit, v_kind
            USING ERRCODE = 'KQ001',
                  DETAIL  = jsonb_build_object(
                                'carrier_type', v_carrier_type,
                                'carrier_id',   v_carrier_id,
                                'kind',         v_kind,
                                'limit',        v_limit,
                                'used',         v_used)::text;
    END IF;

    RAISE EXCEPTION '% % has no ceiling stated for %', v_carrier_type, v_carrier_id, v_kind
        USING ERRCODE = 'KQ002',
              DETAIL  = jsonb_build_object(
                            'carrier_type', v_carrier_type,
                            'carrier_id',   v_carrier_id,
                            'kind',         v_kind)::text;
END;
$$;


--
-- Name: FUNCTION kacho_quota_refuse(v_carrier_type text, v_carrier_id text, v_kind text); Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON FUNCTION kacho_iam.kacho_quota_refuse(v_carrier_type text, v_carrier_id text, v_kind text) IS 'the ONLY producer of a quota refusal, generated for every owner from one template: both the advisory read and the authoritative charge call it, so their text, SQLSTATE and details cannot drift apart — there is one source, not five agreeing copies';


--
-- Name: kacho_rate_refuse(text, text); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.kacho_rate_refuse(v_carrier_id text, v_kind text) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_max    bigint;
    v_window bigint;
BEGIN
    SELECT max_events, window_seconds INTO v_max, v_window
      FROM kacho_iam.account_admission_rate_limits
     WHERE withdrawn_at IS NULL AND kind = v_kind;

    IF FOUND THEN
        RAISE EXCEPTION 'identity % has reached its admission rate of % % per % seconds',
                        v_carrier_id, v_max, v_kind, v_window
            USING ERRCODE = 'KQ004',
                  DETAIL  = jsonb_build_object(
                                'carrier_type',   'identity',
                                'carrier_id',     v_carrier_id,
                                'kind',           v_kind,
                                'max_events',     v_max,
                                'window_seconds', v_window)::text;
    END IF;

    RAISE EXCEPTION 'identity % has no admission rate stated for %', v_carrier_id, v_kind
        USING ERRCODE = 'KQ005',
              DETAIL  = jsonb_build_object(
                            'carrier_type', 'identity',
                            'carrier_id',   v_carrier_id,
                            'kind',         v_kind)::text;
END;
$$;


--
-- Name: FUNCTION kacho_rate_refuse(v_carrier_id text, v_kind text); Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON FUNCTION kacho_iam.kacho_rate_refuse(v_carrier_id text, v_kind text) IS 'the only producer of a rate refusal: KQ004 = the window is full (wait), KQ005 = no rate stated (the administrator must state one). Separate from kacho_quota_refuse because that one is rendered from a template shared by six owners and speaks about the VOLUME row — this lane exists for one owner only';


--
-- Name: limits_scope_ref_exists(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.limits_scope_ref_exists() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.scope    = OLD.scope
       AND NEW.scope_id = OLD.scope_id THEN
        RETURN NEW;
    END IF;

    IF NEW.scope = 'DEFAULT' THEN
        RETURN NEW;
    ELSIF NEW.scope = 'ACCOUNT' THEN
        PERFORM 1 FROM kacho_iam.accounts WHERE id = NEW.scope_id FOR KEY SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE    = '23503',
                CONSTRAINT = 'limits_scope_ref',
                MESSAGE    = format('Account %s not found', NEW.scope_id);
        END IF;
    ELSIF NEW.scope = 'PROJECT' THEN
        PERFORM 1 FROM kacho_iam.projects WHERE id = NEW.scope_id FOR KEY SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE    = '23503',
                CONSTRAINT = 'limits_scope_ref',
                MESSAGE    = format('Project %s not found', NEW.scope_id);
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = format('Illegal argument scope %s', NEW.scope);
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: limits_stamp_revision(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.limits_stamp_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.limit_value  IS NOT DISTINCT FROM OLD.limit_value
       AND NEW.withdrawn_at IS NOT DISTINCT FROM OLD.withdrawn_at THEN
        -- Ничего наблюдаемого не изменилось: тянущие не обязаны об этом узнать.
        NEW.revision := OLD.revision;
        RETURN NEW;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('kacho_iam.limits_revision'));
    NEW.revision := nextval('kacho_iam.limits_revision_seq');
    RETURN NEW;
END;
$$;


--
-- Name: limits_withdraw_for_scope_object(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.limits_withdraw_for_scope_object() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE kacho_iam.limits
       SET withdrawn_at = now()
     WHERE scope        = TG_ARGV[0]
       AND scope_id     = OLD.id
       AND withdrawn_at IS NULL;
    RETURN OLD;
END;
$$;


--
-- Name: membership_carrying_rights_is_kept(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.membership_carrying_rights_is_kept() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM kacho_iam.accounts WHERE id = OLD.account_id) THEN
        RETURN NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM kacho_iam.users WHERE id = OLD.user_id) THEN
        RETURN NULL;
    END IF;
    IF EXISTS (
        SELECT 1 FROM kacho_iam.memberships m
         WHERE m.user_id = OLD.user_id AND m.account_id = OLD.account_id)
    THEN
        RETURN NULL;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM kacho_iam.access_bindings b
         WHERE b.status = 'ACTIVE'
           AND (
                 (b.subject_type = 'user' AND b.subject_id = OLD.user_id)
              OR EXISTS (
                   SELECT 1 FROM kacho_iam.access_binding_subjects s
                    WHERE s.binding_id = b.id
                      AND s.subject_type = 'user'
                      AND s.subject_id = OLD.user_id)
               )
           AND (
                 (b.resource_type = 'account' AND b.resource_id = OLD.account_id)
              OR (b.resource_type = 'project' AND EXISTS (
                    SELECT 1 FROM kacho_iam.projects p
                     WHERE p.id = b.resource_id AND p.account_id = OLD.account_id))
               )
    )
    THEN
        RAISE EXCEPTION
            'Membership of user % in account % still carries active access bindings',
            OLD.user_id, OLD.account_id
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'membership_carrying_rights_is_kept';
    END IF;
    RETURN NULL;
END;
$$;


--
-- Name: membership_mirror_from_user(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.membership_mirror_from_user() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Первое появление человека: членство, названное колонкой строки,
        -- заводится здесь. Пустой аккаунт пропускается — строка без аккаунта
        -- законна, а членства без аккаунта не бывает.
        IF NEW.account_id IS NOT NULL AND NEW.account_id <> '' THEN
            INSERT INTO kacho_iam.memberships (id, user_id, account_id, state, invited_by, created_at, updated_at)
            VALUES (kacho_iam.membership_mirror_id(NEW.id, NEW.account_id),
                    NEW.id,
                    NEW.account_id,
                    CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END,
                    NEW.invited_by,
                    NEW.created_at,
                    now())
            ON CONFLICT (user_id, account_id) DO UPDATE
               SET state      = EXCLUDED.state,
                   invited_by = EXCLUDED.invited_by,
                   updated_at = now()
             WHERE kacho_iam.memberships.state      IS DISTINCT FROM EXCLUDED.state
                OR kacho_iam.memberships.invited_by IS DISTINCT FROM EXCLUDED.invited_by;
        END IF;
    ELSE
        -- Правка строки: зеркало ПРАВИТ существующее членство и НЕ заводит
        -- нового. Снятое членство не возвращается ничем, кроме приглашения.
        UPDATE kacho_iam.memberships m
           SET state      = CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END,
               invited_by = NEW.invited_by,
               updated_at = now()
         WHERE m.user_id = NEW.id
           AND m.account_id = NEW.account_id
           AND (m.state      IS DISTINCT FROM CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END
             OR m.invited_by IS DISTINCT FROM NEW.invited_by);
    END IF;

    -- Первый вход: человек перестал быть приглашённым — значит приглашённым он
    -- не остаётся НИ В ОДНОМ аккаунте (20260823053000, воспроизведено дословно).
    IF NEW.invite_status <> 'PENDING' THEN
        UPDATE kacho_iam.memberships
           SET state = 'ACTIVE', updated_at = now()
         WHERE user_id = NEW.id AND state = 'PENDING';
    END IF;

    RETURN NULL;
END;
$$;


--
-- Name: membership_mirror_id(text, text); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.membership_mirror_id(p_user_id text, p_account_id text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT 'mbr-' || substr(md5('membership:' || p_user_id || ':' || p_account_id), 1, 17);
$$;


--
-- Name: minted_cutoff_on_client_removal(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.minted_cutoff_on_client_removal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO kacho_iam.minted_token_revocations (subject, revoke_before, reason, revoked_by)
    VALUES (OLD.id, now(), 'client key revoked: registry row removed', 'kacho_iam:client-key-revoked')
    ON CONFLICT (subject) DO UPDATE
       SET revoke_before = GREATEST(kacho_iam.minted_token_revocations.revoke_before, EXCLUDED.revoke_before),
           reason        = EXCLUDED.reason,
           revoked_by    = EXCLUDED.revoked_by,
           updated_at    = now();
    RETURN NULL;
END;
$$;


--
-- Name: minted_cutoff_on_owner_deactivation(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.minted_cutoff_on_owner_deactivation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO kacho_iam.minted_token_revocations (subject, revoke_before, reason, revoked_by)
    VALUES (NEW.id, now(), 'owner is no longer active', 'kacho_iam:owner-deactivated')
    ON CONFLICT (subject) DO UPDATE
       SET revoke_before = GREATEST(kacho_iam.minted_token_revocations.revoke_before, EXCLUDED.revoke_before),
           reason        = EXCLUDED.reason,
           revoked_by    = EXCLUDED.revoked_by,
           updated_at    = now();
    RETURN NULL;
END;
$$;


--
-- Name: principal_not_referenced_as_subject(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.principal_not_referenced_as_subject() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM kacho_iam.access_binding_subjects
         WHERE subject_type = TG_ARGV[0]
           AND subject_id   = OLD.id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE    = '23503',
            CONSTRAINT = 'access_binding_subjects_subject_ref',
            MESSAGE    = format('%s %s is referenced by an access binding subject and cannot be deleted',
                                TG_ARGV[0], OLD.id);
    END IF;
    RETURN OLD;
END;
$$;


--
-- Name: provider_compensation_outbox_notify(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.provider_compensation_outbox_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('kacho_iam_provider_compensation_outbox', NEW.id::text);
    RETURN NEW;
END;
$$;


--
-- Name: relation_fact_from_journal(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.relation_fact_from_journal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_user      text := NEW.payload ->> 'user';
    v_object    text := NEW.payload ->> 'object';
    v_relations text[];
    v_relation  text;
    v_type      text;
    v_id        text;
    v_colon     int;
BEGIN
    -- Набор ВЫИГРЫВАЕТ у скаляра: на выдаче набора присутствуют оба поля, и
    -- скаляр там — эхо для пода прежнего выпуска, а не весь предмет строки.
    IF jsonb_array_length(coalesce(NEW.payload -> 'relations', '[]'::jsonb)) > 0 THEN
        SELECT array_agg(value) INTO v_relations
          FROM jsonb_array_elements_text(NEW.payload -> 'relations') AS value;
    ELSIF NEW.payload ->> 'relation' IS NOT NULL THEN
        v_relations := ARRAY[NEW.payload ->> 'relation'];
    END IF;

    IF v_user IS NULL OR v_relations IS NULL OR v_object IS NULL THEN
        RAISE EXCEPTION
            'fga_outbox: строка без user/relation/object (%). Прямой факт складывается из этого журнала, и строка, которую нельзя спроецировать, дала бы движку право, о котором своя БД не знает.',
            NEW.payload;
    END IF;

    -- Глагол выводится из выдачи и копией не хранится (см. 0098). Набор из
    -- одних глаголов выходит здесь — до разбора объекта, как и одиночный.
    v_relations := ARRAY(SELECT r FROM unnest(v_relations) AS r WHERE r NOT LIKE 'v\_%');
    IF array_length(v_relations, 1) IS NULL THEN
        RETURN NULL;
    END IF;

    v_colon := position(':' in v_object);
    IF v_colon <= 1 OR v_colon = length(v_object) THEN
        RAISE EXCEPTION
            'fga_outbox: объект % не имеет формы "<тип>:<идентификатор>" — спроецировать прямой факт нельзя.',
            v_object;
    END IF;
    v_type := substr(v_object, 1, v_colon - 1);
    v_id   := substr(v_object, v_colon + 1);

    IF v_type LIKE '%.%' THEN
        RAISE EXCEPTION
            'fga_outbox: тип объекта % назван словарём каталога. Вопрос о доступе приходит словарём модели прав, и такая строка не совпала бы ни с одним вопросом.',
            v_type;
    END IF;

    FOREACH v_relation IN ARRAY v_relations LOOP
        IF NEW.event_type = 'fga.tuple.write' THEN
            INSERT INTO kacho_iam.relation_fact
                   (object_type, object_id, relation, subject, source_version, created_at)
            VALUES (v_type, v_id, v_relation, v_user, NEW.created_at, now())
            ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
               SET source_version = EXCLUDED.source_version
             WHERE relation_fact.source_version < EXCLUDED.source_version;
        ELSIF NEW.event_type = 'fga.tuple.delete' THEN
            DELETE FROM kacho_iam.relation_fact
             WHERE object_type = v_type AND object_id = v_id
               AND relation = v_relation AND subject = v_user
               AND source_version <= NEW.created_at;
        END IF;
    END LOOP;
    RETURN NULL;
END $$;


--
-- Name: FUNCTION relation_fact_from_journal(); Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON FUNCTION kacho_iam.relation_fact_from_journal() IS 'Проекция журнала намерений в прямой факт. Читает обе формы строки: набор отношений одной выдачи (`relations`, выигрывает у скаляра — он на выдаче лишь эхо) и одиночное `relation`. Отношение-глагол (v_*) НЕ переносится: его форма E выводит из выдачи, и копия сделала бы теневое сравнение тождеством.';


--
-- Name: resource_reconcile_outbox_notify(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.resource_reconcile_outbox_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('kacho_iam_resource_reconcile_outbox', NEW.id::text);
    RETURN NEW;
END;
$$;


--
-- Name: role_rule_selector_types_live(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.role_rule_selector_types_live() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    declared_type text;
BEGIN
    FOREACH declared_type IN ARRAY NEW.object_types LOOP
        -- FOR KEY SHARE — тот же замок, который взял бы внешний ключ, будь он на
        -- элемент массива выразим. Он не даёт снятию строки каталога разойтись с
        -- этой записью по разным снимкам: снятие меняет `live`, входящий в
        -- уникальные ограничения — цели внешних ключей, то есть обновляет КЛЮЧ и
        -- берёт FOR UPDATE, а FOR UPDATE с FOR KEY SHARE конфликтует.
        PERFORM 1 FROM kacho_iam.catalog_resource cr
         WHERE cr.dotted = declared_type AND cr.live
           FOR KEY SHARE OF cr;
        IF NOT FOUND THEN
            RAISE EXCEPTION
                'object_types: % is not a live platform resource (role %)',
                declared_type, NEW.role_id
                USING ERRCODE = '23514',
                      CONSTRAINT = 'role_rule_selectors_types_live';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;


--
-- Name: FUNCTION role_rule_selector_types_live(); Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON FUNCTION kacho_iam.role_rule_selector_types_live() IS 'Референт ТРЕТЬЕЙ поверхности проекции правила: каждый элемент role_rule_selectors.object_types обязан называть живую строку kacho_iam.catalog_resource. Внешний ключ на элемент массива невыразим, проверка в коде запрещена (ban #10) — поэтому триггер. Проверяется КАЖДЫЙ элемент; отказ 23514 называет элемент и роль. Локальная переменная названа declared_type, а не именем колонки catalog_resource: совпадение имён даёт 42702 на КАЖДОЙ записи селектора. Строка каталога читается ПОД FOR KEY SHARE — тем же замком, который взял бы внешний ключ: без него снятие строки и запись селектора расходятся по своим снимкам (перекос записи, #1985).';


--
-- Name: subject_ref_exists(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.subject_ref_exists() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    parent_is_system boolean;
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.subject_type = OLD.subject_type
       AND NEW.subject_id   = OLD.subject_id THEN
        RETURN NEW;
    END IF;

    IF NEW.subject_type = 'user' AND NEW.subject_id = '*' THEN
        IF TG_TABLE_NAME = 'access_binding_subjects' THEN
            SELECT b.is_system INTO parent_is_system
              FROM kacho_iam.access_bindings b
             WHERE b.id = NEW.binding_id
             FOR KEY SHARE;
            IF NOT FOUND OR NOT parent_is_system THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'Illegal argument subject_id * on a non-system access binding';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.subject_type = 'user' THEN
        PERFORM 1 FROM kacho_iam.users
            WHERE id = NEW.subject_id FOR KEY SHARE;
    ELSIF NEW.subject_type = 'service_account' THEN
        PERFORM 1 FROM kacho_iam.service_accounts
            WHERE id = NEW.subject_id FOR KEY SHARE;
    ELSIF NEW.subject_type = 'group' THEN
        PERFORM 1 FROM kacho_iam.groups
            WHERE id = NEW.subject_id FOR KEY SHARE;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = format('Illegal argument subject_type %s', NEW.subject_type);
    END IF;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503',
            MESSAGE = format('%s %s not found', NEW.subject_type, NEW.subject_id);
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: text_array_longest(text[]); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.text_array_longest(a text[]) RETURNS integer
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $$ SELECT coalesce(max(length(x)), 0) FROM unnest(a) AS x $$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: access_binding_emitted_tuples; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.access_binding_emitted_tuples (
    binding_id text NOT NULL,
    fga_user text NOT NULL,
    relation text NOT NULL,
    object text NOT NULL,
    source text DEFAULT 'binding'::text NOT NULL,
    CONSTRAINT access_binding_emitted_tuples_object_nonempty CHECK ((object <> ''::text)),
    CONSTRAINT access_binding_emitted_tuples_relation_nonempty CHECK ((relation <> ''::text)),
    CONSTRAINT access_binding_emitted_tuples_source_ck CHECK ((source = ANY (ARRAY['binding'::text, 'member'::text]))),
    CONSTRAINT access_binding_emitted_tuples_user_nonempty CHECK ((fga_user <> ''::text))
);


--
-- Name: access_binding_subjects; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.access_binding_subjects (
    binding_id text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    ordinal integer DEFAULT 0 NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    CONSTRAINT access_binding_subjects_id_nonempty_ck CHECK ((subject_id <> ''::text)),
    CONSTRAINT access_binding_subjects_type_ck CHECK ((subject_type = ANY (ARRAY['user'::text, 'service_account'::text, 'group'::text])))
);


--
-- Name: access_binding_target_members; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.access_binding_target_members (
    binding_id text NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    verification_status text DEFAULT 'PENDING_VERIFICATION'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    role_id text NOT NULL,
    rule_fp text NOT NULL,
    live boolean DEFAULT true NOT NULL,
    CONSTRAINT access_binding_target_members_id_nonempty CHECK ((object_id <> ''::text)),
    CONSTRAINT access_binding_target_members_live_true CHECK (live),
    CONSTRAINT access_binding_target_members_rulefp_nonempty CHECK ((rule_fp <> ''::text)),
    CONSTRAINT access_binding_target_members_status_valid CHECK ((verification_status = ANY (ARRAY['PENDING_VERIFICATION'::text, 'ACTIVE'::text, 'REJECTED'::text]))),
    CONSTRAINT access_binding_target_members_type_nonempty CHECK ((object_type <> ''::text))
);


--
-- Name: COLUMN access_binding_target_members.live; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.access_binding_target_members.live IS 'Константа true. Колонка существует ради ключа access_binding_target_members_role_live_fk: сослаться на «эта роль И она жива» без неё нечем. Константа законна потому, что строка состава СНИМАЕТСЯ, а не помечается.';


--
-- Name: access_bindings; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.access_bindings (
    id text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    role_id text,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    status text DEFAULT 'ACTIVE'::text NOT NULL,
    expires_at timestamp with time zone,
    granted_by_user_id text DEFAULT ''::text NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by_user_id text,
    scope smallint NOT NULL,
    deletion_protection boolean DEFAULT false NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    target jsonb DEFAULT '{"allInScope": true}'::jsonb NOT NULL,
    target_digest text DEFAULT 'all'::text NOT NULL,
    granted_relation text DEFAULT ''::text NOT NULL,
    is_system boolean DEFAULT false NOT NULL,
    CONSTRAINT access_bindings_expires_future_ck CHECK (((expires_at IS NULL) OR (expires_at > created_at))),
    CONSTRAINT access_bindings_grant_form_ck CHECK ((((role_id IS NOT NULL) AND (granted_relation = ''::text)) OR ((role_id IS NULL) AND (granted_relation <> ''::text)))),
    CONSTRAINT access_bindings_granted_by_check CHECK ((length(granted_by_user_id) <= 64)),
    CONSTRAINT access_bindings_granted_relation_shape_ck CHECK (((granted_relation = ''::text) OR (granted_relation ~ '^[a-z][a-z0-9_]*$'::text))),
    CONSTRAINT access_bindings_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels)),
    CONSTRAINT access_bindings_relation_form_anchor_ck CHECK (((granted_relation = ''::text) OR (resource_type = ANY (ARRAY['cluster'::text, 'account'::text, 'project'::text])))),
    CONSTRAINT access_bindings_relation_form_is_system_ck CHECK (((granted_relation = ''::text) OR is_system)),
    CONSTRAINT access_bindings_resource_ck CHECK (((resource_type ~ '^[a-z][a-z0-9_]*$'::text) OR (resource_type = '*'::text))),
    CONSTRAINT access_bindings_revoked_by_check CHECK (((revoked_by_user_id IS NULL) OR (length(revoked_by_user_id) <= 64))),
    CONSTRAINT access_bindings_revoked_consistency_ck CHECK ((((status = 'REVOKED'::text) AND (revoked_at IS NOT NULL)) OR ((status = ANY (ARRAY['PENDING'::text, 'ACTIVE'::text])) AND (revoked_at IS NULL) AND (revoked_by_user_id IS NULL)))),
    CONSTRAINT access_bindings_scope_ck CHECK ((scope = ANY (ARRAY[1, 2, 3]))),
    CONSTRAINT access_bindings_status_ck CHECK ((status = ANY (ARRAY['PENDING'::text, 'ACTIVE'::text, 'REVOKED'::text]))),
    CONSTRAINT access_bindings_subject_ck CHECK ((subject_type = ANY (ARRAY['user'::text, 'service_account'::text, 'group'::text]))),
    CONSTRAINT access_bindings_target_resources_card_ck CHECK (((jsonb_typeof((target -> 'resources'::text)) <> 'array'::text) OR (jsonb_array_length((target -> 'resources'::text)) <= 256))),
    CONSTRAINT access_bindings_wildcard_subject_is_system_ck CHECK (((subject_id <> '*'::text) OR (is_system AND (subject_type = 'user'::text))))
);


--
-- Name: COLUMN access_bindings.granted_relation; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.access_bindings.granted_relation IS 'Имя отношения модели, выдаваемое напрямую на области выдачи. Взаимоисключающе с role_id.';


--
-- Name: COLUMN access_bindings.is_system; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.access_bindings.is_system IS 'Выдача заведена платформой. Только для чтения на публичном контракте.';


--
-- Name: account_admission_rate_limits; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.account_admission_rate_limits (
    id bigint NOT NULL,
    kind text NOT NULL,
    max_events bigint NOT NULL,
    window_seconds bigint NOT NULL,
    withdrawn_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT account_admission_rate_limits_kind_ck CHECK ((kind ~ '^[a-z][a-z0-9]*\.[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)?$'::text)),
    CONSTRAINT account_admission_rate_limits_max_ck CHECK ((max_events >= 0)),
    CONSTRAINT account_admission_rate_limits_window_ck CHECK ((window_seconds > 0))
);


--
-- Name: TABLE account_admission_rate_limits; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.account_admission_rate_limits IS 'the ceiling on the RATE at which one identity may create accounts: how many per window. Separate from kacho_iam.limits because the value here is a PAIR and because the closed catalogue of countable kinds admits only real authz object types — a rate is not a thing one counts instances of';


--
-- Name: account_admission_rate_limits_id_seq; Type: SEQUENCE; Schema: kacho_iam; Owner: -
--

CREATE SEQUENCE kacho_iam.account_admission_rate_limits_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: account_admission_rate_limits_id_seq; Type: SEQUENCE OWNED BY; Schema: kacho_iam; Owner: -
--

ALTER SEQUENCE kacho_iam.account_admission_rate_limits_id_seq OWNED BY kacho_iam.account_admission_rate_limits.id;


--
-- Name: accounts; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.accounts (
    id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    owner_user_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT accounts_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT accounts_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels)),
    CONSTRAINT accounts_name_check CHECK ((name ~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'::text))
);


--
-- Name: audit_outbox; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.audit_outbox (
    id text NOT NULL,
    event_type text NOT NULL,
    tenant_account_id text,
    event_payload jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    sent_at timestamp with time zone,
    last_error text,
    CONSTRAINT audit_outbox_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT audit_outbox_event_type_check CHECK (((length(event_type) >= 1) AND (length(event_type) <= 128) AND (event_type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'::text))),
    CONSTRAINT audit_outbox_id_check CHECK ((id ~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$'::text)),
    CONSTRAINT audit_outbox_payload_object_ck CHECK ((jsonb_typeof(event_payload) = 'object'::text)),
    CONSTRAINT audit_outbox_sent_at_check CHECK (((status = 'sent'::text) = (sent_at IS NOT NULL))),
    CONSTRAINT audit_outbox_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'sent'::text])))
);


--
-- Name: catalog_module; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.catalog_module (
    module text NOT NULL,
    retired_at timestamp with time zone,
    retired_reason text,
    live boolean DEFAULT true NOT NULL,
    CONSTRAINT catalog_module_live_matches_retired CHECK ((live = (retired_at IS NULL))),
    CONSTRAINT catalog_module_nonempty CHECK ((module <> ''::text)),
    CONSTRAINT catalog_module_undotted CHECK ((module !~~ '%.%'::text))
);


--
-- Name: TABLE catalog_module; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.catalog_module IS 'Каталог модулей платформы. Источник посева — domain.KnownModules(). Строка живёт, пока retired_at IS NULL; согласие держит проверка, а не писатель.';


--
-- Name: catalog_resource; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.catalog_resource (
    module text NOT NULL,
    resource text NOT NULL,
    dotted text NOT NULL,
    retired_at timestamp with time zone,
    retired_reason text,
    superseded_by text,
    live boolean DEFAULT true NOT NULL,
    module_live boolean GENERATED ALWAYS AS (
CASE
    WHEN live THEN true
    ELSE NULL::boolean
END) STORED,
    object_type text NOT NULL,
    CONSTRAINT catalog_resource_dotted_form CHECK ((dotted = ((module || '.'::text) || resource))),
    CONSTRAINT catalog_resource_live_matches_retired CHECK ((live = (retired_at IS NULL))),
    CONSTRAINT catalog_resource_module_undotted CHECK ((module !~~ '%.%'::text)),
    CONSTRAINT catalog_resource_nonempty CHECK (((module <> ''::text) AND (resource <> ''::text))),
    CONSTRAINT catalog_resource_object_type_form CHECK ((object_type ~ '^[a-z][a-z0-9_]*$'::text)),
    CONSTRAINT catalog_resource_resource_undotted CHECK ((resource !~~ '%.%'::text)),
    CONSTRAINT catalog_resource_successor_only_when_retired CHECK (((superseded_by IS NULL) OR (NOT live)))
);


--
-- Name: TABLE catalog_resource; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.catalog_resource IS 'Каталог грантуемых типов. Источник посева — authzmap.objectTypes (27 живых) плюс domain.retiredTypes (3 снятых с преемником). Ключ role_rule_ref_res_fk ссылается на (module, resource, live), ключ role_verb_type_fk — на (dotted, live).';


--
-- Name: COLUMN catalog_resource.superseded_by; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.catalog_resource.superseded_by IS 'Точечное имя ЖИВОГО ресурса взамен снятого. Читается путём чтения каталога: в прерванной транзакции отказа чтения нет by construction, поэтому текст отказа преемника не называет и не обещает.';


--
-- Name: COLUMN catalog_resource.module_live; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.catalog_resource.module_live IS 'Составляющая ключа «мой модуль ЖИВ». У живой строки — true, у снятой — NULL, и NULL здесь означает «эта строка модуль не удерживает», а не «значение не задано»: ключ с пустой составляющей считается выполненным (MATCH SIMPLE). Константа true сделала бы модуль неснимаемым — снятые строки каталога не удаляются.';


--
-- Name: COLUMN catalog_resource.object_type; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.catalog_resource.object_type IS 'Имя типа МОДЕЛИ ПРАВ (vpc_network, account), которым адресуется отношение v_<глагол>. Объявляется строкой манифеста (resources[].objectType) и приезжает вместе с ресурсом: правила вывода из пары не существует — у storage/registry имя ресурса множественное, а тип единственного числа, у ярусных предков иерархии тип идёт без приставки модуля. Без этой колонки тип, заведённый применением манифеста в работающем процессе, не доезжал бы до проекции вовсе (#1816, IAM-CT-2-14).';


--
-- Name: catalog_verb; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.catalog_verb (
    module text NOT NULL,
    resource text NOT NULL,
    verb text NOT NULL,
    retired_at timestamp with time zone,
    retired_reason text,
    live boolean DEFAULT true NOT NULL,
    per_object boolean DEFAULT true NOT NULL,
    resource_live boolean GENERATED ALWAYS AS (
CASE
    WHEN live THEN true
    ELSE NULL::boolean
END) STORED,
    CONSTRAINT catalog_verb_canonical CHECK ((verb = lower(btrim(verb)))),
    CONSTRAINT catalog_verb_live_matches_retired CHECK ((live = (retired_at IS NULL))),
    CONSTRAINT catalog_verb_nonempty CHECK ((verb <> ''::text)),
    CONSTRAINT catalog_verb_undotted CHECK ((verb !~~ '%.%'::text))
);


--
-- Name: TABLE catalog_verb; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.catalog_verb IS 'Каталог глаголов ресурса, ДВУМЯ половинами: пообъектная (per_object = true) — источник посева authzmap.typeVerbRelations; ярусная (per_object = false) — классы действия без пообъектного референта by construction (create). Ключ role_rule_ref_verb_fk судит АВТОРСКИЙ глагол правила и ссылается на обе; набор глаголов ТИПА остаётся пообъектным.';


--
-- Name: COLUMN catalog_verb.per_object; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.catalog_verb.per_object IS 'Строка ПРОИЗВОДИТ пообъектное отношение v_<verb> на своём типе. Ложь — глагол законен АВТОРСКИ и не даёт кортежа ни на одном объекте: его действие несёт ярус на родителе. Читается internal/catalog.NewFacts: ярусная строка в набор глаголов типа НЕ входит, поэтому не материализуется.';


--
-- Name: COLUMN catalog_verb.resource_live; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.catalog_verb.resource_live IS 'Составляющая ключа «мой ресурс ЖИВ». У живой строки — true, у снятой — NULL, и NULL здесь означает «эта строка ресурс не удерживает», а не «значение не задано»: ключ с пустой составляющей не проверяется вовсе (MATCH SIMPLE). Константа true сделала бы ресурс неснимаемым — снятые строки каталога не удаляются. СУЩЕСТВОВАНИЕ ресурса эта колонка не утверждает: его держит catalog_verb_resource_fk, и потому тот ключ не снимается.';


--
-- Name: client_assertion_replay; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.client_assertion_replay (
    client_id text NOT NULL,
    assertion_id text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    redeemed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT client_assertion_replay_assertion_ck CHECK (((length(assertion_id) >= 1) AND (length(assertion_id) <= 256))),
    CONSTRAINT client_assertion_replay_client_ck CHECK (((length(client_id) >= 1) AND (length(client_id) <= 128)))
);


--
-- Name: TABLE client_assertion_replay; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.client_assertion_replay IS 'Погашенные утверждения клиента: пара «клиент + идентификатор однократности». Допуск — один оператор, уникальность держит первичный ключ. Строка живёт до истечения утверждения и убирается сборщиком.';


--
-- Name: cluster_admin_grants; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.cluster_admin_grants (
    id text NOT NULL,
    cluster_id text DEFAULT 'cluster_kacho_root'::text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    granted_by text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    granted_until timestamp with time zone,
    CONSTRAINT cluster_admin_grants_granted_by_check CHECK (((length(granted_by) >= 1) AND (length(granted_by) <= 64))),
    CONSTRAINT cluster_admin_grants_id_check CHECK ((id ~ '^cag_[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT cluster_admin_grants_subject_id_check CHECK (((length(subject_id) >= 1) AND (length(subject_id) <= 64))),
    CONSTRAINT cluster_admin_grants_subject_type_check CHECK ((subject_type = ANY (ARRAY['user'::text, 'service_account'::text]))),
    CONSTRAINT cluster_admin_grants_until_check CHECK (((granted_until IS NULL) OR (granted_until > granted_at)))
);


--
-- Name: clusters; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.clusters (
    id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT clusters_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT clusters_id_singleton_ck CHECK ((id = 'cluster_kacho_root'::text)),
    CONSTRAINT clusters_name_check CHECK (((length(name) >= 1) AND (length(name) <= 64) AND (name ~ '^[a-z][-a-z0-9]{0,62}[a-z0-9]?$'::text)))
);


--
-- Name: federated_trusted_issuers; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.federated_trusted_issuers (
    issuer text NOT NULL,
    subject text NOT NULL,
    sa_oauth_client_id text NOT NULL,
    public_key_pem text NOT NULL,
    key_algorithm text NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federated_trusted_issuers_alg_ck CHECK ((key_algorithm = ANY (ARRAY['ES256'::text, 'RS256'::text, 'EdDSA'::text]))),
    CONSTRAINT federated_trusted_issuers_expires_future_ck CHECK (((expires_at IS NULL) OR (expires_at > created_at))),
    CONSTRAINT federated_trusted_issuers_issuer_ck CHECK (((btrim(issuer) <> ''::text) AND (length(issuer) <= 512))),
    CONSTRAINT federated_trusted_issuers_key_not_blank CHECK (((btrim(public_key_pem) <> ''::text) AND (length(public_key_pem) <= 8192))),
    CONSTRAINT federated_trusted_issuers_subject_ck CHECK (((btrim(subject) <> ''::text) AND (length(subject) <= 512)))
);


--
-- Name: TABLE federated_trusted_issuers; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.federated_trusted_issuers IS 'Перечень доверенных издателей утверждения (#1124). Читается проверкой утверждения на пути запроса (internal/clientassertion, федеративная полоса) — до этой задачи перечень вёл внешний поставщик, и решение о доверии принимал он. Пара (issuer, subject) глобально уникальна: иначе разрешение стало бы недетерминированным. Пустая таблица означает «не доверяем никому» и является законным состоянием.';


--
-- Name: fga_outbox; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.fga_outbox (
    id bigint NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT fga_outbox_event_type_check CHECK ((event_type = ANY (ARRAY['fga.tuple.write'::text, 'fga.tuple.delete'::text])))
)
WITH (autovacuum_analyze_scale_factor='0.0', autovacuum_analyze_threshold='1000', autovacuum_vacuum_scale_factor='0.0', autovacuum_vacuum_threshold='1000');


--
-- Name: fga_outbox_id_seq; Type: SEQUENCE; Schema: kacho_iam; Owner: -
--

CREATE SEQUENCE kacho_iam.fga_outbox_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fga_outbox_id_seq; Type: SEQUENCE OWNED BY; Schema: kacho_iam; Owner: -
--

ALTER SEQUENCE kacho_iam.fga_outbox_id_seq OWNED BY kacho_iam.fga_outbox.id;


--
-- Name: group_members; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.group_members (
    group_id text NOT NULL,
    member_type text NOT NULL,
    member_id text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT group_members_type_check CHECK ((member_type = ANY (ARRAY['user'::text, 'service_account'::text])))
);


--
-- Name: groups; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.groups (
    id text NOT NULL,
    account_id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT groups_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT groups_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels)),
    CONSTRAINT groups_name_check CHECK ((name ~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'::text))
);


--
-- Name: identity_admission_windows; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.identity_admission_windows (
    carrier_id text NOT NULL,
    kind text NOT NULL,
    window_started_at timestamp with time zone DEFAULT now() NOT NULL,
    admitted bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT identity_admission_windows_admitted_ck CHECK ((admitted >= 0)),
    CONSTRAINT identity_admission_windows_carrier_ck CHECK ((carrier_id <> ''::text))
);


--
-- Name: TABLE identity_admission_windows; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.identity_admission_windows IS 'one row per identity and kind: when the current window started and how many admissions it has taken. A fixed window, not a sliding one — a sliding window needs a row per event and a sweeper. The cost is named rather than hidden: across a window boundary up to 2N admissions are possible';


--
-- Name: COLUMN identity_admission_windows.carrier_id; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.identity_admission_windows.carrier_id IS 'the external login subject (users.external_id), the same carrier the volume ceiling counts by — a user row is a membership and would hand out the bypass';


--
-- Name: identity_journal; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.identity_journal (
    identity text NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT identity_journal_identity_ck CHECK ((identity <> ''::text))
);


--
-- Name: TABLE identity_journal; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.identity_journal IS 'accumulating ledger of every login identity the platform has ever seen. Rows are never removed, not even when the person leaves: the question asked of it is about the whole life of the platform, and an instantaneous count answers a different one. Monotone by construction, so growth is defined on it';


--
-- Name: COLUMN identity_journal.identity; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.identity_journal.identity IS 'the external login subject (users.external_id), NOT a user row id: a user row is a membership scoped to one account, and one person holds one per account';


--
-- Name: interactive_clients; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.interactive_clients (
    id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    redirect_uris text[] NOT NULL,
    post_logout_redirect_uris text[] DEFAULT '{}'::text[] NOT NULL,
    client_id text NOT NULL,
    audiences text[] DEFAULT '{}'::text[] NOT NULL,
    grant_types text[] DEFAULT '{}'::text[] NOT NULL,
    token_endpoint_auth_method text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'ACTIVE'::text NOT NULL,
    CONSTRAINT interactive_clients_id_form_ck CHECK ((id ~ '^ic-[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT interactive_clients_name_check CHECK ((name ~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT interactive_clients_post_logout_uris_count_ck CHECK ((COALESCE(array_length(post_logout_redirect_uris, 1), 0) <= 16)),
    CONSTRAINT interactive_clients_redirect_uris_count_ck CHECK (((COALESCE(array_length(redirect_uris, 1), 0) >= 1) AND (COALESCE(array_length(redirect_uris, 1), 0) <= 16))),
    CONSTRAINT interactive_clients_status_ck CHECK ((status = ANY (ARRAY['ACTIVE'::text, 'DELETING'::text])))
);


--
-- Name: invite_mail_outbox; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.invite_mail_outbox (
    id bigint NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    resource_kind text DEFAULT ''::text NOT NULL,
    resource_id text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sent_at timestamp with time zone,
    last_error text,
    attempt_count integer DEFAULT 0 NOT NULL,
    CONSTRAINT invite_mail_outbox_event_type_check CHECK ((event_type = ANY (ARRAY['mail.invite.send'::text]))),
    CONSTRAINT invite_mail_outbox_partition_key_ck CHECK ((length(resource_id) > 0)),
    CONSTRAINT invite_mail_outbox_payload_object_ck CHECK ((jsonb_typeof(payload) = 'object'::text)),
    CONSTRAINT invite_mail_outbox_recipient_ck CHECK (COALESCE(((jsonb_typeof((payload -> 'to'::text)) = 'string'::text) AND (length((payload ->> 'to'::text)) > 0)), false))
);


--
-- Name: invite_mail_outbox_id_seq; Type: SEQUENCE; Schema: kacho_iam; Owner: -
--

CREATE SEQUENCE kacho_iam.invite_mail_outbox_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: invite_mail_outbox_id_seq; Type: SEQUENCE OWNED BY; Schema: kacho_iam; Owner: -
--

ALTER SEQUENCE kacho_iam.invite_mail_outbox_id_seq OWNED BY kacho_iam.invite_mail_outbox.id;


--
-- Name: limits; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.limits (
    id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    scope text NOT NULL,
    scope_id text DEFAULT ''::text NOT NULL,
    kind text NOT NULL,
    limit_value bigint NOT NULL,
    withdrawn_at timestamp with time zone,
    revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT limits_id_form_ck CHECK ((id ~ '^lim-[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT limits_kind_form_ck CHECK ((kind ~ '^[a-z][a-z0-9]*\.[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)?$'::text)),
    CONSTRAINT limits_scope_ck CHECK ((scope = ANY (ARRAY['DEFAULT'::text, 'ACCOUNT'::text, 'PROJECT'::text]))),
    CONSTRAINT limits_scope_subject_ck CHECK ((((scope = 'DEFAULT'::text) AND (scope_id = ''::text)) OR ((scope <> 'DEFAULT'::text) AND (scope_id <> ''::text)))),
    CONSTRAINT limits_value_nonnegative_ck CHECK ((limit_value >= 0))
);


--
-- Name: limits_revision_seq; Type: SEQUENCE; Schema: kacho_iam; Owner: -
--

CREATE SEQUENCE kacho_iam.limits_revision_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: memberships; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.memberships (
    id text NOT NULL,
    user_id text NOT NULL,
    account_id text NOT NULL,
    state text DEFAULT 'ACTIVE'::text NOT NULL,
    invited_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT memberships_id_form_check CHECK ((id ~ '^mbr-[0-9abcdefghjkmnpqrstvwxyz]{17}$'::text)),
    CONSTRAINT memberships_state_check CHECK ((state = ANY (ARRAY['PENDING'::text, 'ACTIVE'::text])))
);


--
-- Name: minted_token_revocations; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.minted_token_revocations (
    subject text NOT NULL,
    revoke_before timestamp with time zone NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    revoked_by text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT minted_token_revocations_decider_ck CHECK (((length(revoked_by) >= 1) AND (length(revoked_by) <= 128))),
    CONSTRAINT minted_token_revocations_reason_ck CHECK ((length(reason) <= 256)),
    CONSTRAINT minted_token_revocations_subject_ck CHECK (((length(subject) >= 1) AND (length(subject) <= 128)))
);


--
-- Name: TABLE minted_token_revocations; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.minted_token_revocations IS 'Отзыв токенов, отчеканенных платформой: всё, выпущенное субъекту раньше revoke_before, недействительно. Читается авторитетом отзыва на пути запроса.';


--
-- Name: operations; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.operations (
    id text NOT NULL,
    description text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text DEFAULT 'anonymous'::text NOT NULL,
    principal_type text DEFAULT 'system'::text NOT NULL,
    principal_id text DEFAULT 'bootstrap'::text NOT NULL,
    principal_display_name text DEFAULT 'kacho-iam-bootstrap'::text NOT NULL,
    modified_at timestamp with time zone DEFAULT now() NOT NULL,
    done boolean DEFAULT false NOT NULL,
    metadata_type text,
    metadata_data bytea,
    resource_id text,
    error_code integer,
    error_message text,
    error_details bytea,
    response_type text,
    response_data bytea,
    account_id text,
    CONSTRAINT operations_principal_type_check CHECK ((principal_type = ANY (ARRAY['system'::text, 'anonymous'::text, 'user'::text, 'service_account'::text])))
);


--
-- Name: project_resource_quotas; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.project_resource_quotas (
    carrier_type text NOT NULL,
    carrier_id text NOT NULL,
    kind text NOT NULL,
    used bigint DEFAULT 0 NOT NULL,
    limit_value bigint NOT NULL,
    source_scope text NOT NULL,
    source_scope_id text DEFAULT ''::text NOT NULL,
    limit_revision bigint DEFAULT 0 NOT NULL,
    synced_at timestamp with time zone,
    account_id text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT project_resource_quotas_account_mirror_ck CHECK ((((carrier_type = ANY (ARRAY['identity'::text, 'iam.user'::text])) AND (account_id = ''::text)) OR ((carrier_type <> ALL (ARRAY['identity'::text, 'iam.user'::text])) AND (account_id <> ''::text)))),
    CONSTRAINT project_resource_quotas_carrier_ck CHECK (((carrier_type = ANY (ARRAY['project'::text, 'account'::text, 'identity'::text, 'iam.user'::text, 'iam.serviceAccount'::text])) AND (carrier_id <> ''::text))),
    CONSTRAINT project_resource_quotas_limit_ck CHECK ((limit_value >= 0)),
    CONSTRAINT project_resource_quotas_scope_ck CHECK ((source_scope = ANY (ARRAY['DEFAULT'::text, 'ACCOUNT'::text, 'PROJECT'::text]))),
    CONSTRAINT project_resource_quotas_used_ck CHECK ((used >= 0))
);


--
-- Name: TABLE project_resource_quotas; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.project_resource_quotas IS 'resource-count accounting rows of the limit owner. iam is the only service that both states values and charges one of them: the accounts it counts live in this database, so the charge shares the transaction with the insert and the snapshot is refreshed from the authority in that same statement';


--
-- Name: COLUMN project_resource_quotas.carrier_id; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.project_resource_quotas.carrier_id IS 'for carrier_type=identity this is the external login subject (users.external_id), NOT a user row id: a user row is a membership scoped to one account, and counting per membership would hand out the bypass';


--
-- Name: CONSTRAINT project_resource_quotas_account_mirror_ck ON project_resource_quotas; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON CONSTRAINT project_resource_quotas_account_mirror_ck ON kacho_iam.project_resource_quotas IS 'the account mirror is required of every carrier that BELONGS to exactly one account. The login identity has no account, and a person belongs to many: writing one of them would state a membership that does not hold. A service account belongs to exactly one, and carries it';


--
-- Name: projects; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.projects (
    id text NOT NULL,
    account_id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT projects_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT projects_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels)),
    CONSTRAINT projects_name_check CHECK ((name ~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'::text))
);


--
-- Name: provider_compensation_outbox; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.provider_compensation_outbox (
    id bigint NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    resource_kind text DEFAULT ''::text NOT NULL,
    resource_id text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sent_at timestamp with time zone,
    last_error text,
    attempt_count integer DEFAULT 0 NOT NULL,
    CONSTRAINT provider_compensation_outbox_event_type_check CHECK ((event_type = ANY (ARRAY['provider.oauth_client.delete'::text, 'provider.trust_grant.delete'::text]))),
    CONSTRAINT provider_compensation_outbox_payload_object_ck CHECK ((jsonb_typeof(payload) = 'object'::text)),
    CONSTRAINT provider_compensation_outbox_subject_ck CHECK (COALESCE((((event_type = 'provider.oauth_client.delete'::text) AND (COALESCE(jsonb_typeof((payload -> 'client_id'::text)), ''::text) = 'string'::text) AND (COALESCE(length((payload ->> 'client_id'::text)), 0) > 0) AND ((payload -> 'grant_id'::text) IS NULL)) OR ((event_type = 'provider.trust_grant.delete'::text) AND (COALESCE(jsonb_typeof((payload -> 'grant_id'::text)), ''::text) = 'string'::text) AND (COALESCE(length((payload ->> 'grant_id'::text)), 0) > 0) AND ((payload -> 'client_id'::text) IS NULL))), false))
);


--
-- Name: provider_compensation_outbox_id_seq; Type: SEQUENCE; Schema: kacho_iam; Owner: -
--

CREATE SEQUENCE kacho_iam.provider_compensation_outbox_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: provider_compensation_outbox_id_seq; Type: SEQUENCE OWNED BY; Schema: kacho_iam; Owner: -
--

ALTER SEQUENCE kacho_iam.provider_compensation_outbox_id_seq OWNED BY kacho_iam.provider_compensation_outbox.id;


--
-- Name: recovery_completions; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.recovery_completions (
    recovery_jti text NOT NULL,
    external_id text NOT NULL,
    user_id text NOT NULL,
    revoked_session_count integer DEFAULT 0 NOT NULL,
    completed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT recovery_completions_count_check CHECK ((revoked_session_count >= 0)),
    CONSTRAINT recovery_completions_external_id_check CHECK (((length(external_id) >= 1) AND (length(external_id) <= 128))),
    CONSTRAINT recovery_completions_jti_check CHECK (((length(recovery_jti) >= 1) AND (length(recovery_jti) <= 128))),
    CONSTRAINT recovery_completions_user_id_check CHECK (((length(user_id) >= 1) AND (length(user_id) <= 64)))
);


--
-- Name: TABLE recovery_completions; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.recovery_completions IS 'Idempotency ledger for the Kratos recovery-completed webhook. PK recovery_jti dedups at-least-once delivery via INSERT … ON CONFLICT DO NOTHING; stores user_id / revoked_session_count for idempotent replay.';


--
-- Name: relation_fact; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.relation_fact (
    object_type text NOT NULL,
    object_id text NOT NULL,
    relation text NOT NULL,
    subject text NOT NULL,
    source_version timestamp with time zone DEFAULT '-infinity'::timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    condition_name text DEFAULT ''::text NOT NULL,
    condition_params jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT relation_fact_condition_params_is_object CHECK ((jsonb_typeof(condition_params) = 'object'::text)),
    CONSTRAINT relation_fact_object_id_nonempty CHECK ((object_id <> ''::text)),
    CONSTRAINT relation_fact_object_type_model_dictionary CHECK ((object_type !~~ '%.%'::text)),
    CONSTRAINT relation_fact_object_type_nonempty CHECK ((object_type <> ''::text)),
    CONSTRAINT relation_fact_params_require_condition CHECK (((condition_name <> ''::text) OR (condition_params = '{}'::jsonb))),
    CONSTRAINT relation_fact_relation_nonempty CHECK ((relation <> ''::text)),
    CONSTRAINT relation_fact_subject_nonempty CHECK ((subject <> ''::text))
);


--
-- Name: COLUMN relation_fact.object_type; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.relation_fact.object_type IS 'Тип объекта в словаре МОДЕЛИ ПРАВ — как в кортеже отношения, из которого факт записан.';


--
-- Name: resource_mirror; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.resource_mirror (
    object_type text NOT NULL,
    object_id text NOT NULL,
    parent_project_id text DEFAULT ''::text NOT NULL,
    parent_account_id text DEFAULT ''::text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    source_version timestamp with time zone DEFAULT '-infinity'::timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT resource_mirror_id_nonempty CHECK ((object_id <> ''::text)),
    CONSTRAINT resource_mirror_labels_object CHECK ((jsonb_typeof(labels) = 'object'::text)),
    CONSTRAINT resource_mirror_type_nonempty CHECK ((object_type <> ''::text))
);


--
-- Name: resource_parent_edge; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.resource_parent_edge (
    object_type text NOT NULL,
    object_id text NOT NULL,
    parent_type text NOT NULL,
    parent_id text NOT NULL,
    depth integer NOT NULL,
    source_version timestamp with time zone DEFAULT '-infinity'::timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT resource_parent_edge_depth_bounded CHECK (((depth >= 1) AND (depth <= 4))),
    CONSTRAINT resource_parent_edge_no_self CHECK ((NOT ((object_type = parent_type) AND (object_id = parent_id)))),
    CONSTRAINT resource_parent_edge_object_id_nonempty CHECK ((object_id <> ''::text)),
    CONSTRAINT resource_parent_edge_object_type_model_dictionary CHECK ((object_type !~~ '%.%'::text)),
    CONSTRAINT resource_parent_edge_object_type_nonempty CHECK ((object_type <> ''::text)),
    CONSTRAINT resource_parent_edge_parent_id_nonempty CHECK ((parent_id <> ''::text)),
    CONSTRAINT resource_parent_edge_parent_type_model_dictionary CHECK ((parent_type !~~ '%.%'::text)),
    CONSTRAINT resource_parent_edge_parent_type_nonempty CHECK ((parent_type <> ''::text))
);


--
-- Name: TABLE resource_parent_edge; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.resource_parent_edge IS 'Цепь предков объекта в том виде, в каком её прислал владелец объекта: строка на предка, глубина — расстояние (1 — непосредственный). ЗАМЫКАНИЕМ НЕ ЯВЛЯЕТСЯ и схемой не требуется: производители шлют короткую цепь (обычно одно звено). СЮДА ПИШУТ, А ЧИТАЮТ ИЗ resource_scope_edge (миграция 740001): вопрос о доступе поднимается по представлению, которое добавляет к этим строкам два звена, выводимых из собственной схемы iam, — project→account и account→cluster. Прежде чем менять обход на одно чтение, докажи полноту замыкания: его не даёт ни эта таблица, ни представление.';


--
-- Name: COLUMN resource_parent_edge.object_type; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.resource_parent_edge.object_type IS 'Тип объекта в словаре МОДЕЛИ ПРАВ (vpc_network, account, cluster) — тем же, каким приходит вопрос о доступе и каким названы relation_fact.object_type и access_bindings.resource_type. НЕ словарь каталога (vpc.network): соединение по разным написаниям не совпадает никогда и молча.';


--
-- Name: COLUMN resource_parent_edge.parent_type; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.resource_parent_edge.parent_type IS 'Тип предка на расстоянии depth. Строка на дальнего предка ДОПУСКАЕТСЯ схемой, но производителями сегодня не пишется.';


--
-- Name: COLUMN resource_parent_edge.parent_id; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.resource_parent_edge.parent_id IS 'Идентификатор предка на расстоянии depth. Наличие строки на дальнего предка не гарантировано — цепь собирается обходом.';


--
-- Name: resource_reconcile_outbox; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.resource_reconcile_outbox (
    id bigint NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    event_type text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sent_at timestamp with time zone,
    last_error text,
    attempt_count integer DEFAULT 0 NOT NULL,
    CONSTRAINT resource_reconcile_outbox_event_valid CHECK ((event_type = ANY (ARRAY['mirror.upsert'::text, 'mirror.delete'::text]))),
    CONSTRAINT resource_reconcile_outbox_id_nonempty CHECK ((object_id <> ''::text)),
    CONSTRAINT resource_reconcile_outbox_type_nonempty CHECK ((object_type <> ''::text))
);


--
-- Name: resource_reconcile_outbox_id_seq; Type: SEQUENCE; Schema: kacho_iam; Owner: -
--

ALTER TABLE kacho_iam.resource_reconcile_outbox ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME kacho_iam.resource_reconcile_outbox_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: roles; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.roles (
    id text NOT NULL,
    account_id text,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    permissions jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    cluster_id text,
    project_id text,
    rules jsonb DEFAULT '[]'::jsonb NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_system boolean GENERATED ALWAYS AS ((cluster_id IS NOT NULL)) STORED,
    owner_module text,
    retired_at timestamp with time zone,
    retired_reason text,
    retired_by text,
    live boolean DEFAULT true NOT NULL,
    CONSTRAINT roles_custom_name_check CHECK ((is_system OR (name ~ '^[a-z][a-z0-9_]{0,40}$'::text))),
    CONSTRAINT roles_definition_tier_xor CHECK ((num_nonnulls(cluster_id, account_id, project_id) = 1)),
    CONSTRAINT roles_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT roles_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels)),
    CONSTRAINT roles_live_matches_retired CHECK ((live = (retired_at IS NULL))),
    CONSTRAINT roles_owner_module_is_cluster_tier CHECK (((owner_module IS NULL) OR is_system)),
    CONSTRAINT roles_owner_module_name_prefix CHECK (((owner_module IS NULL) OR ("left"(name, (length(owner_module) + 1)) = (owner_module || '.'::text)))),
    CONSTRAINT roles_permissions_valid CHECK ((((jsonb_array_length(permissions) = 0) AND (jsonb_array_length(rules) > 0)) OR kacho_iam.iam_permissions_valid(permissions))),
    CONSTRAINT roles_rule_wildcards_confined CHECK (kacho_iam.iam_rule_wildcards_confined(rules, owner_module)),
    CONSTRAINT roles_rules_valid CHECK (kacho_iam.iam_rules_valid(rules)),
    CONSTRAINT roles_system_name_check CHECK (((NOT is_system) OR (name ~ '^[a-z][-a-z0-9]*(\.[a-z][a-z0-9_]*){0,2}$'::text)))
);


--
-- Name: COLUMN roles.owner_module; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.roles.owner_module IS 'Модуль, которому принадлежит роль. NULL — платформенная роль (admin/edit/view/owner, kacho-system.*): её объявляет платформа, и послабление подстановки у неё полное. Непустое значение — роль, объявленная манифестом этого модуля: подстановка законна ровно в пределах названного модуля (roles_rule_wildcards_confined), а имя составлено из владельца (roles_owner_module_name_prefix). Признак is_system при этом НЕ меняется ни на одну строку: роль модуля остаётся системной, и арендатор её по-прежнему не правит. Задача продукта #1032.';


--
-- Name: COLUMN roles.retired_at; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.roles.retired_at IS 'Момент снятия роли. NULL — роль объявлена. Согласие с live держит проверка roles_live_matches_retired, а не писатель.';


--
-- Name: COLUMN roles.retired_reason; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.roles.retired_reason IS 'Причина снятия — то, что арендатор читает у отобранного права. Без неё «отобрали» неотличимо от «сломалось».';


--
-- Name: COLUMN roles.retired_by; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.roles.retired_by IS 'Кто снял: сегодня — процессный актор пути старта; глагол применения назовёт проверенную личность вызывающего. Колонка NULLABLE, и это отличие от applied_by двух ведомостей (20260903215500, там NOT NULL DEFAULT '') названо намеренно: здесь пустого значения у снятой строки НЕ БЫВАЕТ — производитель заводится тем же изменением, что и колонка, и пишет автора всегда. NULL означает «роль не снята», а не «автора потеряли», и согласие с этим держит roles_live_matches_retired.';


--
-- Name: COLUMN roles.live; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.roles.live IS 'Живость строки роли. Колонка ОБЫЧНАЯ, а не выражение: на ней стоит референт uniqueness (id, live), а выражение референтом быть не может. Умолчание true делает существующие строки живыми БЕЗ обратного заполнения.';


--
-- Name: CONSTRAINT roles_owner_module_is_cluster_tier ON roles; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON CONSTRAINT roles_owner_module_is_cluster_tier ON kacho_iam.roles IS 'Роль с владельцем-модулем стоит на кластерном ярусе. До этого ограничения инвариант держали ДВА софтверных места (пропуск не-кластерного яруса применителем и единственный писатель owner_module) и — побочно — две проверки ИМЕНИ, требования которых несовместимы. Ни одно из четырёх не про владение: первые два снимаются вторым писателем, вторые два — послаблением формы имени. Задача продукта #2020.';


--
-- Name: service_accounts; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.service_accounts (
    id text NOT NULL,
    account_id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT service_accounts_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT service_accounts_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels)),
    CONSTRAINT service_accounts_name_check CHECK ((name ~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'::text))
);


--
-- Name: resource_scope_edge; Type: VIEW; Schema: kacho_iam; Owner: -
--

CREATE VIEW kacho_iam.resource_scope_edge AS
 SELECT e.object_type,
    e.object_id,
    e.parent_type,
    e.parent_id,
    e.depth
   FROM kacho_iam.resource_parent_edge e
UNION ALL
 SELECT 'project'::text AS object_type,
    f.object_id,
    split_part(f.subject, ':'::text, 1) AS parent_type,
    substr(f.subject, (POSITION((':'::text) IN (f.subject)) + 1)) AS parent_id,
    1 AS depth
   FROM kacho_iam.relation_fact f
  WHERE ((f.object_type = 'project'::text) AND (f.relation = split_part(f.subject, ':'::text, 1)) AND (POSITION(('#'::text) IN (f.subject)) = 0) AND (NOT (EXISTS ( SELECT 1
           FROM kacho_iam.resource_parent_edge e
          WHERE ((e.object_type = 'project'::text) AND (e.object_id = f.object_id))))))
UNION ALL
 SELECT 'account'::text AS object_type,
    a.id AS object_id,
    'cluster'::text AS parent_type,
    c.id AS parent_id,
    1 AS depth
   FROM (kacho_iam.accounts a
     CROSS JOIN kacho_iam.clusters c)
  WHERE (NOT (EXISTS ( SELECT 1
           FROM kacho_iam.resource_parent_edge e
          WHERE ((e.object_type = 'account'::text) AND (e.object_id = a.id)))))
UNION ALL
 SELECT 'iam_user'::text AS object_type,
    m.user_id AS object_id,
    'account'::text AS parent_type,
    m.account_id AS parent_id,
    1 AS depth
   FROM kacho_iam.memberships m
  WHERE ((COALESCE(m.account_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kacho_iam.resource_parent_edge e
          WHERE ((e.object_type = 'iam_user'::text) AND (e.object_id = m.user_id))))))
UNION ALL
 SELECT 'iam_group'::text AS object_type,
    o.id AS object_id,
    'account'::text AS parent_type,
    o.account_id AS parent_id,
    1 AS depth
   FROM kacho_iam.groups o
  WHERE ((COALESCE(o.account_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kacho_iam.resource_parent_edge e
          WHERE ((e.object_type = 'iam_group'::text) AND (e.object_id = o.id))))))
UNION ALL
 SELECT 'iam_service_account'::text AS object_type,
    o.id AS object_id,
    'account'::text AS parent_type,
    o.account_id AS parent_id,
    1 AS depth
   FROM kacho_iam.service_accounts o
  WHERE ((COALESCE(o.account_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kacho_iam.resource_parent_edge e
          WHERE ((e.object_type = 'iam_service_account'::text) AND (e.object_id = o.id))))))
UNION ALL
 SELECT 'iam_role'::text AS object_type,
    o.id AS object_id,
    'account'::text AS parent_type,
    o.account_id AS parent_id,
    1 AS depth
   FROM kacho_iam.roles o
  WHERE ((COALESCE(o.account_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kacho_iam.resource_parent_edge e
          WHERE ((e.object_type = 'iam_role'::text) AND (e.object_id = o.id))))))
UNION ALL
 SELECT 'iam_role'::text AS object_type,
    o.id AS object_id,
    'project'::text AS parent_type,
    o.project_id AS parent_id,
    1 AS depth
   FROM kacho_iam.roles o
  WHERE ((COALESCE(o.project_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kacho_iam.resource_parent_edge e
          WHERE ((e.object_type = 'iam_role'::text) AND (e.object_id = o.id))))))
UNION ALL
 SELECT 'iam_access_binding'::text AS object_type,
    o.id AS object_id,
    lower(o.resource_type) AS parent_type,
    o.resource_id AS parent_id,
    1 AS depth
   FROM kacho_iam.access_bindings o
  WHERE ((lower(o.resource_type) = ANY (ARRAY['project'::text, 'account'::text, 'cluster'::text])) AND (COALESCE(o.resource_id, ''::text) <> ''::text) AND (NOT (EXISTS ( SELECT 1
           FROM kacho_iam.resource_parent_edge e
          WHERE ((e.object_type = 'iam_access_binding'::text) AND (e.object_id = o.id))))));


--
-- Name: VIEW resource_scope_edge; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON VIEW kacho_iam.resource_scope_edge IS 'Цепь областей, какой её читает вопрос о доступе: рёбра, присланные владельцами ресурсов (resource_parent_edge), ПЛЮС достроенные звенья. Предок ПРОЕКТА берётся из проекции журнала (relation_fact), предок АККАУНТА — из схемы (accounts × clusters). Предок ЛИЧНОСТИ — из kacho_iam.memberships (#471): принадлежность аккаунту перестала быть колонкой строки человека и стала отдельной связью, которых у него может быть несколько; состояние членства не читается — звено есть указатель вверх, а не выдача. Предок ГРУППЫ, СЛУЖЕБНОЙ УЧЁТКИ и РОЛИ — колонкой их собственной строки; предок ПРИВЯЗКИ — парой resource_type/resource_id для трёх областных значений закрытого набора isBindableScope. Правило одно: источник, полный ПО ПОСТРОЕНИЮ для ЭТОГО звена. Владелец, назвавший цепь своего объекта сам, вывод отменяет (NOT EXISTS). ПИСАТЬ СЮДА НЕЛЬЗЯ: производители пишут в resource_parent_edge и в журнал.';


--
-- Name: role_grant_orphan; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.role_grant_orphan (
    role_id text NOT NULL,
    object_type text NOT NULL,
    verb text NOT NULL,
    source text NOT NULL,
    reason text NOT NULL,
    orphaned_at timestamp with time zone DEFAULT now() NOT NULL,
    applied_by text DEFAULT ''::text NOT NULL,
    cause text DEFAULT 'catalog_retired'::text NOT NULL,
    CONSTRAINT role_grant_orphan_cause_known CHECK ((cause = ANY (ARRAY['catalog_retired'::text, 'role_retired'::text]))),
    CONSTRAINT role_grant_orphan_reason_nonempty CHECK ((reason <> ''::text)),
    CONSTRAINT role_grant_orphan_source_known CHECK ((source = ANY (ARRAY['role_verb'::text, 'rule_ref'::text]))),
    CONSTRAINT role_grant_orphan_type_nonempty CHECK ((object_type <> ''::text))
);


--
-- Name: TABLE role_grant_orphan; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.role_grant_orphan IS 'Выдачи и объявления, потерявшие референт при снятии строки каталога. Снятие ПЕРЕСЕЛЯЕТ, а не отбирает молча: без этой таблицы отобранное право было бы неотличимо от никогда не выданного.';


--
-- Name: COLUMN role_grant_orphan.applied_by; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.role_grant_orphan.applied_by IS 'Автор применения, снявшего эту строку: проверенная личность вызывающего на пути глагола либо названный процессный актор на пути старта. НЕ учётка, под которой исполнялась транзакция. ПУСТАЯ строка означает «строка переселена до заведения колонки», а НЕ «автора потеряли».';


--
-- Name: COLUMN role_grant_orphan.cause; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.role_grant_orphan.cause IS 'ПОЧЕМУ строка переселена: catalog_retired — снята строка каталога, на которую ссылалось правило; role_retired — снята сама роль. Причина входит в первичный ключ, потому что обе могут относиться к одной паре «тип × глагол»: оживление роли снимает строки СВОЕЙ причины и не трогает чужих.';


--
-- Name: role_rule_ref; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.role_rule_ref (
    role_id text NOT NULL,
    module text NOT NULL,
    resource text NOT NULL,
    verb text,
    live boolean DEFAULT true NOT NULL,
    CONSTRAINT role_rule_ref_live_true CHECK (live),
    CONSTRAINT role_rule_ref_module_undotted CHECK ((module !~~ '%.%'::text)),
    CONSTRAINT role_rule_ref_nonempty CHECK (((module <> ''::text) AND (resource <> ''::text))),
    CONSTRAINT role_rule_ref_resource_undotted CHECK ((resource !~~ '%.%'::text)),
    CONSTRAINT role_rule_ref_verb_nonempty CHECK (((verb IS NULL) OR (verb <> ''::text))),
    CONSTRAINT role_rule_ref_verb_undotted CHECK (((verb IS NULL) OR (verb !~~ '%.%'::text)))
);


--
-- Name: TABLE role_rule_ref; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.role_rule_ref IS 'Проекция ОБЪЯВЛЕННЫХ сегментов правила роли — то, на чём внешний ключ в каталог ВОЗМОЖЕН (на roles.rules jsonb он невыразим: подзапрос в CHECK отвергается DDL). Строка кладётся на КАЖДЫЙ объявленный сегмент, а не на резолвящийся. АВТОР один — role_repo.ReplaceRuleRefs: форму строки объявляет только тот, кто её вносит. Снимать вправе и не-автор (применитель каталога, когда референт снят), но снятое он обязан ПЕРЕСЕЛИТЬ в role_grant_orphan тем же оператором.';


--
-- Name: COLUMN role_rule_ref.verb; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.role_rule_ref.verb IS 'NULL — ЯКОРЬ (правило не сузило глаголы). Ключ ресурса на такой строке проверяется, ключ глагола пропускается MATCH SIMPLE — ресурс уже проверен первым.';


--
-- Name: role_rule_selectors; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.role_rule_selectors (
    role_id text NOT NULL,
    rule_fp text NOT NULL,
    object_types text[] NOT NULL,
    match_labels jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    arm text NOT NULL,
    resource_names text[] DEFAULT '{}'::text[] NOT NULL,
    live boolean DEFAULT true NOT NULL,
    CONSTRAINT role_rule_selectors_arm_shape CHECK ((((arm = 'labels'::text) AND (match_labels <> '{}'::jsonb) AND (cardinality(resource_names) = 0)) OR ((arm = 'names'::text) AND (match_labels = '{}'::jsonb) AND (cardinality(resource_names) >= 1)) OR ((arm = 'anchor'::text) AND (match_labels = '{}'::jsonb) AND (cardinality(resource_names) = 0)))),
    CONSTRAINT role_rule_selectors_arm_valid CHECK ((arm = ANY (ARRAY['anchor'::text, 'names'::text, 'labels'::text]))),
    CONSTRAINT role_rule_selectors_fp_nonempty CHECK ((rule_fp <> ''::text)),
    CONSTRAINT role_rule_selectors_labels_obj CHECK ((jsonb_typeof(match_labels) = 'object'::text)),
    CONSTRAINT role_rule_selectors_labels_valid CHECK (kacho_iam.kacho_labels_valid(match_labels)),
    CONSTRAINT role_rule_selectors_live_true CHECK (live),
    CONSTRAINT role_rule_selectors_types_nonempty CHECK ((cardinality(object_types) >= 1))
);


--
-- Name: COLUMN role_rule_selectors.object_types; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.role_rule_selectors.object_types IS 'Типы объектов в ТОЧЕЧНОЙ форме. Один словарь с role_verb.object_type: соединение по разным написаниям не совпадает никогда и молча.';


--
-- Name: COLUMN role_rule_selectors.live; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.role_rule_selectors.live IS 'Константа true. Колонка существует ради ключа role_rule_selectors_role_live_fk: сослаться на «эту роль И она жива» без неё нечем. Константа законна потому, что строка селектора СНИМАЕТСЯ, а не помечается.';


--
-- Name: role_selector_prune; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.role_selector_prune (
    role_id text NOT NULL,
    rule_fp text NOT NULL,
    object_type text NOT NULL,
    outcome text NOT NULL,
    retired_reason text,
    pruned_at timestamp with time zone DEFAULT now() NOT NULL,
    applied_by text DEFAULT ''::text NOT NULL,
    CONSTRAINT role_selector_prune_fp_nonempty CHECK ((rule_fp <> ''::text)),
    CONSTRAINT role_selector_prune_outcome_known CHECK ((outcome = ANY (ARRAY['shortened'::text, 'dropped'::text]))),
    CONSTRAINT role_selector_prune_type_nonempty CHECK ((object_type <> ''::text))
);


--
-- Name: TABLE role_selector_prune; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.role_selector_prune IS 'Элементы третьей проекции правила, вырезанные применителем каталога при снятии строки ресурса. Вырезание необратимо; без этой ведомости объём был виден ТОЛЬКО в плане применения, а постфактум — ниоткуда. Ведомость действует вперёд: уже вырезанное в ней не появится. Потолка на популяцию она не вводит и не подразумевает — потолок запрещал бы починку, см. #1034.';


--
-- Name: COLUMN role_selector_prune.outcome; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.role_selector_prune.outcome IS 'shortened — у строки селектора остался живой тип, она укорочена; dropped — живого типа не осталось, строка снята целиком. Разные события для разбирающего последствия, поэтому колонка, а не сумма.';


--
-- Name: COLUMN role_selector_prune.pruned_at; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.role_selector_prune.pruned_at IS 'Время ТРАНЗАКЦИИ применения: у всех строк одного применения совпадает дословно, и по нему собирается вырезанное одним заходом. Отдельного идентификатора применения не заводится — он был бы вторым носителем уже выразимого факта.';


--
-- Name: COLUMN role_selector_prune.applied_by; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.role_selector_prune.applied_by IS 'Автор применения, вырезавшего этот тип из отбора правила. Та же величина и тот же источник, что у role_grant_orphan.applied_by: вопрос «кто снял» у обеих ведомостей общий — арендатор не различает, какой из проекций правила он лишился. ПУСТАЯ строка означает «строка вырезана до заведения колонки».';


--
-- Name: role_verb; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.role_verb (
    role_id text NOT NULL,
    object_type text NOT NULL,
    verb text NOT NULL,
    live boolean DEFAULT true NOT NULL,
    CONSTRAINT role_verb_live_true CHECK (live),
    CONSTRAINT role_verb_type_nonempty CHECK ((object_type <> ''::text)),
    CONSTRAINT role_verb_verb_canonical CHECK ((verb = lower(btrim(verb)))),
    CONSTRAINT role_verb_verb_nonempty CHECK ((verb <> ''::text))
);


--
-- Name: TABLE role_verb; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.role_verb IS 'Проекция «роль → тип объекта × глагол» — то, из чего цепь вердикта собирает ответ «разрешено ли действие». АВТОР один — role_repo.ReplaceRoleVerbs: форму строки объявляет только тот, кто её вносит. Снимать вправе и не-автор (применитель каталога, когда снят ресурс, на который ссылается role_verb_type_fk), но снятое он обязан ПЕРЕСЕЛИТЬ в role_grant_orphan тем же оператором.';


--
-- Name: COLUMN role_verb.object_type; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.role_verb.object_type IS 'Тип объекта в ТОЧЕЧНОЙ форме (iam.account, vpc.network) — той же, какой названы типы в role_rule_selectors.object_types. НЕ форма модели прав (vpc_network): вопрос о доступе приходит ею, и перевод делается на входе читателя.';


--
-- Name: COLUMN role_verb.live; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.role_verb.live IS 'Константа true. Колонка существует ради ключа role_verb_type_fk: сослаться на «эту строку каталога И она жива» без неё нечем.';


--
-- Name: service_account_oauth_clients; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.service_account_oauth_clients (
    id text NOT NULL,
    sva_id text NOT NULL,
    hydra_client_id text,
    description text DEFAULT ''::text NOT NULL,
    created_by_user_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    public_key_pem text DEFAULT ''::text NOT NULL,
    key_algorithm text DEFAULT ''::text NOT NULL,
    trusted_subjects jsonb DEFAULT '[]'::jsonb NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    declared_audiences text[] DEFAULT '{}'::text[] NOT NULL,
    credential_kind text NOT NULL,
    secret_hash bytea DEFAULT '\x'::bytea NOT NULL,
    CONSTRAINT sa_oauth_clients_declared_audiences_wellformed CHECK (((NOT (''::text = ANY (declared_audiences))) AND (array_position(declared_audiences, NULL::text) IS NULL) AND (kacho_iam.text_array_longest(declared_audiences) <= 512))),
    CONSTRAINT service_account_oauth_clients_credential_kind_ck CHECK ((credential_kind = ANY (ARRAY['KEYPAIR'::text, 'SECRET'::text, 'FEDERATED'::text, 'LEGACY'::text]))),
    CONSTRAINT service_account_oauth_clients_credential_shape_ck CHECK (
CASE credential_kind
    WHEN 'KEYPAIR'::text THEN ((secret_hash = '\x'::bytea) AND (hydra_client_id IS NOT NULL))
    WHEN 'SECRET'::text THEN ((octet_length(secret_hash) = 32) AND (public_key_pem = ''::text) AND (key_algorithm = ''::text) AND (trusted_subjects = '[]'::jsonb) AND (expires_at IS NOT NULL) AND (hydra_client_id IS NULL))
    WHEN 'FEDERATED'::text THEN ((secret_hash = '\x'::bytea) AND (public_key_pem = ''::text) AND (trusted_subjects <> '[]'::jsonb) AND (hydra_client_id IS NOT NULL))
    WHEN 'LEGACY'::text THEN ((secret_hash = '\x'::bytea) AND (hydra_client_id IS NOT NULL))
    ELSE NULL::boolean
END),
    CONSTRAINT service_account_oauth_clients_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT service_account_oauth_clients_expires_future_ck CHECK (((expires_at IS NULL) OR (expires_at > created_at))),
    CONSTRAINT service_account_oauth_clients_hydra_client_id_check CHECK (((hydra_client_id IS NULL) OR ((length(hydra_client_id) >= 1) AND (length(hydra_client_id) <= 128) AND (hydra_client_id ~ '^[A-Za-z0-9._:-]+$'::text)))),
    CONSTRAINT service_account_oauth_clients_id_check CHECK ((id ~ '^soc_?[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT service_account_oauth_clients_key_algorithm_check CHECK ((key_algorithm = ANY (ARRAY[''::text, 'ES256'::text, 'RS256'::text, 'EdDSA'::text]))),
    CONSTRAINT service_account_oauth_clients_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels)),
    CONSTRAINT service_account_oauth_clients_trusted_subjects_array_ck CHECK ((jsonb_typeof(trusted_subjects) = 'array'::text))
);


--
-- Name: COLUMN service_account_oauth_clients.credential_kind; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.service_account_oauth_clients.credential_kind IS 'Вид удостоверения. Записывается при вставке; читателем НЕ вычисляется. LEGACY описывает строки прежнего потока и не выдаётся ни одним глаголом.';


--
-- Name: COLUMN service_account_oauth_clients.secret_hash; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.service_account_oauth_clients.secret_hash IS 'sha256 по идентификатору строки И секретной части вместе, 32 байта. Сам секрет не хранится нигде: он существует только в теле ответа, полученного вызывающим выдачи.';


--
-- Name: session_revocations; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.session_revocations (
    token_jti text NOT NULL,
    revoked_at timestamp with time zone DEFAULT now() NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    user_id text NOT NULL,
    ttl_expires_at timestamp with time zone NOT NULL,
    revoked_by_user_id text,
    CONSTRAINT session_revocations_reason_check CHECK ((length(reason) <= 256)),
    CONSTRAINT session_revocations_revoked_by_check CHECK (((revoked_by_user_id IS NULL) OR (length(revoked_by_user_id) <= 64))),
    CONSTRAINT session_revocations_token_jti_check CHECK (((length(token_jti) >= 1) AND (length(token_jti) <= 128))),
    CONSTRAINT session_revocations_ttl_future_ck CHECK ((ttl_expires_at > revoked_at))
);


--
-- Name: subject_change_outbox; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.subject_change_outbox (
    id bigint NOT NULL,
    subject_id text NOT NULL,
    op text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    event_type text,
    payload jsonb NOT NULL,
    CONSTRAINT subject_change_op_check CHECK ((op = ANY (ARRAY['binding_upsert'::text, 'binding_delete'::text, 'group_member_change'::text, 'binding_grant'::text, 'binding_revoke'::text]))),
    CONSTRAINT subject_change_payload_is_object CHECK ((jsonb_typeof(payload) = 'object'::text)),
    CONSTRAINT subject_change_payload_names_subject CHECK (((COALESCE(jsonb_typeof((payload -> 'subject_id'::text)), ''::text) = 'string'::text) AND (COALESCE((payload ->> 'subject_id'::text), ''::text) <> ''::text)))
);


--
-- Name: CONSTRAINT subject_change_op_check ON subject_change_outbox; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON CONSTRAINT subject_change_op_check ON kacho_iam.subject_change_outbox IS 'Словарь видов события очереди смены субъекта. Каждое значение обязано иметь производителя в не-тестовом коде iam — это держит гейт internal/repohygiene TestQueueEventValueHasAProducer. Union двух написаний: op-псевдонимы (binding_upsert/binding_delete) и канонические event_type (binding_grant/binding_revoke/group_member_change), потому что deriveOpFromEventType пропускает незнакомый вид в op как есть. Расширяя словарь, заводи производителя тем же изменением: значение без производителя обещает подсистему, которой нет.';


--
-- Name: subject_change_outbox_id_seq; Type: SEQUENCE; Schema: kacho_iam; Owner: -
--

CREATE SEQUENCE kacho_iam.subject_change_outbox_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: subject_change_outbox_id_seq; Type: SEQUENCE OWNED BY; Schema: kacho_iam; Owner: -
--

ALTER SEQUENCE kacho_iam.subject_change_outbox_id_seq OWNED BY kacho_iam.subject_change_outbox.id;


--
-- Name: token_signing_keys; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.token_signing_keys (
    kid text NOT NULL,
    algorithm text NOT NULL,
    state text NOT NULL,
    public_key_pem text NOT NULL,
    private_key_wrapped bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    not_after timestamp with time zone NOT NULL,
    activated_at timestamp with time zone,
    retired_at timestamp with time zone,
    removed_at timestamp with time zone,
    compromised_at timestamp with time zone,
    CONSTRAINT token_signing_keys_algorithm_ck CHECK ((algorithm = ANY (ARRAY['RS256'::text, 'ES256'::text, 'EdDSA'::text]))),
    CONSTRAINT token_signing_keys_kid_ck CHECK ((kid ~ '^[A-Za-z0-9._:-]{1,128}$'::text)),
    CONSTRAINT token_signing_keys_not_after_ck CHECK ((not_after > created_at)),
    CONSTRAINT token_signing_keys_private_key_ck CHECK (((octet_length(private_key_wrapped) >= 1) AND (octet_length(private_key_wrapped) <= 32768))),
    CONSTRAINT token_signing_keys_public_key_ck CHECK (((length(public_key_pem) >= 1) AND (length(public_key_pem) <= 16384))),
    CONSTRAINT token_signing_keys_state_ck CHECK ((state = ANY (ARRAY['PUBLISHED'::text, 'ACTIVE'::text, 'RETIRED'::text, 'REMOVED'::text, 'COMPROMISED'::text]))),
    CONSTRAINT token_signing_keys_state_stamps_ck CHECK ((((state = 'PUBLISHED'::text) AND (activated_at IS NULL) AND (retired_at IS NULL) AND (removed_at IS NULL) AND (compromised_at IS NULL)) OR ((state = 'ACTIVE'::text) AND (activated_at IS NOT NULL) AND (retired_at IS NULL) AND (removed_at IS NULL) AND (compromised_at IS NULL)) OR ((state = 'RETIRED'::text) AND (retired_at IS NOT NULL) AND (removed_at IS NULL) AND (compromised_at IS NULL)) OR ((state = 'REMOVED'::text) AND (removed_at IS NOT NULL) AND (compromised_at IS NULL)) OR ((state = 'COMPROMISED'::text) AND (compromised_at IS NOT NULL))))
);


--
-- Name: user_oauth_clients; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.user_oauth_clients (
    id text NOT NULL,
    user_id text NOT NULL,
    hydra_client_id text,
    description text DEFAULT ''::text NOT NULL,
    created_by_user_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    public_key_pem text DEFAULT ''::text NOT NULL,
    key_algorithm text DEFAULT ''::text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    credential_kind text NOT NULL,
    secret_hash bytea DEFAULT '\x'::bytea NOT NULL,
    CONSTRAINT user_oauth_clients_credential_kind_ck CHECK ((credential_kind = ANY (ARRAY['KEYPAIR'::text, 'SECRET'::text, 'LEGACY'::text]))),
    CONSTRAINT user_oauth_clients_credential_shape_ck CHECK (
CASE credential_kind
    WHEN 'KEYPAIR'::text THEN (secret_hash = '\x'::bytea)
    WHEN 'SECRET'::text THEN ((octet_length(secret_hash) = 32) AND (public_key_pem = ''::text) AND (key_algorithm = ''::text) AND (expires_at IS NOT NULL) AND (hydra_client_id IS NULL))
    WHEN 'LEGACY'::text THEN (secret_hash = '\x'::bytea)
    ELSE NULL::boolean
END),
    CONSTRAINT user_oauth_clients_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT user_oauth_clients_expires_future_ck CHECK (((expires_at IS NULL) OR (expires_at > created_at))),
    CONSTRAINT user_oauth_clients_hydra_client_id_check CHECK (((hydra_client_id IS NULL) OR ((length(hydra_client_id) >= 1) AND (length(hydra_client_id) <= 128) AND (hydra_client_id ~ '^[A-Za-z0-9._:-]+$'::text)))),
    CONSTRAINT user_oauth_clients_id_check CHECK ((id ~ '^uoc_?[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT user_oauth_clients_key_algorithm_check CHECK ((key_algorithm = ANY (ARRAY[''::text, 'ES256'::text, 'RS256'::text, 'EdDSA'::text]))),
    CONSTRAINT user_oauth_clients_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels))
);


--
-- Name: COLUMN user_oauth_clients.hydra_client_id; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.user_oauth_clients.hydra_client_id IS 'Идентификатор клиента у внешнего поставщика. NULL — регистрации у него нет (выдача её больше не заводит); непустое значение принадлежит строке прежнего выпуска и держит окно двух издателей.';


--
-- Name: COLUMN user_oauth_clients.credential_kind; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.user_oauth_clients.credential_kind IS 'Вид удостоверения. Записывается при вставке; читателем НЕ вычисляется.';


--
-- Name: COLUMN user_oauth_clients.secret_hash; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON COLUMN kacho_iam.user_oauth_clients.secret_hash IS 'sha256 по идентификатору строки И секретной части вместе, 32 байта.';


--
-- Name: user_token_revocations; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.user_token_revocations (
    user_id text NOT NULL,
    revoke_before timestamp with time zone NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    revoked_by_user_id text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_token_revocations_reason_check CHECK ((length(reason) <= 256)),
    CONSTRAINT user_token_revocations_revoked_by_check CHECK (((revoked_by_user_id IS NULL) OR (length(revoked_by_user_id) <= 64)))
);


--
-- Name: TABLE user_token_revocations; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TABLE kacho_iam.user_token_revocations IS 'Per-user revoke-all-before cutoff. Refresh-hook denies a token whose session auth_time <= revoke_before. Backs admin ForceLogout + Revoke(revoke_all_user_tokens).';


--
-- Name: users; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.users (
    id text NOT NULL,
    external_id text NOT NULL,
    email text NOT NULL,
    display_name text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    account_id text NOT NULL,
    invite_status text DEFAULT 'ACTIVE'::text NOT NULL,
    invited_by text,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT users_display_name_check CHECK ((length(display_name) <= 128)),
    CONSTRAINT users_email_check CHECK (((length(email) >= 3) AND (length(email) <= 254) AND (email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'::text))),
    CONSTRAINT users_external_id_check CHECK (((length(external_id) >= 0) AND (length(external_id) <= 256))),
    CONSTRAINT users_invite_status_check CHECK ((invite_status = ANY (ARRAY['PENDING'::text, 'ACTIVE'::text, 'BLOCKED'::text]))),
    CONSTRAINT users_invite_status_consistency CHECK ((((invite_status = 'PENDING'::text) AND (external_id = ''::text)) OR ((invite_status = ANY (ARRAY['ACTIVE'::text, 'BLOCKED'::text])) AND (length(external_id) > 0)))),
    CONSTRAINT users_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels))
);


--
-- Name: account_admission_rate_limits id; Type: DEFAULT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.account_admission_rate_limits ALTER COLUMN id SET DEFAULT nextval('kacho_iam.account_admission_rate_limits_id_seq'::regclass);


--
-- Name: fga_outbox id; Type: DEFAULT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.fga_outbox ALTER COLUMN id SET DEFAULT nextval('kacho_iam.fga_outbox_id_seq'::regclass);


--
-- Name: invite_mail_outbox id; Type: DEFAULT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.invite_mail_outbox ALTER COLUMN id SET DEFAULT nextval('kacho_iam.invite_mail_outbox_id_seq'::regclass);


--
-- Name: provider_compensation_outbox id; Type: DEFAULT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.provider_compensation_outbox ALTER COLUMN id SET DEFAULT nextval('kacho_iam.provider_compensation_outbox_id_seq'::regclass);


--
-- Name: subject_change_outbox id; Type: DEFAULT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.subject_change_outbox ALTER COLUMN id SET DEFAULT nextval('kacho_iam.subject_change_outbox_id_seq'::regclass);


--
-- Data for Name: access_binding_emitted_tuples; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source) VALUES ('acb1296746dc06ec9e25', 'group:grp1ed8897b56bb9106f#member', 'quota_reader', 'cluster:cluster_kacho_root', 'binding');
INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source) VALUES ('acb0b5b813e060702892', 'service_account:sva3e9556e76be67f816', 'system_viewer', 'cluster:cluster_kacho_root', 'binding');
INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source) VALUES ('acb952a120de6e5bae37', 'service_account:sva85816c3a904b6bac6', 'system_viewer', 'cluster:cluster_kacho_root', 'binding');
INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source) VALUES ('acb59447ac7288264db6', 'service_account:sva8e7d21b2c8a633cd1', 'system_viewer', 'cluster:cluster_kacho_root', 'binding');
INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source) VALUES ('acbd89dbba69fd956d5e', 'service_account:svab91854890de887e6d', 'system_admin', 'cluster:cluster_kacho_root', 'binding');
INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source) VALUES ('acbc5d32d66fc8dc4952', 'user:*', 'viewer', 'cluster:cluster_kacho_root', 'binding');
INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source) VALUES ('acb9e920fb038c7e4f74', 'group:grp258e6bbe9bbe45568#member', 'fga_writer', 'cluster:cluster_kacho_root', 'binding');


--
-- Data for Name: access_binding_subjects; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal, resource_type, resource_id) VALUES ('acb13303edeb2b3605c8', 'user', 'usr1a18042d81fb438d6', 0, 'account', 'acc1a18042d81fb438d6');
INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal, resource_type, resource_id) VALUES ('acb1296746dc06ec9e25', 'group', 'grp1ed8897b56bb9106f', 0, 'cluster', 'cluster_kacho_root');
INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal, resource_type, resource_id) VALUES ('acb0b5b813e060702892', 'service_account', 'sva3e9556e76be67f816', 0, 'cluster', 'cluster_kacho_root');
INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal, resource_type, resource_id) VALUES ('acb952a120de6e5bae37', 'service_account', 'sva85816c3a904b6bac6', 0, 'cluster', 'cluster_kacho_root');
INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal, resource_type, resource_id) VALUES ('acb59447ac7288264db6', 'service_account', 'sva8e7d21b2c8a633cd1', 0, 'cluster', 'cluster_kacho_root');
INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal, resource_type, resource_id) VALUES ('acbd89dbba69fd956d5e', 'service_account', 'svab91854890de887e6d', 0, 'cluster', 'cluster_kacho_root');
INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal, resource_type, resource_id) VALUES ('acbc5d32d66fc8dc4952', 'user', '*', 0, 'cluster', 'cluster_kacho_root');
INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal, resource_type, resource_id) VALUES ('acb9e920fb038c7e4f74', 'group', 'grp258e6bbe9bbe45568', 0, 'cluster', 'cluster_kacho_root');


--
-- Data for Name: access_binding_target_members; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: access_bindings; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, created_at, status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, scope, deletion_protection, labels, target, target_digest, granted_relation, is_system) VALUES ('acb13303edeb2b3605c8', 'user', 'usr1a18042d81fb438d6', 'rol72122ce96bfec66e2', 'account', 'acc1a18042d81fb438d6', now(), 'ACTIVE', NULL, 'system', NULL, NULL, 2, true, '{}', '{"allInScope": true}', 'all', '', false);
INSERT INTO kacho_iam.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, created_at, status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, scope, deletion_protection, labels, target, target_digest, granted_relation, is_system) VALUES ('acb1296746dc06ec9e25', 'group', 'grp1ed8897b56bb9106f', NULL, 'cluster', 'cluster_kacho_root', now(), 'ACTIVE', NULL, '', NULL, NULL, 1, true, '{}', '{"allInScope": true}', 'all', 'quota_reader', true);
INSERT INTO kacho_iam.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, created_at, status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, scope, deletion_protection, labels, target, target_digest, granted_relation, is_system) VALUES ('acb0b5b813e060702892', 'service_account', 'sva3e9556e76be67f816', NULL, 'cluster', 'cluster_kacho_root', now(), 'ACTIVE', NULL, '', NULL, NULL, 1, true, '{}', '{"allInScope": true}', 'all', 'system_viewer', true);
INSERT INTO kacho_iam.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, created_at, status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, scope, deletion_protection, labels, target, target_digest, granted_relation, is_system) VALUES ('acb952a120de6e5bae37', 'service_account', 'sva85816c3a904b6bac6', NULL, 'cluster', 'cluster_kacho_root', now(), 'ACTIVE', NULL, '', NULL, NULL, 1, true, '{}', '{"allInScope": true}', 'all', 'system_viewer', true);
INSERT INTO kacho_iam.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, created_at, status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, scope, deletion_protection, labels, target, target_digest, granted_relation, is_system) VALUES ('acb59447ac7288264db6', 'service_account', 'sva8e7d21b2c8a633cd1', NULL, 'cluster', 'cluster_kacho_root', now(), 'ACTIVE', NULL, '', NULL, NULL, 1, true, '{}', '{"allInScope": true}', 'all', 'system_viewer', true);
INSERT INTO kacho_iam.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, created_at, status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, scope, deletion_protection, labels, target, target_digest, granted_relation, is_system) VALUES ('acbd89dbba69fd956d5e', 'service_account', 'svab91854890de887e6d', NULL, 'cluster', 'cluster_kacho_root', now(), 'ACTIVE', NULL, '', NULL, NULL, 1, true, '{}', '{"allInScope": true}', 'all', 'system_admin', true);
INSERT INTO kacho_iam.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, created_at, status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, scope, deletion_protection, labels, target, target_digest, granted_relation, is_system) VALUES ('acbc5d32d66fc8dc4952', 'user', '*', NULL, 'cluster', 'cluster_kacho_root', now(), 'ACTIVE', NULL, '', NULL, NULL, 1, true, '{}', '{"allInScope": true}', 'all', 'viewer', true);
INSERT INTO kacho_iam.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, created_at, status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, scope, deletion_protection, labels, target, target_digest, granted_relation, is_system) VALUES ('acb9e920fb038c7e4f74', 'group', 'grp258e6bbe9bbe45568', NULL, 'cluster', 'cluster_kacho_root', now(), 'ACTIVE', NULL, '', NULL, NULL, 1, true, '{}', '{"allInScope": true}', 'all', 'fga_writer', true);


--
-- Data for Name: account_admission_rate_limits; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.account_admission_rate_limits (id, kind, max_events, window_seconds, withdrawn_at, created_at) VALUES (1, 'iam.account', 3, 3600, NULL, now());


--
-- Data for Name: accounts; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.accounts (id, name, description, labels, owner_user_id, created_at) VALUES ('acc1a18042d81fb438d6', 'kacho-system', 'System account anchoring internal module service-accounts (SEC-C)', '{}', 'usr1a18042d81fb438d6', now());


--
-- Data for Name: audit_outbox; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: catalog_module; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.catalog_module (module, retired_at, retired_reason, live) VALUES ('iam', NULL, NULL, true);
INSERT INTO kacho_iam.catalog_module (module, retired_at, retired_reason, live) VALUES ('vpc', NULL, NULL, true);
INSERT INTO kacho_iam.catalog_module (module, retired_at, retired_reason, live) VALUES ('compute', NULL, NULL, true);
INSERT INTO kacho_iam.catalog_module (module, retired_at, retired_reason, live) VALUES ('loadbalancer', NULL, NULL, true);
INSERT INTO kacho_iam.catalog_module (module, retired_at, retired_reason, live) VALUES ('registry', NULL, NULL, true);
INSERT INTO kacho_iam.catalog_module (module, retired_at, retired_reason, live) VALUES ('storage', NULL, NULL, true);


--
-- Data for Name: catalog_resource; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('compute', 'guestAccessKey', 'compute.guestAccessKey', NULL, NULL, NULL, true, 'compute_guest_access_key');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('compute', 'instance', 'compute.instance', NULL, NULL, NULL, true, 'compute_instance');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('compute', 'placementGroup', 'compute.placementGroup', NULL, NULL, NULL, true, 'compute_placement_group');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('iam', 'accessBinding', 'iam.accessBinding', NULL, NULL, NULL, true, 'iam_access_binding');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('iam', 'account', 'iam.account', NULL, NULL, NULL, true, 'account');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('iam', 'group', 'iam.group', NULL, NULL, NULL, true, 'iam_group');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('iam', 'project', 'iam.project', NULL, NULL, NULL, true, 'project');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('iam', 'role', 'iam.role', NULL, NULL, NULL, true, 'iam_role');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('iam', 'serviceAccount', 'iam.serviceAccount', NULL, NULL, NULL, true, 'iam_service_account');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('iam', 'user', 'iam.user', NULL, NULL, NULL, true, 'iam_user');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('loadbalancer', 'listeners', 'loadbalancer.listeners', NULL, NULL, NULL, true, 'nlb_listener');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('loadbalancer', 'networkLoadBalancers', 'loadbalancer.networkLoadBalancers', NULL, NULL, NULL, true, 'nlb_network_load_balancer');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('loadbalancer', 'targetGroups', 'loadbalancer.targetGroups', NULL, NULL, NULL, true, 'nlb_target_group');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('registry', 'registries', 'registry.registries', NULL, NULL, NULL, true, 'registry_registry');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('registry', 'repositories', 'registry.repositories', NULL, NULL, NULL, true, 'registry_repository');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('storage', 'images', 'storage.images', NULL, NULL, NULL, true, 'storage_image');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('storage', 'snapshots', 'storage.snapshots', NULL, NULL, NULL, true, 'storage_snapshot');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('storage', 'volumes', 'storage.volumes', NULL, NULL, NULL, true, 'storage_volume');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('vpc', 'address', 'vpc.address', NULL, NULL, NULL, true, 'vpc_address');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('vpc', 'addressPool', 'vpc.addressPool', NULL, NULL, NULL, true, 'vpc_address_pool');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('vpc', 'cidrGroup', 'vpc.cidrGroup', NULL, NULL, NULL, true, 'vpc_cidr_group');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('vpc', 'gateway', 'vpc.gateway', NULL, NULL, NULL, true, 'vpc_gateway');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('vpc', 'network', 'vpc.network', NULL, NULL, NULL, true, 'vpc_network');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('vpc', 'networkInterface', 'vpc.networkInterface', NULL, NULL, NULL, true, 'vpc_network_interface');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('vpc', 'routeTable', 'vpc.routeTable', NULL, NULL, NULL, true, 'vpc_route_table');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('vpc', 'securityGroup', 'vpc.securityGroup', NULL, NULL, NULL, true, 'vpc_security_group');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('vpc', 'subnet', 'vpc.subnet', NULL, NULL, NULL, true, 'vpc_subnet');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('compute', 'disk', 'compute.disk', now(), 'блочное хранение принадлежит kacho-storage; вторая копия ресурса снята', 'storage.volumes', false, 'compute_disk');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('compute', 'image', 'compute.image', now(), 'блочное хранение принадлежит kacho-storage; вторая копия ресурса снята', 'storage.images', false, 'compute_image');
INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type) VALUES ('compute', 'snapshot', 'compute.snapshot', now(), 'блочное хранение принадлежит kacho-storage; вторая копия ресурса снята', 'storage.snapshots', false, 'compute_snapshot');


--
-- Data for Name: catalog_verb; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'guestAccessKey', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'guestAccessKey', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'guestAccessKey', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'guestAccessKey', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'instance', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'instance', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'instance', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'instance', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'placementGroup', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'placementGroup', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'placementGroup', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'placementGroup', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'accessBinding', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'accessBinding', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'accessBinding', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'accessBinding', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'account', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'account', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'account', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'account', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'group', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'group', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'group', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'group', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'project', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'project', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'project', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'project', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'role', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'role', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'role', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'role', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'serviceAccount', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'serviceAccount', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'serviceAccount', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'serviceAccount', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'user', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'user', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'listeners', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'listeners', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'listeners', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'listeners', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'networkLoadBalancers', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'networkLoadBalancers', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'networkLoadBalancers', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'networkLoadBalancers', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'targetGroups', 'addtargets', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'targetGroups', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'targetGroups', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'targetGroups', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'targetGroups', 'removetargets', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'targetGroups', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('registry', 'registries', 'create', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('registry', 'registries', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('registry', 'registries', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('registry', 'registries', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('registry', 'registries', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('registry', 'repositories', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('registry', 'repositories', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('registry', 'repositories', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('registry', 'repositories', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'images', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'images', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'images', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'images', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'snapshots', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'snapshots', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'snapshots', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'snapshots', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'volumes', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'volumes', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'volumes', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'volumes', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'address', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'address', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'address', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'address', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'addressPool', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'addressPool', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'addressPool', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'addressPool', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'cidrGroup', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'cidrGroup', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'cidrGroup', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'cidrGroup', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'gateway', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'gateway', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'gateway', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'gateway', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'network', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'network', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'network', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'network', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'networkInterface', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'networkInterface', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'networkInterface', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'networkInterface', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'routeTable', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'routeTable', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'routeTable', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'routeTable', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'securityGroup', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'securityGroup', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'securityGroup', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'securityGroup', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'subnet', 'delete', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'subnet', 'get', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'subnet', 'list', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'subnet', 'update', NULL, NULL, true, true);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'guestAccessKey', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'instance', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('compute', 'placementGroup', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'accessBinding', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'account', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'group', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'project', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'role', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'serviceAccount', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('iam', 'user', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'listeners', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'networkLoadBalancers', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('loadbalancer', 'targetGroups', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('registry', 'repositories', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'images', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'snapshots', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('storage', 'volumes', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'address', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'addressPool', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'cidrGroup', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'gateway', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'network', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'networkInterface', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'routeTable', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'securityGroup', 'create', NULL, NULL, true, false);
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, retired_at, retired_reason, live, per_object) VALUES ('vpc', 'subnet', 'create', NULL, NULL, true, false);


--
-- Data for Name: client_assertion_replay; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: cluster_admin_grants; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.cluster_admin_grants (id, cluster_id, subject_type, subject_id, granted_by, granted_at, granted_until) VALUES ('cag_5f4510f927a011885', 'cluster_kacho_root', 'service_account', 'svab91854890de887e6d', 'bootstrap', now(), NULL);


--
-- Data for Name: clusters; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.clusters (id, name, description, created_at) VALUES ('cluster_kacho_root', 'kacho-root', 'Root cluster for Kachō control plane', now());


--
-- Data for Name: federated_trusted_issuers; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: fga_outbox; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (1, 'fga.tuple.write', '{"user": "service_account:sva85816c3a904b6bac6", "object": "iam_fgaproxy:system", "relation": "fga_writer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (2, 'fga.tuple.write', '{"user": "service_account:sva8e7d21b2c8a633cd1", "object": "iam_fgaproxy:system", "relation": "fga_writer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (3, 'fga.tuple.write', '{"user": "service_account:svac4faf3358e07191f5", "object": "iam_fgaproxy:system", "relation": "fga_writer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (5, 'fga.tuple.write', '{"user": "service_account:sva3e9556e76be67f816", "object": "cluster:cluster_kacho_root", "relation": "system_viewer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (6, 'fga.tuple.write', '{"user": "service_account:sva85816c3a904b6bac6", "object": "cluster:cluster_kacho_root", "relation": "system_viewer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (7, 'fga.tuple.write', '{"user": "service_account:sva8e7d21b2c8a633cd1", "object": "cluster:cluster_kacho_root", "relation": "system_viewer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (8, 'fga.tuple.write', '{"user": "service_account:sva9e62bc58c3f0e45ea", "object": "iam_fgaproxy:system", "relation": "fga_writer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (9, 'fga.tuple.write', '{"user": "service_account:sva8ef8aa106f83f84e0", "object": "iam_fgaproxy:system", "relation": "fga_writer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (10, 'fga.tuple.write', '{"user": "service_account:svab91854890de887e6d", "object": "cluster:cluster_kacho_root", "relation": "system_admin"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (11, 'fga.tuple.delete', '{"user": "service_account:sva35c43c9fcf0146411", "object": "cluster:cluster_kacho_root", "relation": "system_viewer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (12, 'fga.tuple.write', '{"user": "service_account:sva85816c3a904b6bac6", "object": "group:grp1ed8897b56bb9106f", "relation": "member"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (13, 'fga.tuple.write', '{"user": "group:grp1ed8897b56bb9106f#member", "object": "cluster:cluster_kacho_root", "relation": "quota_reader"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (14, 'fga.tuple.write', '{"user": "service_account:svac4faf3358e07191f5", "object": "group:grp1ed8897b56bb9106f", "relation": "member"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (15, 'fga.tuple.write', '{"user": "service_account:sva9e62bc58c3f0e45ea", "object": "group:grp1ed8897b56bb9106f", "relation": "member"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (16, 'fga.tuple.write', '{"user": "service_account:sva8ef8aa106f83f84e0", "object": "group:grp1ed8897b56bb9106f", "relation": "member"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (17, 'fga.tuple.write', '{"user": "service_account:sva8e7d21b2c8a633cd1", "object": "group:grp1ed8897b56bb9106f", "relation": "member"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (18, 'fga.tuple.write', '{"user": "user:*", "object": "cluster:cluster_kacho_root", "relation": "viewer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (19, 'fga.tuple.write', '{"user": "service_account:sva85816c3a904b6bac6", "object": "group:grp258e6bbe9bbe45568", "relation": "member"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (20, 'fga.tuple.write', '{"user": "service_account:sva8e7d21b2c8a633cd1", "object": "group:grp258e6bbe9bbe45568", "relation": "member"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (21, 'fga.tuple.write', '{"user": "service_account:sva8ef8aa106f83f84e0", "object": "group:grp258e6bbe9bbe45568", "relation": "member"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (22, 'fga.tuple.write', '{"user": "service_account:sva9e62bc58c3f0e45ea", "object": "group:grp258e6bbe9bbe45568", "relation": "member"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (23, 'fga.tuple.write', '{"user": "service_account:svac4faf3358e07191f5", "object": "group:grp258e6bbe9bbe45568", "relation": "member"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (24, 'fga.tuple.write', '{"user": "group:grp258e6bbe9bbe45568#member", "object": "cluster:cluster_kacho_root", "relation": "fga_writer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (25, 'fga.tuple.delete', '{"user": "service_account:sva85816c3a904b6bac6", "object": "iam_fgaproxy:system", "relation": "fga_writer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (26, 'fga.tuple.delete', '{"user": "service_account:sva8e7d21b2c8a633cd1", "object": "iam_fgaproxy:system", "relation": "fga_writer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (27, 'fga.tuple.delete', '{"user": "service_account:sva8ef8aa106f83f84e0", "object": "iam_fgaproxy:system", "relation": "fga_writer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (28, 'fga.tuple.delete', '{"user": "service_account:sva9e62bc58c3f0e45ea", "object": "iam_fgaproxy:system", "relation": "fga_writer"}', now());
INSERT INTO kacho_iam.fga_outbox (id, event_type, payload, created_at) VALUES (29, 'fga.tuple.delete', '{"user": "service_account:svac4faf3358e07191f5", "object": "iam_fgaproxy:system", "relation": "fga_writer"}', now());


--
-- Data for Name: group_members; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.group_members (group_id, member_type, member_id, added_at) VALUES ('grp1ed8897b56bb9106f', 'service_account', 'sva85816c3a904b6bac6', now());
INSERT INTO kacho_iam.group_members (group_id, member_type, member_id, added_at) VALUES ('grp1ed8897b56bb9106f', 'service_account', 'svac4faf3358e07191f5', now());
INSERT INTO kacho_iam.group_members (group_id, member_type, member_id, added_at) VALUES ('grp1ed8897b56bb9106f', 'service_account', 'sva9e62bc58c3f0e45ea', now());
INSERT INTO kacho_iam.group_members (group_id, member_type, member_id, added_at) VALUES ('grp1ed8897b56bb9106f', 'service_account', 'sva8ef8aa106f83f84e0', now());
INSERT INTO kacho_iam.group_members (group_id, member_type, member_id, added_at) VALUES ('grp1ed8897b56bb9106f', 'service_account', 'sva8e7d21b2c8a633cd1', now());
INSERT INTO kacho_iam.group_members (group_id, member_type, member_id, added_at) VALUES ('grp258e6bbe9bbe45568', 'service_account', 'sva85816c3a904b6bac6', now());
INSERT INTO kacho_iam.group_members (group_id, member_type, member_id, added_at) VALUES ('grp258e6bbe9bbe45568', 'service_account', 'sva8e7d21b2c8a633cd1', now());
INSERT INTO kacho_iam.group_members (group_id, member_type, member_id, added_at) VALUES ('grp258e6bbe9bbe45568', 'service_account', 'sva8ef8aa106f83f84e0', now());
INSERT INTO kacho_iam.group_members (group_id, member_type, member_id, added_at) VALUES ('grp258e6bbe9bbe45568', 'service_account', 'sva9e62bc58c3f0e45ea', now());
INSERT INTO kacho_iam.group_members (group_id, member_type, member_id, added_at) VALUES ('grp258e6bbe9bbe45568', 'service_account', 'svac4faf3358e07191f5', now());


--
-- Data for Name: groups; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.groups (id, account_id, name, description, labels, created_at) VALUES ('grp1ed8897b56bb9106f', 'acc1a18042d81fb438d6', 'module-quota-readers', 'Owner-service accounts allowed to read effective resource-count limits (issue #291)', '{}', now());
INSERT INTO kacho_iam.groups (id, account_id, name, description, labels, created_at) VALUES ('grp258e6bbe9bbe45568', 'acc1a18042d81fb438d6', 'module-relation-writers', 'Module service accounts allowed to write relation tuples through iam (issue #914)', '{}', now());


--
-- Data for Name: identity_admission_windows; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: identity_journal; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: interactive_clients; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: invite_mail_outbox; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: limits; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000001', now(), 'DEFAULT', '', 'vpc.network', 16, NULL, 1);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000002', now(), 'DEFAULT', '', 'vpc.subnet', 64, NULL, 2);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000003', now(), 'DEFAULT', '', 'vpc.address', 256, NULL, 3);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000004', now(), 'DEFAULT', '', 'vpc.networkInterface', 128, NULL, 4);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000005', now(), 'DEFAULT', '', 'vpc.securityGroup', 64, NULL, 5);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000006', now(), 'DEFAULT', '', 'vpc.routeTable', 32, NULL, 6);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000007', now(), 'DEFAULT', '', 'vpc.gateway', 16, NULL, 7);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000008', now(), 'DEFAULT', '', 'vpc.cidrGroup', 64, NULL, 8);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000009', now(), 'DEFAULT', '', 'iam.project', 16, NULL, 9);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000010', now(), 'DEFAULT', '', 'vpc.network.subnet', 16, NULL, 10);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000011', now(), 'DEFAULT', '', 'vpc.network.routeTable', 8, NULL, 11);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000012', now(), 'DEFAULT', '', 'vpc.network.securityGroup', 16, NULL, 12);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000014', now(), 'DEFAULT', '', 'iam.user', 128, NULL, 14);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000015', now(), 'DEFAULT', '', 'iam.serviceAccount', 128, NULL, 15);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000016', now(), 'DEFAULT', '', 'iam.group', 64, NULL, 16);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000017', now(), 'DEFAULT', '', 'iam.role', 64, NULL, 17);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000018', now(), 'DEFAULT', '', 'iam.accessBinding', 512, NULL, 18);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000019', now(), 'DEFAULT', '', 'compute.instance', 32, NULL, 19);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000020', now(), 'DEFAULT', '', 'compute.guestAccessKey', 64, NULL, 20);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000021', now(), 'DEFAULT', '', 'compute.placementGroup', 16, NULL, 21);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000022', now(), 'DEFAULT', '', 'storage.volumes', 64, NULL, 22);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000023', now(), 'DEFAULT', '', 'storage.snapshots', 128, NULL, 23);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000024', now(), 'DEFAULT', '', 'storage.images', 32, NULL, 24);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000025', now(), 'DEFAULT', '', 'loadbalancer.networkLoadBalancers', 16, NULL, 25);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000026', now(), 'DEFAULT', '', 'loadbalancer.targetGroups', 64, NULL, 26);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000027', now(), 'DEFAULT', '', 'loadbalancer.listeners', 64, NULL, 27);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000028', now(), 'DEFAULT', '', 'registry.registries', 8, NULL, 28);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000029', now(), 'DEFAULT', '', 'registry.repositories', 256, NULL, 29);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000030', now(), 'DEFAULT', '', 'loadbalancer.networkLoadBalancers.listeners', 16, NULL, 30);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000031', now(), 'DEFAULT', '', 'registry.registries.repositories', 64, NULL, 31);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000032', now(), 'DEFAULT', '', 'iam.account', 5, NULL, 32);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000033', now(), 'DEFAULT', '', 'iam.user.credential', 12, NULL, 35);
INSERT INTO kacho_iam.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES ('lim-00000000000000034', now(), 'DEFAULT', '', 'iam.serviceAccount.credential', 24, NULL, 36);


--
-- Data for Name: memberships; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.memberships (id, user_id, account_id, state, invited_by, created_at, updated_at) VALUES ('mbr-abc4b224e47e60508', 'usr1a18042d81fb438d6', 'acc1a18042d81fb438d6', 'PENDING', NULL, now(), now());


--
-- Data for Name: minted_token_revocations; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: operations; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: project_resource_quotas; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.project_resource_quotas (carrier_type, carrier_id, kind, used, limit_value, source_scope, source_scope_id, limit_revision, synced_at, account_id, created_at, updated_at) VALUES ('iam.user', 'usr1a18042d81fb438d6', 'iam.user.credential', 0, 10, 'DEFAULT', '', 33, now(), '', now(), now());
INSERT INTO kacho_iam.project_resource_quotas (carrier_type, carrier_id, kind, used, limit_value, source_scope, source_scope_id, limit_revision, synced_at, account_id, created_at, updated_at) VALUES ('iam.serviceAccount', 'svac4faf3358e07191f5', 'iam.serviceAccount.credential', 0, 20, 'DEFAULT', '', 34, now(), 'acc1a18042d81fb438d6', now(), now());
INSERT INTO kacho_iam.project_resource_quotas (carrier_type, carrier_id, kind, used, limit_value, source_scope, source_scope_id, limit_revision, synced_at, account_id, created_at, updated_at) VALUES ('iam.serviceAccount', 'sva9e62bc58c3f0e45ea', 'iam.serviceAccount.credential', 0, 20, 'DEFAULT', '', 34, now(), 'acc1a18042d81fb438d6', now(), now());
INSERT INTO kacho_iam.project_resource_quotas (carrier_type, carrier_id, kind, used, limit_value, source_scope, source_scope_id, limit_revision, synced_at, account_id, created_at, updated_at) VALUES ('iam.serviceAccount', 'sva8e7d21b2c8a633cd1', 'iam.serviceAccount.credential', 0, 20, 'DEFAULT', '', 34, now(), 'acc1a18042d81fb438d6', now(), now());
INSERT INTO kacho_iam.project_resource_quotas (carrier_type, carrier_id, kind, used, limit_value, source_scope, source_scope_id, limit_revision, synced_at, account_id, created_at, updated_at) VALUES ('iam.serviceAccount', 'sva85816c3a904b6bac6', 'iam.serviceAccount.credential', 0, 20, 'DEFAULT', '', 34, now(), 'acc1a18042d81fb438d6', now(), now());
INSERT INTO kacho_iam.project_resource_quotas (carrier_type, carrier_id, kind, used, limit_value, source_scope, source_scope_id, limit_revision, synced_at, account_id, created_at, updated_at) VALUES ('iam.serviceAccount', 'sva8ef8aa106f83f84e0', 'iam.serviceAccount.credential', 0, 20, 'DEFAULT', '', 34, now(), 'acc1a18042d81fb438d6', now(), now());
INSERT INTO kacho_iam.project_resource_quotas (carrier_type, carrier_id, kind, used, limit_value, source_scope, source_scope_id, limit_revision, synced_at, account_id, created_at, updated_at) VALUES ('iam.serviceAccount', 'svab91854890de887e6d', 'iam.serviceAccount.credential', 0, 20, 'DEFAULT', '', 34, now(), 'acc1a18042d81fb438d6', now(), now());
INSERT INTO kacho_iam.project_resource_quotas (carrier_type, carrier_id, kind, used, limit_value, source_scope, source_scope_id, limit_revision, synced_at, account_id, created_at, updated_at) VALUES ('iam.serviceAccount', 'sva3e9556e76be67f816', 'iam.serviceAccount.credential', 0, 20, 'DEFAULT', '', 34, now(), 'acc1a18042d81fb438d6', now(), now());


--
-- Data for Name: projects; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: provider_compensation_outbox; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: recovery_completions; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: relation_fact; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('cluster', 'cluster_kacho_root', 'quota_reader', 'group:grp1ed8897b56bb9106f#member', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('cluster', 'cluster_kacho_root', 'system_viewer', 'service_account:sva3e9556e76be67f816', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('group', 'grp1ed8897b56bb9106f', 'member', 'service_account:sva85816c3a904b6bac6', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('cluster', 'cluster_kacho_root', 'system_viewer', 'service_account:sva85816c3a904b6bac6', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('group', 'grp1ed8897b56bb9106f', 'member', 'service_account:sva8e7d21b2c8a633cd1', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('cluster', 'cluster_kacho_root', 'system_viewer', 'service_account:sva8e7d21b2c8a633cd1', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('group', 'grp1ed8897b56bb9106f', 'member', 'service_account:sva8ef8aa106f83f84e0', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('group', 'grp1ed8897b56bb9106f', 'member', 'service_account:sva9e62bc58c3f0e45ea', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('cluster', 'cluster_kacho_root', 'system_admin', 'service_account:svab91854890de887e6d', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('group', 'grp1ed8897b56bb9106f', 'member', 'service_account:svac4faf3358e07191f5', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('cluster', 'cluster_kacho_root', 'viewer', 'user:*', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('group', 'grp258e6bbe9bbe45568', 'member', 'service_account:sva85816c3a904b6bac6', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('group', 'grp258e6bbe9bbe45568', 'member', 'service_account:sva8e7d21b2c8a633cd1', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('group', 'grp258e6bbe9bbe45568', 'member', 'service_account:sva8ef8aa106f83f84e0', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('group', 'grp258e6bbe9bbe45568', 'member', 'service_account:sva9e62bc58c3f0e45ea', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('group', 'grp258e6bbe9bbe45568', 'member', 'service_account:svac4faf3358e07191f5', now(), now(), '', '{}');
INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params) VALUES ('cluster', 'cluster_kacho_root', 'fga_writer', 'group:grp258e6bbe9bbe45568#member', now(), now(), '', '{}');


--
-- Data for Name: resource_mirror; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: resource_parent_edge; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: resource_reconcile_outbox; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: role_grant_orphan; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: role_rule_ref; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol096a471229217fbcf', 'vpc', 'address', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol096a471229217fbcf', 'vpc', 'address', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol1469d1a633ceae4b5', 'vpc', 'securityGroup', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol1469d1a633ceae4b5', 'vpc', 'securityGroup', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol213ce142e75132019', 'iam', 'accessBinding', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol213ce142e75132019', 'iam', 'accessBinding', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol213ce142e75132019', 'iam', 'accessBinding', 'update', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol26a49318d88632af2', 'vpc', 'gateway', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol26a49318d88632af2', 'vpc', 'gateway', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol31f5c2b4e7b3ee06c', 'vpc', 'subnet', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol31f5c2b4e7b3ee06c', 'vpc', 'subnet', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol34c4d5f1c7c722230', 'iam', 'account', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol34c4d5f1c7c722230', 'iam', 'account', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol34c4d5f1c7c722230', 'iam', 'account', 'update', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol38306aa220559b1f6', 'iam', 'serviceAccount', NULL, true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol41dd066874f699c17', 'iam', 'account', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol41dd066874f699c17', 'iam', 'account', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol4d942f110ed3d7c47', 'vpc', 'network', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol4d942f110ed3d7c47', 'vpc', 'network', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol4d942f110ed3d7c47', 'vpc', 'network', 'update', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol5e145d87ee378211f', 'iam', 'serviceAccount', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol5e145d87ee378211f', 'iam', 'serviceAccount', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol5e145d87ee378211f', 'iam', 'serviceAccount', 'update', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol6307d201bf18e6763', 'iam', 'account', NULL, true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol672f1ac772fab8697', 'iam', 'role', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol672f1ac772fab8697', 'iam', 'role', 'update', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol674f6a6d7e4eeb3b6', 'iam', 'project', NULL, true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol68b2520862bf7a921', 'vpc', 'subnet', NULL, true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol6a079e6a177963990', 'iam', 'group', NULL, true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol6be01c0948936754b', 'compute', 'instance', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol6be01c0948936754b', 'compute', 'instance', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol79a7325eb0d31fad4', 'compute', 'instance', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol79a7325eb0d31fad4', 'compute', 'instance', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol79a7325eb0d31fad4', 'compute', 'instance', 'update', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol7ad445624b1d0e9a1', 'iam', 'project', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol7ad445624b1d0e9a1', 'iam', 'project', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol7b4c84039b79327e5', 'iam', 'project', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol7b4c84039b79327e5', 'iam', 'project', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol7b4c84039b79327e5', 'iam', 'project', 'update', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol88958a1dfa5ddf047', 'vpc', 'securityGroup', NULL, true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol8df6147b3aa962b57', 'vpc', 'address', NULL, true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol8ed48ecc3878c2e73', 'vpc', 'network', NULL, true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol91e90d7a1d4d02658', 'vpc', 'subnet', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol91e90d7a1d4d02658', 'vpc', 'subnet', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol91e90d7a1d4d02658', 'vpc', 'subnet', 'update', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol9aeb6b9c5d5b01ec0', 'vpc', 'gateway', NULL, true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol9d5dc5ed6308cee2a', 'vpc', 'gateway', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol9d5dc5ed6308cee2a', 'vpc', 'gateway', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rol9d5dc5ed6308cee2a', 'vpc', 'gateway', 'update', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rola227db99b2e9bd131', 'vpc', 'securityGroup', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rola227db99b2e9bd131', 'vpc', 'securityGroup', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rola227db99b2e9bd131', 'vpc', 'securityGroup', 'update', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolab84e08ef4b5e0b22', 'vpc', 'routeTable', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolab84e08ef4b5e0b22', 'vpc', 'routeTable', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolb18c533133af2f130', 'iam', 'accessBinding', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolb18c533133af2f130', 'iam', 'accessBinding', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolc98b067591ded99e5', 'iam', 'group', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolc98b067591ded99e5', 'iam', 'group', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolca0d037b77856bea8', 'vpc', 'address', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolca0d037b77856bea8', 'vpc', 'address', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolca0d037b77856bea8', 'vpc', 'address', 'update', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rold4f364618280185aa', 'iam', 'group', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rold4f364618280185aa', 'iam', 'group', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rold4f364618280185aa', 'iam', 'group', 'update', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rold8267982db70ea7f0', 'vpc', 'routeTable', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rold8267982db70ea7f0', 'vpc', 'routeTable', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rold8267982db70ea7f0', 'vpc', 'routeTable', 'update', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolddd484b2677346167', 'vpc', 'routeTable', NULL, true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('role1eb529620e1ff235', 'iam', 'accessBinding', NULL, true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('role2f47108d41b38f39', 'iam', 'user', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('role2f47108d41b38f39', 'iam', 'user', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('role563eb4128875f8d1', 'loadbalancer', 'listeners', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('role563eb4128875f8d1', 'loadbalancer', 'listeners', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('role563eb4128875f8d1', 'loadbalancer', 'networkLoadBalancers', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('role563eb4128875f8d1', 'loadbalancer', 'networkLoadBalancers', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('role563eb4128875f8d1', 'loadbalancer', 'targetGroups', 'addtargets', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('role563eb4128875f8d1', 'loadbalancer', 'targetGroups', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('role563eb4128875f8d1', 'loadbalancer', 'targetGroups', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('role563eb4128875f8d1', 'loadbalancer', 'targetGroups', 'removetargets', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('role6859cc35f67d659e', 'iam', 'role', NULL, true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolecba563ba8698e792', 'loadbalancer', 'listeners', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolecba563ba8698e792', 'loadbalancer', 'listeners', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolecba563ba8698e792', 'loadbalancer', 'networkLoadBalancers', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolecba563ba8698e792', 'loadbalancer', 'networkLoadBalancers', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolecba563ba8698e792', 'loadbalancer', 'targetGroups', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolecba563ba8698e792', 'loadbalancer', 'targetGroups', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolee27bb5ba1efb68cb', 'iam', 'role', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolfc25814dc6989172d', 'iam', 'serviceAccount', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolfc25814dc6989172d', 'iam', 'serviceAccount', 'list', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolfe4e91e8c9f6542a6', 'compute', 'instance', NULL, true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolfe683216e63311d3f', 'vpc', 'network', 'get', true);
INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb, live) VALUES ('rolfe683216e63311d3f', 'vpc', 'network', 'list', true);


--
-- Data for Name: role_rule_selectors; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.role_rule_selectors (role_id, rule_fp, object_types, match_labels, created_at, updated_at, arm, resource_names, live) VALUES ('rol21232f297a57a5a74', '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4', '{compute.guestAccessKey,compute.instance,compute.placementGroup,iam.accessBinding,iam.account,iam.group,iam.project,iam.role,iam.serviceAccount,iam.user,loadbalancer.listeners,loadbalancer.networkLoadBalancers,loadbalancer.targetGroups,registry.registries,registry.repositories,storage.images,storage.snapshots,storage.volumes,vpc.address,vpc.cidrGroup,vpc.gateway,vpc.network,vpc.networkInterface,vpc.routeTable,vpc.securityGroup,vpc.subnet}', '{}', now(), now(), 'anchor', '{}', true);
INSERT INTO kacho_iam.role_rule_selectors (role_id, rule_fp, object_types, match_labels, created_at, updated_at, arm, resource_names, live) VALUES ('rolde95b43bceeb4b998', 'e4919459188e4b7b3786370b6c0899a79b4df159bd1988aef0b3ad23bb5aacfe', '{compute.guestAccessKey,compute.instance,compute.placementGroup,iam.accessBinding,iam.account,iam.group,iam.project,iam.role,iam.serviceAccount,iam.user,loadbalancer.listeners,loadbalancer.networkLoadBalancers,loadbalancer.targetGroups,registry.registries,registry.repositories,storage.images,storage.snapshots,storage.volumes,vpc.address,vpc.cidrGroup,vpc.gateway,vpc.network,vpc.networkInterface,vpc.routeTable,vpc.securityGroup,vpc.subnet}', '{}', now(), now(), 'anchor', '{}', true);
INSERT INTO kacho_iam.role_rule_selectors (role_id, rule_fp, object_types, match_labels, created_at, updated_at, arm, resource_names, live) VALUES ('rol1bda80f2be4d3658e', 'fe68d56d542e8b599256b1a7eee6e31eed6db358e7254af4b5e25c7195dcf68e', '{compute.guestAccessKey,compute.instance,compute.placementGroup,iam.accessBinding,iam.account,iam.group,iam.project,iam.role,iam.serviceAccount,iam.user,loadbalancer.listeners,loadbalancer.networkLoadBalancers,loadbalancer.targetGroups,registry.registries,registry.repositories,storage.images,storage.snapshots,storage.volumes,vpc.address,vpc.cidrGroup,vpc.gateway,vpc.network,vpc.networkInterface,vpc.routeTable,vpc.securityGroup,vpc.subnet}', '{}', now(), now(), 'anchor', '{}', true);
INSERT INTO kacho_iam.role_rule_selectors (role_id, rule_fp, object_types, match_labels, created_at, updated_at, arm, resource_names, live) VALUES ('rol72122ce96bfec66e2', '3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4', '{compute.guestAccessKey,compute.instance,compute.placementGroup,iam.accessBinding,iam.account,iam.group,iam.project,iam.role,iam.serviceAccount,iam.user,loadbalancer.listeners,loadbalancer.networkLoadBalancers,loadbalancer.targetGroups,registry.registries,registry.repositories,storage.images,storage.snapshots,storage.volumes,vpc.address,vpc.cidrGroup,vpc.gateway,vpc.network,vpc.networkInterface,vpc.routeTable,vpc.securityGroup,vpc.subnet}', '{}', now(), now(), 'anchor', '{}', true);


--
-- Data for Name: role_selector_prune; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: role_verb; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: roles; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol21232f297a57a5a74', NULL, 'admin', 'Global super-admin (all modules, all resources, all verbs)', '["*.*.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "*", "resources": ["*"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol6307d201bf18e6763', NULL, 'iam.account.admin', 'Admin Account (CRUD)', '["iam.account.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "iam", "resources": ["account"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol674f6a6d7e4eeb3b6', NULL, 'iam.project.admin', 'Admin Project', '["iam.project.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "iam", "resources": ["project"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rolde95b43bceeb4b998', NULL, 'edit', 'Global edit-only (update operations on all resources, no create/delete/admin)', '["*.*.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list", "update"], "module": "*", "resources": ["*"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol34c4d5f1c7c722230', NULL, 'iam.account.edit', 'Edit Account (update only)', '["iam.account.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list", "update"], "module": "iam", "resources": ["account"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol7b4c84039b79327e5', NULL, 'iam.project.edit', 'Edit Project', '["iam.project.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list", "update"], "module": "iam", "resources": ["project"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol8df6147b3aa962b57', NULL, 'vpc.address.admin', 'Admin Address', '["vpc.address.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "vpc", "resources": ["address"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rolfe4e91e8c9f6542a6', NULL, 'compute.instance.admin', 'Admin Instance', '["compute.instance.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "compute", "resources": ["instance"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol000000000sysadmin', NULL, 'kacho-system.admin', 'Built-in system administrator (all permissions across all scopes)', '["*.*.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "*", "resources": ["*"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol38306aa220559b1f6', NULL, 'iam.service_account.admin', 'Admin ServiceAccount', '["iam.serviceAccount.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "iam", "resources": ["serviceAccount"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol000000000sysviewer', NULL, 'kacho-system.viewer', 'Built-in system viewer (read-only)', '["*.*.*.read", "*.*.*.list", "*.*.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "*", "resources": ["*"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol1bda80f2be4d3658e', NULL, 'view', 'Global read-only (read/list/get all)', '["*.*.*.read", "*.*.*.list", "*.*.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "*", "resources": ["*"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol26a49318d88632af2', NULL, 'vpc.gateway.view', 'Read Gateway', '["vpc.gateway.*.read", "vpc.gateway.*.list", "vpc.gateway.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "vpc", "resources": ["gateway"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol41dd066874f699c17', NULL, 'iam.account.view', 'Read Account', '["iam.account.*.read", "iam.account.*.list", "iam.account.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "iam", "resources": ["account"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol6be01c0948936754b', NULL, 'compute.instance.view', 'Read Instance', '["compute.instance.*.read", "compute.instance.*.list", "compute.instance.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "compute", "resources": ["instance"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol7ad445624b1d0e9a1', NULL, 'iam.project.view', 'Read Project', '["iam.project.*.read", "iam.project.*.list", "iam.project.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "iam", "resources": ["project"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('role2f47108d41b38f39', NULL, 'iam.user.view', 'Read User', '["iam.user.*.read", "iam.user.*.list", "iam.user.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "iam", "resources": ["user"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol9d5dc5ed6308cee2a', NULL, 'vpc.gateway.edit', 'Edit Gateway', '["vpc.gateway.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list", "update"], "module": "vpc", "resources": ["gateway"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol79a7325eb0d31fad4', NULL, 'compute.instance.edit', 'Edit Instance', '["compute.instance.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list", "update"], "module": "compute", "resources": ["instance"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol6a079e6a177963990', NULL, 'iam.group.admin', 'Admin Group', '["iam.group.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "iam", "resources": ["group"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('role6859cc35f67d659e', NULL, 'iam.role.admin', 'Admin Role catalog', '["iam.role.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "iam", "resources": ["role"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol8ed48ecc3878c2e73', NULL, 'vpc.network.admin', 'Admin Network', '["vpc.network.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "vpc", "resources": ["network"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol68b2520862bf7a921', NULL, 'vpc.subnet.admin', 'Admin Subnet', '["vpc.subnet.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "vpc", "resources": ["subnet"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol9aeb6b9c5d5b01ec0', NULL, 'vpc.gateway.admin', 'Admin Gateway', '["vpc.gateway.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "vpc", "resources": ["gateway"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rold4f364618280185aa', NULL, 'iam.group.edit', 'Edit Group', '["iam.group.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list", "update"], "module": "iam", "resources": ["group"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol672f1ac772fab8697', NULL, 'iam.role.edit', 'Edit Role', '["iam.role.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "update"], "module": "iam", "resources": ["role"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol5e145d87ee378211f', NULL, 'iam.service_account.edit', 'Edit ServiceAccount', '["iam.serviceAccount.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list", "update"], "module": "iam", "resources": ["serviceAccount"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('role1eb529620e1ff235', NULL, 'iam.access_binding.admin', 'Admin AccessBinding', '["iam.accessBinding.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "iam", "resources": ["accessBinding"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rolee27bb5ba1efb68cb', NULL, 'iam.role.view', 'Read Role', '["iam.role.*.read", "iam.role.*.list", "iam.role.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list"], "module": "iam", "resources": ["role"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol213ce142e75132019', NULL, 'iam.access_binding.edit', 'Edit AccessBinding', '["iam.accessBinding.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list", "update"], "module": "iam", "resources": ["accessBinding"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol88958a1dfa5ddf047', NULL, 'vpc.security_group.admin', 'Admin SecurityGroup', '["vpc.securityGroup.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "vpc", "resources": ["securityGroup"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol096a471229217fbcf', NULL, 'vpc.address.view', 'Read Address', '["vpc.address.*.read", "vpc.address.*.list", "vpc.address.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "vpc", "resources": ["address"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol31f5c2b4e7b3ee06c', NULL, 'vpc.subnet.view', 'Read Subnet', '["vpc.subnet.*.read", "vpc.subnet.*.list", "vpc.subnet.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "vpc", "resources": ["subnet"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rolb18c533133af2f130', NULL, 'iam.access_binding.view', 'Read AccessBinding', '["iam.accessBinding.*.read", "iam.accessBinding.*.list", "iam.accessBinding.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "iam", "resources": ["accessBinding"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rolc98b067591ded99e5', NULL, 'iam.group.view', 'Read Group', '["iam.group.*.read", "iam.group.*.list", "iam.group.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "iam", "resources": ["group"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rolfc25814dc6989172d', NULL, 'iam.service_account.view', 'Read ServiceAccount', '["iam.serviceAccount.*.read", "iam.serviceAccount.*.list", "iam.serviceAccount.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "iam", "resources": ["serviceAccount"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rolfe683216e63311d3f', NULL, 'vpc.network.view', 'Read Network', '["vpc.network.*.read", "vpc.network.*.list", "vpc.network.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "vpc", "resources": ["network"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol72122ce96bfec66e2', NULL, 'owner', 'Account owner (all modules, all resources, all verbs within the account)', '["*.*.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "*", "resources": ["*"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol4d942f110ed3d7c47', NULL, 'vpc.network.edit', 'Edit Network', '["vpc.network.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list", "update"], "module": "vpc", "resources": ["network"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol91e90d7a1d4d02658', NULL, 'vpc.subnet.edit', 'Edit Subnet', '["vpc.subnet.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list", "update"], "module": "vpc", "resources": ["subnet"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rolca0d037b77856bea8', NULL, 'vpc.address.edit', 'Edit Address', '["vpc.address.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list", "update"], "module": "vpc", "resources": ["address"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rola227db99b2e9bd131', NULL, 'vpc.security_group.edit', 'Edit SecurityGroup', '["vpc.securityGroup.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list", "update"], "module": "vpc", "resources": ["securityGroup"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rold8267982db70ea7f0', NULL, 'vpc.route_table.edit', 'Edit RouteTable', '["vpc.routeTable.*.update"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list", "update"], "module": "vpc", "resources": ["routeTable"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('role563eb4128875f8d1', NULL, 'loadbalancer.target_manager', 'NLB target manager (addTargets/removeTargets/getTargetStates + viewer on LB hierarchy)', '["loadbalancer.targetGroups.*.addTargets", "loadbalancer.targetGroups.*.removeTargets", "loadbalancer.networkLoadBalancers.*.getTargetStates", "loadbalancer.targetGroups.*.get", "loadbalancer.targetGroups.*.list", "loadbalancer.targetGroups.*.listOperations", "loadbalancer.networkLoadBalancers.*.get", "loadbalancer.networkLoadBalancers.*.list", "loadbalancer.listeners.*.get", "loadbalancer.listeners.*.list"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["addTargets", "removeTargets", "get", "list"], "module": "loadbalancer", "resources": ["targetGroups"]}, {"verbs": ["get", "list"], "module": "loadbalancer", "resources": ["networkLoadBalancers"]}, {"verbs": ["get", "list"], "module": "loadbalancer", "resources": ["listeners"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rolddd484b2677346167', NULL, 'vpc.route_table.admin', 'Admin RouteTable', '["vpc.routeTable.*.*"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["*"], "module": "vpc", "resources": ["routeTable"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rol1469d1a633ceae4b5', NULL, 'vpc.security_group.view', 'Read SecurityGroup', '["vpc.securityGroup.*.read", "vpc.securityGroup.*.list", "vpc.securityGroup.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "vpc", "resources": ["securityGroup"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rolab84e08ef4b5e0b22', NULL, 'vpc.route_table.view', 'Read RouteTable', '["vpc.routeTable.*.read", "vpc.routeTable.*.list", "vpc.routeTable.*.get"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["list", "get"], "module": "vpc", "resources": ["routeTable"]}]', '{}', NULL, NULL, NULL, NULL, true);
INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, created_at, cluster_id, project_id, rules, labels, owner_module, retired_at, retired_reason, retired_by, live) VALUES ('rolecba563ba8698e792', NULL, 'loadbalancer.operator', 'NLB operator (start/stop/getTargetStates/listOperations + viewer on LB hierarchy)', '["loadbalancer.listeners.*.get", "loadbalancer.listeners.*.list", "loadbalancer.listeners.*.listOperations", "loadbalancer.networkLoadBalancers.*.get", "loadbalancer.networkLoadBalancers.*.getTargetStates", "loadbalancer.networkLoadBalancers.*.list", "loadbalancer.networkLoadBalancers.*.listOperations", "loadbalancer.targetGroups.*.get", "loadbalancer.targetGroups.*.list", "loadbalancer.targetGroups.*.listOperations"]', now(), 'cluster_kacho_root', NULL, '[{"verbs": ["get", "list"], "module": "loadbalancer", "resources": ["networkLoadBalancers"]}, {"verbs": ["get", "list"], "module": "loadbalancer", "resources": ["listeners"]}, {"verbs": ["get", "list"], "module": "loadbalancer", "resources": ["targetGroups"]}]', '{}', NULL, NULL, NULL, NULL, true);


--
-- Data for Name: service_account_oauth_clients; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: service_accounts; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.service_accounts (id, account_id, name, description, created_at, enabled, labels) VALUES ('sva85816c3a904b6bac6', 'acc1a18042d81fb438d6', 'kacho-vpc', 'Module SA: kacho-vpc (SEC-C least-priv)', now(), true, '{}');
INSERT INTO kacho_iam.service_accounts (id, account_id, name, description, created_at, enabled, labels) VALUES ('sva8e7d21b2c8a633cd1', 'acc1a18042d81fb438d6', 'kacho-compute', 'Module SA: kacho-compute (SEC-C least-priv)', now(), true, '{}');
INSERT INTO kacho_iam.service_accounts (id, account_id, name, description, created_at, enabled, labels) VALUES ('svac4faf3358e07191f5', 'acc1a18042d81fb438d6', 'kacho-nlb', 'Module SA: kacho-nlb (SEC-C least-priv)', now(), true, '{}');
INSERT INTO kacho_iam.service_accounts (id, account_id, name, description, created_at, enabled, labels) VALUES ('sva3e9556e76be67f816', 'acc1a18042d81fb438d6', 'kacho-api-gateway', 'Module SA: kacho-api-gateway (SEC-C identity-only)', now(), true, '{}');
INSERT INTO kacho_iam.service_accounts (id, account_id, name, description, created_at, enabled, labels) VALUES ('sva9e62bc58c3f0e45ea', 'acc1a18042d81fb438d6', 'kacho-registry', 'Module SA: kacho-registry (SEC-C least-priv)', now(), true, '{}');
INSERT INTO kacho_iam.service_accounts (id, account_id, name, description, created_at, enabled, labels) VALUES ('sva8ef8aa106f83f84e0', 'acc1a18042d81fb438d6', 'kacho-storage', 'Module SA: kacho-storage (SEC-C least-priv)', now(), true, '{}');
INSERT INTO kacho_iam.service_accounts (id, account_id, name, description, created_at, enabled, labels) VALUES ('svab91854890de887e6d', 'acc1a18042d81fb438d6', 'kacho-bootstrap-admin', 'Bootstrap admin ServiceAccount for non-interactive production-mode token mint (#58)', now(), true, '{}');


--
-- Data for Name: session_revocations; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: subject_change_outbox; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: token_signing_keys; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: user_oauth_clients; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: user_token_revocations; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--



--
-- Data for Name: users; Type: TABLE DATA; Schema: kacho_iam; Owner: -
--

INSERT INTO kacho_iam.users (id, external_id, email, display_name, created_at, account_id, invite_status, invited_by, labels) VALUES ('usr1a18042d81fb438d6', '', 'system@kacho.local', 'Kacho System (module SA owner)', now(), 'acc1a18042d81fb438d6', 'PENDING', NULL, '{}');


--
-- Name: account_admission_rate_limits_id_seq; Type: SEQUENCE SET; Schema: kacho_iam; Owner: -
--

SELECT pg_catalog.setval('kacho_iam.account_admission_rate_limits_id_seq', 1, true);


--
-- Name: fga_outbox_id_seq; Type: SEQUENCE SET; Schema: kacho_iam; Owner: -
--

SELECT pg_catalog.setval('kacho_iam.fga_outbox_id_seq', 29, true);


--
-- Name: invite_mail_outbox_id_seq; Type: SEQUENCE SET; Schema: kacho_iam; Owner: -
--

SELECT pg_catalog.setval('kacho_iam.invite_mail_outbox_id_seq', 1, false);


--
-- Name: limits_revision_seq; Type: SEQUENCE SET; Schema: kacho_iam; Owner: -
--

SELECT pg_catalog.setval('kacho_iam.limits_revision_seq', 36, true);


--
-- Name: provider_compensation_outbox_id_seq; Type: SEQUENCE SET; Schema: kacho_iam; Owner: -
--

SELECT pg_catalog.setval('kacho_iam.provider_compensation_outbox_id_seq', 1, false);


--
-- Name: resource_reconcile_outbox_id_seq; Type: SEQUENCE SET; Schema: kacho_iam; Owner: -
--

SELECT pg_catalog.setval('kacho_iam.resource_reconcile_outbox_id_seq', 1, false);


--
-- Name: subject_change_outbox_id_seq; Type: SEQUENCE SET; Schema: kacho_iam; Owner: -
--

SELECT pg_catalog.setval('kacho_iam.subject_change_outbox_id_seq', 1, false);


--
-- Name: access_binding_emitted_tuples access_binding_emitted_tuples_pk; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_binding_emitted_tuples
    ADD CONSTRAINT access_binding_emitted_tuples_pk PRIMARY KEY (binding_id, fga_user, relation, object);


--
-- Name: access_binding_subjects access_binding_subjects_pk; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_binding_subjects
    ADD CONSTRAINT access_binding_subjects_pk PRIMARY KEY (binding_id, subject_type, subject_id);


--
-- Name: access_binding_target_members access_binding_target_members_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_binding_target_members
    ADD CONSTRAINT access_binding_target_members_pkey PRIMARY KEY (binding_id, role_id, rule_fp, object_type, object_id);


--
-- Name: access_bindings access_bindings_id_scope_uk; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_bindings
    ADD CONSTRAINT access_bindings_id_scope_uk UNIQUE (id, resource_type, resource_id);


--
-- Name: access_bindings access_bindings_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_bindings
    ADD CONSTRAINT access_bindings_pkey PRIMARY KEY (id);


--
-- Name: account_admission_rate_limits account_admission_rate_limits_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.account_admission_rate_limits
    ADD CONSTRAINT account_admission_rate_limits_pkey PRIMARY KEY (id);


--
-- Name: accounts accounts_name_unique; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.accounts
    ADD CONSTRAINT accounts_name_unique UNIQUE (name);


--
-- Name: accounts accounts_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id);


--
-- Name: audit_outbox audit_outbox_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.audit_outbox
    ADD CONSTRAINT audit_outbox_pkey PRIMARY KEY (id);


--
-- Name: catalog_module catalog_module_live_uk; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.catalog_module
    ADD CONSTRAINT catalog_module_live_uk UNIQUE (module, live);


--
-- Name: catalog_module catalog_module_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.catalog_module
    ADD CONSTRAINT catalog_module_pkey PRIMARY KEY (module);


--
-- Name: catalog_resource catalog_resource_dotted_live_uk; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.catalog_resource
    ADD CONSTRAINT catalog_resource_dotted_live_uk UNIQUE (dotted, live);


--
-- Name: catalog_resource catalog_resource_live_uk; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.catalog_resource
    ADD CONSTRAINT catalog_resource_live_uk UNIQUE (module, resource, live);


--
-- Name: catalog_resource catalog_resource_object_type_live_uk; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.catalog_resource
    ADD CONSTRAINT catalog_resource_object_type_live_uk UNIQUE (object_type, live);


--
-- Name: catalog_resource catalog_resource_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.catalog_resource
    ADD CONSTRAINT catalog_resource_pkey PRIMARY KEY (module, resource);


--
-- Name: catalog_verb catalog_verb_live_uk; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.catalog_verb
    ADD CONSTRAINT catalog_verb_live_uk UNIQUE (module, resource, verb, live);


--
-- Name: catalog_verb catalog_verb_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.catalog_verb
    ADD CONSTRAINT catalog_verb_pkey PRIMARY KEY (module, resource, verb);


--
-- Name: client_assertion_replay client_assertion_replay_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.client_assertion_replay
    ADD CONSTRAINT client_assertion_replay_pkey PRIMARY KEY (client_id, assertion_id);


--
-- Name: cluster_admin_grants cluster_admin_grants_cluster_subject_uniq; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.cluster_admin_grants
    ADD CONSTRAINT cluster_admin_grants_cluster_subject_uniq UNIQUE (cluster_id, subject_id);


--
-- Name: cluster_admin_grants cluster_admin_grants_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.cluster_admin_grants
    ADD CONSTRAINT cluster_admin_grants_pkey PRIMARY KEY (id);


--
-- Name: clusters clusters_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.clusters
    ADD CONSTRAINT clusters_pkey PRIMARY KEY (id);


--
-- Name: federated_trusted_issuers federated_trusted_issuers_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.federated_trusted_issuers
    ADD CONSTRAINT federated_trusted_issuers_pkey PRIMARY KEY (issuer, subject);


--
-- Name: fga_outbox fga_outbox_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.fga_outbox
    ADD CONSTRAINT fga_outbox_pkey PRIMARY KEY (id);


--
-- Name: fga_outbox fga_outbox_relation_present_check; Type: CHECK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE kacho_iam.fga_outbox
    ADD CONSTRAINT fga_outbox_relation_present_check CHECK (((((payload ->> 'relation'::text) IS NOT NULL) AND ((payload ->> 'relation'::text) <> ''::text)) OR (jsonb_array_length(COALESCE((payload -> 'relations'::text), '[]'::jsonb)) > 0))) NOT VALID;


--
-- Name: group_members group_members_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.group_members
    ADD CONSTRAINT group_members_pkey PRIMARY KEY (group_id, member_type, member_id);


--
-- Name: groups groups_account_name_unique; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.groups
    ADD CONSTRAINT groups_account_name_unique UNIQUE (account_id, name);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: identity_admission_windows identity_admission_windows_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.identity_admission_windows
    ADD CONSTRAINT identity_admission_windows_pkey PRIMARY KEY (carrier_id, kind);


--
-- Name: identity_journal identity_journal_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.identity_journal
    ADD CONSTRAINT identity_journal_pkey PRIMARY KEY (identity);


--
-- Name: interactive_clients interactive_clients_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.interactive_clients
    ADD CONSTRAINT interactive_clients_pkey PRIMARY KEY (id);


--
-- Name: invite_mail_outbox invite_mail_outbox_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.invite_mail_outbox
    ADD CONSTRAINT invite_mail_outbox_pkey PRIMARY KEY (id);


--
-- Name: limits limits_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.limits
    ADD CONSTRAINT limits_pkey PRIMARY KEY (id);


--
-- Name: memberships memberships_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.memberships
    ADD CONSTRAINT memberships_pkey PRIMARY KEY (id);


--
-- Name: minted_token_revocations minted_token_revocations_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.minted_token_revocations
    ADD CONSTRAINT minted_token_revocations_pkey PRIMARY KEY (subject);


--
-- Name: operations operations_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (id);


--
-- Name: project_resource_quotas project_resource_quotas_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.project_resource_quotas
    ADD CONSTRAINT project_resource_quotas_pkey PRIMARY KEY (carrier_type, carrier_id, kind);


--
-- Name: projects projects_account_name_unique; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.projects
    ADD CONSTRAINT projects_account_name_unique UNIQUE (account_id, name);


--
-- Name: projects projects_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);


--
-- Name: provider_compensation_outbox provider_compensation_outbox_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.provider_compensation_outbox
    ADD CONSTRAINT provider_compensation_outbox_pkey PRIMARY KEY (id);


--
-- Name: recovery_completions recovery_completions_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.recovery_completions
    ADD CONSTRAINT recovery_completions_pkey PRIMARY KEY (recovery_jti);


--
-- Name: relation_fact relation_fact_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.relation_fact
    ADD CONSTRAINT relation_fact_pkey PRIMARY KEY (object_type, object_id, relation, subject);


--
-- Name: resource_mirror resource_mirror_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.resource_mirror
    ADD CONSTRAINT resource_mirror_pkey PRIMARY KEY (object_type, object_id);


--
-- Name: resource_parent_edge resource_parent_edge_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.resource_parent_edge
    ADD CONSTRAINT resource_parent_edge_pkey PRIMARY KEY (object_type, object_id, depth);


--
-- Name: resource_reconcile_outbox resource_reconcile_outbox_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.resource_reconcile_outbox
    ADD CONSTRAINT resource_reconcile_outbox_pkey PRIMARY KEY (id);


--
-- Name: role_grant_orphan role_grant_orphan_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_grant_orphan
    ADD CONSTRAINT role_grant_orphan_pkey PRIMARY KEY (role_id, object_type, verb, source, cause);


--
-- Name: role_rule_selectors role_rule_selectors_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_rule_selectors
    ADD CONSTRAINT role_rule_selectors_pkey PRIMARY KEY (role_id, rule_fp);


--
-- Name: role_selector_prune role_selector_prune_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_selector_prune
    ADD CONSTRAINT role_selector_prune_pkey PRIMARY KEY (role_id, rule_fp, object_type);


--
-- Name: role_verb role_verb_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_verb
    ADD CONSTRAINT role_verb_pkey PRIMARY KEY (role_id, object_type, verb);


--
-- Name: roles roles_id_live_uk; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.roles
    ADD CONSTRAINT roles_id_live_uk UNIQUE (id, live);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: service_account_oauth_clients service_account_oauth_clients_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.service_account_oauth_clients
    ADD CONSTRAINT service_account_oauth_clients_pkey PRIMARY KEY (id);


--
-- Name: service_accounts service_accounts_account_name_unique; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.service_accounts
    ADD CONSTRAINT service_accounts_account_name_unique UNIQUE (account_id, name);


--
-- Name: service_accounts service_accounts_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.service_accounts
    ADD CONSTRAINT service_accounts_pkey PRIMARY KEY (id);


--
-- Name: session_revocations session_revocations_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.session_revocations
    ADD CONSTRAINT session_revocations_pkey PRIMARY KEY (token_jti);


--
-- Name: subject_change_outbox subject_change_outbox_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.subject_change_outbox
    ADD CONSTRAINT subject_change_outbox_pkey PRIMARY KEY (id);


--
-- Name: token_signing_keys token_signing_keys_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.token_signing_keys
    ADD CONSTRAINT token_signing_keys_pkey PRIMARY KEY (kid);


--
-- Name: user_oauth_clients user_oauth_clients_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_pkey PRIMARY KEY (id);


--
-- Name: user_token_revocations user_token_revocations_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.user_token_revocations
    ADD CONSTRAINT user_token_revocations_pkey PRIMARY KEY (user_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: access_binding_subjects_binding_ordinal_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_binding_subjects_binding_ordinal_idx ON kacho_iam.access_binding_subjects USING btree (binding_id, ordinal);


--
-- Name: access_binding_subjects_subject_scope_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_binding_subjects_subject_scope_idx ON kacho_iam.access_binding_subjects USING btree (subject_type, subject_id, resource_type, resource_id);


--
-- Name: access_binding_target_members_object_binding_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_binding_target_members_object_binding_idx ON kacho_iam.access_binding_target_members USING btree (object_type, object_id, binding_id) INCLUDE (role_id, rule_fp, verification_status);


--
-- Name: access_binding_target_members_object_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_binding_target_members_object_idx ON kacho_iam.access_binding_target_members USING btree (object_type, object_id);


--
-- Name: access_binding_target_members_pending_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_binding_target_members_pending_idx ON kacho_iam.access_binding_target_members USING btree (binding_id) WHERE (verification_status = 'PENDING_VERIFICATION'::text);


--
-- Name: access_bindings_active_grant_uniq; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX access_bindings_active_grant_uniq ON kacho_iam.access_bindings USING btree (subject_id, subject_type, role_id, resource_type, resource_id, target_digest) WHERE (revoked_at IS NULL);


--
-- Name: access_bindings_active_relation_grant_uniq; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX access_bindings_active_relation_grant_uniq ON kacho_iam.access_bindings USING btree (subject_type, subject_id, granted_relation, resource_type, resource_id) WHERE ((granted_relation <> ''::text) AND (revoked_at IS NULL));


--
-- Name: access_bindings_cursor_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_cursor_idx ON kacho_iam.access_bindings USING btree (created_at, id);


--
-- Name: access_bindings_expires_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_expires_idx ON kacho_iam.access_bindings USING btree (expires_at) WHERE ((expires_at IS NOT NULL) AND (status = 'ACTIVE'::text));


--
-- Name: access_bindings_labels_gin; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_labels_gin ON kacho_iam.access_bindings USING gin (labels jsonb_path_ops);


--
-- Name: access_bindings_recent_cursor_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_recent_cursor_idx ON kacho_iam.access_bindings USING btree (created_at DESC, id);


--
-- Name: access_bindings_resource_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_resource_idx ON kacho_iam.access_bindings USING btree (resource_type, resource_id);


--
-- Name: access_bindings_role_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_role_idx ON kacho_iam.access_bindings USING btree (role_id);


--
-- Name: access_bindings_scope_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_scope_idx ON kacho_iam.access_bindings USING btree (scope, resource_type);


--
-- Name: access_bindings_status_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_status_idx ON kacho_iam.access_bindings USING btree (status);


--
-- Name: access_bindings_subject_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_subject_idx ON kacho_iam.access_bindings USING btree (subject_type, subject_id);


--
-- Name: account_admission_rate_limits_kind_uk; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX account_admission_rate_limits_kind_uk ON kacho_iam.account_admission_rate_limits USING btree (kind) WHERE (withdrawn_at IS NULL);


--
-- Name: accounts_cursor_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX accounts_cursor_idx ON kacho_iam.accounts USING btree (created_at, id);


--
-- Name: accounts_labels_gin; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX accounts_labels_gin ON kacho_iam.accounts USING gin (labels jsonb_path_ops);


--
-- Name: accounts_owner_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX accounts_owner_idx ON kacho_iam.accounts USING btree (owner_user_id);


--
-- Name: audit_outbox_federation_event_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX audit_outbox_federation_event_idx ON kacho_iam.audit_outbox USING btree (created_at) WHERE (event_type ~~ 'iam.federation.%'::text);


--
-- Name: audit_outbox_pending_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX audit_outbox_pending_idx ON kacho_iam.audit_outbox USING btree (created_at, id) WHERE (status <> 'sent'::text);


--
-- Name: audit_outbox_tenant_account_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX audit_outbox_tenant_account_idx ON kacho_iam.audit_outbox USING btree (tenant_account_id, created_at) WHERE (tenant_account_id IS NOT NULL);


--
-- Name: client_assertion_replay_expires_at_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX client_assertion_replay_expires_at_idx ON kacho_iam.client_assertion_replay USING btree (expires_at);


--
-- Name: cluster_admin_grants_cluster_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX cluster_admin_grants_cluster_idx ON kacho_iam.cluster_admin_grants USING btree (cluster_id);


--
-- Name: cluster_admin_grants_subject_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX cluster_admin_grants_subject_unique ON kacho_iam.cluster_admin_grants USING btree (subject_type, subject_id) WHERE (granted_until IS NULL);


--
-- Name: federated_trusted_issuers_by_client_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX federated_trusted_issuers_by_client_idx ON kacho_iam.federated_trusted_issuers USING btree (sa_oauth_client_id);


--
-- Name: group_members_member_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX group_members_member_idx ON kacho_iam.group_members USING btree (member_type, member_id);


--
-- Name: groups_account_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX groups_account_idx ON kacho_iam.groups USING btree (account_id);


--
-- Name: groups_cursor_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX groups_cursor_idx ON kacho_iam.groups USING btree (created_at, id);


--
-- Name: groups_labels_gin; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX groups_labels_gin ON kacho_iam.groups USING gin (labels jsonb_path_ops);


--
-- Name: identity_journal_first_seen_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX identity_journal_first_seen_idx ON kacho_iam.identity_journal USING btree (first_seen_at);


--
-- Name: interactive_clients_client_id_uk; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX interactive_clients_client_id_uk ON kacho_iam.interactive_clients USING btree (client_id);


--
-- Name: interactive_clients_created_at_id_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX interactive_clients_created_at_id_idx ON kacho_iam.interactive_clients USING btree (created_at, id);


--
-- Name: interactive_clients_name_uk; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX interactive_clients_name_uk ON kacho_iam.interactive_clients USING btree (name);


--
-- Name: invite_mail_outbox_partition_head_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX invite_mail_outbox_partition_head_idx ON kacho_iam.invite_mail_outbox USING btree (resource_id, id) WHERE (sent_at IS NULL);


--
-- Name: invite_mail_outbox_pending_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX invite_mail_outbox_pending_idx ON kacho_iam.invite_mail_outbox USING btree (attempt_count, id) WHERE (sent_at IS NULL);


--
-- Name: limits_created_at_id_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX limits_created_at_id_idx ON kacho_iam.limits USING btree (created_at, id);


--
-- Name: limits_revision_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX limits_revision_idx ON kacho_iam.limits USING btree (revision);


--
-- Name: limits_scope_kind_uk; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX limits_scope_kind_uk ON kacho_iam.limits USING btree (scope, scope_id, kind) WHERE (withdrawn_at IS NULL);


--
-- Name: limits_scope_lookup_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX limits_scope_lookup_idx ON kacho_iam.limits USING btree (scope, scope_id) WHERE (withdrawn_at IS NULL);


--
-- Name: memberships_account_cursor_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX memberships_account_cursor_idx ON kacho_iam.memberships USING btree (account_id, created_at, id);


--
-- Name: memberships_user_account_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX memberships_user_account_unique ON kacho_iam.memberships USING btree (user_id, account_id);


--
-- Name: minted_token_revocations_revoke_before_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX minted_token_revocations_revoke_before_idx ON kacho_iam.minted_token_revocations USING btree (revoke_before);


--
-- Name: operations_account_id_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX operations_account_id_idx ON kacho_iam.operations USING btree (account_id, created_at, id) WHERE (account_id IS NOT NULL);


--
-- Name: operations_created_at_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX operations_created_at_idx ON kacho_iam.operations USING btree (created_at);


--
-- Name: operations_cursor_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX operations_cursor_idx ON kacho_iam.operations USING btree (created_at, id);


--
-- Name: operations_done_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX operations_done_idx ON kacho_iam.operations USING btree (done);


--
-- Name: operations_principal_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX operations_principal_idx ON kacho_iam.operations USING btree (principal_type, principal_id);


--
-- Name: operations_resource_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX operations_resource_idx ON kacho_iam.operations USING btree (resource_id);


--
-- Name: projects_account_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX projects_account_idx ON kacho_iam.projects USING btree (account_id);


--
-- Name: projects_cursor_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX projects_cursor_idx ON kacho_iam.projects USING btree (created_at, id);


--
-- Name: projects_labels_gin; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX projects_labels_gin ON kacho_iam.projects USING gin (labels jsonb_path_ops);


--
-- Name: provider_compensation_outbox_pending_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX provider_compensation_outbox_pending_idx ON kacho_iam.provider_compensation_outbox USING btree (attempt_count, id) WHERE (sent_at IS NULL);


--
-- Name: relation_fact_by_subject; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX relation_fact_by_subject ON kacho_iam.relation_fact USING btree (subject, relation);


--
-- Name: relation_fact_conditioned; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX relation_fact_conditioned ON kacho_iam.relation_fact USING btree (condition_name) WHERE (condition_name <> ''::text);


--
-- Name: resource_mirror_labels_gin; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX resource_mirror_labels_gin ON kacho_iam.resource_mirror USING gin (labels);


--
-- Name: resource_mirror_parent_project_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX resource_mirror_parent_project_idx ON kacho_iam.resource_mirror USING btree (parent_project_id);


--
-- Name: resource_parent_edge_by_parent; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX resource_parent_edge_by_parent ON kacho_iam.resource_parent_edge USING btree (parent_type, parent_id);


--
-- Name: resource_reconcile_outbox_unsent_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX resource_reconcile_outbox_unsent_idx ON kacho_iam.resource_reconcile_outbox USING btree (id) WHERE (sent_at IS NULL);


--
-- Name: role_rule_ref_pair_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX role_rule_ref_pair_idx ON kacho_iam.role_rule_ref USING btree (module, resource);


--
-- Name: role_rule_ref_uk; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX role_rule_ref_uk ON kacho_iam.role_rule_ref USING btree (role_id, module, resource, COALESCE(verb, ''::text));


--
-- Name: role_rule_selectors_object_types_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX role_rule_selectors_object_types_idx ON kacho_iam.role_rule_selectors USING gin (object_types);


--
-- Name: role_verb_by_type_verb; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX role_verb_by_type_verb ON kacho_iam.role_verb USING btree (object_type, verb);


--
-- Name: roles_acc_custom_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX roles_acc_custom_unique ON kacho_iam.roles USING btree (account_id, name) WHERE ((is_system = false) AND (account_id IS NOT NULL));


--
-- Name: roles_account_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX roles_account_idx ON kacho_iam.roles USING btree (account_id) WHERE (account_id IS NOT NULL);


--
-- Name: roles_cluster_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX roles_cluster_idx ON kacho_iam.roles USING btree (cluster_id) WHERE (cluster_id IS NOT NULL);


--
-- Name: roles_cursor_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX roles_cursor_idx ON kacho_iam.roles USING btree (created_at, id);


--
-- Name: roles_labels_gin; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX roles_labels_gin ON kacho_iam.roles USING gin (labels jsonb_path_ops);


--
-- Name: roles_prj_custom_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX roles_prj_custom_unique ON kacho_iam.roles USING btree (project_id, name) WHERE ((is_system = false) AND (project_id IS NOT NULL));


--
-- Name: roles_project_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX roles_project_idx ON kacho_iam.roles USING btree (project_id) WHERE (project_id IS NOT NULL);


--
-- Name: roles_system_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX roles_system_unique ON kacho_iam.roles USING btree (cluster_id, name) WHERE (is_system = true);


--
-- Name: sa_oauth_clients_expires_at_reclaim_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX sa_oauth_clients_expires_at_reclaim_idx ON kacho_iam.service_account_oauth_clients USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: service_account_oauth_clients_hydra_client_id_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX service_account_oauth_clients_hydra_client_id_unique ON kacho_iam.service_account_oauth_clients USING btree (hydra_client_id);


--
-- Name: service_account_oauth_clients_secret_hash_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX service_account_oauth_clients_secret_hash_unique ON kacho_iam.service_account_oauth_clients USING btree (secret_hash) WHERE (credential_kind = 'SECRET'::text);


--
-- Name: service_accounts_account_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX service_accounts_account_idx ON kacho_iam.service_accounts USING btree (account_id);


--
-- Name: service_accounts_cursor_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX service_accounts_cursor_idx ON kacho_iam.service_accounts USING btree (created_at, id);


--
-- Name: service_accounts_enabled_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX service_accounts_enabled_idx ON kacho_iam.service_accounts USING btree (account_id) WHERE (enabled = true);


--
-- Name: service_accounts_labels_gin; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX service_accounts_labels_gin ON kacho_iam.service_accounts USING gin (labels jsonb_path_ops);


--
-- Name: session_revocations_recent_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX session_revocations_recent_idx ON kacho_iam.session_revocations USING btree (revoked_at, token_jti) WHERE (revoked_at > '2000-01-01 00:00:00+00'::timestamp with time zone);


--
-- Name: INDEX session_revocations_recent_idx; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON INDEX kacho_iam.session_revocations_recent_idx IS 'Cache warm-up при холодном старте api-gateway pod; query: SELECT token_jti FROM session_revocations WHERE revoked_at > now() - INTERVAL ''24 hours''';


--
-- Name: session_revocations_ttl_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX session_revocations_ttl_idx ON kacho_iam.session_revocations USING btree (ttl_expires_at);


--
-- Name: session_revocations_user_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX session_revocations_user_idx ON kacho_iam.session_revocations USING btree (user_id);


--
-- Name: token_signing_keys_keyset_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX token_signing_keys_keyset_idx ON kacho_iam.token_signing_keys USING btree (created_at, kid) WHERE (state = ANY (ARRAY['PUBLISHED'::text, 'ACTIVE'::text, 'RETIRED'::text]));


--
-- Name: token_signing_keys_one_active; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX token_signing_keys_one_active ON kacho_iam.token_signing_keys USING btree (state) WHERE (state = 'ACTIVE'::text);


--
-- Name: user_oauth_clients_expires_at_reclaim_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX user_oauth_clients_expires_at_reclaim_idx ON kacho_iam.user_oauth_clients USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: user_oauth_clients_hydra_client_id_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX user_oauth_clients_hydra_client_id_unique ON kacho_iam.user_oauth_clients USING btree (hydra_client_id);


--
-- Name: user_oauth_clients_secret_hash_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX user_oauth_clients_secret_hash_unique ON kacho_iam.user_oauth_clients USING btree (secret_hash) WHERE (credential_kind = 'SECRET'::text);


--
-- Name: user_oauth_clients_user_id_id_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX user_oauth_clients_user_id_id_idx ON kacho_iam.user_oauth_clients USING btree (user_id, id);


--
-- Name: users_account_email_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX users_account_email_unique ON kacho_iam.users USING btree (account_id, lower(email));


--
-- Name: users_account_external_id_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX users_account_external_id_unique ON kacho_iam.users USING btree (account_id, external_id) WHERE (external_id <> ''::text);


--
-- Name: users_active_external_id_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX users_active_external_id_idx ON kacho_iam.users USING btree (external_id) WHERE ((invite_status = 'ACTIVE'::text) AND (external_id <> ''::text));


--
-- Name: users_active_external_id_uniq; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX users_active_external_id_uniq ON kacho_iam.users USING btree (external_id) WHERE ((invite_status = 'ACTIVE'::text) AND (external_id <> ''::text));


--
-- Name: users_cursor_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX users_cursor_idx ON kacho_iam.users USING btree (created_at, id);


--
-- Name: users_email_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX users_email_idx ON kacho_iam.users USING btree (lower(email));


--
-- Name: users_email_pending_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX users_email_pending_idx ON kacho_iam.users USING btree (lower(email)) WHERE (invite_status = 'PENDING'::text);


--
-- Name: users_identity_email_uniq; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX users_identity_email_uniq ON kacho_iam.users USING btree (lower(email));


--
-- Name: users_identity_external_id_uniq; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX users_identity_external_id_uniq ON kacho_iam.users USING btree (external_id) WHERE (external_id <> ''::text);


--
-- Name: users_labels_gin; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX users_labels_gin ON kacho_iam.users USING gin (labels jsonb_path_ops);


--
-- Name: access_binding_subjects access_binding_subjects_carries_scope_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER access_binding_subjects_carries_scope_trg BEFORE INSERT ON kacho_iam.access_binding_subjects FOR EACH ROW EXECUTE FUNCTION kacho_iam.access_binding_subject_carries_scope();


--
-- Name: access_binding_subjects access_binding_subjects_subject_exists_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER access_binding_subjects_subject_exists_trg BEFORE INSERT OR UPDATE ON kacho_iam.access_binding_subjects FOR EACH ROW EXECUTE FUNCTION kacho_iam.subject_ref_exists();


--
-- Name: access_bindings access_bindings_role_assignable_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER access_bindings_role_assignable_trg BEFORE INSERT OR UPDATE ON kacho_iam.access_bindings FOR EACH ROW EXECUTE FUNCTION kacho_iam.access_binding_role_assignable();


--
-- Name: access_bindings access_bindings_role_is_live_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER access_bindings_role_is_live_trg BEFORE INSERT OR UPDATE ON kacho_iam.access_bindings FOR EACH ROW EXECUTE FUNCTION kacho_iam.access_bindings_role_is_live();


--
-- Name: access_bindings access_bindings_scope_default_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER access_bindings_scope_default_trg BEFORE INSERT ON kacho_iam.access_bindings FOR EACH ROW EXECUTE FUNCTION kacho_iam.access_bindings_scope_default();


--
-- Name: access_bindings access_bindings_subject_exists_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER access_bindings_subject_exists_trg BEFORE INSERT OR UPDATE ON kacho_iam.access_bindings FOR EACH ROW EXECUTE FUNCTION kacho_iam.subject_ref_exists();


--
-- Name: accounts accounts_quota_count; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE CONSTRAINT TRIGGER accounts_quota_count AFTER INSERT OR DELETE ON kacho_iam.accounts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION kacho_iam.kacho_quota_count('iam.account');


--
-- Name: accounts accounts_rate_admission; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE CONSTRAINT TRIGGER accounts_rate_admission AFTER INSERT ON kacho_iam.accounts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION kacho_iam.kacho_admission_rate_count('iam.account');


--
-- Name: accounts accounts_withdraw_limits_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER accounts_withdraw_limits_trg BEFORE DELETE ON kacho_iam.accounts FOR EACH ROW EXECUTE FUNCTION kacho_iam.limits_withdraw_for_scope_object('ACCOUNT');


--
-- Name: group_members group_members_member_exists_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER group_members_member_exists_trg BEFORE INSERT OR UPDATE ON kacho_iam.group_members FOR EACH ROW EXECUTE FUNCTION kacho_iam.group_members_member_exists();


--
-- Name: groups groups_subject_ref_before_delete_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER groups_subject_ref_before_delete_trg BEFORE DELETE ON kacho_iam.groups FOR EACH ROW EXECUTE FUNCTION kacho_iam.principal_not_referenced_as_subject('group');


--
-- Name: interactive_clients interactive_clients_uris_wellformed_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER interactive_clients_uris_wellformed_trg BEFORE INSERT OR UPDATE ON kacho_iam.interactive_clients FOR EACH ROW EXECUTE FUNCTION kacho_iam.interactive_client_uris_wellformed();


--
-- Name: invite_mail_outbox invite_mail_outbox_notify_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER invite_mail_outbox_notify_trg AFTER INSERT ON kacho_iam.invite_mail_outbox FOR EACH ROW EXECUTE FUNCTION kacho_iam.invite_mail_outbox_notify();


--
-- Name: limits limits_scope_ref_exists_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER limits_scope_ref_exists_trg BEFORE INSERT OR UPDATE ON kacho_iam.limits FOR EACH ROW EXECUTE FUNCTION kacho_iam.limits_scope_ref_exists();


--
-- Name: limits limits_stamp_revision_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER limits_stamp_revision_trg BEFORE INSERT OR UPDATE ON kacho_iam.limits FOR EACH ROW EXECUTE FUNCTION kacho_iam.limits_stamp_revision();


--
-- Name: memberships membership_carrying_rights_is_kept; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE CONSTRAINT TRIGGER membership_carrying_rights_is_kept AFTER DELETE ON kacho_iam.memberships DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION kacho_iam.membership_carrying_rights_is_kept();


--
-- Name: users membership_mirrors_user_row; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER membership_mirrors_user_row AFTER INSERT OR UPDATE OF account_id, invite_status, invited_by ON kacho_iam.users FOR EACH ROW EXECUTE FUNCTION kacho_iam.membership_mirror_from_user();


--
-- Name: projects projects_withdraw_limits_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER projects_withdraw_limits_trg BEFORE DELETE ON kacho_iam.projects FOR EACH ROW EXECUTE FUNCTION kacho_iam.limits_withdraw_for_scope_object('PROJECT');


--
-- Name: provider_compensation_outbox provider_compensation_outbox_notify_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER provider_compensation_outbox_notify_trg AFTER INSERT ON kacho_iam.provider_compensation_outbox FOR EACH ROW EXECUTE FUNCTION kacho_iam.provider_compensation_outbox_notify();


--
-- Name: fga_outbox relation_fact_follows_journal; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER relation_fact_follows_journal AFTER INSERT ON kacho_iam.fga_outbox FOR EACH ROW EXECUTE FUNCTION kacho_iam.relation_fact_from_journal();


--
-- Name: resource_reconcile_outbox resource_reconcile_outbox_notify_trigger; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER resource_reconcile_outbox_notify_trigger AFTER INSERT ON kacho_iam.resource_reconcile_outbox FOR EACH ROW EXECUTE FUNCTION kacho_iam.resource_reconcile_outbox_notify();


--
-- Name: role_rule_selectors role_rule_selectors_types_live; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER role_rule_selectors_types_live BEFORE INSERT OR UPDATE ON kacho_iam.role_rule_selectors FOR EACH ROW EXECUTE FUNCTION kacho_iam.role_rule_selector_types_live();


--
-- Name: service_account_oauth_clients sa_oauth_client_removal_cuts_minted_tokens; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER sa_oauth_client_removal_cuts_minted_tokens AFTER DELETE ON kacho_iam.service_account_oauth_clients FOR EACH ROW WHEN (((old.expires_at IS NULL) OR (old.expires_at > now()))) EXECUTE FUNCTION kacho_iam.minted_cutoff_on_client_removal();


--
-- Name: TRIGGER sa_oauth_client_removal_cuts_minted_tokens ON service_account_oauth_clients; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TRIGGER sa_oauth_client_removal_cuts_minted_tokens ON kacho_iam.service_account_oauth_clients IS 'mirror of the user-side trigger: only a credential that was LIVE at removal leaves a cut-off row';


--
-- Name: service_account_oauth_clients sa_oauth_clients_quota_count; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER sa_oauth_clients_quota_count AFTER INSERT OR DELETE ON kacho_iam.service_account_oauth_clients FOR EACH ROW EXECUTE FUNCTION kacho_iam.kacho_quota_count('iam.serviceAccount.credential', 'sva_id');


--
-- Name: service_accounts service_account_deactivation_cuts_minted_tokens; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER service_account_deactivation_cuts_minted_tokens AFTER UPDATE OF enabled ON kacho_iam.service_accounts FOR EACH ROW WHEN ((old.enabled AND (NOT new.enabled))) EXECUTE FUNCTION kacho_iam.minted_cutoff_on_owner_deactivation();


--
-- Name: service_accounts service_accounts_quota_carrier_credential; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER service_accounts_quota_carrier_credential AFTER INSERT OR DELETE ON kacho_iam.service_accounts FOR EACH ROW EXECUTE FUNCTION kacho_iam.kacho_quota_carrier_lifecycle('iam.serviceAccount.credential');


--
-- Name: service_accounts service_accounts_subject_ref_before_delete_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER service_accounts_subject_ref_before_delete_trg BEFORE DELETE ON kacho_iam.service_accounts FOR EACH ROW EXECUTE FUNCTION kacho_iam.principal_not_referenced_as_subject('service_account');


--
-- Name: users user_deactivation_cuts_minted_tokens; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER user_deactivation_cuts_minted_tokens AFTER UPDATE OF invite_status ON kacho_iam.users FOR EACH ROW WHEN (((old.invite_status = 'ACTIVE'::text) AND (new.invite_status <> 'ACTIVE'::text))) EXECUTE FUNCTION kacho_iam.minted_cutoff_on_owner_deactivation();


--
-- Name: user_oauth_clients user_oauth_client_removal_cuts_minted_tokens; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER user_oauth_client_removal_cuts_minted_tokens AFTER DELETE ON kacho_iam.user_oauth_clients FOR EACH ROW WHEN (((old.expires_at IS NULL) OR (old.expires_at > now()))) EXECUTE FUNCTION kacho_iam.minted_cutoff_on_client_removal();


--
-- Name: TRIGGER user_oauth_client_removal_cuts_minted_tokens ON user_oauth_clients; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON TRIGGER user_oauth_client_removal_cuts_minted_tokens ON kacho_iam.user_oauth_clients IS 'cuts tokens minted by a credential row that was still LIVE when removed. An already-expired row cannot have minted anything after it expired, and what it minted before is dead by then — the token TTL is trimmed to the remainder of the client lifetime. A cut-off row for it would be a permanent row about a transient nothing, and this table has no sweeper of its own';


--
-- Name: user_oauth_clients user_oauth_clients_quota_count; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER user_oauth_clients_quota_count AFTER INSERT OR DELETE ON kacho_iam.user_oauth_clients FOR EACH ROW EXECUTE FUNCTION kacho_iam.kacho_quota_count('iam.user.credential', 'user_id');


--
-- Name: users users_identity_journal_activate; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER users_identity_journal_activate AFTER UPDATE OF external_id ON kacho_iam.users FOR EACH ROW WHEN (((old.external_id = ''::text) AND (new.external_id <> ''::text))) EXECUTE FUNCTION kacho_iam.identity_journal_note();


--
-- Name: users users_identity_journal_insert; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER users_identity_journal_insert AFTER INSERT ON kacho_iam.users FOR EACH ROW WHEN ((new.external_id <> ''::text)) EXECUTE FUNCTION kacho_iam.identity_journal_note();


--
-- Name: users users_quota_carrier_credential; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER users_quota_carrier_credential AFTER INSERT OR DELETE ON kacho_iam.users FOR EACH ROW EXECUTE FUNCTION kacho_iam.kacho_quota_carrier_lifecycle('iam.user.credential');


--
-- Name: users users_subject_ref_before_delete_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER users_subject_ref_before_delete_trg BEFORE DELETE ON kacho_iam.users FOR EACH ROW EXECUTE FUNCTION kacho_iam.principal_not_referenced_as_subject('user');


--
-- Name: access_binding_emitted_tuples access_binding_emitted_tuples_binding_id_fkey; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_binding_emitted_tuples
    ADD CONSTRAINT access_binding_emitted_tuples_binding_id_fkey FOREIGN KEY (binding_id) REFERENCES kacho_iam.access_bindings(id) ON DELETE CASCADE;


--
-- Name: access_binding_subjects access_binding_subjects_scope_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_binding_subjects
    ADD CONSTRAINT access_binding_subjects_scope_fk FOREIGN KEY (binding_id, resource_type, resource_id) REFERENCES kacho_iam.access_bindings(id, resource_type, resource_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: access_binding_target_members access_binding_target_members_binding_id_fkey; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_binding_target_members
    ADD CONSTRAINT access_binding_target_members_binding_id_fkey FOREIGN KEY (binding_id) REFERENCES kacho_iam.access_bindings(id) ON DELETE CASCADE;


--
-- Name: access_binding_target_members access_binding_target_members_role_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_binding_target_members
    ADD CONSTRAINT access_binding_target_members_role_fk FOREIGN KEY (role_id) REFERENCES kacho_iam.roles(id) ON DELETE CASCADE;


--
-- Name: access_binding_target_members access_binding_target_members_role_live_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_binding_target_members
    ADD CONSTRAINT access_binding_target_members_role_live_fk FOREIGN KEY (role_id, live) REFERENCES kacho_iam.roles(id, live) ON DELETE CASCADE;


--
-- Name: access_bindings access_bindings_role_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_bindings
    ADD CONSTRAINT access_bindings_role_fk FOREIGN KEY (role_id) REFERENCES kacho_iam.roles(id) ON DELETE RESTRICT;


--
-- Name: accounts accounts_owner_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.accounts
    ADD CONSTRAINT accounts_owner_fk FOREIGN KEY (owner_user_id) REFERENCES kacho_iam.users(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;


--
-- Name: catalog_resource catalog_resource_module_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.catalog_resource
    ADD CONSTRAINT catalog_resource_module_fk FOREIGN KEY (module) REFERENCES kacho_iam.catalog_module(module);


--
-- Name: catalog_resource catalog_resource_module_live_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.catalog_resource
    ADD CONSTRAINT catalog_resource_module_live_fk FOREIGN KEY (module, module_live) REFERENCES kacho_iam.catalog_module(module, live);


--
-- Name: catalog_verb catalog_verb_resource_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.catalog_verb
    ADD CONSTRAINT catalog_verb_resource_fk FOREIGN KEY (module, resource) REFERENCES kacho_iam.catalog_resource(module, resource);


--
-- Name: catalog_verb catalog_verb_resource_live_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.catalog_verb
    ADD CONSTRAINT catalog_verb_resource_live_fk FOREIGN KEY (module, resource, resource_live) REFERENCES kacho_iam.catalog_resource(module, resource, live);


--
-- Name: cluster_admin_grants cluster_admin_grants_cluster_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.cluster_admin_grants
    ADD CONSTRAINT cluster_admin_grants_cluster_fk FOREIGN KEY (cluster_id) REFERENCES kacho_iam.clusters(id) ON DELETE RESTRICT;


--
-- Name: federated_trusted_issuers federated_trusted_issuers_client_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.federated_trusted_issuers
    ADD CONSTRAINT federated_trusted_issuers_client_fk FOREIGN KEY (sa_oauth_client_id) REFERENCES kacho_iam.service_account_oauth_clients(id) ON DELETE CASCADE;


--
-- Name: group_members group_members_group_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.group_members
    ADD CONSTRAINT group_members_group_fk FOREIGN KEY (group_id) REFERENCES kacho_iam.groups(id) ON DELETE CASCADE;


--
-- Name: groups groups_account_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.groups
    ADD CONSTRAINT groups_account_fk FOREIGN KEY (account_id) REFERENCES kacho_iam.accounts(id) ON DELETE RESTRICT;


--
-- Name: memberships memberships_account_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.memberships
    ADD CONSTRAINT memberships_account_fk FOREIGN KEY (account_id) REFERENCES kacho_iam.accounts(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: memberships memberships_user_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.memberships
    ADD CONSTRAINT memberships_user_fk FOREIGN KEY (user_id) REFERENCES kacho_iam.users(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: projects projects_account_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.projects
    ADD CONSTRAINT projects_account_fk FOREIGN KEY (account_id) REFERENCES kacho_iam.accounts(id) ON DELETE RESTRICT;


--
-- Name: role_grant_orphan role_grant_orphan_role_id_fkey; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_grant_orphan
    ADD CONSTRAINT role_grant_orphan_role_id_fkey FOREIGN KEY (role_id) REFERENCES kacho_iam.roles(id) ON DELETE CASCADE;


--
-- Name: role_rule_ref role_rule_ref_res_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_rule_ref
    ADD CONSTRAINT role_rule_ref_res_fk FOREIGN KEY (module, resource, live) REFERENCES kacho_iam.catalog_resource(module, resource, live) DEFERRABLE;


--
-- Name: role_rule_ref role_rule_ref_role_id_fkey; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_rule_ref
    ADD CONSTRAINT role_rule_ref_role_id_fkey FOREIGN KEY (role_id) REFERENCES kacho_iam.roles(id) ON DELETE CASCADE;


--
-- Name: role_rule_ref role_rule_ref_role_live_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_rule_ref
    ADD CONSTRAINT role_rule_ref_role_live_fk FOREIGN KEY (role_id, live) REFERENCES kacho_iam.roles(id, live) ON DELETE CASCADE;


--
-- Name: role_rule_ref role_rule_ref_verb_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_rule_ref
    ADD CONSTRAINT role_rule_ref_verb_fk FOREIGN KEY (module, resource, verb, live) REFERENCES kacho_iam.catalog_verb(module, resource, verb, live) DEFERRABLE;


--
-- Name: role_rule_selectors role_rule_selectors_role_id_fkey; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_rule_selectors
    ADD CONSTRAINT role_rule_selectors_role_id_fkey FOREIGN KEY (role_id) REFERENCES kacho_iam.roles(id) ON DELETE CASCADE;


--
-- Name: role_rule_selectors role_rule_selectors_role_live_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_rule_selectors
    ADD CONSTRAINT role_rule_selectors_role_live_fk FOREIGN KEY (role_id, live) REFERENCES kacho_iam.roles(id, live) ON DELETE CASCADE;


--
-- Name: role_selector_prune role_selector_prune_role_id_fkey; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_selector_prune
    ADD CONSTRAINT role_selector_prune_role_id_fkey FOREIGN KEY (role_id) REFERENCES kacho_iam.roles(id) ON DELETE CASCADE;


--
-- Name: role_verb role_verb_role_id_fkey; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_verb
    ADD CONSTRAINT role_verb_role_id_fkey FOREIGN KEY (role_id) REFERENCES kacho_iam.roles(id) ON DELETE CASCADE;


--
-- Name: role_verb role_verb_role_live_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_verb
    ADD CONSTRAINT role_verb_role_live_fk FOREIGN KEY (role_id, live) REFERENCES kacho_iam.roles(id, live) ON DELETE CASCADE;


--
-- Name: role_verb role_verb_type_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.role_verb
    ADD CONSTRAINT role_verb_type_fk FOREIGN KEY (object_type, live) REFERENCES kacho_iam.catalog_resource(dotted, live) DEFERRABLE;


--
-- Name: roles roles_account_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.roles
    ADD CONSTRAINT roles_account_fk FOREIGN KEY (account_id) REFERENCES kacho_iam.accounts(id) ON DELETE RESTRICT;


--
-- Name: roles roles_cluster_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.roles
    ADD CONSTRAINT roles_cluster_fk FOREIGN KEY (cluster_id) REFERENCES kacho_iam.clusters(id) ON DELETE RESTRICT;


--
-- Name: roles roles_owner_module_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.roles
    ADD CONSTRAINT roles_owner_module_fk FOREIGN KEY (owner_module) REFERENCES kacho_iam.catalog_module(module);


--
-- Name: roles roles_project_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.roles
    ADD CONSTRAINT roles_project_fk FOREIGN KEY (project_id) REFERENCES kacho_iam.projects(id) ON DELETE RESTRICT;


--
-- Name: service_account_oauth_clients service_account_oauth_clients_created_by_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.service_account_oauth_clients
    ADD CONSTRAINT service_account_oauth_clients_created_by_fk FOREIGN KEY (created_by_user_id) REFERENCES kacho_iam.users(id) ON DELETE RESTRICT;


--
-- Name: service_account_oauth_clients service_account_oauth_clients_sva_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.service_account_oauth_clients
    ADD CONSTRAINT service_account_oauth_clients_sva_fk FOREIGN KEY (sva_id) REFERENCES kacho_iam.service_accounts(id) ON DELETE RESTRICT;


--
-- Name: service_accounts service_accounts_account_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.service_accounts
    ADD CONSTRAINT service_accounts_account_fk FOREIGN KEY (account_id) REFERENCES kacho_iam.accounts(id) ON DELETE RESTRICT;


--
-- Name: session_revocations session_revocations_user_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.session_revocations
    ADD CONSTRAINT session_revocations_user_fk FOREIGN KEY (user_id) REFERENCES kacho_iam.users(id) ON DELETE RESTRICT;


--
-- ПОРЯДОК ЭТИХ ДВУХ КЛЮЧЕЙ — ПОВЕДЕНИЕ, А НЕ ОФОРМЛЕНИЕ.
--
-- Оба смотрят на `users(id)`, но по-разному: `user_fk` снимает строку каскадом,
-- `created_by_fk` запрещает снятие. Проверки ссылочной целостности исполняются
-- в порядке СОЗДАНИЯ ограничений, и запрет, созданный первым, срабатывает до
-- каскада — то есть видит строку, которую каскад к тому моменту уже снял бы.
-- Удаление человека, создавшего СВОЁ удостоверение, отвергалось бы `23503`.
--
-- `pg_dump` печатает ключи по алфавиту, и `created_by_fk` встал бы перед
-- `user_fk`. В снятой цепочке порядок обратный, поэтому здесь он восстановлен
-- РУКАМИ: свод обязан воспроизводить не только определения, но и поведение.
--
-- Слепок схемы этого класса не ловит by construction: он сверяет определения
-- ограничений, а не порядок их создания. Ловят две интеграционные пробы —
-- TestUserOAuthClient_09c_UserDelete_CascadesTokens и
-- TestBAT1_47_EveryCascadeCauseTakesTheCredentialDown.
--
-- Name: user_oauth_clients user_oauth_clients_user_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_user_fk FOREIGN KEY (user_id) REFERENCES kacho_iam.users(id) ON DELETE CASCADE;


--
-- Name: user_oauth_clients user_oauth_clients_created_by_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_created_by_fk FOREIGN KEY (created_by_user_id) REFERENCES kacho_iam.users(id) ON DELETE RESTRICT;


--
-- Name: user_token_revocations user_token_revocations_user_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.user_token_revocations
    ADD CONSTRAINT user_token_revocations_user_fk FOREIGN KEY (user_id) REFERENCES kacho_iam.users(id) ON DELETE CASCADE;


--
-- Name: users users_account_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.users
    ADD CONSTRAINT users_account_fk FOREIGN KEY (account_id) REFERENCES kacho_iam.accounts(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;


--
-- Name: users users_invited_by_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.users
    ADD CONSTRAINT users_invited_by_fk FOREIGN KEY (invited_by) REFERENCES kacho_iam.users(id) ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED;


--
-- PostgreSQL database dump complete
--

-- +goose StatementEnd

-- +goose Down

-- Свод откатывается только целиком: пошагово воспроизвести 171 миграцию из
-- одного файла нельзя, и притворяться, что можно, хуже, чем сказать прямо.
--
-- НО «целиком» не значит «молча». Страж ниже пережил сведение НАМЕРЕННО: он
-- стоял в откатной половине одной из снятых миграций, и вместе с ней исчез бы
-- бесшумно — а обратный ход свода разрушительнее того, что он стерёг.
--
-- Он стоит ПЕРВЫМ, до единого разрушающего оператора: отказ после первого
-- DROP оставил бы схему разобранной, и оператор чинил бы две беды вместо одной.
--
-- Почему отказ, а не удаление. Секрет вида SECRET предъявляется арендатору
-- ОДИН раз; в хранилище лежит только его свёртка. Удалённая строка не
-- восстанавливается НИЧЕМ: резервной копии секрета не существует by
-- construction, а повторная выдача даёт другое удостоверение с другим
-- идентификатором — то есть работу по перенастройке каждого предъявителя.
-- Обычная потеря данных обратима восстановлением; эта — нет.
--
-- Почему не комментарий. Обратный ход описан штатной процедурой на странице
-- развёртывания, то есть набирается не задумываясь. Комментарий в этот момент
-- не читают, и он ничего не останавливает: останавливает только отказ.

-- +goose StatementBegin
DO $$
DECLARE
    sa_secrets   bigint;
    user_secrets bigint;
BEGIN
    IF to_regclass('kacho_iam.service_account_oauth_clients') IS NULL THEN
        RETURN;  -- схемы нет: сносить нечего, и считать не в чем
    END IF;

    SELECT count(*) INTO sa_secrets
      FROM kacho_iam.service_account_oauth_clients WHERE credential_kind = 'SECRET';
    SELECT count(*) INTO user_secrets
      FROM kacho_iam.user_oauth_clients WHERE credential_kind = 'SECRET';

    -- Перепись печатается ВСЕГДА, включая ноль: иначе «удостоверений вида
    -- SECRET нет» неотличимо от «их не считали».
    RAISE NOTICE 'обратный ход свода: удостоверений вида SECRET — service_account_oauth_clients %, user_oauth_clients %',
        sa_secrets, user_secrets;

    IF sa_secrets > 0 OR user_secrets > 0 THEN
        -- ВСЁ СУЩЕСТВЕННОЕ — В ОСНОВНОМ СООБЩЕНИИ: goose доносит до оператора
        -- только его, DETAIL и HINT в его вывод не попадают.
        RAISE EXCEPTION
            'REFUSING to roll back the iam baseline: it would IRREVERSIBLY destroy % live SECRET credential(s) '
            '(service_account_oauth_clients %, user_oauth_clients %). Such a credential is shown to the tenant '
            'ONCE and only its digest is stored, so a deleted row cannot be restored from any backup, and '
            're-issuing yields a DIFFERENT credential every holder must be reconfigured for. WAY OUT: revoke '
            'these credentials deliberately through the product verb first (so their holders learn about it), '
            'then roll back — with zero SECRET rows the baseline rolls back cleanly. The rollback is safe '
            'exactly when both counts above are 0.',
            sa_secrets + user_secrets, sa_secrets, user_secrets
        USING
            DETAIL =
                'A SECRET credential is shown to the tenant exactly once and only its digest is stored. '
                'This is not ordinary data loss — it is irreversible.',
            HINT =
                'Revoke the credentials through the product verb, then roll back. Safe when both counts are 0.';
    END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DROP SCHEMA IF EXISTS kacho_iam CASCADE;

-- +goose StatementEnd
