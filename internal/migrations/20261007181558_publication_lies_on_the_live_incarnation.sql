-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- publication_lies_on_the_live_incarnation — голова объекта хранит границу
-- ВОПЛОЩЕНИЯ, а публикация для анонимного чтения — поколение воплощения, на
-- которое она легла (задача PRO-Robotech/kaname#484, полоса K2; сценарии
-- NTF3-186 (в), (д), NTF3-189).
--
-- Санкция: приёмка `docs/specs/sub-phase-NTF-3-kacho-modules-notifications-acceptance.md`
-- репозитория PRO-Robotech/kacho-workspace, Р30 «Публикация для анонимного
-- чтения» и «Производитель поколения — счётчик объекта модуля» (редакции 40–42),
-- отпечаток `1d7d2ad0a39805c3345efb48aee562d76a812e6a19087be427982f7d0d8373ba`.
-- Доводы там; здесь — то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ЧТО МЕНЯЕТСЯ
-- =============================================================================
--   * `object_head.incarnation` — поколение регистрации, начавшей текущее
--     воплощение объекта: регистрация, применённая при отсутствии головы либо
--     поверх надгробия, ставит его своим поколением; регистрация поверх живой
--     головы и снятие его не трогают. У живой головы граница есть всегда
--     (проверка `object_head_live_has_incarnation`); у надгробия, не знавшего
--     живого воплощения, её нет. Пишет её тот же производитель, что голову, —
--     триггер `resource_event` (функция переопределена ниже).
--   * `public_read_publication.object_generation` — поколение объекта по
--     счётчику владельца в транзакции намерения публикации: признак
--     воплощения, а не порядок публикации. Порядок — по-прежнему версия
--     владельца `source_version` (kaname#107). Применение судит воплощение по
--     голове: при надгробии — `object_generation` строго новее надгробия, при
--     живой голове — не старше границы воплощения, головы нет — применяется.
--
-- =============================================================================
-- ПОЧЕМУ БЕЗ ЗАПОЛНЕНИЯ
-- =============================================================================
-- Обе колонки появляются на таблицах, строк в которых к этой миграции нет ни на
-- одной посадке: голова заведена предыдущей миграцией той же полосы, а стенды
-- пересоздаются (решение Д12, прода нет). Заполнить их было бы нечем честно —
-- граница воплощения и поколение воплощения публикации не выводятся из того,
-- что хранится, — поэтому проверки ставятся строгими: база, где строки есть,
-- миграцию не примет и скажет это отказом проверки, а не впишет догадку.

-- +goose Up

ALTER TABLE kaname.object_head ADD COLUMN incarnation bigint;
ALTER TABLE kaname.object_head
  ADD CONSTRAINT object_head_live_has_incarnation CHECK (withdrawn OR incarnation IS NOT NULL);
ALTER TABLE kaname.object_head
  ADD CONSTRAINT object_head_incarnation_within_generation
  CHECK (incarnation IS NULL OR (incarnation > 0 AND incarnation <= generation));
COMMENT ON COLUMN kaname.object_head.incarnation IS 'Граница воплощения (Р30 «Публикация для анонимного чтения»): поколение регистрации, начавшей текущее воплощение объекта, — применённой при отсутствии головы либо поверх надгробия. Публикация живого объекта ложится, только если её object_generation не старше границы. Пишет только триггер resource_event.';

ALTER TABLE kaname.public_read_publication ADD COLUMN object_generation bigint NOT NULL;
ALTER TABLE kaname.public_read_publication
  ADD CONSTRAINT public_read_publication_object_generation_positive CHECK (object_generation > 0);
COMMENT ON COLUMN kaname.public_read_publication.object_generation IS 'Поколение объекта по счётчику владельца в транзакции намерения публикации — признак воплощения, на которое легла публикация (Р30). Снятие объекта уносит строку; регистрация, начавшая воплощение, снимает строку с поколением воплощения меньше своего.';
COMMENT ON COLUMN kaname.public_read_publication.source_version IS 'Версия владельца последнего применённого намерения публикации (publication_version метода SetPublicReadPublication); намерения без версии служба не принимает.';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_event_apply() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_model     text;
  v_live      boolean;
  v_types     text[] := '{}';
  v_ids       text[] := '{}';
  v_ref       text;
  v_colon     integer;
  v_ptype     text;
  v_pmodel    text;
  v_project   text := NEW.parent_project_id;
  v_account   text := NEW.parent_account_id;
  v_applied   boolean;
  v_prev      kaname.resource_mirror%ROWTYPE;
  v_had_prev  boolean;
BEGIN
  -- Имя типа в словаре модели и ливность — у одной строки каталога.
  SELECT cr.object_type, cr.live INTO v_model, v_live
    FROM kaname.catalog_resource cr
   WHERE cr.dotted = NEW.object_type;

  IF NEW.change = 'register' THEN
    -- Условие приёма связывает ВХОД: регистрировать типом, снятым с платформы
    -- или неизвестным, нельзя.
    IF v_model IS NULL OR NOT v_live THEN
      NEW.outcome := 'UNKNOWN_TYPE';
      NEW.refused := NEW.object_type;
      RETURN NEW;
    END IF;
    -- Цепь предков разбирается ДО сравнения с головой: отказ входу не вправе
    -- оставить ни одной записи.
    FOR i IN 1 .. coalesce(array_length(NEW.parent_chain, 1), 0) LOOP
      v_ref := NEW.parent_chain[i];
      v_colon := strpos(v_ref, ':');
      IF v_colon <= 1 OR v_colon = length(v_ref) THEN
        NEW.outcome := 'MALFORMED_PARENT';
        NEW.refused := v_ref;
        RETURN NEW;
      END IF;
      v_ptype := left(v_ref, v_colon - 1);
      IF strpos(v_ptype, '.') > 0 THEN
        SELECT cr.object_type INTO v_pmodel
          FROM kaname.catalog_resource cr
         WHERE cr.dotted = v_ptype;
        IF v_pmodel IS NULL THEN
          NEW.outcome := 'UNKNOWN_TYPE';
          NEW.refused := v_ptype;
          RETURN NEW;
        END IF;
        v_ptype := v_pmodel;
      END IF;
      v_types := v_types || v_ptype;
      v_ids := v_ids || substr(v_ref, v_colon + 1);
      IF v_ptype = 'project' AND NEW.parent_project_id = '' AND NEW.parent_account_id = ''
         AND v_project = '' THEN
        v_project := v_ids[i];
      ELSIF v_ptype = 'account' AND NEW.parent_project_id = '' AND NEW.parent_account_id = ''
         AND v_account = '' THEN
        v_account := v_ids[i];
      END IF;
    END LOOP;
  ELSIF v_model IS NULL THEN
    -- Снятие каталог-условия не спрашивает: снятие типа мягкое, а объект,
    -- зарегистрированный до снятия типа, обязан оставаться удаляемым. Имя без
    -- точки — уже словарь модели; имя с точкой без строки каталога перевести
    -- нечем.
    IF strpos(NEW.object_type, '.') > 0 THEN
      NEW.outcome := 'UNKNOWN_TYPE';
      NEW.refused := NEW.object_type;
      RETURN NEW;
    END IF;
    v_model := NEW.object_type;
  END IF;

  -- Сравнение с головой — одной операцией. Регистрация, применённая при
  -- отсутствии головы либо поверх надгробия, начинает воплощение: её поколение
  -- ложится границей воплощения. Регистрация поверх живой головы и снятие
  -- границу не трогают.
  INSERT INTO kaname.object_head AS h
    (object_type, object_id, generation, withdrawn, incarnation, updated_at)
  VALUES (NEW.object_type, NEW.object_id, NEW.generation, NEW.change = 'unregister',
          CASE WHEN NEW.change = 'register' THEN NEW.generation END, now())
  ON CONFLICT (object_type, object_id) DO UPDATE
     SET generation  = EXCLUDED.generation,
         withdrawn   = EXCLUDED.withdrawn,
         incarnation = CASE WHEN NOT EXCLUDED.withdrawn AND h.withdrawn
                            THEN EXCLUDED.generation
                            ELSE h.incarnation END,
         updated_at  = now()
   WHERE h.generation < EXCLUDED.generation
  RETURNING true INTO v_applied;

  IF v_applied IS NULL THEN
    NEW.outcome := 'REJECTED_STALE';
    RETURN NEW;
  END IF;

  IF NEW.change = 'unregister' THEN
    DELETE FROM kaname.resource_mirror
     WHERE object_type = NEW.object_type AND object_id = NEW.object_id;
    DELETE FROM kaname.resource_parent_edge
     WHERE object_type = v_model AND object_id = NEW.object_id;
    NEW.outcome := 'APPLIED';
    NEW.projection_unchanged := false;
    RETURN NEW;
  END IF;

  SELECT * INTO v_prev FROM kaname.resource_mirror
   WHERE object_type = NEW.object_type AND object_id = NEW.object_id;
  v_had_prev := FOUND;

  INSERT INTO kaname.resource_mirror AS m
    (object_type, object_id, parent_project_id, parent_account_id, labels, source_version, updated_at)
  VALUES (NEW.object_type, NEW.object_id, v_project, v_account, NEW.labels, NEW.generation, now())
  ON CONFLICT (object_type, object_id) DO UPDATE
     SET parent_project_id = EXCLUDED.parent_project_id,
         parent_account_id = EXCLUDED.parent_account_id,
         labels            = EXCLUDED.labels,
         source_version    = EXCLUDED.source_version,
         updated_at        = now();

  -- Цепь — состояние, а не приращение: полная замена.
  DELETE FROM kaname.resource_parent_edge
   WHERE object_type = v_model AND object_id = NEW.object_id;
  FOR i IN 1 .. coalesce(array_length(v_types, 1), 0) LOOP
    INSERT INTO kaname.resource_parent_edge
      (object_type, object_id, parent_type, parent_id, depth, source_version, updated_at)
    VALUES (v_model, NEW.object_id, v_types[i], v_ids[i], i, NEW.generation, now());
  END LOOP;

  NEW.outcome := 'APPLIED';
  NEW.projection_unchanged := v_had_prev
    AND v_prev.parent_project_id = v_project
    AND v_prev.parent_account_id = v_account
    AND v_prev.labels = NEW.labels;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose Down

ALTER TABLE kaname.public_read_publication DROP CONSTRAINT public_read_publication_object_generation_positive;
ALTER TABLE kaname.public_read_publication DROP COLUMN object_generation;
COMMENT ON COLUMN kaname.public_read_publication.source_version IS 'Версия владельца последнего применённого намерения. ''-infinity'' — намерения без версии, порядка не доказывающие.';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_event_apply() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_model     text;
  v_live      boolean;
  v_types     text[] := '{}';
  v_ids       text[] := '{}';
  v_ref       text;
  v_colon     integer;
  v_ptype     text;
  v_pmodel    text;
  v_project   text := NEW.parent_project_id;
  v_account   text := NEW.parent_account_id;
  v_applied   boolean;
  v_prev      kaname.resource_mirror%ROWTYPE;
  v_had_prev  boolean;
BEGIN
  -- Имя типа в словаре модели и ливность — у одной строки каталога.
  SELECT cr.object_type, cr.live INTO v_model, v_live
    FROM kaname.catalog_resource cr
   WHERE cr.dotted = NEW.object_type;

  IF NEW.change = 'register' THEN
    -- Условие приёма связывает ВХОД: регистрировать типом, снятым с платформы
    -- или неизвестным, нельзя.
    IF v_model IS NULL OR NOT v_live THEN
      NEW.outcome := 'UNKNOWN_TYPE';
      NEW.refused := NEW.object_type;
      RETURN NEW;
    END IF;
    -- Цепь предков разбирается ДО сравнения с головой: отказ входу не вправе
    -- оставить ни одной записи.
    FOR i IN 1 .. coalesce(array_length(NEW.parent_chain, 1), 0) LOOP
      v_ref := NEW.parent_chain[i];
      v_colon := strpos(v_ref, ':');
      IF v_colon <= 1 OR v_colon = length(v_ref) THEN
        NEW.outcome := 'MALFORMED_PARENT';
        NEW.refused := v_ref;
        RETURN NEW;
      END IF;
      v_ptype := left(v_ref, v_colon - 1);
      IF strpos(v_ptype, '.') > 0 THEN
        SELECT cr.object_type INTO v_pmodel
          FROM kaname.catalog_resource cr
         WHERE cr.dotted = v_ptype;
        IF v_pmodel IS NULL THEN
          NEW.outcome := 'UNKNOWN_TYPE';
          NEW.refused := v_ptype;
          RETURN NEW;
        END IF;
        v_ptype := v_pmodel;
      END IF;
      v_types := v_types || v_ptype;
      v_ids := v_ids || substr(v_ref, v_colon + 1);
      IF v_ptype = 'project' AND NEW.parent_project_id = '' AND NEW.parent_account_id = ''
         AND v_project = '' THEN
        v_project := v_ids[i];
      ELSIF v_ptype = 'account' AND NEW.parent_project_id = '' AND NEW.parent_account_id = ''
         AND v_account = '' THEN
        v_account := v_ids[i];
      END IF;
    END LOOP;
  ELSIF v_model IS NULL THEN
    -- Снятие каталог-условия не спрашивает: снятие типа мягкое, а объект,
    -- зарегистрированный до снятия типа, обязан оставаться удаляемым. Имя без
    -- точки — уже словарь модели; имя с точкой без строки каталога перевести
    -- нечем.
    IF strpos(NEW.object_type, '.') > 0 THEN
      NEW.outcome := 'UNKNOWN_TYPE';
      NEW.refused := NEW.object_type;
      RETURN NEW;
    END IF;
    v_model := NEW.object_type;
  END IF;

  -- Сравнение с головой — одной операцией.
  INSERT INTO kaname.object_head AS h (object_type, object_id, generation, withdrawn, updated_at)
  VALUES (NEW.object_type, NEW.object_id, NEW.generation, NEW.change = 'unregister', now())
  ON CONFLICT (object_type, object_id) DO UPDATE
     SET generation = EXCLUDED.generation,
         withdrawn  = EXCLUDED.withdrawn,
         updated_at = now()
   WHERE h.generation < EXCLUDED.generation
  RETURNING true INTO v_applied;

  IF v_applied IS NULL THEN
    NEW.outcome := 'REJECTED_STALE';
    RETURN NEW;
  END IF;

  IF NEW.change = 'unregister' THEN
    DELETE FROM kaname.resource_mirror
     WHERE object_type = NEW.object_type AND object_id = NEW.object_id;
    DELETE FROM kaname.resource_parent_edge
     WHERE object_type = v_model AND object_id = NEW.object_id;
    NEW.outcome := 'APPLIED';
    NEW.projection_unchanged := false;
    RETURN NEW;
  END IF;

  SELECT * INTO v_prev FROM kaname.resource_mirror
   WHERE object_type = NEW.object_type AND object_id = NEW.object_id;
  v_had_prev := FOUND;

  INSERT INTO kaname.resource_mirror AS m
    (object_type, object_id, parent_project_id, parent_account_id, labels, source_version, updated_at)
  VALUES (NEW.object_type, NEW.object_id, v_project, v_account, NEW.labels, NEW.generation, now())
  ON CONFLICT (object_type, object_id) DO UPDATE
     SET parent_project_id = EXCLUDED.parent_project_id,
         parent_account_id = EXCLUDED.parent_account_id,
         labels            = EXCLUDED.labels,
         source_version    = EXCLUDED.source_version,
         updated_at        = now();

  -- Цепь — состояние, а не приращение: полная замена.
  DELETE FROM kaname.resource_parent_edge
   WHERE object_type = v_model AND object_id = NEW.object_id;
  FOR i IN 1 .. coalesce(array_length(v_types, 1), 0) LOOP
    INSERT INTO kaname.resource_parent_edge
      (object_type, object_id, parent_type, parent_id, depth, source_version, updated_at)
    VALUES (v_model, NEW.object_id, v_types[i], v_ids[i], i, NEW.generation, now());
  END LOOP;

  NEW.outcome := 'APPLIED';
  NEW.projection_unchanged := v_had_prev
    AND v_prev.parent_project_id = v_project
    AND v_prev.parent_account_id = v_account
    AND v_prev.labels = NEW.labels;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

ALTER TABLE kaname.object_head DROP CONSTRAINT object_head_incarnation_within_generation;
ALTER TABLE kaname.object_head DROP CONSTRAINT object_head_live_has_incarnation;
ALTER TABLE kaname.object_head DROP COLUMN incarnation;
