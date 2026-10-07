-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- object_generation_has_one_projection_producer — версия объекта в службе
-- доступа становится целым поколением, у объекта появляется голова (включая
-- надгробие снятия), а проекцию объекта пишет ОДИН производитель — триггер
-- `resource_event` на приёме регистрации либо снятия (задача
-- PRO-Robotech/kaname#484, полоса K2; сценарии NTF3-174 (д), (к), (н),
-- NTF3-180 (г), NTF3-182).
--
-- Санкция: приёмка `docs/specs/sub-phase-NTF-3-kacho-modules-notifications-acceptance.md`
-- репозитория PRO-Robotech/kacho-workspace, Р30 «Приём поколения — CAS» и
-- «Поколение и проекция — один производитель» (редакция 39, решения Д133 и
-- Д134 B2), отпечаток
-- `6e7444a4d53e7a3ebfa423f9da5420344ae6a0ed2f43ce33ff7796f8db189ae6`. Доводы там;
-- здесь — то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ЧТО МЕНЯЕТСЯ
-- =============================================================================
--   * `resource_mirror.source_version` и `resource_parent_edge.source_version` —
--     `bigint`, поколение владельца. Прежние строки получают `0`: «ни одно
--     поколение ещё не применено». Значение это не выдумано: прежняя версия была
--     меткой времени, а не поколением, и с поколением владельца она не
--     сравнима; любое поколение `>= 1` её законно перекрывает. Заполнения здесь
--     нет — это перевод типа столбца, а не запись данных.
--   * `object_head` — голова объекта: последнее ПРИМЕНЁННОЕ поколение и признак
--     надгробия. Регистрация и снятие применяются, только если поколение строго
--     новее головы; надгробие (`withdrawn`) — та же голова, поэтому регистрация
--     поколения не новее снятия зеркала не восстанавливает.
--   * `resource_event_intake` — приём: строка на одно намерение регистрации
--     либо снятия. Триггер `resource_event` (BEFORE INSERT) сравнивает поколение
--     с головой и либо пишет голову, зеркало и рёбра предков одной транзакцией,
--     либо ставит исход `REJECTED_STALE`, не записав НИЧЕГО. Исход приёма
--     возвращается вставке (`RETURNING`), сама строка приёма после этого
--     снимается триггером `resource_event_discard` (AFTER INSERT): журналом она
--     не является, и копиться ей незачем.
--
-- =============================================================================
-- ПОЧЕМУ ПРОИЗВОДИТЕЛЬ — ТРИГГЕР, А НЕ КОД
-- =============================================================================
-- Писателей проекции было несколько: сценарий использования регистрации,
-- проход по сиротам зеркала, дымовая проба посева и посевщик сетки порядков —
-- каждый своим оператором, и сравнение версии жило в каждом своей копией.
-- Один производитель в базе делает сравнение с головой и запись проекции ОДНИМ
-- местом: обойти его, записав проекцию мимо сравнения, нечем. Свойство держит
-- гейт `internal/repohygiene` `TestObjectProjectionHasOneProducer` (NTF3-180
-- (г)) — по коду Go, по миграциям вне функций и по функциям базы.
--
-- =============================================================================
-- КАК СЕРИАЛИЗУЮТСЯ КОНКУРЕНТЫ
-- =============================================================================
-- Сравнение с головой — `INSERT … ON CONFLICT DO UPDATE … WHERE generation <
-- EXCLUDED.generation`: одна операция, а не чтение-и-действие (запрет #10).
-- Конкурент, вставляющий ту же голову, ждёт на уникальном ключе и пересчитывает
-- условие по закоммиченной строке. Применившая транзакция держит замок строки
-- головы до коммита, поэтому все дальнейшие записи проекции этого объекта
-- исполняются строго по одному, в порядке применённых поколений.
--
-- =============================================================================
-- РОДИТЕЛЬ ИЗ ЦЕПИ ВЫВОДИТСЯ ЗДЕСЬ
-- =============================================================================
-- Строка зеркала с пустыми обеими колонками родителя и непустой цепью предков
-- невидима материализации, хотя родителя ей прислал сам владелец (kacho#2051).
-- Прежде её чинил проход по сиротам — вторым писателем. Теперь колонки
-- выводятся из той же цепи при приёме: ближайший предок вида `project` и
-- ближайший вида `account`. Строки, легшие до этой миграции, приводит к факту
-- следующая регистрация владельцем; проход их называет.

-- +goose Up

ALTER TABLE kaname.resource_mirror ALTER COLUMN source_version DROP DEFAULT;
ALTER TABLE kaname.resource_mirror ALTER COLUMN source_version TYPE bigint USING 0;
ALTER TABLE kaname.resource_mirror ALTER COLUMN source_version SET DEFAULT 0;
ALTER TABLE kaname.resource_mirror
  ADD CONSTRAINT resource_mirror_generation_nonnegative CHECK (source_version >= 0);
COMMENT ON COLUMN kaname.resource_mirror.source_version IS 'Поколение объекта у владельца, последнее применённое к этой строке (Р30 «Поколение и проекция»). 0 — строка легла до поколений; любое поколение >= 1 её перекрывает. Пишет только триггер resource_event.';

ALTER TABLE kaname.resource_parent_edge ALTER COLUMN source_version DROP DEFAULT;
ALTER TABLE kaname.resource_parent_edge ALTER COLUMN source_version TYPE bigint USING 0;
ALTER TABLE kaname.resource_parent_edge ALTER COLUMN source_version SET DEFAULT 0;
ALTER TABLE kaname.resource_parent_edge
  ADD CONSTRAINT resource_parent_edge_generation_nonnegative CHECK (source_version >= 0);
COMMENT ON COLUMN kaname.resource_parent_edge.source_version IS 'Поколение объекта, которым легла эта цепь (Р30 «Поколение и проекция»). 0 — ребро легло до поколений. Пишет только триггер resource_event.';

CREATE TABLE kaname.object_head (
    object_type text NOT NULL,
    object_id   text NOT NULL,
    generation  bigint NOT NULL,
    withdrawn   boolean NOT NULL,
    updated_at  timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT object_head_pkey PRIMARY KEY (object_type, object_id),
    CONSTRAINT object_head_type_nonempty CHECK (object_type <> ''),
    CONSTRAINT object_head_id_nonempty CHECK (object_id <> ''),
    CONSTRAINT object_head_generation_positive CHECK (generation > 0)
);
COMMENT ON TABLE kaname.object_head IS 'Голова объекта (Р30 «Приём поколения — CAS»): последнее применённое поколение регистрации либо снятия. Регистрация и снятие применяются, только если их поколение строго новее; иначе исход REJECTED_STALE. Ключ — тот же, что у resource_mirror (тип словарём каталога). Пишет только триггер resource_event.';
COMMENT ON COLUMN kaname.object_head.withdrawn IS 'Надгробие: последнее применённое намерение — снятие. Живой строки зеркала у такого объекта нет, а регистрация поколения не новее этого его не восстанавливает.';

CREATE TABLE kaname.resource_event_intake (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    change               text NOT NULL,
    object_type          text NOT NULL,
    object_id            text NOT NULL,
    generation           bigint NOT NULL,
    parent_project_id    text DEFAULT '' NOT NULL,
    parent_account_id    text DEFAULT '' NOT NULL,
    labels               jsonb DEFAULT '{}'::jsonb NOT NULL,
    parent_chain         text[] DEFAULT '{}'::text[] NOT NULL,
    outcome              text,
    projection_unchanged boolean,
    refused              text,
    CONSTRAINT resource_event_intake_change CHECK (change IN ('register', 'unregister')),
    CONSTRAINT resource_event_intake_type_nonempty CHECK (object_type <> ''),
    CONSTRAINT resource_event_intake_id_nonempty CHECK (object_id <> ''),
    CONSTRAINT resource_event_intake_generation_positive CHECK (generation > 0),
    CONSTRAINT resource_event_intake_labels_object CHECK (jsonb_typeof(labels) = 'object')
);
COMMENT ON TABLE kaname.resource_event_intake IS 'Приём намерения регистрации либо снятия объекта. Строка живёт одну вставку: триггер resource_event применяет её (или отвергает) и ставит исход, вставка читает исход через RETURNING, триггер resource_event_discard снимает строку. Журналом не является.';
COMMENT ON COLUMN kaname.resource_event_intake.outcome IS 'Исход приёма, ставит триггер: APPLIED, REJECTED_STALE (поколение не новее головы — ничего не записано), UNKNOWN_TYPE (типа нет в живом каталоге; refused называет тип), MALFORMED_PARENT (звено цепи не формы <type>:<id>; refused называет звено).';

-- +goose StatementBegin
CREATE FUNCTION kaname.resource_event_apply() RETURNS trigger
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
COMMENT ON FUNCTION kaname.resource_event_apply() IS 'Единственный производитель проекции объекта (Р30, NTF3-180 (г)): сравнение поколения с головой object_head и либо запись головы, зеркала resource_mirror и цепи resource_parent_edge, либо исход REJECTED_STALE без единой записи.';

CREATE TRIGGER resource_event
  BEFORE INSERT ON kaname.resource_event_intake
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_event_apply();

-- +goose StatementBegin
CREATE FUNCTION kaname.resource_event_discard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM kaname.resource_event_intake WHERE id = NEW.id;
  RETURN NULL;
END;
$$;
-- +goose StatementEnd
COMMENT ON FUNCTION kaname.resource_event_discard() IS 'Снимает строку приёма после того, как вставка получила исход через RETURNING: приём не журнал.';

CREATE TRIGGER resource_event_discard
  AFTER INSERT ON kaname.resource_event_intake
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_event_discard();

-- +goose Down

DROP TRIGGER resource_event_discard ON kaname.resource_event_intake;
DROP FUNCTION kaname.resource_event_discard();
DROP TRIGGER resource_event ON kaname.resource_event_intake;
DROP FUNCTION kaname.resource_event_apply();
DROP TABLE kaname.resource_event_intake;
DROP TABLE kaname.object_head;

ALTER TABLE kaname.resource_parent_edge DROP CONSTRAINT resource_parent_edge_generation_nonnegative;
ALTER TABLE kaname.resource_parent_edge ALTER COLUMN source_version DROP DEFAULT;
ALTER TABLE kaname.resource_parent_edge
  ALTER COLUMN source_version TYPE timestamp with time zone USING '-infinity'::timestamp with time zone;
ALTER TABLE kaname.resource_parent_edge
  ALTER COLUMN source_version SET DEFAULT '-infinity'::timestamp with time zone;

ALTER TABLE kaname.resource_mirror DROP CONSTRAINT resource_mirror_generation_nonnegative;
ALTER TABLE kaname.resource_mirror ALTER COLUMN source_version DROP DEFAULT;
ALTER TABLE kaname.resource_mirror
  ALTER COLUMN source_version TYPE timestamp with time zone USING '-infinity'::timestamp with time zone;
ALTER TABLE kaname.resource_mirror
  ALTER COLUMN source_version SET DEFAULT '-infinity'::timestamp with time zone;
