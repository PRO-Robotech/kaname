-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- kacho#455: строку, на которой разбор откажет, записать НЕЛЬЗЯ — у ОБЕИХ
-- коммутативных очередей.
--
-- ПРЕДМЕТ. Очереди subject_change_outbox и provider_compensation_outbox дренятся,
-- травят строки и возврата отравленных не имеют. Возврат им не построить и не
-- осмыслить: он собирается вокруг ключа партиции, которого у коммутативного
-- потока нет, а смысл травления — разблокировать партицию, которой тоже нет.
-- Поэтому обе объявили `PermanentPolicy: drainer.RetryPermanent` и перестали
-- травить постоянный отказ ПРИМЕНЕНИЯ.
--
-- Остался ровно один путь отравления — отказ РАЗБОРА, и он остался намеренно:
-- тело строки не станет разбираемым ни от какого события. Значит утверждение
-- «травиться нечему» держится на одном факте, и факт этот принадлежит СХЕМЕ:
-- неразбираемую строку нельзя записать.
--
-- =============================================================================
-- ПОЧЕМУ ЭТО ЗАТРАГИВАЕТ И ВТОРУЮ ОЧЕРЕДЬ, У КОТОРОЙ ОГРАНИЧЕНИЕ УЖЕ БЫЛО
-- =============================================================================
-- Ограничение «предмет назван ровно один» стоит с миграции 0080 и выглядит
-- исчерпывающим. Оно таковым НЕ является, и найдено это вставкой, а не чтением:
-- строка `{"reason":"r"}` при виде события `provider.oauth_client.delete`
-- принимается.
--
-- Механизм — трёхзначная логика SQL, и он бьёт по КАЖДОМУ предикату над
-- отсутствующим ключом jsonb:
--
--   payload -> 'client_id'                  → SQL NULL   (ключа нет)
--   jsonb_typeof(NULL)                      → NULL
--   NULL = 'string'                         → NULL
--   NULL AND … OR (false AND …)             → NULL
--   CHECK, давший NULL, СЧИТАЕТСЯ ВЫПОЛНЕННЫМ — отвергает только FALSE.
--
-- То есть ограничение отвергало неверный ТИП значения и пропускало его
-- ОТСУТСТВИЕ — ровно ту форму, ради которой писалось. Ошибка не видна ни в
-- обзоре (предикат читается как исчерпывающий), ни в прогоне на пустой базе.
--
-- Отдельно назван и второй сорт той же ошибки, стоивший первой редакции ЭТОЙ
-- миграции: `jsonb_typeof` для строки JSON возвращает `'string'`, а не `'text'`.
-- Предикат со сравнением с `'text'` не выполняется НИКОГДА — то есть отвергает
-- в том числе законное намерение. Поймано положительным контролем пробы; без
-- него ограничение выглядело бы работающим, потому что отрицательные случаи оно
-- проходило.
--
-- Поэтому ниже КАЖДЫЙ предикат над содержимым jsonb сделан NULL-безопасным
-- (`COALESCE(…)`), а не «внимательно написанным».
--
-- ПОРЯДОК. Ограничения ставятся ПОСЛЕ уборки строк, которые им не отвечают:
-- иначе ALTER не пройдёт на живой базе. Недоставленное намерение эта миграция не
-- выбрасывает ни при каких условиях — оно и есть то, что защищается.

-- +goose Up
-- +goose StatementBegin

-- =============================================================================
-- 1. subject_change_outbox
-- =============================================================================

-- Тело негодной формы чинится тем же способом, каким миграция 0023 досыпала его
-- легаси-строкам: из колонок строки, которые NOT NULL и несут ровно то, что
-- декодер и читал бы. Это не «выбросить», а «дать доехать»: строка, которая
-- иначе была бы отравлена разбором, становится доставляемой.
UPDATE kacho_iam.subject_change_outbox
   SET payload = jsonb_build_object(
           'subject_id',  subject_id,
           'event_type',  COALESCE(event_type, op),
           'op',          op)
 WHERE payload IS NULL
    OR jsonb_typeof(payload) <> 'object'
    OR COALESCE(jsonb_typeof(payload -> 'subject_id'), '') <> 'string'
    OR COALESCE(payload ->> 'subject_id', '') = '';

ALTER TABLE kacho_iam.subject_change_outbox
    ALTER COLUMN payload SET NOT NULL;

ALTER TABLE kacho_iam.subject_change_outbox
    ADD CONSTRAINT subject_change_payload_is_object
        CHECK (jsonb_typeof(payload) = 'object');

-- Условие держит ровно то, что читает декодер: непустую строку в поле ТЕЛА.
-- Именно поле тела, а не одноимённый столбец: декодер получает только байты
-- payload и о столбцах не знает, поэтому стеречь столбец значило бы стеречь не
-- ту величину.
ALTER TABLE kacho_iam.subject_change_outbox
    ADD CONSTRAINT subject_change_payload_names_subject
        CHECK (COALESCE(jsonb_typeof(payload -> 'subject_id'), '') = 'string'
               AND COALESCE(payload ->> 'subject_id', '') <> '');

-- =============================================================================
-- 2. provider_compensation_outbox — тот же предикат, сделанный NULL-безопасным
-- =============================================================================

-- Строки, которые прежнее ограничение пропустило по трёхзначной логике. Здесь
-- уборка ЗАКОНЧЕНА удалением, а не починкой, и это единственное место миграции,
-- где строка выбрасывается: у компенсации нет колонок, из которых можно
-- восстановить предмет, — координата снятия живёт ТОЛЬКО в теле. Строка, не
-- называющая ни клиента, ни гранта, не описывает никакого действия: применить её
-- нельзя, и «доставить» её означало бы позвать провайдера без предмета.
DELETE FROM kacho_iam.provider_compensation_outbox
 WHERE NOT COALESCE(
     (event_type = 'provider.oauth_client.delete'
      AND COALESCE(jsonb_typeof(payload -> 'client_id'), '') = 'string'
      AND COALESCE(length(payload ->> 'client_id'), 0) > 0
      AND payload -> 'grant_id' IS NULL)
     OR
     (event_type = 'provider.trust_grant.delete'
      AND COALESCE(jsonb_typeof(payload -> 'grant_id'), '') = 'string'
      AND COALESCE(length(payload ->> 'grant_id'), 0) > 0
      AND payload -> 'client_id' IS NULL)
   , false);

ALTER TABLE kacho_iam.provider_compensation_outbox
    DROP CONSTRAINT IF EXISTS provider_compensation_outbox_subject_ck;

ALTER TABLE kacho_iam.provider_compensation_outbox
    ADD CONSTRAINT provider_compensation_outbox_subject_ck
        CHECK (COALESCE(
            (event_type = 'provider.oauth_client.delete'
             AND COALESCE(jsonb_typeof(payload -> 'client_id'), '') = 'string'
             AND COALESCE(length(payload ->> 'client_id'), 0) > 0
             AND payload -> 'grant_id' IS NULL)
            OR
            (event_type = 'provider.trust_grant.delete'
             AND COALESCE(jsonb_typeof(payload -> 'grant_id'), '') = 'string'
             AND COALESCE(length(payload ->> 'grant_id'), 0) > 0
             AND payload -> 'client_id' IS NULL)
          , false));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Возврат к редакции 0080 — вместе с её дырой: откат обязан восстанавливать
-- состояние, а не улучшать его.
ALTER TABLE kacho_iam.provider_compensation_outbox
    DROP CONSTRAINT IF EXISTS provider_compensation_outbox_subject_ck;

ALTER TABLE kacho_iam.provider_compensation_outbox
    ADD CONSTRAINT provider_compensation_outbox_subject_ck
        CHECK (
            (event_type = 'provider.oauth_client.delete'
             AND jsonb_typeof(payload -> 'client_id') = 'string'
             AND length(payload ->> 'client_id') > 0
             AND payload -> 'grant_id' IS NULL)
            OR
            (event_type = 'provider.trust_grant.delete'
             AND jsonb_typeof(payload -> 'grant_id') = 'string'
             AND length(payload ->> 'grant_id') > 0
             AND payload -> 'client_id' IS NULL)
        );

ALTER TABLE kacho_iam.subject_change_outbox
    DROP CONSTRAINT IF EXISTS subject_change_payload_names_subject;

ALTER TABLE kacho_iam.subject_change_outbox
    DROP CONSTRAINT IF EXISTS subject_change_payload_is_object;

ALTER TABLE kacho_iam.subject_change_outbox
    ALTER COLUMN payload DROP NOT NULL;

-- +goose StatementEnd
