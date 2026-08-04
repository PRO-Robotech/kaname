-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- provider_compensation_outbox — очередь компенсаций частично исполненной саги
-- «зарегистрировать OAuth-клиента у провайдера → закоммитить свою строку».
--
-- ЗАЧЕМ ОТДЕЛЬНАЯ ТАБЛИЦА, А НЕ ВЕТКА В fga_outbox. Существующие очереди iam
-- несут намерения про НАШЕ состояние (tuple'ы, зеркала, аудит) и эмитятся В ТОЙ
-- ЖЕ транзакции, что и ресурс. Здесь предмет другой: объект живёт у ЧУЖОГО
-- владельца (провайдер идентичности), а компенсируемая транзакция — та самая,
-- которая ОТКАТИЛАСЬ, поэтому намерение физически не может ехать в ней. Оно
-- коммитится своей транзакцией до того, как Operation помечается ошибкой.
--
-- ПОЧЕМУ ЭТО НУЖНО. Клиента у провайдера приходится создавать ДО коммита своей
-- строки: строка обязана нести client_id, который назначает провайдер. Прямой
-- вызов снятия на неудаче — не гарантия: он сам может отказать (провайдер и есть
-- то, что лежит), а процесс может умереть между провалом коммита и уборкой. В
-- обоих случаях у провайдера остаётся объект, о котором в нашей БД нет ни одной
-- записи: назвать его нечем и убрать некому.
--
-- ПОЧЕМУ БЕЗ PartitionColumn (осознанно, не по забывчивости). Порядок между
-- строками одного ключа нужен там, где события НЕ коммутируют — типично пара
-- «создать ↔ снять» одного объекта. Здесь событие ровно одного вида: снять
-- клиента. Два снятия одного client_id коммутируют и идемпотентны (провайдер
-- отвечает 404 на повторное, клиент трактует 404 как исполнено), поэтому
-- финальное состояние сходится при любом порядке — условие (а) из
-- drainer.Config.PartitionColumn выполнено. Следовательно обязательная пара
-- partial-индексов под partition-head-claim здесь не нужна, и лишний индекс не
-- заводится: каждый лишний порядок над pending-строками — это план, который
-- планировщик выберет именно тогда, когда очередь глубокая.
--
-- Строка НИКОГДА не пишется на успешном пути: успешная сага компенсации не
-- порождает, иначе дренаж снял бы живого клиента.

CREATE SEQUENCE kacho_iam.provider_compensation_outbox_id_seq
    AS bigint START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;

CREATE TABLE kacho_iam.provider_compensation_outbox (
    id            bigint      NOT NULL DEFAULT nextval('kacho_iam.provider_compensation_outbox_id_seq'::regclass) PRIMARY KEY,
    -- event_type — единственный вид компенсации на сегодня. CHECK держит
    -- словарь закрытым: опечатка в вызывающем даёт 23514 на записи, а не
    -- строку, которую дренаж не умеет применить и вечно ретраит.
    event_type    text        NOT NULL,
    -- payload — {"client_id": ..., "origin": ..., "reason": ...}. Дренаж читает
    -- ТОЛЬКО payload (Decoder[T] получает его одного), поэтому client_id обязан
    -- лежать здесь, а не только в денормализованной колонке.
    payload       jsonb       NOT NULL,
    -- resource_kind / resource_id — денормализация для наблюдаемости и для
    -- утверждений в пробах; дренаж их не читает.
    resource_kind text        NOT NULL DEFAULT '',
    resource_id   text        NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    -- sent_at IS NULL → компенсация ещё не исполнена; NOT NULL → исполнена.
    sent_at       timestamptz,
    last_error    text,
    -- attempt_count — попытки дренажа; ≥ MaxAttempts → poisoned-skip.
    attempt_count integer     NOT NULL DEFAULT 0,

    CONSTRAINT provider_compensation_outbox_event_type_check
        CHECK (event_type = ANY (ARRAY['provider.oauth_client.delete'::text])),
    CONSTRAINT provider_compensation_outbox_payload_object_ck
        CHECK (jsonb_typeof(payload) = 'object'::text),
    -- client_id обязан быть непустой строкой: пустое значение уехало бы в
    -- дренаж и превратилось бы в вызов снятия «ничего» — форма компенсации без
    -- предмета.
    CONSTRAINT provider_compensation_outbox_client_id_ck
        CHECK (jsonb_typeof(payload -> 'client_id') = 'string'
               AND length(payload ->> 'client_id') > 0)
);

ALTER SEQUENCE kacho_iam.provider_compensation_outbox_id_seq
    OWNED BY kacho_iam.provider_compensation_outbox.id;

-- Единственный обязательный partial-индекс: внешний упорядоченный скан claim'а
-- `ORDER BY (attempt_count, id) WHERE sent_at IS NULL`. Размер тянется за
-- pending-хвостом, а не за append-mostly таблицей.
CREATE INDEX provider_compensation_outbox_pending_idx
    ON kacho_iam.provider_compensation_outbox (attempt_count, id)
    WHERE sent_at IS NULL;

-- +goose StatementBegin
-- pg_notify на каждый INSERT — дренаж просыпается без poll-задержки.
CREATE OR REPLACE FUNCTION kacho_iam.provider_compensation_outbox_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('kacho_iam_provider_compensation_outbox', NEW.id::text);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER provider_compensation_outbox_notify_trg
    AFTER INSERT ON kacho_iam.provider_compensation_outbox
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.provider_compensation_outbox_notify();
-- +goose StatementEnd

-- +goose Down

DROP TRIGGER IF EXISTS provider_compensation_outbox_notify_trg ON kacho_iam.provider_compensation_outbox;
DROP FUNCTION IF EXISTS kacho_iam.provider_compensation_outbox_notify();
DROP TABLE IF EXISTS kacho_iam.provider_compensation_outbox;
DROP SEQUENCE IF EXISTS kacho_iam.provider_compensation_outbox_id_seq;
