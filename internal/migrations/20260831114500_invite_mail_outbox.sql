-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- invite_mail_outbox — очередь писем ПРИГЛАШЕНИЯ.
--
-- Основание: приёмка sub-phase-ID-MAIL-1-mail-delivery-acceptance.md, решения
-- Р23 (у письма приглашения производитель — НАШ код) и Р25 (отправка идёт через
-- очередь в нашей базе, и она же — писатель счётчика исходов). Объём §10 пп. 20
-- и 21, порядок §11 шаг 8а.
--
-- ЗАЧЕМ ОЧЕРЕДЬ, А НЕ ВЫЗОВ ИЗ ОБРАБОТЧИКА. Строка приглашения и намерение
-- отправить письмо обязаны появиться ОДНОЙ транзакцией: при откате приглашения
-- письма нет ВОВСЕ, а при состоявшемся приглашении намерение переживает смерть
-- процесса. Прямой вызов ретранслятора из обработчика не даёт ни того, ни
-- другого: он теряет письмо на любой недоступности узла и отправляет письмо о
-- приглашении, которого не случилось, если транзакция откатится после вызова.
--
-- ЗАЧЕМ ОТДЕЛЬНАЯ ТАБЛИЦА, А НЕ ВЕТКА В СУЩЕСТВУЮЩЕЙ. Пять очередей iam несут
-- намерения про НАШЕ состояние (кортежи, зеркала, аудит, компенсации). Здесь
-- предмет иной: внешний эффект, ВИДИМЫЙ АДРЕСАТУ. У него другой применитель,
-- другой режим отказа и другая цена повтора — повторно доставленное письмо
-- человек видит, тогда как повторно записанный кортеж не замечает никто.
--
-- ПОЧЕМУ КЛЮЧ ПАРТИЦИИ ЕСТЬ (`resource_id` — строка приглашённого), хотя поток
-- и коммутативен по виду события. Ключ здесь покупает три вещи, и каждая —
-- свойство, а не удобство:
--   1. ПОРЯДОК ПИСЕМ ОДНОМУ ЧЕЛОВЕКУ. Повторная отправка приглашения видна
--      адресату; порядок писем в его ящике — часть того, что он видит. Клейм по
--      голове партиции держит его cross-batch и cross-replica.
--   2. РАДИУС ЗАСТРЯВШЕЙ СТРОКИ — ОДИН ПОЛУЧАТЕЛЬ. Без ключа отравленная строка
--      не блокирует никого, но и застрявшая доставка одному человеку ничем не
--      отделена от остальных: клейм берёт строки вперемешку.
--   3. УБОРКА ДОСТАВЛЕННЫХ ВЫРАЗИМА. Общий уборщик платформы
--      (`outbox.NewQueueSweeper`) ОТКАЗЫВАЕТ НА СБОРКЕ без ключа партиции —
--      без него нельзя пощадить доставленную строку, защищающую отравленного
--      предшественника от оживления. Очередь без ключа растёт вечно и уходит в
--      реестр роста долгом; с ключом её рост ограничен.
-- Цена названа честно: постоянно-временный отказ по ОДНОМУ получателю
-- задерживает его же последующие письма (голова партиции), пока не будет
-- отравлен по числу попыток. Радиус — один адресат, остальные дренятся.

CREATE SEQUENCE kacho_iam.invite_mail_outbox_id_seq
    AS bigint START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;

CREATE TABLE kacho_iam.invite_mail_outbox (
    id            bigint      NOT NULL DEFAULT nextval('kacho_iam.invite_mail_outbox_id_seq'::regclass) PRIMARY KEY,
    -- event_type — единственный вид события на сегодня. CHECK держит словарь
    -- ЗАКРЫТЫМ: опечатка в вызывающем даёт 23514 на записи, а не строку, которую
    -- дренаж не умеет применить и вечно ретраит.
    event_type    text        NOT NULL,
    -- payload — {"to": ..., "account_id": ..., "user_id": ..., "login_url": ...}.
    -- Дренаж читает ТОЛЬКО payload (Decoder[T] получает его одного), поэтому
    -- адресат обязан лежать здесь, а не только в денормализованной колонке.
    --
    -- ПРЕДЪЯВИТЕЛЯ ЗДЕСЬ НЕТ И БЫТЬ НЕ ДОЛЖНО (Р24): письмо приглашения несёт
    -- призыв и адрес страницы входа, а доступ даёт владение почтовым ящиком,
    -- доказанное подтверждением адреса у поставщика. Ссылка-предъявитель в
    -- очереди была бы предъявителем, лежащим в базе дольше своего письма.
    payload       jsonb       NOT NULL,
    -- resource_kind / resource_id — денормализация для наблюдаемости и для
    -- утверждений в пробах. resource_id ДОПОЛНИТЕЛЬНО служит КЛЮЧОМ ПАРТИЦИИ
    -- порядка (см. шапку), поэтому пустым он быть не вправе: пустое значение
    -- слило бы все письма в одну партицию и сделало бы порядок общим для всех
    -- адресатов сразу.
    resource_kind text        NOT NULL DEFAULT '',
    resource_id   text        NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    -- sent_at IS NULL → письмо ещё не сдано ретранслятору; NOT NULL → сдано.
    --
    -- ИМЕННО СДАНО, А НЕ ПОЛУЧЕНО АДРЕСАТОМ. Дальше ретранслятора наш вердикт не
    -- идёт, и продукт нигде не утверждает доставку (Р15). Колонка называется по
    -- общей форме очередей платформы; читать её как «доставлено» — ошибка,
    -- которую этот комментарий и закрывает.
    sent_at       timestamptz,
    last_error    text,
    -- attempt_count — попытки дренажа; ≥ MaxAttempts → отравлена и пропускается.
    -- ЧИСЛО ПОВТОРОВ — величина проводки (drainer.Config.MaxAttempts), и она
    -- ОТДЕЛЬНАЯ от предела времени на одну попытку, который живёт у отправителя.
    attempt_count integer     NOT NULL DEFAULT 0,

    CONSTRAINT invite_mail_outbox_event_type_check
        CHECK (event_type = ANY (ARRAY['mail.invite.send'::text])),
    CONSTRAINT invite_mail_outbox_payload_object_ck
        CHECK (jsonb_typeof(payload) = 'object'::text),
    -- Адресат обязан быть непустой строкой: строка без адресата уехала бы в
    -- дренаж и превратилась бы в отправку «никому» — форма отправки без
    -- предмета. Декодер отвергает такую строку постоянным отказом, но записать
    -- её нельзя вовсе, и это первый рубеж, а не единственный.
    --
    -- COALESCE ЗДЕСЬ НЕСУЩИЙ, А НЕ УКРАШЕНИЕ. Ограничение CHECK пропускает
    -- строку, на которой предикат дал NULL, а не false, — это трёхзначная
    -- логика SQL, а не особенность этой таблицы. У ОТСУТСТВУЮЩЕГО ключа
    -- `payload -> 'to'` есть значение NULL, `jsonb_typeof(NULL)` тоже NULL, и
    -- всё сравнение вырождается в NULL: ограничение, написанное без COALESCE,
    -- отвергает ПУСТОГО адресата и пропускает ОТСУТСТВУЮЩЕГО — то есть ровно
    -- тот вход, ради которого писалось. Поймано пробой
    -- Test_InviteMailQueue_RefusesARowWithoutASubject, а не чтением: обе формы
    -- выглядят одинаково строгими.
    CONSTRAINT invite_mail_outbox_recipient_ck
        CHECK (coalesce(jsonb_typeof(payload -> 'to') = 'string'
                        AND length(payload ->> 'to') > 0, false)),
    -- Ключ партиции обязан быть назван: см. комментарий у resource_id.
    CONSTRAINT invite_mail_outbox_partition_key_ck
        CHECK (length(resource_id) > 0)
);

ALTER SEQUENCE kacho_iam.invite_mail_outbox_id_seq
    OWNED BY kacho_iam.invite_mail_outbox.id;

-- Частичных индексов РОВНО ДВА, и это набор, а не перечисление удобных:
--
--   * (resource_id, id) — коррелированный анти-джойн клейма по ГОЛОВЕ ПАРТИЦИИ
--     («не бери строку, пока в её партиции есть доставляемый предшественник») и
--     тот же предикат у уборки доставленных;
--   * (attempt_count, id) — внешний упорядоченный скан самого клейма
--     (`ORDER BY (attempt_count, id) WHERE sent_at IS NULL`).
--
-- Размер обоих тянется за НЕДОСТАВЛЕННЫМ хвостом, а не за append-mostly
-- таблицей. Третий частичный индекс здесь был бы планом, который планировщик
-- выберет именно тогда, когда очередь глубокая.
CREATE INDEX invite_mail_outbox_partition_head_idx
    ON kacho_iam.invite_mail_outbox (resource_id, id)
    WHERE sent_at IS NULL;

CREATE INDEX invite_mail_outbox_pending_idx
    ON kacho_iam.invite_mail_outbox (attempt_count, id)
    WHERE sent_at IS NULL;

-- +goose StatementBegin
-- pg_notify на каждый INSERT — дренаж просыпается без poll-задержки.
CREATE OR REPLACE FUNCTION kacho_iam.invite_mail_outbox_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('kacho_iam_invite_mail_outbox', NEW.id::text);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER invite_mail_outbox_notify_trg
    AFTER INSERT ON kacho_iam.invite_mail_outbox
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.invite_mail_outbox_notify();
-- +goose StatementEnd

-- +goose Down

DROP TRIGGER IF EXISTS invite_mail_outbox_notify_trg ON kacho_iam.invite_mail_outbox;
DROP FUNCTION IF EXISTS kacho_iam.invite_mail_outbox_notify();
DROP TABLE IF EXISTS kacho_iam.invite_mail_outbox;
DROP SEQUENCE IF EXISTS kacho_iam.invite_mail_outbox_id_seq;
