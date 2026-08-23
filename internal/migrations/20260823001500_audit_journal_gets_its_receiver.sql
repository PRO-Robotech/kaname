-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- =============================================================================
-- У журнала аудита появился приёмник: учётные колонки приводятся к доставке.
-- =============================================================================
-- Задача `PRO-Robotech/kacho#812`.
--
-- ЧТО ИЗМЕНИЛОСЬ. Журнал аудита control-plane перестал быть очередью без
-- адресата: строки вывозятся в поток структурных записей службы и помечаются
-- доставленными. Прежде из четырёх объявленных состояний достижимо было ровно
-- одно, и строка оставалась в нём навсегда.
--
-- ПОЧЕМУ БАЗУ НАДО ТРОГАТЬ. Доставка обязана быть ВИДНА в самой строке, иначе
-- «доставлено» и «поле забыли заполнить» выглядят одинаково: у таблицы не было
-- ни отметки времени доставки, ни места для причины отказа приёмника. Обе
-- колонки заводятся здесь, а отметка связывается с состоянием ограничением —
-- как у журнала службы вычислений, чтобы одна и та же форма читалась одинаково
-- в обеих службах.
--
-- ПОЧЕМУ СЛОВАРЬ СОСТОЯНИЙ СУЖАЕТСЯ ДО ДВУХ. Он становится ровно таким, каким
-- его производит код: `'pending'` и `'sent'`. Двух других не пишет никто и
-- никогда не писал — «полёта» не существует, потому что строка держится
-- блокировкой своей транзакции от клейма до пометки (срыв процесса откатывает
-- клейм целиком), а терминального отказа не существует, потому что у приёмника
-- нет класса «не приму никогда»: единственная непринимаемая запись — та, у
-- которой нет идентификатора или глагола, а такой строки не бывает, обе колонки
-- закрыты формой. Держать состояние, которого продукт произвести не умеет,
-- значит обещать подсистему, которой нет.
--
-- ЧТО ДЕЛАЕТСЯ СО СТАРЫМИ СТРОКАМИ. Ничего, кроме приведения состояния: строки,
-- накопленные до появления приёмника, остаются недоставленными и вывозятся
-- обычным порядком. Оператор приведения к `'pending'` рассчитан на НОЛЬ строк
-- (производителя у снимаемых состояний не было ни одного) и стоит здесь затем,
-- чтобы сужение ограничения не отказало на строке, о которой мы не знаем.
--
-- ИНДЕКС. Прежний частичный индекс был построен под выборку по состоянию;
-- вывоз обходит очередь В ПОРЯДКЕ СОЗДАНИЯ, поэтому индекс перестраивается так,
-- чтобы порядок брался из него, а не из сортировки всей накопленной головы.
-- Время следующей попытки в ключ не входит намеренно: отложенных строк мало
-- (их создаёт только отказ приёмника), и отсеивать их дешевле фильтром, чем
-- платить за ведущий столбец, который порядка не даёт.

-- +goose Up

UPDATE kacho_iam.audit_outbox
   SET status = 'pending'
 WHERE status NOT IN ('pending', 'sent');

ALTER TABLE kacho_iam.audit_outbox
    DROP CONSTRAINT IF EXISTS audit_outbox_status_check;

ALTER TABLE kacho_iam.audit_outbox
    ADD CONSTRAINT audit_outbox_status_check
        CHECK (status = ANY (ARRAY['pending'::text, 'sent'::text]));

ALTER TABLE kacho_iam.audit_outbox
    ADD COLUMN IF NOT EXISTS sent_at timestamptz;

ALTER TABLE kacho_iam.audit_outbox
    ADD COLUMN IF NOT EXISTS last_error text;

-- Отправленная запись обязана нести время отправки, неотправленная — не нести:
-- иначе «доставлено» и «поле забыли заполнить» выглядят одинаково.
ALTER TABLE kacho_iam.audit_outbox
    ADD CONSTRAINT audit_outbox_sent_at_check
        CHECK ((status = 'sent') = (sent_at IS NOT NULL));

DROP INDEX IF EXISTS kacho_iam.audit_outbox_status_next_attempt_idx;

CREATE INDEX IF NOT EXISTS audit_outbox_pending_idx
    ON kacho_iam.audit_outbox (created_at, id)
    WHERE status <> 'sent';

-- +goose Down

DROP INDEX IF EXISTS kacho_iam.audit_outbox_pending_idx;

CREATE INDEX audit_outbox_status_next_attempt_idx
    ON kacho_iam.audit_outbox USING btree (status, next_attempt_at)
    WHERE (status = ANY (ARRAY['pending'::text, 'in_flight'::text]));

ALTER TABLE kacho_iam.audit_outbox
    DROP CONSTRAINT IF EXISTS audit_outbox_sent_at_check;

ALTER TABLE kacho_iam.audit_outbox
    DROP COLUMN IF EXISTS last_error;

ALTER TABLE kacho_iam.audit_outbox
    DROP COLUMN IF EXISTS sent_at;

ALTER TABLE kacho_iam.audit_outbox
    DROP CONSTRAINT IF EXISTS audit_outbox_status_check;

ALTER TABLE kacho_iam.audit_outbox
    ADD CONSTRAINT audit_outbox_status_check
        CHECK ((status = ANY (ARRAY['pending'::text, 'in_flight'::text, 'sent'::text, 'failed'::text])));
