-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0080_provider_compensation_trust_grant.sql — второй вид компенсации: снятие
-- доверительного гранта у провайдера.
--
-- ПРЕДМЕТ. Выдача федеративного ключа регистрирует у провайдера доверие к
-- КАЖДОМУ доверенному субъекту отдельным вызовом — это веер из N независимых
-- обращений, и понятия «группа» у провайдера нет. Отказ на k-м оставляет k-1
-- гранта стоять. До этой миграции их не снимал никто и снять было нечем: метода
-- удаления в клиенте провайдера не существовало, а идентификатор, который
-- провайдер присваивает гранту, вызывающий выбрасывал.
--
-- Оставшийся грант — не «висящая строка»: он и есть выданное доверие. Пока он
-- стоит, провайдер продолжает принимать внешнее утверждение этого субъекта, хотя
-- ключа, ради которого доверие выдавалось, в нашей базе нет.
--
-- ЧТО МЕНЯЕТСЯ. Словарь видов компенсации расширяется вторым значением, а
-- проверка непустого идентификатора становится РАЗВИЛКОЙ по виду: у снятия
-- клиента обязателен `client_id`, у снятия гранта — `grant_id`. Прежняя
-- безусловная проверка `client_id` отвергла бы вторую компенсацию целиком, то
-- есть новый вид намерения было бы невозможно записать.
--
-- Развилка выражена ОДНОЙ проверкой, а не двумя независимыми: две проверки об
-- одном предмете допускают строку, удовлетворяющую обеим (оба поля непусты) —
-- намерение, у которого два предмета и ни одного однозначного. Здесь такая
-- строка отвергается на записи.

-- +goose Up

ALTER TABLE kacho_iam.provider_compensation_outbox
    DROP CONSTRAINT provider_compensation_outbox_event_type_check;

ALTER TABLE kacho_iam.provider_compensation_outbox
    ADD CONSTRAINT provider_compensation_outbox_event_type_check
        CHECK (event_type = ANY (ARRAY[
            'provider.oauth_client.delete'::text,
            'provider.trust_grant.delete'::text
        ]));

ALTER TABLE kacho_iam.provider_compensation_outbox
    DROP CONSTRAINT provider_compensation_outbox_client_id_ck;

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

-- +goose Down

ALTER TABLE kacho_iam.provider_compensation_outbox
    DROP CONSTRAINT provider_compensation_outbox_subject_ck;

ALTER TABLE kacho_iam.provider_compensation_outbox
    ADD CONSTRAINT provider_compensation_outbox_client_id_ck
        CHECK (jsonb_typeof(payload -> 'client_id') = 'string'
               AND length(payload ->> 'client_id') > 0);

ALTER TABLE kacho_iam.provider_compensation_outbox
    DROP CONSTRAINT provider_compensation_outbox_event_type_check;

ALTER TABLE kacho_iam.provider_compensation_outbox
    ADD CONSTRAINT provider_compensation_outbox_event_type_check
        CHECK (event_type = ANY (ARRAY['provider.oauth_client.delete'::text]));
