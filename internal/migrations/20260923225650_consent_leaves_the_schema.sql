-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- consent_leaves_the_schema — СОГЛАСИЕ СУБЪЕКТА покидает схему: таблица
-- `kaname.consent_grants` и причина отзыва семейства `consent-withdrawn`
-- (задача PRO-Robotech/kaname#404, остаток #313).
--
-- Санкция: решение К8 волны PRO-Robotech/kaname#358 (комментарий
-- https://github.com/PRO-Robotech/kaname/issues/358#issuecomment-5784900896) на
-- основании одобренной приёмки LINE-A-1, редакция 3 (событие
-- https://github.com/PRO-Robotech/kacho/issues/2721#issuecomment-5751175183),
-- сценарий LINE-A-1-09: первопартийный клиент согласие ПРОПУСКАЕТ. Доводы там;
-- здесь — то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ПОЧЕМУ НОВАЯ МИГРАЦИЯ, А НЕ ПРАВКА ДВУХ ПРИМЕНЁННЫХ
-- =============================================================================
-- Таблицу завела `20260920175119`, значение словаря — `20260920175117`. Правка
-- применённого файла не доезжает до базы, где он уже применён: мигратор сверяет
-- версию, а не содержимое (ban #5).
--
-- =============================================================================
-- ЧТО СНИМАЕТСЯ И ПОЧЕМУ НЕЧЕГО ПЕРЕНОСИТЬ
-- =============================================================================
-- У таблицы согласий нет ни одного писателя и читателя вне проб: слой доступа
-- согласия снят тем же изменением, и вызывающих у него не было ни одного. У
-- значения `consent-withdrawn` писателя не было никогда — ни в продукте, ни в
-- пробе (перепись kaname#339). Словарь домена `FamilyRevocationReasons()`
-- сужен тем же изменением; совпадение двух словарей держит проба
-- `TestIntegration_RevocationVocabularyAgreesWithTheDomain`.
--
-- Строка семейства с этой причиной может появиться только ручным оператором. Её
-- накат НЕ переписывает в другую причину — это подделало бы запись о том, почему
-- выданное отозвано, — а ОТКАЗЫВАЕТ: ограничение ставится с проверкой лежащих
-- строк, и такая строка отвергает его кодом 23514. Откатывается накат целиком:
-- он исполняется одной транзакцией, таблица согласий остаётся на месте.
--
-- Строки согласий, если они есть у установки, до наката считает страж сноса
-- (`dropguard.json`): накатчик отказывает, пока таблица не пуста и оператор не
-- назвал этот снос.
--
-- =============================================================================
-- ЗАХВАТ
-- =============================================================================
-- Снос таблицы с внешними ключами снимает их служебные триггеры с таблиц, на
-- которые она ссылается, и берёт на них ИСКЛЮЧИТЕЛЬНЫЙ захват: на время наката
-- заперты `consent_grants`, `users`, `interactive_clients` и `token_families`
-- (измерено `pg_locks` на Postgres 16 для таблицы с двумя внешними ключами и
-- для смены ограничения). Писатели этих таблиц ждут конца наката;
-- ожидание по кругу с писателем движок разрывает отказом одной из сторон, и
-- отказавший накат повторяем — частичного состояния у него нет.

-- +goose Up

-- Форма сноса — каноническая для дерева: её узнаёт распознаватель стража.
-- Таблица уносит свои индексы, ограничения и ключи.
DROP TABLE IF EXISTS kaname.consent_grants;

-- Ограничение снимается и ставится заново ПОД ТЕМ ЖЕ ИМЕНЕМ: имя — координата,
-- по которой его читают пробы словаря и снимает откат.
ALTER TABLE kaname.token_families
    DROP CONSTRAINT token_families_revoked_reason_ck;
ALTER TABLE kaname.token_families
    ADD CONSTRAINT token_families_revoked_reason_ck CHECK (
        ((revoked_reason IS NULL) OR (revoked_reason = ANY (ARRAY[
            'code-replay'::text, 'refresh-replay'::text, 'logout'::text,
            'session-ended'::text, 'client-removed'::text]))));

-- +goose Down

-- Откат возвращает СТРОЕНИЕ — значение словаря и таблицу с её ограничениями,
-- ключами, индексами и комментарием ровно в том виде, в каком их оставили
-- `20260920175117` и `20260920175119`, — и НЕ возвращает строк согласий: их
-- неоткуда взять. Вызывающих у слоя доступа согласия вне проб не было ни
-- одного (перепись kaname#404), поэтому у установки, не писавшей в таблицу
-- ручным оператором, возвращать нечего. Совпадение строения держит проба
-- `TestIntegration_ConsentLeavingRollsBackToTheSameStructure`.
--
-- Расширение словаря лежащих строк не трогает: каждая из них удовлетворяет и
-- широкому ограничению.
ALTER TABLE kaname.token_families
    DROP CONSTRAINT token_families_revoked_reason_ck;
ALTER TABLE kaname.token_families
    ADD CONSTRAINT token_families_revoked_reason_ck CHECK (
        ((revoked_reason IS NULL) OR (revoked_reason = ANY (ARRAY[
            'code-replay'::text, 'refresh-replay'::text, 'logout'::text,
            'session-ended'::text, 'consent-withdrawn'::text, 'client-removed'::text]))));

-- +goose StatementBegin
CREATE TABLE kaname.consent_grants (
    id         text NOT NULL,
    user_id    text NOT NULL,
    client_id  text NOT NULL,
    scope      text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT consent_grants_pkey PRIMARY KEY (id),
    CONSTRAINT consent_grants_id_form_ck CHECK ((id ~ '^cg-[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT consent_grants_subject_client_scope_uk UNIQUE (user_id, client_id, scope),
    CONSTRAINT consent_grants_user_fk FOREIGN KEY (user_id)
        REFERENCES kaname.users(id) ON DELETE CASCADE,
    CONSTRAINT consent_grants_client_fk FOREIGN KEY (client_id)
        REFERENCES kaname.interactive_clients(client_id) ON DELETE CASCADE,
    CONSTRAINT consent_grants_scope_ck CHECK (((scope <> ''::text) AND (length(scope) <= 128))),
    CONSTRAINT consent_grants_revoked_after_granted_ck CHECK (
        ((revoked_at IS NULL) OR (revoked_at >= granted_at)))
);
-- +goose StatementEnd

COMMENT ON TABLE kaname.consent_grants IS
  'Согласие субъекта на область для интерактивного клиента (kaname#313). Строка на ТРОЙКУ «человек, клиент, область»; уникальность держит ограничение базы. Отзыв — отметка revoked_at на той же строке; повторное согласие снимает отметку, второй строки не заводится. «Согласия не было» и «согласие отозвано» обязаны различаться.';

CREATE INDEX consent_grants_user_client_idx ON kaname.consent_grants USING btree (user_id, client_id);
CREATE INDEX consent_grants_client_id_idx ON kaname.consent_grants USING btree (client_id);
