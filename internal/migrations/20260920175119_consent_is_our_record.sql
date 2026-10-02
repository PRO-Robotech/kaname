-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- consent_is_our_record — СОГЛАСИЕ СУБЪЕКТА становится записью службы (задача
-- PRO-Robotech/kaname#313).
--
-- =============================================================================
-- ЧТО ИЗМЕРЕНО
-- =============================================================================
-- `grep -ic 'consent' internal/migrations/*.sql | awk -F: '{s+=$2} END {print s+0}'`
-- → 0: дома под согласие в схеме не было ВОВСЕ. (Слово «согласие» в комментариях
-- цепочки относится к согласию данных между кодом и схемой — не к согласию
-- субъекта.) Согласие держал внешний поставщик, и своего ответа на вопрос «на
-- что этот человек согласился этому клиенту» у службы не было ни одного.
--
-- =============================================================================
-- СТРОКА — НА ТРОЙКУ, И УНИКАЛЬНОСТЬ ДЕРЖИТ БАЗА
-- =============================================================================
-- Одна строка на тройку «человек, клиент, область». Уникальность выражена
-- ОГРАНИЧЕНИЕМ (`consent_grants_subject_client_scope_uk`), а не проверкой
-- писателя: два одновременных согласия на одну тройку обе прошли бы проверку
-- «нет ли уже» и записали бы две строки, после чего отзыв снимал бы ОДНУ из
-- них, а вторая продолжала бы действовать (ban #10).
--
-- Область — СКАЛЯР, по строке на имя, а не массив: уникальность тройки на
-- массиве выродилась бы в уникальность НАБОРА, и `{openid,profile}` рядом с
-- `{openid}` были бы двумя разными «тройками» при одном и том же openid.
-- Отзыв одной области из набора тогда требовал бы перезаписи чужих строк.
--
-- =============================================================================
-- ОТЗЫВ — ОТМЕТКА НА ТОЙ ЖЕ СТРОКЕ
-- =============================================================================
-- Строка живёт после отзыва и несёт `revoked_at`; повторное согласие на ту же
-- тройку — снятие отметки и новый `granted_at` на ТОЙ ЖЕ строке
-- (`ON CONFLICT … DO UPDATE`), а не вторая строка. Поэтому ограничение
-- уникальности — ПОЛНОЕ, а не частичное: частичное «только среди неотозванных»
-- допускало бы накопление отозванных близнецов, и «когда этот человек это
-- согласие давал» перестало бы иметь единственный ответ.
--
-- Удаления здесь нет: «согласия не было» и «согласие отозвано» — разные ответы,
-- и удалённая строка их не различает. Строку уносит только уход человека или
-- клиента — каскадом.

-- +goose Up

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
    -- ТРОЙКА субъект-клиент-область. Механизм базы, а не проверка писателя.
    CONSTRAINT consent_grants_subject_client_scope_uk UNIQUE (user_id, client_id, scope),
    CONSTRAINT consent_grants_user_fk FOREIGN KEY (user_id)
        REFERENCES kaname.users(id) ON DELETE CASCADE,
    CONSTRAINT consent_grants_client_fk FOREIGN KEY (client_id)
        REFERENCES kaname.interactive_clients(client_id) ON DELETE CASCADE,
    -- Пустая область — не «все права», а отсутствие решения.
    CONSTRAINT consent_grants_scope_ck CHECK (((scope <> ''::text) AND (length(scope) <= 128))),
    CONSTRAINT consent_grants_revoked_after_granted_ck CHECK (
        ((revoked_at IS NULL) OR (revoked_at >= granted_at)))
);
-- +goose StatementEnd

COMMENT ON TABLE kaname.consent_grants IS
  'Согласие субъекта на область для интерактивного клиента (kaname#313). Строка на ТРОЙКУ «человек, клиент, область»; уникальность держит ограничение базы. Отзыв — отметка revoked_at на той же строке; повторное согласие снимает отметку, второй строки не заводится. «Согласия не было» и «согласие отозвано» обязаны различаться.';

CREATE INDEX consent_grants_user_client_idx ON kaname.consent_grants USING btree (user_id, client_id);
-- Отзыв по клиенту (снятие клиента, отзыв всего выданного) идёт по этой оси.
CREATE INDEX consent_grants_client_id_idx ON kaname.consent_grants USING btree (client_id);

-- +goose Down

-- Откат снимает согласия. Материал здесь не секретный и восстановим самой
-- церемонией: у клиента, чьё согласие снято, спросят снова — это нормальный
-- путь полосы, а не потеря невосстановимого.
DROP TABLE kaname.consent_grants;
