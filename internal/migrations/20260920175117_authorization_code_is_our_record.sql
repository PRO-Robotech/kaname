-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- authorization_code_is_our_record — КОД АВТОРИЗАЦИИ и СЕМЕЙСТВО выданного по
-- нему становятся записями службы (задача PRO-Robotech/kaname#313).
--
-- До этой миграции собственной церемонии OAuth в схеме не было НИ ОДНОЙ строки:
-- `grep -ic 'authorization_code\|code_challenge\|pkce' internal/migrations/*.sql`
-- давал 0, выдача шла через внешнего поставщика (`internal/clients/hydra_*.go`).
--
-- =============================================================================
-- ПОЧЕМУ ФОРМА ИМЕННО ТАКАЯ: ГАШЕНИЕ ОДНОЙ ИНСТРУКЦИЕЙ
-- =============================================================================
-- Движок внешнего поставщика читает код ВНЕ транзакции и гасит ВНУТРИ, значит
-- атомарности обмена он не даёт: две одновременные копии запроса обе читают код
-- живым, обе доходят до безусловного `UPDATE`, и по одному коду уходит ДВОЙНАЯ
-- выдача. Положительный путь при этом зелёный — последовательная проба такую
-- реализацию не отличает от верной.
--
-- Поэтому форма строки подчинена ОДНОМУ требованию: обмен обязан выражаться
-- ОДНИМ оператором с условием на ПРЕЖНЕЕ состояние и возвратом затронутой
-- строки —
--
--   UPDATE kaname.authorization_codes
--      SET active = false, deactivated_at = now(), deactivated_reason = 'redeemed'
--    WHERE code_digest = $1 AND active AND expires_at > now() AND <семейство живо>
--   RETURNING …;
--
-- Ноль затронутых строк — отказ, и он ОДИН на всех проигравших. Пары «прочитать,
-- затем записать» здесь нет и быть не может: условие и запись исполняет сам
-- движок под строчным замком (ban #10).
--
-- =============================================================================
-- СНЯТИЕ — ОТМЕТКА, А НЕ УДАЛЕНИЕ
-- =============================================================================
-- Использованный код ПОМЕЧАЕТСЯ неактивным и ЖИВЁТ до истечения. Обнаружение
-- повторного использования строится на различении «неактивен» и «не найден»:
-- первое — повтор, и по нему отзывается ВСЁ семейство; второе — неизвестный
-- код. Удалённая строка неотличима от никогда не существовавшей, и удаление
-- стоило бы ровно этого различения. Строки после истечения убирает уборка.
--
-- =============================================================================
-- СЕМЕЙСТВО — ДОМ КОНТЕКСТА ЦЕРЕМОНИИ, И СОГЛАСИЕ ДЕРЖИТ КЛЮЧ
-- =============================================================================
-- Клиент, человек, сессия и область живут на строке семейства И на строке кода
-- (так их читает обмен одним запросом, без соединения). Два написания молча
-- разойтись НЕ МОГУТ: код и обновляющий токен ссылаются на семейство СОСТАВНЫМ
-- внешним ключом по всем четырём столбцам сразу — расхождение отвергает база,
-- а не проверка писателя.
--
-- Сессия обязательна и уходит вместе с собой каскадом: код, выданный в сессии,
-- которой больше нет, обменять всё равно нельзя, а строка без сессии читалась бы
-- как «выдан вне входа».

-- +goose Up

-- +goose StatementBegin
CREATE TABLE kaname.token_families (
    id             text NOT NULL,
    client_id      text NOT NULL,
    user_id        text NOT NULL,
    session_id     text NOT NULL,
    scope          text[] NOT NULL,
    created_at     timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at     timestamp with time zone,
    revoked_reason text,
    CONSTRAINT token_families_pkey PRIMARY KEY (id),
    -- Составной ключ, на который ссылаются код и обновляющий токен: он и делает
    -- согласие контекста свойством СХЕМЫ.
    CONSTRAINT token_families_context_uk UNIQUE (id, client_id, user_id, session_id, scope),
    CONSTRAINT token_families_id_form_ck CHECK ((id ~ '^tfm-[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT token_families_client_fk FOREIGN KEY (client_id)
        REFERENCES kaname.interactive_clients(client_id) ON DELETE CASCADE,
    CONSTRAINT token_families_user_fk FOREIGN KEY (user_id)
        REFERENCES kaname.users(id) ON DELETE CASCADE,
    CONSTRAINT token_families_session_fk FOREIGN KEY (session_id)
        REFERENCES kaname.human_sessions(id) ON DELETE CASCADE,
    -- Область непуста, без пустых имён и без NULL: пустая область — не «все
    -- права», а отсутствие решения, и хранить её как область нельзя.
    CONSTRAINT token_families_scope_ck CHECK (
        (cardinality(scope) > 0)
        AND (array_position(scope, NULL::text) IS NULL)
        AND (NOT (scope && ARRAY[''::text]))),
    CONSTRAINT token_families_revoked_pair_ck CHECK (((revoked_at IS NULL) = (revoked_reason IS NULL))),
    -- Словарь причин отзыва ЗАКРЫТ: корзины «прочее» у него нет.
    CONSTRAINT token_families_revoked_reason_ck CHECK (
        ((revoked_reason IS NULL) OR (revoked_reason = ANY (ARRAY[
            'code-replay'::text, 'refresh-replay'::text, 'logout'::text,
            'session-ended'::text, 'consent-withdrawn'::text, 'client-removed'::text]))))
);
-- +goose StatementEnd

COMMENT ON TABLE kaname.token_families IS
  'Семейство выданного по одному коду авторизации (kaname#313). Несёт контекст церемонии — клиента, человека, сессию, область — и отметку отзыва. Отзыв семейства снимает ВСЁ выданное по нему.';

CREATE INDEX token_families_user_id_idx ON kaname.token_families USING btree (user_id);
CREATE INDEX token_families_session_id_idx ON kaname.token_families USING btree (session_id);
CREATE INDEX token_families_client_id_idx ON kaname.token_families USING btree (client_id);

-- +goose StatementBegin
CREATE TABLE kaname.authorization_codes (
    code_digest           text NOT NULL,
    family_id             text NOT NULL,
    client_id             text NOT NULL,
    user_id               text NOT NULL,
    session_id            text NOT NULL,
    scope                 text[] NOT NULL,
    redirect_uri          text NOT NULL,
    code_challenge        text NOT NULL,
    code_challenge_method text NOT NULL,
    issued_at             timestamp with time zone DEFAULT now() NOT NULL,
    expires_at            timestamp with time zone NOT NULL,
    active                boolean DEFAULT true NOT NULL,
    deactivated_at        timestamp with time zone,
    deactivated_reason    text,
    CONSTRAINT authorization_codes_pkey PRIMARY KEY (code_digest),
    -- Сам код НЕ хранится: хранится его свёртка (SHA-256, шестнадцатерично) —
    -- копия таблицы не даёт ни одного годного кода. Та же форма, что у свёртки
    -- носителя сессии (`human_sessions.bearer_digest`).
    CONSTRAINT authorization_codes_digest_form_ck CHECK ((code_digest ~ '^[0-9a-f]{64}$'::text)),
    -- Составной ключ на семейство: контекст кода не может разойтись с семейством.
    CONSTRAINT authorization_codes_family_fk FOREIGN KEY (family_id, client_id, user_id, session_id, scope)
        REFERENCES kaname.token_families(id, client_id, user_id, session_id, scope) ON DELETE CASCADE,
    -- Одно семейство заводится ОДНИМ кодом: второй код того же семейства — это
    -- вторая церемония, и семейство ей полагается своё.
    CONSTRAINT authorization_codes_family_uk UNIQUE (family_id),
    CONSTRAINT authorization_codes_redirect_uri_ck CHECK (
        ((redirect_uri ~ '^https://[^/?#]+'::text) AND (POSITION(('#'::text) IN (redirect_uri)) = 0)
         AND (length(redirect_uri) <= 512))),
    -- PKCE ОБЯЗАТЕЛЕН и метод один — S256 (RFC 7636 §4.2). `plain` не заводится:
    -- значение вне словаря законным стать не может ни одним решением, а колонка,
    -- допускающая его, была бы местом, куда он однажды ляжет.
    CONSTRAINT authorization_codes_challenge_method_ck CHECK ((code_challenge_method = 'S256'::text)),
    -- Испытание — 43 знака base64url без выравнивания: SHA-256 от верификатора.
    CONSTRAINT authorization_codes_challenge_form_ck CHECK ((code_challenge ~ '^[A-Za-z0-9_-]{43}$'::text)),
    CONSTRAINT authorization_codes_expiry_after_issue_ck CHECK ((expires_at > issued_at)),
    -- Признак активности и отметка снятия — ОДНО состояние, записанное дважды;
    -- согласие держит база, а не писатель.
    CONSTRAINT authorization_codes_active_pair_ck CHECK ((active = (deactivated_at IS NULL))),
    CONSTRAINT authorization_codes_deactivated_pair_ck CHECK (((deactivated_at IS NULL) = (deactivated_reason IS NULL))),
    CONSTRAINT authorization_codes_deactivated_reason_ck CHECK (
        ((deactivated_reason IS NULL) OR (deactivated_reason = ANY (ARRAY[
            'redeemed'::text, 'family-revoked'::text]))))
);
-- +goose StatementEnd

COMMENT ON TABLE kaname.authorization_codes IS
  'Код авторизации собственной церемонии (kaname#313). Хранится СВЁРТКОЙ. Обмен — ОДИН оператор с условием на прежнее состояние и возвратом строки; ноль затронутых строк означает отказ и отзыв семейства. Использованный код помечается неактивным и ЖИВЁТ до истечения: «неактивен» и «не найден» обязаны различаться.';

COMMENT ON COLUMN kaname.authorization_codes.active IS
  'Признак активности. Условие одноинструкционного гашения; читателем НЕ вычисляется.';

CREATE INDEX authorization_codes_expires_at_idx ON kaname.authorization_codes USING btree (expires_at);
CREATE INDEX authorization_codes_user_id_idx ON kaname.authorization_codes USING btree (user_id);

-- Свёртка кода не идёт в статистику планировщика: ищут её только равенством по
-- первичному ключу, а выборка значений в `pg_stats` была бы выдачей свёрток
-- всякому, кто читает статистику (гейт `TestSecretMaterialCandidatesAreAllAdjudicated`).
ALTER TABLE kaname.authorization_codes ALTER COLUMN code_digest SET STATISTICS 0;

-- +goose StatementBegin
CREATE TABLE kaname.refresh_tokens (
    token_digest       text NOT NULL,
    family_id          text NOT NULL,
    client_id          text NOT NULL,
    user_id            text NOT NULL,
    session_id         text NOT NULL,
    scope              text[] NOT NULL,
    generation         integer NOT NULL,
    issued_at          timestamp with time zone DEFAULT now() NOT NULL,
    expires_at         timestamp with time zone NOT NULL,
    active             boolean DEFAULT true NOT NULL,
    deactivated_at     timestamp with time zone,
    deactivated_reason text,
    successor_digest   text,
    CONSTRAINT refresh_tokens_pkey PRIMARY KEY (token_digest),
    CONSTRAINT refresh_tokens_digest_form_ck CHECK ((token_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT refresh_tokens_family_fk FOREIGN KEY (family_id, client_id, user_id, session_id, scope)
        REFERENCES kaname.token_families(id, client_id, user_id, session_id, scope) ON DELETE CASCADE,
    -- Поколение в семействе ОДНО на номер: две строки одного номера означали бы
    -- разветвление семейства, то есть ту же двойную выдачу, только на ротации.
    CONSTRAINT refresh_tokens_generation_uk UNIQUE (family_id, generation),
    CONSTRAINT refresh_tokens_generation_ck CHECK ((generation >= 0)),
    CONSTRAINT refresh_tokens_expiry_after_issue_ck CHECK ((expires_at > issued_at)),
    CONSTRAINT refresh_tokens_active_pair_ck CHECK ((active = (deactivated_at IS NULL))),
    CONSTRAINT refresh_tokens_deactivated_pair_ck CHECK (((deactivated_at IS NULL) = (deactivated_reason IS NULL))),
    CONSTRAINT refresh_tokens_deactivated_reason_ck CHECK (
        ((deactivated_reason IS NULL) OR (deactivated_reason = ANY (ARRAY[
            'rotated'::text, 'family-revoked'::text])))),
    -- Преемник есть РОВНО у ротации: снятый отзывом токен преемника не имеет, а
    -- ротация без преемника означала бы потерянное поколение.
    CONSTRAINT refresh_tokens_successor_pair_ck CHECK (
        ((successor_digest IS NULL) = (deactivated_reason IS DISTINCT FROM 'rotated'::text))),
    CONSTRAINT refresh_tokens_successor_form_ck CHECK (
        ((successor_digest IS NULL) OR (successor_digest ~ '^[0-9a-f]{64}$'::text)))
);
-- +goose StatementEnd

COMMENT ON TABLE kaname.refresh_tokens IS
  'Обновляющий токен собственной церемонии (kaname#313). Хранится СВЁРТКОЙ. Ротация — ТОТ ЖЕ механизм, что обмен кода: один оператор с условием на прежнее состояние и возвратом. Отротированный токен помечается неактивным и ЖИВЁТ до истечения — повтор обязан отличаться от неизвестного.';

CREATE INDEX refresh_tokens_family_id_idx ON kaname.refresh_tokens USING btree (family_id);
CREATE INDEX refresh_tokens_expires_at_idx ON kaname.refresh_tokens USING btree (expires_at);

ALTER TABLE kaname.refresh_tokens ALTER COLUMN token_digest SET STATISTICS 0;
ALTER TABLE kaname.refresh_tokens ALTER COLUMN successor_digest SET STATISTICS 0;

-- +goose Down

-- Откат снимает записи, которые восстанавливаются САМОЙ ЦЕРЕМОНИЕЙ: код живёт
-- минуты, обновляющий токен перевыпускается повторным входом. Невосстановимого
-- материала здесь нет — в отличие от способов входа, чей откат уничтожать
-- отказывается.
--
-- Порядок обратен заведению: ссылающиеся уходят раньше семейства.
DROP TABLE kaname.refresh_tokens;
DROP TABLE kaname.authorization_codes;
DROP TABLE kaname.token_families;
