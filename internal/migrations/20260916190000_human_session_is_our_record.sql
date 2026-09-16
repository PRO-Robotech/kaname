-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- human_session_is_our_record — СЕССИЯ ЧЕЛОВЕКА становится записью службы, а
-- вместе с ней память первой аутентификации личности и следы неверных
-- предъявлений (фаза Ф3, задача PRO-Robotech/kacho#1269).
--
-- Санкция: одобренная Ф3
-- (`docs/engineering/acceptance/login-lane-issues-our-session-and-logout-ends-it-server-side.md`,
-- решения Р1, Р5, Р10; §4.1 п.2, п.6, п.10) над одобренной Ф1 и F4d Р5.
-- Доводы там; здесь — только то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- СЕССИЯ — СТРОКА С ЗАКРЫТЫМ СОСТАВОМ (Р1)
-- =============================================================================
-- Носитель НЕ хранится: хранится его свёртка (SHA-256, шестнадцатерично) —
-- копия таблицы не даёт ни одного годного носителя. Свёртка уникальна: два
-- носителя одной записи — это перевыпуск, а не две строки.
--
-- СРОК — ОДИН СТОЛБЕЦ (`expires_at`), и это держит гейт F4d-27
-- (`TestHumanSessionExpiryIsDeclaredOnce`): второе объявление срока — окно
-- бездействия, второй момент истечения — находка. Два столбца-момента рядом
-- сроком НЕ являются: `authenticated_at` (неподвижен, Ф11 Р6) и
-- `last_presented_at` (сдвигается предъявлением способа).
--
-- УРОВЕНЬ — ОБЯЗАТЕЛЕН и из оси Ф11 («сессии без уровня не бывает» — Ф11 Р1).
-- Множество предъявленного НЕПУСТО и из словаря `assurance.Methods()`; словарь
-- в ограничении — второе написание, и его сверяет с производителем проба
-- `TestHumanSessionMethodVocabularyAgreesWithTheRule`.
--
-- СНЯТИЕ — ОТМЕТКА, А НЕ УДАЛЕНИЕ (`ended_at`, `ended_reason`). Резолв по
-- снятой строке обязан отличаться от резолва по неизвестному значению ТОЛЬКО
-- клеткой счётчика (Ф3-27: снята · истекла · заблокирована · неизвестна) —
-- удалённая строка неотличима от никогда не существовавшей. Снятую и истёкшую
-- строку убирает уборка (Ф3-49), а не глагол.
--
-- Человек — `users.id`; строка уходит вместе с ним каскадом. Причина снятия —
-- те же значения, что пишут писатели отсечки (`logout`, `password-change`).
--
-- =============================================================================
-- ПАМЯТЬ ПЕРВОЙ АУТЕНТИФИКАЦИИ — ЗАПИСЬ НА ЛИЧНОСТЬ, ОДИН ПИСАТЕЛЬ (Р5)
-- =============================================================================
-- Заводится первой выдачей сессии нашей посадкой и НЕ ПЕРЕЗАПИСЫВАЕТСЯ: операция
-- берёт МЕНЬШИЙ из двух моментов (`LEAST`), поэтому при стоящей записи ничего не
-- меняет и коммутативна под конкуренцией (ban #10). Переживает срок и снятие
-- всех сессий; уборке не подлежит — рост ограничен числом личностей.
--
-- =============================================================================
-- СЛЕДЫ НЕВЕРНЫХ ПРЕДЪЯВЛЕНИЙ — ПО ДВУМ ОСЯМ (Р10)
-- =============================================================================
-- Одна строка на одно неверное предъявление; ось — адрес (нормализованный ключ
-- почты) либо источник (адрес из заголовка допущенного вызывающего). Счёт — число
-- строк в окне; успешный вход снимает строки оси «адрес». Строки старше самого
-- длинного окна убирает уборка.
--
-- Личных данных здесь нет сверх того, что уже несёт `users.email`: ключ оси
-- «адрес» — тот же адрес; ось «источник» — адрес узла, не человека.

-- +goose Up

CREATE TABLE kaname.human_sessions (
    id                       text NOT NULL,
    user_id                  text NOT NULL,
    bearer_digest            text NOT NULL,
    authenticated_at         timestamp with time zone NOT NULL,
    last_presented_at        timestamp with time zone NOT NULL,
    expires_at               timestamp with time zone NOT NULL,
    assurance_level          text NOT NULL,
    presented_methods        text[] NOT NULL,
    password_change_required boolean DEFAULT false NOT NULL,
    ended_at                 timestamp with time zone,
    ended_reason             text,
    created_at               timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT human_sessions_pkey PRIMARY KEY (id),
    CONSTRAINT human_sessions_user_fk FOREIGN KEY (user_id)
        REFERENCES kaname.users(id) ON DELETE CASCADE,
    CONSTRAINT human_sessions_bearer_digest_uniq UNIQUE (bearer_digest),
    CONSTRAINT human_sessions_bearer_digest_check CHECK ((bearer_digest ~ '^[0-9a-f]{64}$'::text)),
    -- Ось уровня ЗАКРЫТА и совпадает с `internal/assurance` (Ф11 Р1).
    CONSTRAINT human_sessions_assurance_level_check CHECK ((assurance_level = ANY (ARRAY['1'::text, '2'::text, '3'::text]))),
    -- Словарь способов ЗАКРЫТ и совпадает с `assurance.Methods()`.
    CONSTRAINT human_sessions_presented_methods_check CHECK (
        (cardinality(presented_methods) > 0)
        AND (presented_methods <@ ARRAY['password'::text, 'totp'::text, 'lookup_secret'::text, 'webauthn'::text, 'recovery_code'::text])),
    CONSTRAINT human_sessions_expiry_after_auth_check CHECK ((expires_at > authenticated_at)),
    CONSTRAINT human_sessions_presented_not_before_auth_check CHECK ((last_presented_at >= authenticated_at)),
    -- Снятие несёт и момент, и причину — либо ни того, ни другого.
    CONSTRAINT human_sessions_ended_pair_check CHECK (((ended_at IS NULL) = (ended_reason IS NULL))),
    CONSTRAINT human_sessions_ended_reason_check CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text]))))
);

COMMENT ON TABLE kaname.human_sessions IS
  'Наша сессия человека (Ф3, kacho#1269). Носитель хранится СВЁРТКОЙ (bearer_digest); срок один — expires_at; уровень обязателен; снятие — отметка ended_at/ended_reason, строку убирает уборка.';

CREATE INDEX human_sessions_user_id_idx ON kaname.human_sessions USING btree (user_id);
-- Уборка идёт по сроку и по отметке снятия; частичный индекс держит её дешёвой.
CREATE INDEX human_sessions_expires_at_idx ON kaname.human_sessions USING btree (expires_at);

CREATE TABLE kaname.human_first_authentications (
    user_id                text NOT NULL,
    first_authenticated_at timestamp with time zone NOT NULL,
    CONSTRAINT human_first_authentications_pkey PRIMARY KEY (user_id),
    CONSTRAINT human_first_authentications_user_fk FOREIGN KEY (user_id)
        REFERENCES kaname.users(id) ON DELETE CASCADE
);

COMMENT ON TABLE kaname.human_first_authentications IS
  'Момент ПЕРВОЙ аутентификации личности нашей посадкой (Ф3 Р5). Один писатель — выдача сессии, LEAST; никогда не поднимается; уборке не подлежит.';

CREATE TABLE kaname.login_failures (
    scope     text NOT NULL,
    key       text NOT NULL,
    failed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT login_failures_scope_check CHECK ((scope = ANY (ARRAY['address'::text, 'source'::text]))),
    CONSTRAINT login_failures_key_check CHECK ((key <> ''::text))
);

COMMENT ON TABLE kaname.login_failures IS
  'Неверные предъявления пароля по оси адреса и источника (Ф3 Р10): одна строка на попытку; счёт — строки в окне; успешный вход снимает ось address; строки старше окна убирает уборка.';

CREATE INDEX login_failures_scope_key_failed_at_idx ON kaname.login_failures USING btree (scope, key, failed_at);
CREATE INDEX login_failures_failed_at_idx ON kaname.login_failures USING btree (failed_at);

-- +goose Down

-- Откат снимает записи, которые восстанавливаются ВХОДОМ: сессия — повторной
-- аутентификацией, след неверного предъявления — сам по себе не ценность. Память
-- первой аутентификации восстановима ХУЖЕ (её момент — свойство прошлого), но
-- окно её жизни объявлено S2…S3 (Ф3 Р5), и после снятия компонента поставщика
-- предмета у неё нет; до того откат этой миграции означает откат всей полосы
-- входа, и отсечки, датированные этой памятью, остаются в `user_token_revocations`.
DROP TABLE kaname.login_failures;
DROP TABLE kaname.human_first_authentications;
DROP TABLE kaname.human_sessions;
