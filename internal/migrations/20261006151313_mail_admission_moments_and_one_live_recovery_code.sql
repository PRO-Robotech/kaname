-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- mail_admission_moments_and_one_live_recovery_code — хранилище почты личности
-- на ленте notify (задача PRO-Robotech/kaname#484, полоса F1 маршрута
-- PRO-Robotech/kacho#2917; приёмка NTF-2, замысел §6 «Схема БД»).
--
-- =============================================================================
-- ЧТО ЗАВОДИТСЯ
-- =============================================================================
-- * mail_windows — якорь окна адресата (назначение, ключ). Строка нужна для
--   блокировки: работа окна заводит её `ON CONFLICT DO NOTHING` и затем берёт
--   `FOR UPDATE` (З11).
-- * mail_window_letters — моменты писем окна. Момент несёт идентификатор строки
--   ленты своей транзакции: `feed_id` не пуст и не NULL, поэтому «момент без
--   строки ленты» невыразим (CX2-32). Внешнего ключа на ленту НЕТ: удаление
--   строки ленты по сроку момент не трогает и окна не ослабляет.
-- * pending_registrations — ожидающая запись регистрации «сначала письмо»
--   (З14). Адреса открытым текстом нет; код однозначно указывает запись адреса
--   (`UNIQUE (address_digest, code_digest)`, CX2-33). Индекс полный: живость
--   записи зависит от часов и в предикат частичного индекса не входит.
-- * invite_acts — счёт актов приглашения (З24). Внешних ключей НЕТ ни на
--   аккаунт, ни на человека (CX2-21): аккаунт удаляется физически, и каскад
--   уменьшал бы счёт поперёк аккаунтов удалением аккаунта. Строку снимает только
--   уборка по сроку.
-- * trusted_devices — метка доверенного устройства (З18): свёртка значения
--   уникальна, уборка — по моменту выдачи.
-- * security_notice_ledger — одно извещение безопасности на (событие аудита,
--   шаблон, адресат) (З16, И11): вставка `ON CONFLICT DO NOTHING`.
-- * recovery_codes.superseded_at и частичный UNIQUE «живой код у человека один»
--   (З12) — та же форма, что у email_verification_codes, где она уже стоит
--   (миграция 20260927190000).
--
-- Якорь снимается уборкой только без моментов и записей; страховка базы —
-- внешние ключи моментов и записей на якорь с ON DELETE RESTRICT, а не CASCADE:
-- снятие якоря с живым моментом отвергает база (CX2-35 (а)), и уборка окна не
-- уменьшает ни при каком порядке операторов.
--
-- =============================================================================
-- ЧЕГО ЗДЕСЬ НЕТ
-- =============================================================================
-- Таблицы прежней почты (очередь писем, окно писем на адрес, окно источника)
-- этой миграцией НЕ снимаются: их читает и пишет живой код службы. Снятие — фаза
-- сужения, оно садится одним изменением с переписью потребителей (замысел З6).
--
-- =============================================================================
-- ПЕРЕНОС ДАННЫХ
-- =============================================================================
-- Прежний код восстановления удаляет неприменённые коды человека перед выдачей
-- нового в той же транзакции, поэтому два живых кода у человека появляются
-- только гонкой двух запросов. Перед созданием индекса такие строки сужаются к
-- самому позднему коду одним оператором: прежние помечаются вытесненными, а не
-- удаляются — код восстановления служит ключом идемпотентности журнала
-- завершений. Отметка вытеснения ставится не раньше выдачи (ограничение ниже).

-- +goose Up

CREATE TABLE kaname.mail_windows (
    purpose    text                     NOT NULL,
    key_digest bytea                    NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT mail_windows_pkey PRIMARY KEY (purpose, key_digest),
    CONSTRAINT mail_windows_purpose_check
        CHECK ((purpose = ANY (ARRAY['recovery'::text, 'verification'::text, 'registration'::text]))),
    CONSTRAINT mail_windows_key_digest_check CHECK ((octet_length(key_digest) = 32))
);

COMMENT ON TABLE kaname.mail_windows IS
  'Якорь окна писем адресата (назначение, ключ): строка для блокировки работы окна (З11). Снимается уборкой только без моментов и записей; внешние ключи моментов и записей регистрации — RESTRICT.';

CREATE TABLE kaname.mail_window_letters (
    id              text                     NOT NULL,
    purpose         text                     NOT NULL,
    key_digest      bytea                    NOT NULL,
    kind            text                     NOT NULL,
    device_label_id text,
    at              timestamp with time zone NOT NULL,
    feed_id         text                     NOT NULL,
    CONSTRAINT mail_window_letters_pkey PRIMARY KEY (id),
    CONSTRAINT mail_window_letters_id_check CHECK (((length(id) >= 1) AND (length(id) <= 128))),
    CONSTRAINT mail_window_letters_kind_check
        CHECK ((kind = ANY (ARRAY['progression'::text, 'floor'::text, 'trusted_device'::text, 'throttled'::text]))),
    CONSTRAINT mail_window_letters_device_label_check
        CHECK (((kind = 'trusted_device'::text) = (device_label_id IS NOT NULL))),
    CONSTRAINT mail_window_letters_device_label_form_check
        CHECK (((device_label_id IS NULL) OR (device_label_id <> ''::text))),
    CONSTRAINT mail_window_letters_feed_id_check CHECK ((feed_id <> ''::text)),
    CONSTRAINT mail_window_letters_window_fk FOREIGN KEY (purpose, key_digest)
        REFERENCES kaname.mail_windows(purpose, key_digest) ON DELETE RESTRICT
);

COMMENT ON TABLE kaname.mail_window_letters IS
  'Момент письма окна адресата (З11). feed_id — строка ленты той же транзакции, без внешнего ключа: удаление строки ленты по сроку момент не трогает. Уборка — сроком из функции З26.';

-- Окно читается по ключу во времени; индекс же служит внешнему ключу на якорь.
CREATE INDEX mail_window_letters_window_idx
    ON kaname.mail_window_letters USING btree (purpose, key_digest, at);
-- Уборка по сроку.
CREATE INDEX mail_window_letters_at_idx ON kaname.mail_window_letters USING btree (at);

CREATE TABLE kaname.pending_registrations (
    id             text                     NOT NULL,
    purpose        text                     DEFAULT 'registration'::text NOT NULL,
    key_digest     bytea                    NOT NULL,
    address_digest bytea                    NOT NULL,
    password_hash  text                     NOT NULL,
    password_probe bytea                    NOT NULL,
    code_digest    bytea                    NOT NULL,
    created_at     timestamp with time zone NOT NULL,
    expires_at     timestamp with time zone NOT NULL,
    CONSTRAINT pending_registrations_pkey PRIMARY KEY (id),
    CONSTRAINT pending_registrations_id_check CHECK (((length(id) >= 1) AND (length(id) <= 128))),
    CONSTRAINT pending_registrations_purpose_check CHECK ((purpose = 'registration'::text)),
    CONSTRAINT pending_registrations_address_digest_check CHECK ((octet_length(address_digest) = 32)),
    CONSTRAINT pending_registrations_password_hash_check CHECK ((password_hash <> ''::text)),
    CONSTRAINT pending_registrations_password_probe_check CHECK ((octet_length(password_probe) = 32)),
    CONSTRAINT pending_registrations_code_digest_check CHECK ((octet_length(code_digest) = 32)),
    CONSTRAINT pending_registrations_expiry_after_creation_check CHECK ((expires_at > created_at)),
    CONSTRAINT pending_registrations_address_code_uniq UNIQUE (address_digest, code_digest),
    CONSTRAINT pending_registrations_window_fk FOREIGN KEY (purpose, key_digest)
        REFERENCES kaname.mail_windows(purpose, key_digest) ON DELETE RESTRICT
);

COMMENT ON TABLE kaname.pending_registrations IS
  'Ожидающая запись регистрации «сначала письмо» (З14). Адреса открытым текстом нет: address_digest — свёртка ключа учётки; code_digest — свёртка адреса и кода, однозначно указывающая запись адреса. Уборка — expires_at плюс сутки.';

CREATE INDEX pending_registrations_address_idx
    ON kaname.pending_registrations USING btree (address_digest, expires_at);
CREATE INDEX pending_registrations_window_idx
    ON kaname.pending_registrations USING btree (purpose, key_digest);
CREATE INDEX pending_registrations_expires_at_idx
    ON kaname.pending_registrations USING btree (expires_at);

ALTER TABLE kaname.pending_registrations ALTER COLUMN password_hash SET STATISTICS 0;
ALTER TABLE kaname.pending_registrations ALTER COLUMN password_probe SET STATISTICS 0;
ALTER TABLE kaname.pending_registrations ALTER COLUMN code_digest SET STATISTICS 0;

CREATE TABLE kaname.invite_acts (
    id         text                     NOT NULL,
    account_id text                     NOT NULL,
    kind       text                     NOT NULL,
    key_digest bytea                    NOT NULL,
    at         timestamp with time zone NOT NULL,
    lettered   boolean                  NOT NULL,
    feed_id    text,
    CONSTRAINT invite_acts_pkey PRIMARY KEY (id),
    CONSTRAINT invite_acts_id_check CHECK (((length(id) >= 1) AND (length(id) <= 128))),
    CONSTRAINT invite_acts_account_id_check CHECK ((account_id <> ''::text)),
    CONSTRAINT invite_acts_kind_check CHECK ((kind = ANY (ARRAY['invite'::text, 'resend'::text]))),
    CONSTRAINT invite_acts_key_digest_check CHECK ((octet_length(key_digest) = 32)),
    CONSTRAINT invite_acts_lettered_check CHECK ((lettered = (feed_id IS NOT NULL))),
    CONSTRAINT invite_acts_feed_id_check CHECK (((feed_id IS NULL) OR (feed_id <> ''::text)))
);

COMMENT ON TABLE kaname.invite_acts IS
  'Счёт актов приглашения (З24): строка на каждый принятый акт invite или resend. Внешних ключей нет намеренно (CX2-21): удаление аккаунта или человека счёт не уменьшает. Строку снимает только уборка по сроку З26.';

CREATE INDEX invite_acts_account_idx ON kaname.invite_acts USING btree (account_id, kind, at);
CREATE INDEX invite_acts_recipient_idx ON kaname.invite_acts USING btree (key_digest, at) WHERE lettered;
CREATE INDEX invite_acts_at_idx ON kaname.invite_acts USING btree (at);

CREATE TABLE kaname.trusted_devices (
    id           text                     NOT NULL,
    user_id      text                     NOT NULL,
    label_digest bytea                    NOT NULL,
    issued_at    timestamp with time zone NOT NULL,
    CONSTRAINT trusted_devices_pkey PRIMARY KEY (id),
    CONSTRAINT trusted_devices_id_check CHECK (((length(id) >= 1) AND (length(id) <= 128))),
    CONSTRAINT trusted_devices_label_digest_check CHECK ((octet_length(label_digest) = 32)),
    CONSTRAINT trusted_devices_label_digest_uniq UNIQUE (label_digest),
    CONSTRAINT trusted_devices_user_fk FOREIGN KEY (user_id)
        REFERENCES kaname.users(id) ON DELETE CASCADE
);

COMMENT ON TABLE kaname.trusted_devices IS
  'Метка доверенного устройства (З18): свёртка значения метки, человек и момент выдачи. Уборка — по issued_at сроком из функции З26.';

CREATE INDEX trusted_devices_user_id_idx ON kaname.trusted_devices USING btree (user_id);
CREATE INDEX trusted_devices_issued_idx ON kaname.trusted_devices USING btree (issued_at);

ALTER TABLE kaname.trusted_devices ALTER COLUMN label_digest SET STATISTICS 0;

CREATE TABLE kaname.security_notice_ledger (
    audit_event_id    text                     NOT NULL,
    template          text                     NOT NULL,
    recipient_user_id text                     NOT NULL,
    created_at        timestamp with time zone NOT NULL,
    CONSTRAINT security_notice_ledger_pkey PRIMARY KEY (audit_event_id, template, recipient_user_id),
    CONSTRAINT security_notice_ledger_audit_event_id_check CHECK ((audit_event_id <> ''::text)),
    CONSTRAINT security_notice_ledger_template_check CHECK ((template <> ''::text)),
    CONSTRAINT security_notice_ledger_recipient_check CHECK ((recipient_user_id <> ''::text))
);

COMMENT ON TABLE kaname.security_notice_ledger IS
  'Извещение безопасности по событию аудита (З16, И11): одна строка на (событие, шаблон, адресат), вставка ON CONFLICT DO NOTHING в транзакции события. Уборка — сроком хранения аудита.';

CREATE INDEX security_notice_ledger_created_at_idx
    ON kaname.security_notice_ledger USING btree (created_at);

-- Запечатанные атрибуты строки ленты — секретный материал: ANALYZE положил бы
-- их значения в каталог второй копией, которую не затирает затирание строки.
-- Файл ленты порождён генератором и сверяется побайтово, поэтому исключение
-- ставится здесь, первой миграцией после него.
ALTER TABLE kaname.kaname_notification_outbox ALTER COLUMN secret_attrs SET STATISTICS 0;

ALTER TABLE kaname.recovery_codes ADD COLUMN superseded_at timestamp with time zone;

UPDATE kaname.recovery_codes c
   SET superseded_at = greatest(now(), c.issued_at)
 WHERE c.consumed_at IS NULL
   AND EXISTS (
       SELECT 1 FROM kaname.recovery_codes later
        WHERE later.user_id = c.user_id
          AND later.consumed_at IS NULL
          AND (later.issued_at, later.id) > (c.issued_at, c.id));

ALTER TABLE kaname.recovery_codes
    ADD CONSTRAINT recovery_codes_superseded_not_before_issue_check
        CHECK (((superseded_at IS NULL) OR (superseded_at >= issued_at)));
ALTER TABLE kaname.recovery_codes
    ADD CONSTRAINT recovery_codes_one_end_check
        CHECK (((consumed_at IS NULL) OR (superseded_at IS NULL)));

-- Живой код у человека один: новое письмо вытесняет прежний (З12).
CREATE UNIQUE INDEX recovery_codes_one_live_per_user
    ON kaname.recovery_codes USING btree (user_id)
    WHERE ((consumed_at IS NULL) AND (superseded_at IS NULL));

-- +goose Down

-- Откат возвращает строение до этой миграции. Строки новых таблиц не
-- переносятся: ими пользуется только код, который откатываемая ревизия не несёт.
-- Отметки вытеснения кодов восстановления снимаются вместе с колонкой; прежний
-- код снова видит такие коды живыми и вытесняет их удалением при следующей
-- выдаче.
ALTER TABLE kaname.kaname_notification_outbox ALTER COLUMN secret_attrs SET STATISTICS -1;

DROP INDEX kaname.recovery_codes_one_live_per_user;
ALTER TABLE kaname.recovery_codes DROP CONSTRAINT recovery_codes_one_end_check;
ALTER TABLE kaname.recovery_codes DROP CONSTRAINT recovery_codes_superseded_not_before_issue_check;
ALTER TABLE kaname.recovery_codes DROP COLUMN superseded_at;

DROP TABLE kaname.security_notice_ledger;
DROP TABLE kaname.trusted_devices;
DROP TABLE kaname.invite_acts;
DROP TABLE kaname.pending_registrations;
DROP TABLE kaname.mail_window_letters;
DROP TABLE kaname.mail_windows;
