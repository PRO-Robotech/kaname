-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- address_verification_is_our_verb — ПОДТВЕРЖДЕНИЕ АДРЕСА становится глаголом
-- службы: код подтверждения — запись службы, письмо подтверждения — третий вид
-- нашей почтовой очереди, причина конца сессии `email-verified` входит в
-- закрытый словарь, окна писем и обращений считаются одним оператором (задача
-- PRO-Robotech/kaname#456).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`,
-- редакция 3, SHA-256
-- `f2d1fe852333af5412591a7ef2740d651086c408715e2083f47d3d075a755853`
-- (событие одобрения
-- https://github.com/PRO-Robotech/kaname/issues/456#issuecomment-5858582161;
-- решения Р7, Р8, Р9, Р10, Р13; §9 п. 7). Доводы там; здесь — то, что нужно
-- читателю СХЕМЫ.
--
-- =============================================================================
-- ТРЕТИЙ ВИД ПИСЬМА — В ТОЙ ЖЕ ОЧЕРЕДИ (Р8)
-- =============================================================================
-- Отправитель, настройка, клетки исхода, повтор и предел попытки — общие с
-- приглашением и восстановлением. Меняется словарь видов события: ограничение
-- применённой миграции (`20260917015400`) снимается и объявляется заново под
-- ТЕМ ЖЕ именем. Две стороны словаря — схема и применитель — сверяет гейт
-- `TestEveryMailKindHasExactlyOneSender`.
--
-- =============================================================================
-- ПРИЧИНА КОНЦА СЕССИИ `email-verified` (Р10 п. 3)
-- =============================================================================
-- Подтверждение снимает все прочие сессии человека: обычное положение получает
-- только та сессия, в которой код предъявлен. Слово добавляется к словарю
-- `human_sessions_ended_reason_check` под тем же именем; лежащих строк накат не
-- трогает.
--
-- =============================================================================
-- КОД ПОДТВЕРЖДЕНИЯ — ПРЕДЪЯВИТЕЛЬ; СРОК, ОДНОКРАТНОСТЬ И ПРЕДЕЛ ДЕРЖИТ БАЗА (Р7)
-- =============================================================================
-- Хранится свёртка (SHA-256), а не значение; прочитанное из строки
-- предъявлением не является. Код принадлежит человеку И значению адреса, на
-- которое выдан (`email`): оператор применения сверяет его с текущим адресом
-- строки человека, и смена адреса после выдачи делает код неподходящим без
-- второй проверки в коде (Ф6 Р10).
--
-- Предъявление — ОДИН оператор: счёт попытки и сверка свёртки не разнесены
-- чтением и записью. Живой код у человека один (частичный уникальный ключ):
-- новое письмо вытесняет прежний отметкой `superseded_at`, строка остаётся —
-- по строкам кодов считается предел писем (Р9: интервал и число за окно).
-- Уборка снимает строки старше окна писем.
--
-- =============================================================================
-- ОКНА: ПИСЬМА НА АДРЕС ПО ВИДУ, ОБРАЩЕНИЯ ПО ИСТОЧНИКУ
-- =============================================================================
-- Окно писем на адрес (`invite_mail_windows`) получает вид письма в ключе:
-- приглашение и восстановление списываются каждое своим окном. Окно обращений
-- по источнику (`source_request_windows`) — новое: регистрация и запрос
-- восстановления списывают его ДО своей работы. Списание и переход окна — один
-- оператор с замком строки окна, как у окна писем.

-- +goose Up

ALTER TABLE kaname.invite_mail_outbox DROP CONSTRAINT invite_mail_outbox_event_type_check;
ALTER TABLE kaname.invite_mail_outbox
    ADD CONSTRAINT invite_mail_outbox_event_type_check
    CHECK ((event_type = ANY (ARRAY['mail.invite.send'::text, 'mail.recovery.send'::text, 'mail.verification.send'::text])));

COMMENT ON TABLE kaname.invite_mail_outbox IS
  'Очередь НАШИХ писем (ID-MAIL-1 Р25; Ф5 Р3; kaname#456 Р8): приглашение, восстановление доступа и подтверждение адреса, каждый вид — своей строкой; отправитель один, вид события — словарь ограничения.';

LOCK TABLE kaname.human_sessions IN ACCESS EXCLUSIVE MODE;
ALTER TABLE kaname.human_sessions
    DROP CONSTRAINT human_sessions_ended_reason_check;
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_ended_reason_check
        CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text, 'second-factor-removed'::text, 'admin-force-logout'::text, 'email-verified'::text]))));

CREATE TABLE kaname.email_verification_codes (
    id            text NOT NULL,
    user_id       text NOT NULL,
    email         text NOT NULL,
    code_digest   text NOT NULL,
    issued_at     timestamp with time zone NOT NULL,
    expires_at    timestamp with time zone NOT NULL,
    attempts      integer DEFAULT 0 NOT NULL,
    consumed_at   timestamp with time zone,
    superseded_at timestamp with time zone,
    created_at    timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT email_verification_codes_pkey PRIMARY KEY (id),
    CONSTRAINT email_verification_codes_user_fk FOREIGN KEY (user_id)
        REFERENCES kaname.users(id) ON DELETE CASCADE,
    CONSTRAINT email_verification_codes_id_check CHECK ((length(id) >= 1) AND (length(id) <= 128)),
    CONSTRAINT email_verification_codes_email_check CHECK ((length(email) >= 3)),
    CONSTRAINT email_verification_codes_digest_uniq UNIQUE (code_digest),
    CONSTRAINT email_verification_codes_digest_check CHECK ((code_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT email_verification_codes_expiry_after_issue_check CHECK ((expires_at > issued_at)),
    CONSTRAINT email_verification_codes_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT email_verification_codes_consumed_not_before_issue_check
        CHECK (((consumed_at IS NULL) OR (consumed_at >= issued_at))),
    CONSTRAINT email_verification_codes_superseded_not_before_issue_check
        CHECK (((superseded_at IS NULL) OR (superseded_at >= issued_at))),
    CONSTRAINT email_verification_codes_one_end_check
        CHECK (((consumed_at IS NULL) OR (superseded_at IS NULL)))
);

COMMENT ON TABLE kaname.email_verification_codes IS
  'Код подтверждения адреса (kaname#456, Р7): значение хранится СВЁРТКОЙ (code_digest); код принадлежит человеку и значению адреса email, на которое выдан; срок — expires_at; применение — consumed_at, вытеснение — superseded_at; предел попыток — attempts, судимый оператором предъявления. Строки — счёт писем для предела Р9.';

-- Живой код у человека один: новое письмо вытесняет прежний (Р7).
CREATE UNIQUE INDEX email_verification_codes_one_live_per_user
    ON kaname.email_verification_codes USING btree (user_id)
    WHERE ((consumed_at IS NULL) AND (superseded_at IS NULL));
-- Счёт писем человека в окне и уборка — по моменту выдачи.
CREATE INDEX email_verification_codes_user_issued_idx
    ON kaname.email_verification_codes USING btree (user_id, issued_at);
CREATE INDEX email_verification_codes_issued_at_idx
    ON kaname.email_verification_codes USING btree (issued_at);

ALTER TABLE kaname.email_verification_codes ALTER COLUMN code_digest SET STATISTICS 0;

-- Окно писем на адрес — по виду письма.
ALTER TABLE kaname.invite_mail_windows ADD COLUMN kind text DEFAULT 'invite' NOT NULL;
ALTER TABLE kaname.invite_mail_windows
    ADD CONSTRAINT invite_mail_windows_kind_check CHECK ((kind = ANY (ARRAY['invite'::text, 'recovery'::text])));
ALTER TABLE kaname.invite_mail_windows DROP CONSTRAINT invite_mail_windows_pkey;
ALTER TABLE kaname.invite_mail_windows ADD CONSTRAINT invite_mail_windows_pkey PRIMARY KEY (kind, recipient);

COMMENT ON TABLE kaname.invite_mail_windows IS
    'Окно частоты НАШИХ писем на адрес по виду письма (ID-MAIL-1, MAIL-25; kaname#456): одна строка на вид и нормализованный адрес; списание и переход окна — одним оператором с блокировкой строки.';

CREATE TABLE kaname.source_request_windows (
    lane              text NOT NULL,
    source            text NOT NULL,
    window_started_at timestamp with time zone NOT NULL,
    requests          integer NOT NULL,
    updated_at        timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT source_request_windows_pkey PRIMARY KEY (lane, source),
    CONSTRAINT source_request_windows_lane_check CHECK ((lane = ANY (ARRAY['registration'::text, 'recovery-request'::text]))),
    CONSTRAINT source_request_windows_source_check CHECK (((length(source) >= 1) AND (length(source) <= 256))),
    CONSTRAINT source_request_windows_requests_positive_check CHECK ((requests >= 1))
);

COMMENT ON TABLE kaname.source_request_windows IS
    'Окно обращений без удостоверения по источнику (kaname#456): регистрация и запрос восстановления списывают его одним оператором ДО своей работы; сверх окна — отказ без побочных записей.';

CREATE INDEX source_request_windows_updated_at_idx ON kaname.source_request_windows USING btree (updated_at);

-- +goose Down

-- Откат снимает то, что восстанавливается новым запросом: код — предъявитель
-- на свой срок, письмо — строка очереди, окна — счётчики. Строки сессий,
-- снятые подтверждением, переводятся в `logout`: различение теряется, факт и
-- момент снятия — нет (форма отката `20260923160455`).
DROP TABLE kaname.source_request_windows;

DELETE FROM kaname.invite_mail_windows WHERE kind <> 'invite';
ALTER TABLE kaname.invite_mail_windows DROP CONSTRAINT invite_mail_windows_pkey;
ALTER TABLE kaname.invite_mail_windows ADD CONSTRAINT invite_mail_windows_pkey PRIMARY KEY (recipient);
ALTER TABLE kaname.invite_mail_windows DROP CONSTRAINT invite_mail_windows_kind_check;
ALTER TABLE kaname.invite_mail_windows DROP COLUMN kind;
COMMENT ON TABLE kaname.invite_mail_windows IS
    'Окно частоты писем приглашения на адрес (ID-MAIL-1, MAIL-25): одна строка на нормализованный адрес; списание и переход окна — одним оператором с блокировкой строки.';

DROP TABLE kaname.email_verification_codes;

LOCK TABLE kaname.human_sessions IN ACCESS EXCLUSIVE MODE;
UPDATE kaname.human_sessions SET ended_reason = 'logout' WHERE ended_reason = 'email-verified';
ALTER TABLE kaname.human_sessions
    DROP CONSTRAINT human_sessions_ended_reason_check;
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_ended_reason_check
        CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text, 'second-factor-removed'::text, 'admin-force-logout'::text]))));

DELETE FROM kaname.invite_mail_outbox WHERE event_type = 'mail.verification.send';
ALTER TABLE kaname.invite_mail_outbox DROP CONSTRAINT invite_mail_outbox_event_type_check;
ALTER TABLE kaname.invite_mail_outbox
    ADD CONSTRAINT invite_mail_outbox_event_type_check
    CHECK ((event_type = ANY (ARRAY['mail.invite.send'::text, 'mail.recovery.send'::text])));
COMMENT ON TABLE kaname.invite_mail_outbox IS
  'Очередь НАШИХ писем (ID-MAIL-1 Р25; Ф5 Р3): приглашение и восстановление доступа, каждый вид — своей строкой; отправитель один, вид события — словарь ограничения.';
