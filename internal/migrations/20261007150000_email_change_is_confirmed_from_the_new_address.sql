-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- email_change_is_confirmed_from_the_new_address — СМЕНА АДРЕСА ПОЧТЫ становится
-- глаголом службы: отложенная смена и её код — запись службы, два новых вида
-- нашего письма, причина конца сессии `email-changed`, вид окна писем
-- адресата `email-change` и вид события очереди смены субъекта
-- `user_email_change` (задача PRO-Robotech/kaname#635).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/email-change-is-confirmed-from-the-new-address.md`,
-- редакция 2, SHA-256
-- `92d7c35d30218e418221a052ca76c257f5c3c649de8337495bdf9941ab248613`
-- (запись `docs/specs/reviews/email-change-is-confirmed-from-the-new-address/92d7c35d30218e418221a052ca76c257f5c3c649de8337495bdf9941ab248613.yaml`,
-- `APPROVED`, событие
-- https://github.com/PRO-Robotech/kaname/issues/635#issuecomment-6035885763;
-- решения Р4, Р5, Р6, Р7, Р8 пп. 4 и 8; §0.2; §6 п. 2). Доводы там; здесь —
-- то, что нужно читателю СХЕМЫ. Применённые миграции не правятся: каждое
-- ограничение снимается и объявляется заново под ТЕМ ЖЕ именем.
--
-- =============================================================================
-- ДВА ВИДА ПИСЬМА — В ТОЙ ЖЕ ОЧЕРЕДИ (Р7)
-- =============================================================================
-- `mail.email-change.send` — код на НОВЫЙ адрес, ставится транзакцией запроса
-- вместе со строкой кода; `mail.email-changed.send` — уведомление на ПРЕЖНИЙ
-- адрес, ставится транзакцией исхода смены. Отправитель, повтор и клетки
-- исхода — общие. Две стороны словаря — схема и применитель — сверяет гейт
-- `TestEveryMailKindHasExactlyOneSender`.
--
-- =============================================================================
-- ПРИЧИНА КОНЦА СЕССИИ `email-changed` (Р8 п. 4)
-- =============================================================================
-- Исход смены снимает все ПРОЧИЕ сессии человека; текущая получает новый
-- носитель. Лежащих строк накат не трогает.
--
-- =============================================================================
-- ОКНО ПИСЕМ АДРЕСАТА `email-change` (Р6)
-- =============================================================================
-- Каждый принятый запрос смены списывается из окна пары «email-change, новый
-- адрес» — и на занятый адрес тоже: разница темпа сама была бы ответом на
-- вопрос «занят ли адрес». Уведомление на прежний адрес окна не списывает.
--
-- =============================================================================
-- ВИД СОБЫТИЯ ОЧЕРЕДИ СМЕНЫ СУБЪЕКТА `user_email_change` (Р8 п. 8)
-- =============================================================================
-- Исход смены пишет ОДНУ строку о человеке (`op` = `event_type` =
-- `user_email_change`, `subject_type` = `user`, адресов нет) тем же методом,
-- которым пишут выдачи и членства. Производитель заводится тем же изменением
-- (`internal/apps/kaname/api/humansession/email_change.go`); читатель края вид
-- события не читает и сбрасывает кеш решений на любой строке. Словарь не
-- менялся ни одной поздней миграцией: объявление `0001_initial.sql`
-- снимается и ставится заново под тем же именем и с тем же описанием.
--
-- =============================================================================
-- ОТЛОЖЕННАЯ СМЕНА — СТРОКА КОДА; СРОК, ОДНОКРАТНОСТЬ, ПРЕДЕЛ ДЕРЖИТ БАЗА (Р5, Р6)
-- =============================================================================
-- Строка — ПРИНЯТЫЙ запрос смены: она и есть единица счёта темпа человека
-- (интервал и число за окно). Новый адрес хранится приведённым. Код хранится
-- СВЁРТКОЙ (SHA-256); у запроса на ЗАНЯТЫЙ адрес свёртки нет (`code_digest`
-- IS NULL, Р4): кода, который мог бы подойти, не существует, и применить такую
-- строку нельзя (`email_change_codes_consumed_needs_code_check`). Живая строка
-- у человека одна (частичный уникальный ключ): новый принятый запрос вытесняет
-- прежнюю отметкой `superseded_at` — и на свободный, и на занятый адрес.
-- Предъявление — один оператор: счёт попытки и сверка свёртки не разнесены
-- чтением и записью. Уникальность нового адреса решает НЕ эта таблица, а ключ
-- `users_identity_email_uniq` в операторе исхода смены.

-- +goose Up

ALTER TABLE kaname.invite_mail_outbox DROP CONSTRAINT invite_mail_outbox_event_type_check;
ALTER TABLE kaname.invite_mail_outbox
    ADD CONSTRAINT invite_mail_outbox_event_type_check
    CHECK ((event_type = ANY (ARRAY['mail.invite.send'::text, 'mail.recovery.send'::text, 'mail.verification.send'::text, 'mail.email-change.send'::text, 'mail.email-changed.send'::text])));

COMMENT ON TABLE kaname.invite_mail_outbox IS
  'Очередь НАШИХ писем (ID-MAIL-1 Р25; Ф5 Р3; kaname#456 Р8; kaname#635 Р7): приглашение, восстановление доступа, подтверждение адреса, код смены адреса и уведомление о смене адреса, каждый вид — своей строкой; отправитель один, вид события — словарь ограничения.';

LOCK TABLE kaname.human_sessions IN ACCESS EXCLUSIVE MODE;
ALTER TABLE kaname.human_sessions
    DROP CONSTRAINT human_sessions_ended_reason_check;
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_ended_reason_check
        CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text, 'second-factor-removed'::text, 'admin-force-logout'::text, 'email-verified'::text, 'email-changed'::text]))));

ALTER TABLE kaname.invite_mail_windows DROP CONSTRAINT invite_mail_windows_kind_check;
ALTER TABLE kaname.invite_mail_windows
    ADD CONSTRAINT invite_mail_windows_kind_check CHECK ((kind = ANY (ARRAY['invite'::text, 'recovery'::text, 'email-change'::text])));

ALTER TABLE kaname.subject_change_outbox DROP CONSTRAINT subject_change_op_check;
ALTER TABLE kaname.subject_change_outbox
    ADD CONSTRAINT subject_change_op_check
    CHECK ((op = ANY (ARRAY['binding_upsert'::text, 'binding_delete'::text, 'group_member_change'::text, 'binding_grant'::text, 'binding_revoke'::text, 'user_email_change'::text])));

COMMENT ON CONSTRAINT subject_change_op_check ON kaname.subject_change_outbox IS 'Словарь видов события очереди смены субъекта. Каждое значение обязано иметь производителя в не-тестовом коде iam — это держит гейт internal/repohygiene TestQueueEventValueHasAProducer. Union двух написаний: op-псевдонимы (binding_upsert/binding_delete) и канонические event_type (binding_grant/binding_revoke/group_member_change), потому что deriveOpFromEventType пропускает незнакомый вид в op как есть. Расширяя словарь, заводи производителя тем же изменением: значение без производителя обещает подсистему, которой нет. user_email_change — исход смены адреса (kaname#635, Р8 п. 8): op и event_type равны.';

CREATE TABLE kaname.email_change_codes (
    id            text NOT NULL,
    user_id       text NOT NULL,
    new_email     text NOT NULL,
    code_digest   text,
    issued_at     timestamp with time zone NOT NULL,
    expires_at    timestamp with time zone NOT NULL,
    attempts      integer DEFAULT 0 NOT NULL,
    consumed_at   timestamp with time zone,
    superseded_at timestamp with time zone,
    created_at    timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT email_change_codes_pkey PRIMARY KEY (id),
    CONSTRAINT email_change_codes_user_fk FOREIGN KEY (user_id)
        REFERENCES kaname.users(id) ON DELETE CASCADE,
    CONSTRAINT email_change_codes_id_check CHECK ((length(id) >= 1) AND (length(id) <= 128)),
    CONSTRAINT email_change_codes_new_email_check
        CHECK (((length(new_email) >= 3) AND (length(new_email) <= 254) AND (new_email = lower(new_email)))),
    CONSTRAINT email_change_codes_digest_uniq UNIQUE (code_digest),
    CONSTRAINT email_change_codes_digest_check CHECK (((code_digest IS NULL) OR (code_digest ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT email_change_codes_expiry_after_issue_check CHECK ((expires_at > issued_at)),
    CONSTRAINT email_change_codes_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT email_change_codes_consumed_not_before_issue_check
        CHECK (((consumed_at IS NULL) OR (consumed_at >= issued_at))),
    CONSTRAINT email_change_codes_superseded_not_before_issue_check
        CHECK (((superseded_at IS NULL) OR (superseded_at >= issued_at))),
    CONSTRAINT email_change_codes_one_end_check
        CHECK (((consumed_at IS NULL) OR (superseded_at IS NULL))),
    CONSTRAINT email_change_codes_consumed_needs_code_check
        CHECK (((consumed_at IS NULL) OR (code_digest IS NOT NULL)))
);

COMMENT ON TABLE kaname.email_change_codes IS
  'Отложенная смена адреса почты и её код (kaname#635, Р4–Р6): строка — ПРИНЯТЫЙ запрос смены и единица счёта темпа человека; new_email — новый адрес в приведённом виде; значение кода хранится СВЁРТКОЙ (code_digest), у запроса на занятый адрес свёртки нет; срок — expires_at; применение — consumed_at, вытеснение — superseded_at; предел попыток — attempts, судимый оператором предъявления. Уникальность адреса решает ключ users_identity_email_uniq в операторе исхода.';

-- Живая отложенная смена у человека одна: новый принятый запрос вытесняет
-- прежнюю (Р5).
CREATE UNIQUE INDEX email_change_codes_one_live_per_user
    ON kaname.email_change_codes USING btree (user_id)
    WHERE ((consumed_at IS NULL) AND (superseded_at IS NULL));
-- Счёт принятых запросов человека в окне и уборка — по моменту выдачи.
CREATE INDEX email_change_codes_user_issued_idx
    ON kaname.email_change_codes USING btree (user_id, issued_at);
CREATE INDEX email_change_codes_issued_at_idx
    ON kaname.email_change_codes USING btree (issued_at);

ALTER TABLE kaname.email_change_codes ALTER COLUMN code_digest SET STATISTICS 0;

-- +goose Down

-- Откат снимает то, что восстанавливается новым запросом: отложенная смена —
-- предъявитель на свой срок, письма — строки очереди, окна — счётчики. Строки
-- сессий, снятые сменой, переводятся в `logout`: различение теряется, факт и
-- момент снятия — нет (форма отката `20260927190000`). Строки очереди смены
-- субъекта нового вида снимаются: читатель края их уже прочёл либо прочтёт
-- соседнюю строку той же смены, а словарь без значения их не примет.
DROP TABLE kaname.email_change_codes;

DELETE FROM kaname.subject_change_outbox WHERE op = 'user_email_change';
ALTER TABLE kaname.subject_change_outbox DROP CONSTRAINT subject_change_op_check;
ALTER TABLE kaname.subject_change_outbox
    ADD CONSTRAINT subject_change_op_check
    CHECK ((op = ANY (ARRAY['binding_upsert'::text, 'binding_delete'::text, 'group_member_change'::text, 'binding_grant'::text, 'binding_revoke'::text])));
COMMENT ON CONSTRAINT subject_change_op_check ON kaname.subject_change_outbox IS 'Словарь видов события очереди смены субъекта. Каждое значение обязано иметь производителя в не-тестовом коде iam — это держит гейт internal/repohygiene TestQueueEventValueHasAProducer. Union двух написаний: op-псевдонимы (binding_upsert/binding_delete) и канонические event_type (binding_grant/binding_revoke/group_member_change), потому что deriveOpFromEventType пропускает незнакомый вид в op как есть. Расширяя словарь, заводи производителя тем же изменением: значение без производителя обещает подсистему, которой нет.';

DELETE FROM kaname.invite_mail_windows WHERE kind = 'email-change';
ALTER TABLE kaname.invite_mail_windows DROP CONSTRAINT invite_mail_windows_kind_check;
ALTER TABLE kaname.invite_mail_windows
    ADD CONSTRAINT invite_mail_windows_kind_check CHECK ((kind = ANY (ARRAY['invite'::text, 'recovery'::text])));

LOCK TABLE kaname.human_sessions IN ACCESS EXCLUSIVE MODE;
UPDATE kaname.human_sessions SET ended_reason = 'logout' WHERE ended_reason = 'email-changed';
ALTER TABLE kaname.human_sessions
    DROP CONSTRAINT human_sessions_ended_reason_check;
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_ended_reason_check
        CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text, 'second-factor-removed'::text, 'admin-force-logout'::text, 'email-verified'::text]))));

DELETE FROM kaname.invite_mail_outbox WHERE event_type IN ('mail.email-change.send', 'mail.email-changed.send');
ALTER TABLE kaname.invite_mail_outbox DROP CONSTRAINT invite_mail_outbox_event_type_check;
ALTER TABLE kaname.invite_mail_outbox
    ADD CONSTRAINT invite_mail_outbox_event_type_check
    CHECK ((event_type = ANY (ARRAY['mail.invite.send'::text, 'mail.recovery.send'::text, 'mail.verification.send'::text])));
COMMENT ON TABLE kaname.invite_mail_outbox IS
  'Очередь НАШИХ писем (ID-MAIL-1 Р25; Ф5 Р3; kaname#456 Р8): приглашение, восстановление доступа и подтверждение адреса, каждый вид — своей строкой; отправитель один, вид события — словарь ограничения.';
