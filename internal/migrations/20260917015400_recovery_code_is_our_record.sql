-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- recovery_code_is_our_record — КОД ВОССТАНОВЛЕНИЯ становится записью службы,
-- письмо восстановления — вторым видом нашей почтовой очереди, а журнал
-- завершений принимает поток без внешнего субъекта (фаза Ф5, задача
-- PRO-Robotech/kacho#1271).
--
-- Санкция: одобренная Ф5 (`docs/engineering/acceptance/recovery-of-access.md`,
-- решения Р1, Р3, Р4; §4.1 пп. 1, 2, 4) над одобренной Ф1 (§4.1 — срок 5 минут
-- переносится дословно, владелец величины — наша настройка). Доводы там; здесь
-- — только то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ВТОРОЙ ВИД ПИСЬМА — В ТОЙ ЖЕ ОЧЕРЕДИ, НОВОЙ МИГРАЦИЕЙ (Р3)
-- =============================================================================
-- Отправитель, настройка, закрытый набор клеток исхода, ограниченный повтор и
-- предел времени на попытку — ОБЩИЕ с письмом приглашения. Меняется одно: перечень
-- видов события очереди перестаёт быть одноэлементным. Перечень закреплён
-- ограничением ПРИМЕНЁННОЙ миграции (`0001_initial.sql`), а применённую не
-- правят (ban #5) — поэтому ограничение снимается и объявляется заново здесь.
--
-- Две стороны словаря — схема и применитель — сверяются гейтом
-- `TestEveryMailKindHasExactlyOneSender` (Ф5-10, Ф5-11): вид без применителя
-- отравил бы строку как «неизвестный вид», применитель без вида — ветвь,
-- которая не исполнится никогда.
--
-- =============================================================================
-- КОД — ПРЕДЪЯВИТЕЛЬ; СРОК И ОДНОКРАТНОСТЬ ДЕРЖИТ БАЗА (Р1)
-- =============================================================================
-- Само значение кода НЕ хранится: хранится его свёртка (SHA-256, шестнадцатерично).
-- Прочитанное из строки предъявлением не является (Ф5-07): свёртка предъявляется
-- как код, свёртка свёртки не совпадёт ни с чем.
--
-- Срок — `expires_at`, ОДИН столбец; величину назначает наша настройка, здесь
-- только требование «позже выдачи». Применение — отметка `consumed_at`, и
-- ставит её ОДИН оператор (`UPDATE … WHERE consumed_at IS NULL AND expires_at >
-- $now RETURNING …`): под конкуренцией два предъявления одного кода увидят одно
-- и то же «ещё не применён», и выиграет ровно одно (Ф5-05).
--
-- Идентификатор строки — идентификатор ПОТОКА восстановления: он и есть ключ
-- идемпотентности журнала завершений (Р4), чеканим его мы.
--
-- Человек — `users.id`; строка уходит вместе с ним каскадом. Применённые и
-- истёкшие строки снимает уборка (реестр `retention`, предмет `recovery_codes`),
-- а не глагол.
--
-- Свёртка не идёт в статистику планировщика: ищут её только равенством по
-- уникальному индексу, а выборка значений в `pg_stats` была бы выдачей свёрток
-- всякому, кто читает статистику (гейт `TestSecretMaterialCandidatesAreAllAdjudicated`).
--
-- =============================================================================
-- ЖУРНАЛ ЗАВЕРШЕНИЙ ПРИНИМАЕТ ПОТОК БЕЗ ВНЕШНЕГО СУБЪЕКТА (Р4)
-- =============================================================================
-- Журнал заведён под обратный вызов поставщика личности, и его строка требовала
-- внешнего субъекта. Источник события меняется (Р4): наш поток называет
-- человека его строкой, а внешнего субъекта у личности, заведённой нашей
-- регистрацией, нет вовсе. Столбец становится необязательным; ограничение длины
-- на заданном значении остаётся. Транзакция завершения — та же.

-- +goose Up

ALTER TABLE kaname.invite_mail_outbox DROP CONSTRAINT invite_mail_outbox_event_type_check;
ALTER TABLE kaname.invite_mail_outbox
    ADD CONSTRAINT invite_mail_outbox_event_type_check
    CHECK ((event_type = ANY (ARRAY['mail.invite.send'::text, 'mail.recovery.send'::text])));

COMMENT ON TABLE kaname.invite_mail_outbox IS
  'Очередь НАШИХ писем (ID-MAIL-1 Р25; Ф5 Р3): приглашение и восстановление доступа, каждый вид — своей строкой; отправитель один, вид события — словарь ограничения.';

CREATE TABLE kaname.recovery_codes (
    id          text NOT NULL,
    user_id     text NOT NULL,
    code_digest text NOT NULL,
    issued_at   timestamp with time zone NOT NULL,
    expires_at  timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at  timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT recovery_codes_pkey PRIMARY KEY (id),
    CONSTRAINT recovery_codes_user_fk FOREIGN KEY (user_id)
        REFERENCES kaname.users(id) ON DELETE CASCADE,
    CONSTRAINT recovery_codes_id_check CHECK ((length(id) >= 1) AND (length(id) <= 128)),
    CONSTRAINT recovery_codes_digest_uniq UNIQUE (code_digest),
    CONSTRAINT recovery_codes_digest_check CHECK ((code_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT recovery_codes_expiry_after_issue_check CHECK ((expires_at > issued_at)),
    CONSTRAINT recovery_codes_consumed_not_before_issue_check
        CHECK (((consumed_at IS NULL) OR (consumed_at >= issued_at)))
);

COMMENT ON TABLE kaname.recovery_codes IS
  'Код восстановления доступа (Ф5, kacho#1271). Значение хранится СВЁРТКОЙ (code_digest); срок один — expires_at; применение — отметка consumed_at одним оператором; id — идентификатор потока, ключ идемпотентности журнала завершений.';

CREATE INDEX recovery_codes_user_id_idx ON kaname.recovery_codes USING btree (user_id);
-- Уборка идёт по сроку и по отметке применения.
CREATE INDEX recovery_codes_expires_at_idx ON kaname.recovery_codes USING btree (expires_at);

ALTER TABLE kaname.recovery_codes ALTER COLUMN code_digest SET STATISTICS 0;

ALTER TABLE kaname.recovery_completions ALTER COLUMN external_id DROP NOT NULL;

COMMENT ON TABLE kaname.recovery_completions IS
  'Журнал завершений восстановления — ключ идемпотентности recovery_jti (INSERT … ON CONFLICT DO NOTHING). Два источника события: обратный вызов поставщика (external_id задан) и наш поток Ф5 (external_id NULL, recovery_jti — идентификатор строки recovery_codes).';

-- +goose Down

-- Откат снимает то, что восстанавливается новым запросом восстановления: код —
-- предъявитель на пять минут, письмо — строка очереди, которую поставит новый
-- запрос. Строки журнала нашего потока снимаются вместе со своим источником:
-- без них столбец не вернуть к обязательному.
DELETE FROM kaname.recovery_completions WHERE external_id IS NULL;
ALTER TABLE kaname.recovery_completions ALTER COLUMN external_id SET NOT NULL;
COMMENT ON TABLE kaname.recovery_completions IS
  'Idempotency ledger for the Kratos recovery-completed webhook. PK recovery_jti dedups at-least-once delivery via INSERT … ON CONFLICT DO NOTHING; stores user_id / revoked_session_count for idempotent replay.';

DROP TABLE kaname.recovery_codes;

DELETE FROM kaname.invite_mail_outbox WHERE event_type = 'mail.recovery.send';
ALTER TABLE kaname.invite_mail_outbox DROP CONSTRAINT invite_mail_outbox_event_type_check;
ALTER TABLE kaname.invite_mail_outbox
    ADD CONSTRAINT invite_mail_outbox_event_type_check
    CHECK ((event_type = ANY (ARRAY['mail.invite.send'::text])));
COMMENT ON TABLE kaname.invite_mail_outbox IS NULL;
