-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- notification_grants — запись выдачи пространства уведомлений и запись
-- шаблона (задача PRO-Robotech/kaname#484, полоса K3).
--
-- Санкция: приёмка `docs/specs/sub-phase-NTF-1-notification-gateway-core-acceptance.md`
-- репозитория PRO-Robotech/kacho-workspace, Р5, одобрена на отпечатке
-- `c19490f97c3f6200eede4cdbdaa31ed74b4da34dd7007d93d0994372dc81c5db`;
-- замысел `docs/changes/issue-2915/design.md`, З18 и §6. Доводы там; здесь —
-- то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ЧТО ДЕРЖИТ БАЗА
-- =============================================================================
-- Запись выдачи — одна на пространство (первичный ключ `namespace`); её
-- заводит посев строкой `INSERT … ON CONFLICT (namespace) DO NOTHING` и не
-- трогает ни в одном поле повторно (надгробие уважается, NTF1-F08).
--
-- Переходы — CAS одним оператором (`Revoke` — `… WHERE revoked_at IS NULL`,
-- `Restore` — `… WHERE revoked_at IS NOT NULL`); ноль строк классифицируется
-- одним чтением ПОСЛЕ неудачной записи. Чтения состояния с последующей
-- безусловной записью нет (NTF1-F18).
--
-- Запись шаблона — одна на пару (первичный ключ `(namespace, template)`),
-- заводится первым `Revoke(namespace, template)`; внешний ключ на запись
-- выдачи `ON DELETE RESTRICT` — шаблон без пространства невыразим. Оси
-- пространства и шаблона независимы.
--
-- `cutoff_at` — момент последнего `Restore` по часам kaname, `timestamptz`
-- полной точности; при чтении не усекается (CX1-08). У ни разу не
-- восстановленной записи отсечки нет.
--
-- `namespace` и `template` — DNS label (RFC 1123): та же форма, что судит
-- обработчик; неверная форма до базы не доезжает, а доехавшая отвергается
-- ограничением.

-- +goose Up

CREATE TABLE kaname.notification_grants (
    namespace  text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    cutoff_at  timestamp with time zone,
    CONSTRAINT notification_grants_pkey PRIMARY KEY (namespace),
    CONSTRAINT notification_grants_namespace_form_ck
        CHECK ((namespace ~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'::text))
);

COMMENT ON TABLE kaname.notification_grants IS
  'Запись выдачи пространства уведомлений (NTF-1 Р5, З18): {пространство, выдано, отозвано, отсечка}. Кортеж sender — её проекция через журнал kaname той же транзакцией. Посев — ON CONFLICT DO NOTHING; переходы Revoke/Restore — CAS по revoked_at.';

CREATE TABLE kaname.notification_template_grants (
    namespace  text NOT NULL,
    template   text NOT NULL,
    revoked_at timestamp with time zone,
    cutoff_at  timestamp with time zone,
    CONSTRAINT notification_template_grants_pkey PRIMARY KEY (namespace, template),
    CONSTRAINT notification_template_grants_namespace_fk FOREIGN KEY (namespace)
        REFERENCES kaname.notification_grants(namespace) ON DELETE RESTRICT,
    CONSTRAINT notification_template_grants_template_form_ck
        CHECK ((template ~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'::text))
);

COMMENT ON TABLE kaname.notification_template_grants IS
  'Запись шаблона пространства уведомлений (NTF-1 Р5, З18): {пространство, шаблон, отозвано, отсечка шаблона}, одна на пару; заводится первым Revoke(namespace, template). Кортеж sender не трогает.';

-- +goose Down

DROP TABLE kaname.notification_template_grants;
DROP TABLE kaname.notification_grants;
