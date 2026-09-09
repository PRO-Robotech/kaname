-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- six_never_charged_kinds_leave_the_accounting — шесть видов службы доступа,
-- которые НИКОГДА не списывались, уходят из учёта вслед за каталогом.
--
-- Задача продукта #2117, приёмка `KAN-QUOTA-1`, сценарий `KAN-Q3-04`,
-- условие готовности `DoD S3` п. 3.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ: «принято-и-проигнорировано», а не потеря контроля
--
-- Виды `iam.project`, `iam.user`, `iam.serviceAccount`, `iam.group`, `iam.role`,
-- `iam.accessBinding` объявлялись каталогом потолков, величина на них
-- принималась, сохранялась и показывалась — и НЕ ПРИМЕНЯЛАСЬ НИ РАЗУ:
-- списывающего триггера нет ни у одного, списания из прод-кода службы нет тоже.
--
-- Разбиение девяти видов службы на 3 действующих и 6 недействующих сделано
-- ПРЕДИКАТОМ, а не по имени вида: действует тот, чей вызов `kacho_quota_count`
-- стоит в применённой миграции. Таких ровно три — `iam.account` (триггер
-- `accounts_quota_count`), `iam.user.credential` (`user_oauth_clients_quota_count`)
-- и `iam.serviceAccount.credential` (`sa_oauth_clients_quota_count`). Они
-- остаются и продолжают наступать; эта миграция их НЕ КАСАЕТСЯ, и предикат
-- ниже назван так, чтобы задеть их было нельзя.
--
-- Поэтому снятие ЗАКРЫВАЕТ обещание, которого продукт не исполнял, а не
-- отбирает у арендатора действующий предел: применять было нечего.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ МИГРАЦИЯ, А НЕ ПОСЕВ
--
-- Строки заведены ПРИМЕНЁННОЙ миграцией `0001_initial.sql` (шесть умолчаний
-- области `DEFAULT`) и обязаны существовать у всякого, кто развернул продукт, —
-- то есть это справочник продукта, а не данные стенда. Снимается он тем же
-- способом, каким заведён, и НОВОЙ миграцией: применённую не правят (ban #5).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО ЭТА МИГРАЦИЯ НЕ ВОССТАНАВЛИВАЕТ ОБРАТНО, И ЭТО СКАЗАНО ПРЯМО
--
-- `Down` возвращает ШЕСТЬ УМОЛЧАНИЙ ровно теми величинами, которыми их сеет
-- `0001_initial.sql`. Величины, назначенные ОПЕРАТОРОМ на область `ACCOUNT` или
-- `PROJECT`, обратно не восстанавливаются: их значения не выводятся ниоткуда,
-- и придумать их значило бы объявить арендатору потолок, которого он не
-- назначал. Ущерба от их снятия нет by construction — ни один из шести видов
-- не списывался, поэтому ни одна назначенная величина ни разу ни на что не
-- влияла, — но факт назван здесь, а не умолчан.
--
-- Строки учёта (`project_resource_quotas`) снимаются вместе с величинами: без
-- своей величины строка учёта описывает потолок, которого больше нет.

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    withdrawn CONSTANT text[] := ARRAY[
        'iam.project',
        'iam.user',
        'iam.serviceAccount',
        'iam.group',
        'iam.role',
        'iam.accessBinding'
    ];
    accounting_removed bigint;
    ceilings_removed   bigint;
    still_charging     bigint;
BEGIN
    -- ОХРАНА ПРЕДПОСЫЛКИ. Эта миграция верна ровно потому, что шесть названных
    -- видов никто не списывает. Появись у любого из них списывающий триггер —
    -- предпосылка неверна, и снятие отобрало бы действующий предел молча.
    SELECT count(*) INTO still_charging
    FROM pg_trigger t
    JOIN pg_proc  p ON p.oid = t.tgfoid
    WHERE NOT t.tgisinternal
      AND p.proname = 'kacho_quota_count'
      AND EXISTS (
          SELECT 1 FROM unnest(withdrawn) AS k(kind)
          WHERE pg_get_triggerdef(t.oid) LIKE '%''' || k.kind || '''%'
      );

    IF still_charging > 0 THEN
        RAISE EXCEPTION 'предпосылка неверна: у % из шести снимаемых видов появился списывающий триггер — снятие отобрало бы ДЕЙСТВУЮЩИЙ предел', still_charging;
    END IF;

    DELETE FROM kaname.project_resource_quotas WHERE kind = ANY (withdrawn);
    GET DIAGNOSTICS accounting_removed = ROW_COUNT;

    DELETE FROM kaname.limits WHERE kind = ANY (withdrawn);
    GET DIAGNOSTICS ceilings_removed = ROW_COUNT;

    -- Перепись печатается всегда: «ноль снятого» обязано быть отличимо от
    -- «ничего не осмотрено», иначе повторное применение на уже чистой базе
    -- неотличимо от миграции, не нашедшей своего предмета.
    RAISE NOTICE 'снято видов %, строк учёта %, величин %',
        array_length(withdrawn, 1), accounting_removed, ceilings_removed;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
INSERT INTO kaname.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES
    ('lim-00000000000000009',  now(), 'DEFAULT', '', 'iam.project',        16, NULL,  9),
    ('lim-00000000000000014', now(), 'DEFAULT', '', 'iam.user',           128, NULL, 14),
    ('lim-00000000000000015', now(), 'DEFAULT', '', 'iam.serviceAccount', 128, NULL, 15),
    ('lim-00000000000000016', now(), 'DEFAULT', '', 'iam.group',           64, NULL, 16),
    ('lim-00000000000000017', now(), 'DEFAULT', '', 'iam.role',            64, NULL, 17),
    ('lim-00000000000000018', now(), 'DEFAULT', '', 'iam.accessBinding',  512, NULL, 18)
ON CONFLICT DO NOTHING;
-- +goose StatementEnd
