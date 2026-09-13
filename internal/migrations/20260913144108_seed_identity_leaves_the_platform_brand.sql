-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- seed_identity_leaves_the_platform_brand — ПОСЕВНАЯ ИДЕНТИЧНОСТЬ перестаёт
-- называть платформу: аккаунт `kacho-system` → `system`, служебная запись
-- `kacho-bootstrap-admin` → `bootstrap-admin`, и вместе с ними три ЗНАЧЕНИЯ,
-- называющие платформу прозой.
--
-- Задача продукта #2554, класс C APPROVED-приёмки
-- `docs/engineering/acceptance/seed-identity-names-its-own-service.md`
-- (§2.1 класс C, §2.3 написание, §8 шаг 5 и место П6). Довод написания здесь не
-- пересказывается — он в §2.3: имя называет УСТАНОВКУ, а не продукт.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ЗНАЧЕНИЯ ПЕРЕВОДЯТСЯ ТОЙ ЖЕ МИГРАЦИЕЙ, ЧТО ИМЕНА
--
-- Почта и отображаемое имя владельца аккаунта — та же строка `users`, описание
-- кластера — та же строка `clusters`. Разнести их по двум миграциям значило бы
-- дважды трогать одну строку ради одного перехода. И назвать аккаунт `system`,
-- оставив его владельца `Kacho System` с почтой `system@kacho.local`, значит
-- выполнить переход ровно НАПОЛОВИНУ — в той половине, которую оператор видит
-- первой.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ИДЕНТИФИКАТОРЫ НЕ ДВИГАЮТСЯ И ЧТО ЭТО ПОТРЕБОВАЛО СДЕЛАТЬ РАНЬШЕ
--
-- Три идентификатора ВЫВОДИЛИСЬ из переводимых имён выражением
-- `'<префикс>' || substr(md5('<имя>'), 1, 17)`. Идентификатор неизменяем на всю
-- жизнь ресурса (ban #15), применённую миграцию править нельзя (ban #5) — значит
-- формула перестаёт быть хозяином, и её место занимает литерал. Пин посажен
-- ОТДЕЛЬНЫМ изменением ДО этой миграции (§8 шаг 3,
-- `internal/apps/kaname/api/bootstrap_token/ids.go`): окно, открытое до пина,
-- приняло бы имя, из которого идентификатор не выводится, при живой деривации —
-- то есть завело бы строку, которую формула не находит.
--
-- Строки адресуются ИДЕНТИФИКАТОРОМ, а не именем: имя — ровно то, что мы
-- двигаем, и искать по нему значило бы искать по величине, о которой спор.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ОПЕРАТОРЫ ПЕРЕИМЕНОВАНИЯ СТОЯТ ЛИТЕРАЛАМИ, А НЕ ПЕРЕМЕННЫМИ
--
-- Довод здесь НЕ тот, который напрашивается, и разница измерена опытом, а не
-- выведена. Напрашивается: «разбор посева по цепочке (`internal/check`,
-- `FoldSeededServiceAccounts`) судит статический оператор, поэтому пишем
-- литералами, чтобы он нас видел». Опыт опровергает: разбор этой миграции
-- НЕ ВИДИТ ВОВСЕ — «операторов о таблице 0». Он делит текст по `;`, и
-- фрагмент начинается словом `IF`, а не `UPDATE`, поэтому отбрасывается ещё до
-- сверки формы. Граница объявлена самим разбором («не понимает PL/pgSQL-блоков
-- `DO $$ … $$`»); неназванным в ней оставалось одно — что три исхода дают ровно
-- ту форму, которая под неё подпадает.
--
-- Действительный довод проще и от разбора не зависит: значение, которое
-- миграция ПИШЕТ, обязано читаться в её тексте. Переменная сделала бы запись
-- вторым объявлением той же величины внутри одного файла — при том что первое
-- уже стоит в условии исхода, — и разошлись бы они молча. Литерал же находит
-- всякий, кто ищет в дереве, куда делось прежнее написание.
--
-- Следствие названо вслух, потому что оно шире этой миграции: миграция,
-- СЕЮЩАЯ личность модуля внутри `DO`-блока, прошла бы мимо разбора так же
-- незаметно. Предмет заведён отдельно — он про разбор, а не про этот перевод.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕГО ЭТА МИГРАЦИЯ НЕ ДЕЛАЕТ — НАЗВАНО, ЧТОБЫ НЕ ИСКАЛИ
--
--   * ИДЕНТИФИКАТОР КЛИЕНТА У ВНЕШНЕГО ПРОВАЙДЕРА не трогает. Он живёт не в
--     нашей базе; переход требует окна У ПРОВАЙДЕРА, цена которого не измерена.
--     Предмет — П1 приёмки;
--   * ИМЕНА СЛУЖЕБНЫХ ЗАПИСЕЙ МОДУЛЕЙ не трогает (`kacho-vpc`, `kacho-compute`,
--     …). Их заводит МАНИФЕСТ модуля платформы, то есть их производитель —
--     чужой продукт, и по критерию разреза они остаются его именами;
--   * ПРОСТРАНСТВА ИМЁН КЛАСТЕРА не трогает — предмет `#2553`, другая ось;
--   * ОКНА в базе не требует. `accounts_name_unique` глобален: двух строк с
--     двумя написаниями не бывает by construction. Окно живёт у ЧИТАТЕЛЯ имени
--     (`domain.SeedIdentityWindow`, применитель манифестов, опубликованная
--     схема) и приезжает своим изменением, ДО этой миграции.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ТРИ ИСХОДА НА КАЖДЫЙ ОБЪЕКТ, И ТРЕТИЙ — ОТКАЗ, А НЕ ТИШИНА
--
--   * значение прежнее         → переписывается;
--   * значение уже объявленное → делать нечего, проход молча;
--   * значение ТРЕТЬЕ          → ОТКАЗ. Имя аккаунта и почта владельца
--                                мутабельны, и оператор вправе был выбрать
--                                своё; затирать его молча значит отобрать ровно
--                                ту свободу, ради которой они мутабельны.

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    v_now  text;
    v_rows bigint;
BEGIN
    -- ─── аккаунт установки ────────────────────────────────────────────────
    SELECT name INTO v_now FROM kaname.accounts WHERE id = 'acc1a18042d81fb438d6';
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'системного аккаунта acc1a18042d81fb438d6 в таблице нет: его сеет свод, и отсутствие означает, что цепочка говорит не о том дереве.';
    END IF;
    IF v_now = 'kacho-system' THEN
        UPDATE kaname.accounts SET name = 'system' WHERE id = 'acc1a18042d81fb438d6';
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        IF v_rows <> 1 THEN
            RAISE EXCEPTION 'перевод имени аккаунта затронул строк %, ожидалась одна.', v_rows;
        END IF;
        RAISE NOTICE 'имя аккаунта переписано kacho-system → system.';
    ELSIF v_now <> 'system' THEN
        RAISE EXCEPTION
            'имя системного аккаунта — %, а переход объявлен с kacho-system на system. Имя мутабельно, и оператор вправе был выбрать своё: затирать его молча нельзя.',
            v_now;
    END IF;

    -- ─── служебная запись чеканки ─────────────────────────────────────────
    SELECT name INTO v_now FROM kaname.service_accounts WHERE id = 'svab91854890de887e6d';
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'служебной записи svab91854890de887e6d в таблице нет: её сеет свод, и отсутствие означает, что цепочка говорит не о том дереве.';
    END IF;
    IF v_now = 'kacho-bootstrap-admin' THEN
        UPDATE kaname.service_accounts SET name = 'bootstrap-admin' WHERE id = 'svab91854890de887e6d';
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        IF v_rows <> 1 THEN
            RAISE EXCEPTION 'перевод имени служебной записи затронул строк %, ожидалась одна.', v_rows;
        END IF;
        RAISE NOTICE 'имя служебной записи переписано kacho-bootstrap-admin → bootstrap-admin.';
    ELSIF v_now <> 'bootstrap-admin' THEN
        RAISE EXCEPTION
            'имя служебной записи чеканки — %, а переход объявлен с kacho-bootstrap-admin на bootstrap-admin. Затирать чужой выбор молча нельзя.',
            v_now;
    END IF;

    -- ─── почта владельца аккаунта (П6) ────────────────────────────────────
    --
    -- Колонка глобально уникальна (`users_identity_email_uniq`), поэтому это
    -- такой же предмет миграции, как имя. Объявленное значение НЕ ЯВЛЯЕТСЯ
    -- почтовым ящиком и говорит это само: `.invalid` зарезервирован RFC 6761 и
    -- не разрешается никогда. Прежнее написание несло бренд платформы и при
    -- этом выглядело адресом, по которому кому-то можно написать.
    SELECT email INTO v_now FROM kaname.users WHERE id = 'usr1a18042d81fb438d6';
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'владельца системного аккаунта usr1a18042d81fb438d6 в таблице нет: его сеет свод.';
    END IF;
    IF v_now = 'system@kacho.local' THEN
        UPDATE kaname.users SET email = 'system@system.invalid' WHERE id = 'usr1a18042d81fb438d6';
        RAISE NOTICE 'почта владельца переписана system@kacho.local → system@system.invalid.';
    ELSIF v_now <> 'system@system.invalid' THEN
        RAISE EXCEPTION
            'почта владельца системного аккаунта — %, а переход объявлен с system@kacho.local на system@system.invalid. Затирать чужой выбор молча нельзя.',
            v_now;
    END IF;

    -- ─── отображаемое имя владельца (П6) ──────────────────────────────────
    SELECT display_name INTO v_now FROM kaname.users WHERE id = 'usr1a18042d81fb438d6';
    IF v_now = 'Kacho System (module SA owner)' THEN
        UPDATE kaname.users SET display_name = 'System (module SA owner)' WHERE id = 'usr1a18042d81fb438d6';
        RAISE NOTICE 'отображаемое имя владельца переписано.';
    ELSIF v_now <> 'System (module SA owner)' THEN
        RAISE EXCEPTION
            'отображаемое имя владельца системного аккаунта — %, а переход объявлен с «Kacho System (module SA owner)». Затирать чужой выбор молча нельзя.',
            v_now;
    END IF;

    -- ─── описание корневого кластера (П6) ─────────────────────────────────
    --
    -- Имя кластера перевела `20260913114722_cluster_name_leaves_the_platform_brand.sql`,
    -- и её шапка прямо назвала описание НЕ своим предметом, вынеся его сюда.
    SELECT description INTO v_now FROM kaname.clusters WHERE id = 'cluster_root';
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'корневого кластера cluster_root в таблице нет: якорь переехал миграцией 20260906214500, и его отсутствие означает, что цепочка говорит не о том дереве.';
    END IF;
    IF v_now = 'Root cluster for Kachō control plane' THEN
        UPDATE kaname.clusters SET description = 'Root cluster of this installation' WHERE id = 'cluster_root';
        RAISE NOTICE 'описание кластера переписано.';
    ELSIF v_now <> 'Root cluster of this installation' THEN
        RAISE EXCEPTION
            'описание корневого кластера — %, а переход объявлен с «Root cluster for Kachō control plane». Затирать чужой выбор молча нельзя.',
            v_now;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    -- Обратный ход возвращает ИМЕННО то, что завёл прямой, и только если оно на
    -- месте: строка с третьим значением обратным ходом не трогается — иначе
    -- откат уничтожил бы чужой след так же молча, как затирание.
    UPDATE kaname.accounts SET name = 'kacho-system'
     WHERE id = 'acc1a18042d81fb438d6' AND name = 'system';
    UPDATE kaname.service_accounts SET name = 'kacho-bootstrap-admin'
     WHERE id = 'svab91854890de887e6d' AND name = 'bootstrap-admin';
    UPDATE kaname.users SET email = 'system@kacho.local'
     WHERE id = 'usr1a18042d81fb438d6' AND email = 'system@system.invalid';
    UPDATE kaname.users SET display_name = 'Kacho System (module SA owner)'
     WHERE id = 'usr1a18042d81fb438d6' AND display_name = 'System (module SA owner)';
    UPDATE kaname.clusters SET description = 'Root cluster for Kachō control plane'
     WHERE id = 'cluster_root' AND description = 'Root cluster of this installation';
END $$;
-- +goose StatementEnd
