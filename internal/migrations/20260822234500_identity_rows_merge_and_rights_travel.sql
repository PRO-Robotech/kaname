-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 20260822234500_identity_rows_merge_and_rights_travel — строки-дубли одного
-- человека сводятся к одной личности, а выданные на них права переезжают на
-- выжившую строку, ОСТАВАЯСЬ в границах своего аккаунта.
-- Стадия S2 перехода IAM-ID-1, задача kacho#472.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ НОМЕР — МЕТКА ВРЕМЕНИ, А НЕ НОМЕР ЗАДАЧИ
--
-- Соглашение `docs/architecture/migration-version-namespace.md` называет форму
-- `<задача><порядок>`, и она ЗАКРЫТА гейтом `TestNewMigrationOutranksEveryAppliedOne`:
-- номер задачи #472 меньше уже применённых (старший — 944001), и мигратор такую
-- версию на живой базе не применяет, роняя старт. Два места об одном предмете —
-- действует то, которое роняет прогон.
--
-- Метка времени даёт и второе, нужное здесь по существу: миграция встаёт ПОСЛЕ
-- всей цепи, поэтому на чистой базе она видит схему целиком — в частности
-- области субъекта выдачи (`access_binding_subjects.resource_type/resource_id`,
-- 732001). Номер по задаче поставил бы её перед ними, и перенос работал бы с
-- таблицей, у которой этих колонок ещё нет.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ — ИЗМЕРЕН, А НЕ ПЕРЕСКАЗАН ИЗ ЗАДАЧИ
--
-- Задача говорит «один человек в двух аккаунтах имеет два идентификатора и два
-- набора прав». Дерево у́же, и знать это обязательно:
--
--   * двух ACTIVE-строк у одного человека быть не может — глобальный ключ
--     `users_active_external_id_uniq` этого не допускает;
--   * а две строки «приглашён» — могут. Приглашение резолвит субъект в
--     старейшую ACTIVE-строку по почте; для ни разу не входившего таковой нет, и
--     право выдаётся на его ПЕР-АККАУНТНУЮ строку. Пригласив такого человека в
--     два аккаунта, получаем две строки и по праву на каждой. Первый вход
--     активирует ОДНУ; вторая остаётся неактивируемой навсегда, а выданное на
--     неё право — ОСИРОТЕВШИМ: лежит в леджере и не действует ни для кого.
--
-- Отсюда работа: свести строки к одной и провести права за ними, не сдвинув ни
-- одной области.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО ЭТА МИГРАЦИЯ НЕ ДЕЛАЕТ
--
-- Не трогает колонку `users.account_id`, не заводит глобальной уникальности
-- почты, не снимает ни одного ключа и не меняет ни одного контракта: всё это —
-- стадия S4 (задача #470), и она идёт ПОСЛЕ снятия аккаунта с методов (#471).
-- Здесь только данные и зеркало.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ГРАНИЦА РЕШАЕМОГО — НАЗВАНА, А НЕ ОБОЙДЕНА МОЛЧА
--
-- Сводятся группы, где снимаемые строки ни разу не входили («приглашён»).
-- Две группы миграция сводить ОТКАЗЫВАЕТСЯ и роняет прогон, называя число:
--
--   1. в группе есть ЗАБЛОКИРОВАННАЯ строка. Блокировка — свойство личности
--      (решение по вопросу В-8 приёмки), и сведение потребовало бы решить, чем
--      становится человек, заблокированный в одном аккаунте и активный в
--      другом. Любой из двух ответов меняет доступ: «активен» снимает
--      блокировку (IAM-ID-1-72 это прямо запрещает), «заблокирован» отнимает
--      доступ там, где его не отнимали. Это продуктовое решение, и миграция не
--      вправе принять его за владельца;
--
--   2. в группе больше одной ACTIVE-строки. Это две РАЗНЫЕ внешние личности на
--      одной почте; сведение отняло бы у человека один из двух способов войти.
--
-- Отказ — не осторожность, а отсутствие исхода: у обеих групп нет верного
-- ответа, который миграция могла бы вычислить. Отказ громкий и называет число,
-- поэтому «мы про это не подумали» отличимо от «этого не было».
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ЗЕРКАЛО ПРАВИТСЯ ЗДЕСЬ ЖЕ, А НЕ ОТДЕЛЬНО
--
-- Зеркало S1 (470001) на всякой правке строки снимает членства, ведущие не в
-- тот аккаунт, что стоит в колонке: `DELETE … WHERE account_id <> NEW.account_id`.
-- Пока членство у человека одно, это верно. Как только перенос даёт человеку
-- второе, ЛЮБАЯ правка его строки — активация первым входом, блокировка, смена
-- отображаемого имени — уничтожает перенесённое членство молча.
--
-- То есть без правки зеркала перенос отменяется первым же входом человека и
-- переносом не является. Разносить их по двум изменениям значило бы оставить
-- дерево в состоянии, где работа предыдущего шага снимается следующим действием
-- пользователя.

-- +goose Up

-- ─────────────────────────────────────────────────────────────────────────────
-- Часть 1. Зеркало становится ДОБАВЛЯЮЩИМ.
--
-- Снята одна ветвь — снятие членств, ведущих в другой аккаунт. Всё остальное
-- воспроизведено дословно: функция пересоздаётся целиком, потому что заменить в
-- ней одну ветвь нечем.
--
-- Прежний `DELETE` защищал от смены аккаунта в строке. Защита остаётся ненужной
-- по той же причине, по какой она была написана «на всякий случай»: принадлежность
-- объявлена hard-immutable, ни один путь записи её не меняет. Но даже если бы
-- менял — снятие ЧУЖИХ членств не является верным ответом на смену колонки после
-- того, как членства перестали быть проекцией строки: колонка называет одно
-- членство из многих, а не все.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.membership_mirror_from_user() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO kacho_iam.memberships (id, user_id, account_id, state, invited_by, created_at, updated_at)
    VALUES (kacho_iam.membership_mirror_id(NEW.id, NEW.account_id),
            NEW.id,
            NEW.account_id,
            CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END,
            NEW.invited_by,
            NEW.created_at,
            now())
    ON CONFLICT (user_id, account_id) DO UPDATE
       SET state      = EXCLUDED.state,
           invited_by = EXCLUDED.invited_by,
           updated_at = now()
     WHERE kacho_iam.memberships.state      IS DISTINCT FROM EXCLUDED.state
        OR kacho_iam.memberships.invited_by IS DISTINCT FROM EXCLUDED.invited_by;

    -- Идентификатор членства в DO UPDATE намеренно не трогается: активация
    -- меняет состояние, а не идентичность.
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- ─────────────────────────────────────────────────────────────────────────────
-- Часть 2. Сведение строк и перенос прав.
-- +goose StatementBegin
DO $merge$
DECLARE
    n_groups        bigint;
    n_blocked_grp   bigint;
    n_multiactive   bigint;
    n_losers        bigint;
    n_users_before  bigint;
    n_users_after   bigint;
    n_moved_members bigint;
    n_moved_grants  bigint;
    n_token_debris  bigint;
    n_dangling      bigint;
BEGIN
    SELECT count(*) INTO n_users_before FROM kacho_iam.users;

    -- Группы дублей по почте. lower() — тот же регистр, каким их различает
    -- существующий ключ `users_account_email_unique`.
    CREATE TEMP TABLE merge_groups ON COMMIT DROP AS
    SELECT lower(email) AS email_key, count(*) AS rows_in_group
      FROM kacho_iam.users
     GROUP BY lower(email)
    HAVING count(*) > 1;

    SELECT count(*) INTO n_groups FROM merge_groups;

    -- ── границы решаемого: отказ громкий и с числом ──────────────────────────
    -- Предикат назван ТЕМ, ЧТО ОН ЗНАЧИТ: сведение умеет рассуждать ровно о двух
    -- состояниях — «активен» и «приглашён». Любое третье оно рассуждать не умеет,
    -- и перечислять их поимённо значило бы промолчать при появлении четвёртого.
    -- Сегодня третье ровно одно, и в отказе ниже оно названо словами.
    SELECT count(*) INTO n_blocked_grp
      FROM merge_groups g
     WHERE EXISTS (SELECT 1 FROM kacho_iam.users u
                    WHERE lower(u.email) = g.email_key
                      AND u.invite_status NOT IN ('ACTIVE', 'PENDING'));

    IF n_blocked_grp > 0 THEN
        RAISE EXCEPTION
            'сведение строк личности: % групп(ы) дублей содержат заблокированную строку. '
            'Блокировка — свойство личности, и чем становится человек, заблокированный в '
            'одном аккаунте и активный в другом, решает владелец продукта, а не миграция: '
            'любой из двух ответов меняет доступ. Разведите такие почты вручную и повторите',
            n_blocked_grp;
    END IF;

    SELECT count(*) INTO n_multiactive
      FROM merge_groups g
     WHERE (SELECT count(*) FROM kacho_iam.users u
             WHERE lower(u.email) = g.email_key AND u.invite_status = 'ACTIVE') > 1;

    IF n_multiactive > 0 THEN
        RAISE EXCEPTION
            'сведение строк личности: у % почт(ы) больше одной активной строки — это две '
            'разные внешние личности на одной почте, и сведение отняло бы у человека один '
            'из двух способов войти. Решается владельцем продукта, не миграцией',
            n_multiactive;
    END IF;

    -- ── выбор канонической строки ────────────────────────────────────────────
    -- Старейшая ACTIVE по почте — та, в которую край резолвит токен и на
    -- которую права уже выданы. Порядок доопределён до ТОТАЛЬНОГО (`id`
    -- последним ключом): при совпадении отметок времени выбор обязан быть
    -- воспроизводимым, иначе два прогона на одинаковых данных дадут разные
    -- выжившие строки.
    CREATE TEMP TABLE merge_plan ON COMMIT DROP AS
    SELECT u.id AS loser_id,
           c.id AS canonical_id,
           u.account_id AS loser_account_id
      FROM kacho_iam.users u
      JOIN merge_groups g ON g.email_key = lower(u.email)
      JOIN LATERAL (
            SELECT k.id
              FROM kacho_iam.users k
             WHERE lower(k.email) = g.email_key
             ORDER BY (k.invite_status = 'ACTIVE') DESC, k.created_at ASC, k.id ASC
             LIMIT 1
           ) c ON true
     WHERE u.id <> c.id;

    SELECT count(*) INTO n_losers FROM merge_plan;

    IF n_losers = 0 THEN
        RAISE NOTICE 'сведение строк личности: групп дублей %, снимаемых строк 0 — '
                     'сводить нечего (осмотрено строк %)', n_groups, n_users_before;
        RETURN;
    END IF;

    -- ── предпосылка снятия: у снимаемой строки нет своих токенов и сессий ────
    -- Снимаемая строка ни разу не входила, поэтому внешней личности у неё нет, а
    -- значит нет ни выпущенных токенов, ни сессий, ни OAuth-клиентов. Это
    -- ПРОВЕРЯЕТСЯ, а не предполагается: если предпосылка неверна, каскад снял бы
    -- отзывы токенов — то есть тихо ВЕРНУЛ бы доступ отозванному.
    SELECT (SELECT count(*) FROM kacho_iam.user_token_revocations r
             WHERE r.user_id IN (SELECT loser_id FROM merge_plan))
         + (SELECT count(*) FROM kacho_iam.refresh_token_counters f
             WHERE f.user_id IN (SELECT loser_id FROM merge_plan))
         + (SELECT count(*) FROM kacho_iam.user_oauth_clients o
             WHERE o.user_id IN (SELECT loser_id FROM merge_plan))
      INTO n_token_debris;

    IF n_token_debris > 0 THEN
        RAISE EXCEPTION
            'сведение строк личности: у снимаемых строк % записей о токенах, счётчиках или '
            'клиентах. Снятие строки унесло бы их каскадом, а среди них бывают ОТЗЫВЫ — '
            'то есть сведение вернуло бы доступ отозванному. Предпосылка «снимаемая строка '
            'ни разу не входила» не выполняется, и продолжать нельзя',
            n_token_debris;
    END IF;

    -- ── членства снимаемых строк переезжают на выжившую ──────────────────────
    WITH moved AS (
        INSERT INTO kacho_iam.memberships (id, user_id, account_id, state, invited_by, created_at, updated_at)
        SELECT kacho_iam.membership_mirror_id(p.canonical_id, m.account_id),
               p.canonical_id, m.account_id, m.state, m.invited_by, m.created_at, now()
          FROM merge_plan p
          JOIN kacho_iam.memberships m ON m.user_id = p.loser_id
        ON CONFLICT (user_id, account_id) DO NOTHING
        RETURNING 1)
    SELECT count(*) INTO n_moved_members FROM moved;

    -- Членства снимаемой строки снимаются ЯВНО и ДО неё самой. Иначе их унёс бы
    -- каскад, а сторож 472002 на каскадном снятии смолчал бы (он коротко
    -- замыкается, когда строки человека уже нет) — то есть перенос прошёл бы,
    -- ни разу не спросив, не осиротил ли он право. Здесь сторож спрашивает: к
    -- этому моменту выдачи уже переставлены ниже… — поэтому снятие идёт ПОСЛЕ
    -- переноса выдач.

    -- ── выдачи переезжают на выжившую строку, СОХРАНЯЯ свою область ──────────
    -- Область не трогается ни в одном стейтменте: у выдачи она своя
    -- (`resource_type`/`resource_id`), и переезд субъекта её не касается. Именно
    -- это и означает «право остаётся в границах того аккаунта, где выдано».

    -- Множественная проекция. Первичный ключ — (binding_id, subject_type,
    -- subject_id), поэтому строка, где выживший УЖЕ назван субъектом той же
    -- выдачи, снимается вместо переставления: иначе UPDATE упёрся бы в ключ.
    DELETE FROM kacho_iam.access_binding_subjects s
     USING merge_plan p
     WHERE s.subject_type = 'user'
       AND s.subject_id = p.loser_id
       AND EXISTS (SELECT 1 FROM kacho_iam.access_binding_subjects t
                    WHERE t.binding_id = s.binding_id
                      AND t.subject_type = 'user'
                      AND t.subject_id = p.canonical_id);

    WITH repointed AS (
        UPDATE kacho_iam.access_binding_subjects s
           SET subject_id = p.canonical_id
          FROM merge_plan p
         WHERE s.subject_type = 'user' AND s.subject_id = p.loser_id
        RETURNING 1)
    SELECT count(*) INTO n_moved_grants FROM repointed;

    -- Легаси-одиночная проекция того же факта.
    UPDATE kacho_iam.access_bindings b
       SET subject_id = p.canonical_id
      FROM merge_plan p
     WHERE b.subject_type = 'user' AND b.subject_id = p.loser_id;

    -- ── прочие ссылки на снимаемую строку ────────────────────────────────────
    -- Снимаемая и выжившая — ОДИН человек, поэтому ссылки переставляются, а не
    -- снимаются: владение аккаунтом сохраняется за тем же человеком, а не
    -- передаётся другому (глагола передачи владения в продукте нет).
    UPDATE kacho_iam.accounts a
       SET owner_user_id = p.canonical_id
      FROM merge_plan p WHERE a.owner_user_id = p.loser_id;

    UPDATE kacho_iam.users u
       SET invited_by = p.canonical_id
      FROM merge_plan p WHERE u.invited_by = p.loser_id;

    UPDATE kacho_iam.memberships m
       SET invited_by = p.canonical_id
      FROM merge_plan p WHERE m.invited_by = p.loser_id;

    UPDATE kacho_iam.session_revocations r
       SET user_id = p.canonical_id
      FROM merge_plan p WHERE r.user_id = p.loser_id;

    UPDATE kacho_iam.user_oauth_clients o
       SET created_by_user_id = p.canonical_id
      FROM merge_plan p WHERE o.created_by_user_id = p.loser_id;

    UPDATE kacho_iam.service_account_oauth_clients o
       SET created_by_user_id = p.canonical_id
      FROM merge_plan p WHERE o.created_by_user_id = p.loser_id;

    UPDATE kacho_iam.recovery_completions rc
       SET user_id = p.canonical_id
      FROM merge_plan p WHERE rc.user_id = p.loser_id;

    -- Кластерная выдача: если выживший её уже держит, дубль снимается, иначе
    -- переставляется. Право остаётся у того же человека и не размножается.
    DELETE FROM kacho_iam.cluster_admin_grants g
     USING merge_plan p
     WHERE g.subject_type = 'user'
       AND g.subject_id = p.loser_id
       AND EXISTS (SELECT 1 FROM kacho_iam.cluster_admin_grants t
                    WHERE t.cluster_id = g.cluster_id
                      AND t.subject_type = 'user'
                      AND t.subject_id = p.canonical_id);

    UPDATE kacho_iam.cluster_admin_grants g
       SET subject_id = p.canonical_id
      FROM merge_plan p
     WHERE g.subject_type = 'user' AND g.subject_id = p.loser_id;

    -- Журнал изменений субъекта ведёт материализацию. Строки снимаемого
    -- субъекта переставляются на выжившего: изменение по-прежнему подлежит
    -- применению, только уже на сведённой личности.
    UPDATE kacho_iam.subject_change_outbox o
       SET subject_id = p.canonical_id
      FROM merge_plan p WHERE o.subject_id = p.loser_id;

    -- Материализованные факты снимаемого субъекта снимаются: их источник
    -- переехал, и реконсайлер выведет факты выжившего заново. Снятие
    -- fail-closed — оно НЕ может расширить доступ, в отличие от переставления.
    DELETE FROM kacho_iam.relation_fact f
     USING merge_plan p
     WHERE f.subject = 'user:' || p.loser_id;

    -- Отзывы чеканенных токенов НЕ трогаются намеренно: запись отзыва,
    -- переставленная или снятая, — это возврат доступа, а предъявить токен
    -- снятой личности всё равно некому. Оставить строку безопасно, снять — нет.

    -- ── членства снимаемых строк снимаются, сторож 472002 спрашивает ─────────
    DELETE FROM kacho_iam.memberships m
     USING merge_plan p WHERE m.user_id = p.loser_id;

    -- ── и сами строки ────────────────────────────────────────────────────────
    DELETE FROM kacho_iam.users u
     USING merge_plan p WHERE u.id = p.loser_id;

    -- ── перепись и проверка полноты ──────────────────────────────────────────
    SELECT count(*) INTO n_users_after FROM kacho_iam.users;

    SELECT (SELECT count(*) FROM kacho_iam.access_bindings b
             WHERE b.subject_type = 'user'
               AND b.subject_id IN (SELECT loser_id FROM merge_plan))
         + (SELECT count(*) FROM kacho_iam.access_binding_subjects s
             WHERE s.subject_type = 'user'
               AND s.subject_id IN (SELECT loser_id FROM merge_plan))
         + (SELECT count(*) FROM kacho_iam.cluster_admin_grants g
             WHERE g.subject_type = 'user'
               AND g.subject_id IN (SELECT loser_id FROM merge_plan))
         + (SELECT count(*) FROM kacho_iam.subject_change_outbox o
             WHERE o.subject_id IN (SELECT loser_id FROM merge_plan))
      INTO n_dangling;

    RAISE NOTICE 'сведение строк личности: групп дублей %, снято строк %, строк было %, '
                 'стало %, членств переехало %, выдач переставлено %, висячих ссылок %',
                 n_groups, n_losers, n_users_before, n_users_after,
                 n_moved_members, n_moved_grants, n_dangling;

    IF n_users_after <> n_users_before - n_losers THEN
        RAISE EXCEPTION
            'сведение строк личности: строк было %, снято %, стало % — сведение тронуло '
            'строки, которых не планировало', n_users_before, n_losers, n_users_after;
    END IF;

    -- Ссылка на снятую строку — это право, субъект которого не резолвится: оно
    -- не действует ни для кого и при этом выглядит выданным. Утверждение
    -- проверяется здесь, а не оставляется обзору диффа.
    IF n_dangling <> 0 THEN
        RAISE EXCEPTION
            'сведение строк личности: осталось % ссылок на снятые строки — перенос '
            'неполон, и часть прав повисла без субъекта', n_dangling;
    END IF;
END
$merge$;
-- +goose StatementEnd

-- +goose Down

-- Сведённые строки обратно не разводятся: снятая строка личности не
-- восстанавливается, а её права уже переехали. Откат возвращает ТОЛЬКО зеркало —
-- то есть ту часть, которая обратима.
--
-- Это сказано прямо, а не умолчано: стадия S2 — первая, чья часть необратима, и
-- знать это до применения важнее, чем иметь формально симметричный шаг.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.membership_mirror_from_user() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM kacho_iam.memberships
     WHERE user_id = NEW.id
       AND account_id <> NEW.account_id;

    INSERT INTO kacho_iam.memberships (id, user_id, account_id, state, invited_by, created_at, updated_at)
    VALUES (kacho_iam.membership_mirror_id(NEW.id, NEW.account_id),
            NEW.id,
            NEW.account_id,
            CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END,
            NEW.invited_by,
            NEW.created_at,
            now())
    ON CONFLICT (user_id, account_id) DO UPDATE
       SET state      = EXCLUDED.state,
           invited_by = EXCLUDED.invited_by,
           updated_at = now()
     WHERE kacho_iam.memberships.state      IS DISTINCT FROM EXCLUDED.state
        OR kacho_iam.memberships.invited_by IS DISTINCT FROM EXCLUDED.invited_by;

    RETURN NULL;
END;
$$;
-- +goose StatementEnd
