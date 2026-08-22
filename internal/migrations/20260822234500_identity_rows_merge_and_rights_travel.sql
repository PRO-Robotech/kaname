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
-- `<задача><порядок>`; уточнением #921 законны ОБЕ формы, а от файла,
-- ДОБАВЛЕННОГО относительно ствола, гейт `TestNewMigrationOutranksEveryAppliedOne`
-- требует именно метку времени. Этого требования довольно, и оно здесь одно.
--
-- Здесь стояло второе основание — «мигратор такую версию на живой базе не
-- применяет, роняя старт». Оно НЕВЕРНО и снято: все семь накатчиков дерева зовут
-- goose с `WithAllowMissing()`, то есть номер меньше применённого применяется, а
-- не роняет старт. Предикат, которым это перемеряется за секунду:
-- `git grep -n WithAllowMissing -- '*.go'` — семь попаданий, по одному на сервис.
--
-- Второе основание — по существу, и оно своё: миграция обязана встать ПОСЛЕ всей
-- цепи, потому что читает области субъекта выдачи
-- (`access_binding_subjects.resource_type/resource_id`, 732001). Номер по задаче
-- #472 поставил бы её перед ними, и перенос работал бы с таблицей, у которой этих
-- колонок ещё нет.
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
-- ТРИ группы миграция сводить ОТКАЗЫВАЕТСЯ и роняет прогон, называя число:
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
--      одной почте; сведение отняло бы у человека один из двух способов войти;
--
--   3. выдача-дубль НАЗЫВАЕТ СУБЪЕКТОМ ТРЕТЬЕГО. Одинаковую живую выдачу двух
--      сводимых строк миграция разрешает сама (ниже), но если у такой выдачи
--      среди субъектов есть кто-то, кроме сводимой личности, то снять её значит
--      отнять право у постороннего, а оставить — упереться в ключ. Кому из двух
--      выдач остаться жить, решает владелец продукта.
--
-- Отказ — не осторожность, а отсутствие исхода: ни у одной из трёх групп нет
-- верного ответа, который миграция могла бы вычислить. Отказ громкий и называет
-- число, поэтому «мы про это не подумали» отличимо от «этого не было».
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕТВЁРТАЯ ФОРМА РЕШАЕТСЯ, А НЕ ОТВЕРГАЕТСЯ: ОДНО И ТО ЖЕ ПРАВО ДВАЖДЫ
--
-- Каноническая строка и дубль могут держать ЖИВУЮ выдачу одной роли на один и
-- тот же объект: приглашение выдало право пер-аккаунтной строке, администратор
-- выдал то же право активной напрямую. Переставить субъект обеих на выжившую
-- нельзя — частичный ключ `access_bindings_active_grant_uniq` (пятёрка + слепок
-- цели, `WHERE revoked_at IS NULL`) допускает ровно одну живую.
--
-- Ответ у этой формы ЕСТЬ, и он не меняет ничьего доступа: право у человека
-- остаётся ровно одно и то же, лишняя запись гасится. Гасится ОТЗЫВОМ, а не
-- удалением, — тем же правилом, каким ту же коллизию разрешала 0003
-- (`status='REVOKED'`, `revoked_at=now()`, `revoked_by_user_id='system:identity-merge'`):
-- цепочка аудита обязана пережить сведение, иначе исчезает след того, что право
-- вообще выдавали. Выживает выдача канонической строки, а если её нет — старейшая
-- по `(created_at, id)`; порядок тотальный, поэтому два прогона на одинаковых
-- данных гасят одно и то же.
--
-- Здесь этой ветви не было, и форма падала СЫРЫМ 23505 из-под легаси-проекции:
-- goose ронял накат, сервис не поднимался, а оператор читал сообщение Postgres
-- вместо предмета. Асимметрия была видна в самом блоке: для множественной
-- проекции дедуплицирующий `DELETE` написан, для легаси-одиночной — нет.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ОКНО, КОТОРОЕ ЭТА МИГРАЦИЯ ОТКРЫВАЕТ — НАЗВАНО, А НЕ УМОЛЧАНО
--
-- Цепь областей ведёт от личности к аккаунту ЧЕРЕЗ ЧЛЕНСТВО (944001, ветвь 4a) и
-- состояние членства не читает. Пока членство у человека одно, у объекта личности
-- ровно один предок-аккаунт. Сведение даёт человеку ВТОРОЕ членство — значит у
-- объекта личности становится два предка, и `iam_user.super_admin: admin from
-- account` начинает выполняться администратором ОБОИХ аккаунтов.
--
-- Что это значит для арендатора, дословно: администратор второго аккаунта
-- получает над ЖИВОЙ личностью человека те же глаголы (`v_get`/`v_list`/
-- `v_update`/`v_delete`), какие до сведения имел над её строкой-приглашением в
-- своём аккаунте. Разница не в перечне глаголов, а в предмете: строка-приглашение
-- была мертва и войти по ней было нельзя, а живая личность — та, которой человек
-- входит везде. Блокировка, поставленная вторым администратором, действует и в
-- первом аккаунте.
--
-- ЭТО НЕ ПОБОЧНЫЙ ЭФФЕКТ, А ЗАЯВЛЕННОЕ СЛЕДСТВИЕ ЛАНДШАФТА: 944001 назвала его
-- заранее («переезд глагола делает его конструируемым в тот же день — и вместе с
-- ним обязана приземлиться СМЕНА ОБЪЕКТА: аккаунт-скоупным объектом становится
-- ЧЛЕНСТВО, а не личность»), и три поверхности дерева УЖЕ требуют, чтобы у
-- человека со вторым членством оба аккаунта назывались
-- (`membership_is_the_account_source_integration_test.go`, стадия S3, #471).
-- Сузить цепь здесь значило бы отменить landed-решение соседней линии, а не
-- закрыть окно.
--
-- ПОЧЕМУ ОКНО ОБЪЯВЛЕНО, А НЕ ЗАКРЫТО ЗДЕСЬ ЖЕ — ЦЕНА ИЗМЕРЕНА. Закрыть его
-- значит завести тип `iam_membership` со СВОИМ полным набором глаголов и снять
-- аккаунт-скоуп с личности. Гейт дрейфа модели безусловен и двусторонен
-- (`authzmap/fga_model_drift_test.go`, R-1/R-2), поэтому тип без пары в каталоге
-- разрешений не заводится, а пара требует контракта и глаголов членства — это
-- стадия S3 линии #471. Замер радиуса по уже существующему аккаунт-скоупному типу
-- (`git grep -rl iam_group` по go/sql/fga/proto/yaml): 66 файлов, из них 36 не
-- тестов, в 20 каталогах — от `pkg/authz` и края до посевных миграций и наборов
-- сквозных проб. Это стадия эпика, а не половина этой миграции; вносить её сюда
-- значило бы посадить половину модели прав (ban #14).
--
-- ПРЕДИКАТ СНЯТИЯ ОКНА — механический, не «когда дойдут руки»:
--   grep -c '^type iam_membership' proto/kacho/cloud/iam/v1/fga_model.fga   # сегодня 0
-- Проба `TestIntegration_MergeWidensTheIdentityScopeExactlyAsDeclared` объявляет
-- этот ноль СВОЕЙ предпосылкой и краснеет, как только тип появится: окно истекает
-- само, а не по чьей-то памяти.
--
-- ОКНО НАБЛЮДАЕМО НА ВЫКАТКЕ: число личностей, получивших дополнительный
-- аккаунт-предок, печатается ниже отдельной строкой (`личностей, чья область
-- расширилась`) — «ноль» обязано быть отличимо от «не считали».
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
    n_grant_shared  bigint;
    n_revoked_dups  bigint;
    n_widened       bigint;
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

    -- ── окно расширения области: СЧИТАЕТСЯ ДО переезда членств ──────────────
    -- Личность, у которой после переезда появится аккаунт-предок, какого у неё не
    -- было. Разбор — в шапке, §«ОКНО, КОТОРОЕ ЭТА МИГРАЦИЯ ОТКРЫВАЕТ»; здесь
    -- важно, что число печатается ВСЕГДА: «ноль» обязано быть отличимо от «не
    -- считали», а окно — заметно оператору на выкатке, а не только читателю
    -- шапки.
    SELECT count(DISTINCT p.canonical_id) INTO n_widened
      FROM merge_plan p
      JOIN kacho_iam.memberships m ON m.user_id = p.loser_id
     WHERE NOT EXISTS (SELECT 1 FROM kacho_iam.memberships c
                        WHERE c.user_id = p.canonical_id
                          AND c.account_id = m.account_id);

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

    -- ── КТО ЗДЕСЬ НЕ ДАЁТ ОСИРОТИТЬ ПРАВО — ПРОВЕРЕНО, А НЕ ВЫВЕДЕНО ─────────
    --
    -- Здесь стояло «сторож 472002 спрашивает, поэтому снятие членств идёт после
    -- переноса выдач». Это НЕВЕРНО, и порядок стейтментов ему безразличен.
    -- Сторож 472002 — отложенный constraint-триггер: он спрашивает на COMMIT, а к
    -- COMMIT строки человека уже нет, и срабатывает его собственное короткое
    -- замыкание (`IF NOT EXISTS (SELECT 1 FROM users …) THEN RETURN NULL`). В
    -- порядке этой миграции он МОЛЧИТ — при любом порядке снятия членств.
    --
    -- Не даёт осиротить право страж 0050 `principal_not_referenced_as_subject`:
    -- он BEFORE DELETE на строке человека и отвергает снятие 23503, пока та
    -- названа субъектом хотя бы одной выдачи — независимо от состояния выдачи и
    -- от того, снято ли членство. Поэтому перенос выдач обязан пройти ДО снятия
    -- строк, и это держится им.
    --
    -- Комментарий, называющий не того сторожа, приглашает следующего переставить
    -- стейтменты «раз тот всё равно поймает». Настоящий держатель закреплён
    -- пробой `TestIntegration_TheGuardAgainstOrphanedGrantsIsTheSubjectRef`:
    -- она показывает, что 0050 говорит, а 472002 на этой форме молчит — и что
    -- 472002 при этом ЖИВ (на форме, где строка человека остаётся, он говорит).

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

    -- ── одно и то же право дважды: лишняя живая выдача ГАСИТСЯ ОТЗЫВОМ ──────
    -- Разбор — в шапке, §«ЧЕТВЁРТАЯ ФОРМА РЕШАЕТСЯ, А НЕ ОТВЕРГАЕТСЯ». Класс
    -- эквивалентности — то, что различает частичный ключ
    -- `access_bindings_active_grant_uniq`: (роль, тип области, область, слепок
    -- цели) среди ЖИВЫХ выдач личности — канонической строки и всех её дублей.
    CREATE TEMP TABLE merge_grant_dups ON COMMIT DROP AS
    WITH kin AS (
        SELECT b.id, b.role_id, b.resource_type, b.resource_id, b.target_digest,
               b.created_at, k.canonical_id,
               (b.subject_id = k.canonical_id) AS already_canonical
          FROM kacho_iam.access_bindings b
          JOIN (SELECT canonical_id, canonical_id AS subject_id FROM merge_plan
                 UNION
                SELECT canonical_id, loser_id     FROM merge_plan) k
            ON k.subject_id = b.subject_id
         WHERE b.subject_type = 'user'
           AND b.revoked_at IS NULL
    )
    SELECT id, canonical_id
      FROM (SELECT kin.*,
                   row_number() OVER (
                     PARTITION BY kin.canonical_id, kin.role_id, kin.resource_type,
                                  kin.resource_id, kin.target_digest
                     ORDER BY kin.already_canonical DESC, kin.created_at ASC, kin.id ASC
                   ) AS rn
              FROM kin) ranked
     WHERE rn > 1;

    -- Гасить выдачу, среди субъектов которой есть ПОСТОРОННИЙ, миграция не
    -- вправе: отзыв снял бы право у того, кого сведение не касается. Это третья
    -- неразрешимая группа (см. шапку) — отказ громкий и с числом.
    SELECT count(*) INTO n_grant_shared
      FROM merge_grant_dups d
     WHERE EXISTS (
             SELECT 1
               FROM kacho_iam.access_binding_subjects s
              WHERE s.binding_id = d.id
                AND NOT (s.subject_type = 'user'
                         AND (s.subject_id = d.canonical_id
                              OR EXISTS (SELECT 1 FROM merge_plan p2
                                          WHERE p2.canonical_id = d.canonical_id
                                            AND p2.loser_id = s.subject_id))));

    IF n_grant_shared > 0 THEN
        RAISE EXCEPTION
            'сведение строк личности: % выдач(и)-дубля названы субъектом не только сводимой '
            'личности. Погасить такую выдачу значит отнять право у постороннего, оставить — '
            'упереться в ключ живой выдачи. Какая из двух одинаковых выдач остаётся жить, '
            'решает владелец продукта, не миграция: разведите их вручную и повторите',
            n_grant_shared;
    END IF;

    WITH revoked AS (
        UPDATE kacho_iam.access_bindings b
           SET status             = 'REVOKED',
               revoked_at         = now(),
               revoked_by_user_id = 'system:identity-merge'
          FROM merge_grant_dups d
         WHERE b.id = d.id
        RETURNING 1)
    SELECT count(*) INTO n_revoked_dups FROM revoked;

    -- Легаси-одиночная проекция того же факта. Живой выдачи-дубля к этому
    -- моменту не осталось, поэтому переставление не встречает ключа: погашенная
    -- выдача из-под `WHERE revoked_at IS NULL` вышла.
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
                 'стало %, членств переехало %, выдач переставлено %, выдач-дублей погашено %, '
                 'висячих ссылок %, личностей, чья область расширилась, %',
                 n_groups, n_losers, n_users_before, n_users_after,
                 n_moved_members, n_moved_grants, n_revoked_dups, n_dangling, n_widened;

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
