-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 20260902062000_authored_verb_dictionary_separates_from_the_per_object_one —
-- АВТОРСКИЙ словарь глаголов отделяется от ПООБЪЕКТНОГО.
--
-- Задача продукта #1863. Решение принято по ban #18 и записано в теле задачи
-- (исход А из двух).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО НЕВЕРНО СЕГОДНЯ
--
-- Ключ `role_rule_ref_verb_fk` (20260901113757) судит АВТОРСКИЙ глагол правила
-- роли по таблице `kacho_iam.catalog_verb`. Но таблица посеяна из
-- `authzmap.typeVerbRelations` — из набора ПООБЪЕКТНЫХ отношений типа. Это
-- разные множества, и различаются они ровно на `create`.
--
-- Следствие наблюдалось сквозным прогоном: посев матрицы прав падал на создании
-- роли `verbs: ["create", "list"]` на `storage.volumes` отказом
-- «verbs: create is not a live verb of resource volumes», и суиты не запускались
-- вовсе. Тот же пример — `verbs = ["get", "list", "create", "update"]` — показан
-- клиенту двумя страницами документации провайдера. Продукт отвергал собственный
-- документированный пример.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ `create` — И ПОЧЕМУ ОН ОДИН
--
-- Глагольное отношение называет операцию НАД ОБЪЕКТОМ, на который указывает
-- кортеж. «Создать» такой операцией не является: в момент решения объекта ещё
-- нет, поэтому вопрос всегда задают родителю. Каталог прав это и делает — записи
-- с глаголом `create` гейтятся ярусом записи на родителе либо ярусом
-- администратора кластера, пообъектного `v_create` среди них нет ни одного
-- (замер и решение — services/iam/docs/engineering/architecture/verb-create-withdrawal.md).
--
-- Остальные четыре канонических класса пообъектный референт ИМЕЮТ там, где тип
-- его объявил; где не объявил — это осознанное сужение ТИПА, а не структурная
-- невозможность. Поэтому ярусным объявляется ровно один класс, и «за компанию»
-- набор не расширяется: каждая лишняя строка открыла бы авторскому правилу ярус
-- на родителе, которого ключ сегодня не пропускает.
--
-- Исключение у `create` есть и правила не отменяет: `registry.registries`
-- объявляет `v_create` ПООБЪЕКТНО (семантика контейнерная — «создать репозиторий
-- в этом пространстве имён» есть операция над объектом реестра). Поэтому ярусной
-- строки у этой пары нет: производитель посева кладёт её только там, где
-- пообъектной нет.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕМ ЭТО НЕ ЯВЛЯЕТСЯ — РАСШИРЕНИЕМ ПРАВ
--
-- Пообъектный `v_create` НЕ воскрешается. Признак `per_object` читает
-- `internal/catalog` (`NewFacts`), и ярусная строка в набор глаголов типа не
-- входит — то есть ни `GrantedVerbs`, ни проекция `role_verb`, ни реконсайлер о
-- ней не узнают. Меняется ПРЕДМЕТ СВЕРКИ ключа, а не набор выданного.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ КОЛОНКА, А НЕ ВТОРАЯ ТАБЛИЦА
--
-- Ключ `role_rule_ref_verb_fk` ссылается на `catalog_verb (module, resource,
-- verb, live)` и обязан пропускать ОБЕ половины словаря. Вторая таблица
-- потребовала бы второго ключа, а два ключа на одном столбце `verb` означают
-- «строка есть хотя бы в одной» — а это дизъюнкция, которой внешним ключом не
-- выразить: `MATCH SIMPLE` проверяет каждый ключ отдельно, и правило,
-- называющее глагол из первой таблицы, отвергалось бы вторым ключом.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ НОВАЯ МИГРАЦИЯ, А НЕ ПРАВКА ПОСЕВА
--
-- 20260901113757 применена, и правке не подлежит (запрет #5). Расхождение
-- литерала с ней делает видимым гейт дерева: он сверяет ПООБЪЕКТНУЮ половину с
-- посевом той миграции, ЯРУСНУЮ — с посевом этой, и обе стороны выводит из
-- одного производителя `authzmap.CatalogSeedVerbs()`.

-- +goose Up

-- ── ПРИЗНАК СЛОВАРЯ ──────────────────────────────────────────────────────────
--
-- Умолчание `true` — не удобство, а утверждение о существующих 109 строках: они
-- посеяны из набора пообъектных отношений и пообъектными являются все до одной.
-- Колонка ОБЫЧНАЯ, а не генерируемая: вывести признак не из чего — он и есть
-- то новое, чего в строке не было.
ALTER TABLE kacho_iam.catalog_verb
  ADD COLUMN per_object boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN kacho_iam.catalog_verb.per_object IS
  'Строка ПРОИЗВОДИТ пообъектное отношение v_<verb> на своём типе. Ложь — глагол законен АВТОРСКИ и не даёт кортежа ни на одном объекте: его действие несёт ярус на родителе. Читается internal/catalog.NewFacts: ярусная строка в набор глаголов типа НЕ входит, поэтому не материализуется.';

COMMENT ON TABLE kacho_iam.catalog_verb IS
  'Каталог глаголов ресурса, ДВУМЯ половинами: пообъектная (per_object = true) — источник посева authzmap.typeVerbRelations; ярусная (per_object = false) — классы действия без пообъектного референта by construction (create). Ключ role_rule_ref_verb_fk судит АВТОРСКИЙ глагол правила и ссылается на обе; набор глаголов ТИПА остаётся пообъектным.';

-- ── ЯРУСНАЯ ПОЛОВИНА СЛОВАРЯ ─────────────────────────────────────────────────
--
-- Перечень ВЫВЕДЕН единственным производителем (`authzmap.CatalogSeedVerbs()`,
-- строки с `PerObject = false`), а не выписан: второй производитель того же
-- перечня разошёлся бы с первым молча. Согласие этого текста с производителем
-- держит гейт дерева, а не аккуратность автора.
--
-- Ресурсов 27, ярусных строк 26: у `registry.registries` глагол `create`
-- объявлен пообъектно, и второй строки та пара не получает — первичный ключ
-- (module, resource, verb) один.
INSERT INTO kacho_iam.catalog_verb (module, resource, verb, per_object) VALUES
  ('compute', 'guestAccessKey', 'create', false),
  ('compute', 'instance', 'create', false),
  ('compute', 'placementGroup', 'create', false),
  ('iam', 'accessBinding', 'create', false),
  ('iam', 'account', 'create', false),
  ('iam', 'group', 'create', false),
  ('iam', 'project', 'create', false),
  ('iam', 'role', 'create', false),
  ('iam', 'serviceAccount', 'create', false),
  ('iam', 'user', 'create', false),
  ('loadbalancer', 'listeners', 'create', false),
  ('loadbalancer', 'networkLoadBalancers', 'create', false),
  ('loadbalancer', 'targetGroups', 'create', false),
  ('registry', 'repositories', 'create', false),
  ('storage', 'images', 'create', false),
  ('storage', 'snapshots', 'create', false),
  ('storage', 'volumes', 'create', false),
  ('vpc', 'address', 'create', false),
  ('vpc', 'addressPool', 'create', false),
  ('vpc', 'cidrGroup', 'create', false),
  ('vpc', 'gateway', 'create', false),
  ('vpc', 'network', 'create', false),
  ('vpc', 'networkInterface', 'create', false),
  ('vpc', 'routeTable', 'create', false),
  ('vpc', 'securityGroup', 'create', false),
  ('vpc', 'subnet', 'create', false);

-- ── САМОПРОВЕРКА ИСХОДА ──────────────────────────────────────────────────────
--
-- Миграция проверяет СВОЙ результат и роняет применение при недостижении.
-- Образец — 20260901113757. Утверждений ЧЕТЫРЕ, и каждое закрывает своё:
-- счёт по ОБЕИМ половинам порознь (общее число скрыло бы перетекание строк из
-- одной в другую, а это и есть тот дефект, ради которого признак заведён) ·
-- покрытие (у какого ресурса глагола не хватает) · неприкосновенность выдачи ·
-- перепись, печатаемая всегда.
-- +goose StatementBegin
DO $$
DECLARE
    live_verbs     int;
    per_object_v   int;
    tier_only_v    int;
    uncovered_res  int;
    dangling_verb  int;
BEGIN
    SELECT count(*) INTO live_verbs   FROM kacho_iam.catalog_verb WHERE live;
    SELECT count(*) INTO per_object_v FROM kacho_iam.catalog_verb WHERE live AND per_object;
    SELECT count(*) INTO tier_only_v  FROM kacho_iam.catalog_verb WHERE live AND NOT per_object;

    IF live_verbs <> 135 OR per_object_v <> 109 OR tier_only_v <> 26 THEN
        RAISE EXCEPTION
            'посев словаря не в полном объёме: живых пар % (ждали 135), пообъектных % '
            '(ждали 109), ярусных % (ждали 26) — неполный авторский словарь продолжает '
            'отвергать документированный пример роли, а лишняя ПООБЪЕКТНАЯ строка вернула '
            'бы материализацию снятого отношения (kacho#1863)',
            live_verbs, per_object_v, tier_only_v;
    END IF;

    -- ПОКРЫТИЕ, а не только счёт. Числа выше падают и на пропущенной строке, и
    -- на лишней, но не говорят, ЧЕГО не хватает; это утверждение говорит: класс
    -- действия, объявленный ярусным, обязан быть авторски законен у КАЖДОГО
    -- живого ресурса — половиной словаря неважно какой. Ровно это и есть предмет
    -- задачи: документированный пример роли называет `create` на ресурсе, и
    -- ресурс без такой строки продолжал бы его отвергать.
    --
    -- Проверка НЕ вакуумна: пропусти посев выше один ресурс — она назовёт число.
    -- Проверять «нет пары в обеих половинах» было бы вакуумно by construction:
    -- первичный ключ (module, resource, verb) двух таких строк не допускает.
    SELECT count(*) INTO uncovered_res
      FROM kacho_iam.catalog_resource cr
     WHERE cr.live
       AND NOT EXISTS (SELECT 1 FROM kacho_iam.catalog_verb cv
                        WHERE cv.module = cr.module AND cv.resource = cr.resource
                          AND cv.verb = 'create' AND cv.live);
    IF uncovered_res <> 0 THEN
        RAISE EXCEPTION
            'живых ресурсов без авторского `create`: % — правило роли, назвавшее его, '
            'по-прежнему отвергается ключом, то есть предмет задачи закрыт не весь '
            '(kacho#1863)', uncovered_res;
    END IF;

    -- Выдача этой миграцией не трогается, и это утверждение, а не надежда:
    -- ярусная строка в набор типа не входит, поэтому число висячих пар выдачи
    -- обязано остаться нулём — тем же, каким его оставила 20260901113757.
    SELECT count(*) INTO dangling_verb
      FROM kacho_iam.role_verb rv
     WHERE NOT EXISTS (SELECT 1 FROM kacho_iam.catalog_resource cr
                        WHERE cr.dotted = rv.object_type AND cr.live)
        OR NOT EXISTS (SELECT 1 FROM kacho_iam.catalog_verb cv
                        WHERE cv.module || '.' || cv.resource = rv.object_type
                          AND cv.verb = rv.verb AND cv.live AND cv.per_object);
    IF dangling_verb <> 0 THEN
        RAISE EXCEPTION
            'висячих пар выдачи после разделения словарей: % — разделение обязано '
            'менять предмет сверки ключа, а не набор выданного (kacho#1863)', dangling_verb;
    END IF;

    -- Перепись печатается ВСЕГДА: «ноль расхождений» обязано быть отличимо от
    -- «ноль прочитанного».
    RAISE NOTICE 'словарь глаголов: живых пар %, пообъектных %, ярусных %, ресурсов без авторского create %, висячих выдач %',
        live_verbs, per_object_v, tier_only_v, uncovered_res, dangling_verb;
END;
$$;
-- +goose StatementEnd

-- +goose Down
--
-- ОТКАТ ОТБИРАЕТ У АРЕНДАТОРА ЖИВОЕ ОБЪЯВЛЕНИЕ, и это сказано прямо.
--
-- Роль, назвавшая `create`, держит строку `role_rule_ref` с ссылкой на ярусную
-- строку словаря. Ключ `role_rule_ref_verb_fk` объявлен `ON DELETE NO ACTION`,
-- поэтому удаление ниже ОТКАЖЕТ, пока такая роль существует, — откат не тихий и
-- не частичный. Снять роли обязан администратор, и это его решение, а не
-- побочный эффект отката.
DELETE FROM kacho_iam.catalog_verb WHERE NOT per_object;

ALTER TABLE kacho_iam.catalog_verb DROP COLUMN per_object;

COMMENT ON TABLE kacho_iam.catalog_verb IS
  'Каталог глаголов, объявленных типом. Источник посева — authzmap.typeVerbRelations (109 пар), переведённых в словарь каталога единственным переходником.';
