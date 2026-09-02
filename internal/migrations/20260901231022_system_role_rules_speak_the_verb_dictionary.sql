-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 20260901231022_system_role_rules_speak_the_verb_dictionary — правила системных
-- ролей называют ГЛАГОЛ так, как его называет каталог платформы.
--
-- Приёмка: services/iam/docs/engineering/acceptance/system-role-segments-resolve.md
-- (APPROVED круга 2). Сценарии IAM-SV-1-01 … IAM-SV-1-16. Задача продукта #1815.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО НЕВЕРНО СЕГОДНЯ
--
-- Правило роли адресует объект тремя сегментами — модуль, ресурс, глагол. После
-- 20260901113757 референт есть у всех трёх, и ключ `role_rule_ref_verb_fk`
-- отвергает глагол, которого каталог не несёт. Но ключ судит то, что через него
-- ПРОХОДИТ, а системная роль заводится сырым SQL миграции и через
-- `ReplaceRuleRefs` не проходит никогда. Поэтому у системной половины проверки
-- не было вовсе, и в ней жили ДВАДЦАТЬ объявлений, не резолвящихся ни в одно
-- право платформы: `read` — 14 троек, `listOperations` — 4, `getTargetStates` — 2.
--
-- Роль ОБЪЯВЛЯЕТ право, которого её собственная проекция не даёт. Арендатор,
-- читающий `vpc.network.view`, видит в правиле `read`; вердикт по её выдаче на
-- чтение отвечает через `get`. Право действует — но НЕ ПОТОМУ, что названо, а
-- потому что рядом названо другое. Роль, где такой глагол оказался бы
-- единственным, не дала бы ничего, и отказ был бы молчаливым: пустое соединение
-- неотличимо от честного «права нет».
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ЭТО НИЧЕГО НЕ ОТНИМАЕТ
--
-- Каноническая форма каждого из трёх глаголов названа не нами, а каталогом прав
-- края: `read` → `get`/`list`; `listOperations` → `list` (`v_list`);
-- `getTargetStates` → `get` (`v_get`). В КАЖДОМ затронутом правиле канонический
-- глагол УЖЕ назван, поэтому приведение схлопывается в снятие: набор глаголов
-- правила не расширяется ни на одно значение, а вычитается второе имя того, что
-- уже названо. Это и есть довод, которого не даёт формулировка «снять как
-- никогда не действовавшие»: мы не отнимаем.
--
-- Проекция вердикта не меняется ни на одну пару — она считается тем же
-- `authzmap.GrantedVerbs`, который эти глаголы уже отбрасывал
-- (IAM-SV-1-04). Ярус не меняется тоже: оба классификатора относят `read`,
-- `listoperations`, `gettargetstates` к наблюдателю вместе с `get` и `list`,
-- которые остаются (IAM-SV-1-05).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДИКАТ — «ГЛАГОЛА НЕТ В КАТАЛОГЕ», А НЕ СПИСОК ИЗ ТРЁХ
--
-- Миграция НЕ перечисляет `read`, `listOperations`, `getTargetStates`. Она
-- снимает всякий авторский глагол, которого не несёт `kacho_iam.catalog_verb` —
-- та самая таблица, на которую ссылается ключ. Список из трёх чинил бы
-- ЭКЗЕМПЛЯРЫ; предикат чинит КЛАСС. И список был бы ВТОРЫМ СЛОВАРЁМ, который
-- разойдётся с каталогом молча; чтение каталога вторым словарём быть не может
-- by construction.
--
-- ПОЛОС ДВЕ, И ИХ НЕЛЬЗЯ СХЛОПЫВАТЬ:
--
--   * КОНКРЕТНАЯ ПАРА (`module <> '*'` и ни один ресурс не `*`) — глагол
--     снимается, если у пары нет живой строки `catalog_verb`;
--   * ПОЛНАЯ ПОДСТАНОВКА (`module = '*'` и все ресурсы `*`) — глагол снимается,
--     если его нет НИ У ОДНОГО типа.
--
-- Схлопнуть в первую нельзя: у пары `*.*` строк каталога нет вовсе (в посеве
-- каталога подстановочных строк ноль), и первый предикат снял бы у ролей `view`
-- и `kacho-system.viewer` ВСЕ глаголы, включая `get` и `list`. Схлопнуть во
-- вторую тоже нельзя: тогда `addTargets` на `vpc.network` прошёл бы законным,
-- потому что его объявляет соседний тип.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- СРАВНЕНИЕ ИДЁТ ПО ПРИВЕДЁННОМУ ГЛАГОЛУ — ИНАЧЕ ПОЛОСА ОТНИМАЕТ ЖИВОЕ ПРАВО
--
-- Стороны нормализованы ПО-РАЗНОМУ, и это свойство схемы, а не соглашение:
-- каталог хранит глагол строго строчным (`CONSTRAINT catalog_verb_canonical
-- CHECK (verb = lower(btrim(verb)))`), а правила говорят ВЕРБЛЮЖЬИМ — решение
-- посева 0031 («collect the camelCase verbs per resource VERBATIM»).
--
-- Сравнение `verb = cv.verb` без приведения не совпало бы НИКОГДА, и полоса
-- конкретной пары сняла бы у `loadbalancer.target_manager` не только
-- `listOperations`, но и ЖИВЫЕ `addTargets` с `removeTargets`: это ровно два
-- глагола, которые в каталоге есть, а по авторскому написанию не нашлись бы.
-- Приводится ТОЛЬКО авторская сторона — у каталога приводить нечего.
-- Образец формы — 20260901113757:490, дословно.
--
-- Авторское написание ОСТАВШИХСЯ глаголов миграция НЕ переписывает: решение
-- 0031 «VERBATIM» не отменяется чужим изменением, и целевые наборы приёмки §2.1
-- записаны с сохранённым написанием.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕГО МИГРАЦИЯ НЕ ТРОГАЕТ, И ЭТО РЕШЕНИЯ, А НЕ ПРОПУСКИ
--
--   * `roles.permissions` — они говорят ДРУГИМ словарём: `listOperations` и
--     `getTargetStates` суть законные ДЕЙСТВИЯ каталога прав края, у них есть
--     производитель. Строки прав, называющие действие ВНЕ каталога прав
--     (`*.*.read` и его четырнадцать конкретных близнецов), — тот же класс на
--     ВТОРОЙ поверхности, с другим владельцем и другим предикатом; заведено
--     задачей продукта #1827 и здесь не чинится: смешение сделало бы вердикт
--     непрослеживаемым;
--   * `roles.id` / `roles.name` — выведены из имени и стоят в уже выданных
--     привязках; менять их значило бы завести новые роли и осиротить выдачи;
--   * `kacho_iam.access_bindings`, `kacho_iam.role_verb` — ни одного оператора:
--     кортежей и строк вердикта по снимаемым глаголам НЕ СУЩЕСТВУЕТ (обе полосы
--     эмиссии фильтруют через `domain.IsVerbOfType`), снимать нечего;
--   * `kacho_iam.role_rule_selectors` — отпечаток правила считается в Go
--     (`Rule.Fingerprint`), в SQL его не воспроизвести; досев на старте снимает
--     строку со старым отпечатком как отсутствующую в текущем наборе. Писать
--     сюда данные значило бы завести второе место, знающее соответствие (довод
--     513001, дословно).
--
-- ПОДСТАНОВОЧНЫЕ РОЛИ ПРАВЯТСЯ ТОЖЕ, и это решение. Предикат снятия задачи
-- (`role_grant_orphan WHERE source = 'rule_ref'` → 0) их не касается:
-- `RuleRefsOf` подстановку пропускает, строк проекции у неё нет, следа нет тоже.
-- Именно поэтому их надо править здесь: `read` в правиле роли `view` невидим и
-- ключу, и гейту дерева — то есть это та же ложь в единственном месте, где её
-- никто не увидит. Правок 21, троек 20; разница — два подстановочных правила.

-- +goose Up

-- ── (0) ПРЕДПОСЫЛКА ПРЕДИКАТА: КАТАЛОГ ПОЛОН ─────────────────────────────────
--
-- Предикат снятия ЧИТАЕТ каталог. На неполном каталоге он снял бы законный
-- глагол — то есть отобрал бы у арендатора живое право, а это необратимо на
-- месте (запрет #5). Проверяется ДО того, как построен набор к снятию.
-- +goose StatementBegin
DO $$
DECLARE
    live_verbs int;
BEGIN
    SELECT count(*) INTO live_verbs FROM kacho_iam.catalog_verb WHERE live;
    IF live_verbs <> 109 THEN
        RAISE EXCEPTION
            'предпосылка нарушена: живых пар глаголов каталога % (ждали 109) — '
            'предикат снятия читает каталог, и на неполном он снимет ЗАКОННЫЙ глагол '
            '(kacho#1815, IAM-SV-1-16)', live_verbs;
    END IF;
END;
$$;
-- +goose StatementEnd

-- ── (1) КЛАССИФИКАЦИЯ ПРАВИЛ ПО ПОЛОСАМ ──────────────────────────────────────
--
-- Полоса выбирается ФОРМОЙ правила, а не догадкой. Правило, не попавшее ни в
-- одну, — полуподстановка; молча выбрать ей полосу значило бы принять решение,
-- которого никто не принимал, поэтому ниже она ОТКАЗ, а не умолчание.
--
-- СОЗДАНИЕ И НАПОЛНЕНИЕ РАЗДЕЛЕНЫ НАМЕРЕННО — не сводить обратно в
-- `CREATE TEMP TABLE … AS SELECT`. Отпечаток отчётов о стоимости вердикта
-- (`services/iam/internal/repo/kacho/pg/scalegrid/fingerprint.go`,
-- `migrationTouchesStructure`) режет файл по `;` и берёт всякий стейтмент, где
-- есть слово CREATE/ALTER/DROP И имя измеряемой таблицы. Слитная форма несёт
-- оба: `DROP` из `ON COMMIT DROP` и `kacho_iam.roles` из чтения. Эта миграция
-- структуры измеряемых таблиц НЕ МЕНЯЕТ (DDL над `kacho_iam.*` в ней ноль), и
-- слитная форма загоняла бы её под отпечаток ложно — то есть требовала бы
-- пересъёмки отчётов ценой около двух часов прогона, ничего в них не изменив.
-- Слепая зона предиката — не наш предмет и заведена задачей продукта #1833.
CREATE TEMP TABLE _sys_rule (
  role_id       text    NOT NULL,
  role_name     text    NOT NULL,
  rule_ord      bigint  NOT NULL,
  rule          jsonb   NOT NULL,
  module        text,
  res_total     bigint  NOT NULL,
  res_wild      bigint  NOT NULL,
  verb_total    bigint  NOT NULL,
  concrete_lane boolean NOT NULL,
  wildcard_lane boolean NOT NULL
) ON COMMIT DROP;

INSERT INTO _sys_rule (role_id, role_name, rule_ord, rule, module,
                       res_total, res_wild, verb_total, concrete_lane, wildcard_lane)
SELECT s.role_id, s.role_name, s.rule_ord, s.rule, s.module,
       s.res_total, s.res_wild, s.verb_total,
       (s.module <> '*' AND s.res_wild = 0 AND s.res_total > 0),
       (s.module =  '*' AND s.res_wild = s.res_total AND s.res_total > 0)
  FROM (
    SELECT r.id                                   AS role_id,
           r.name                                 AS role_name,
           e.ord                                  AS rule_ord,
           e.rule                                 AS rule,
           e.rule ->> 'module'                    AS module,
           (SELECT count(*) FROM jsonb_array_elements_text(e.rule -> 'resources') x)              AS res_total,
           (SELECT count(*) FROM jsonb_array_elements_text(e.rule -> 'resources') x WHERE x = '*') AS res_wild,
           (SELECT count(*) FROM jsonb_array_elements_text(e.rule -> 'verbs') x)                  AS verb_total
      FROM kacho_iam.roles r
      CROSS JOIN LATERAL jsonb_array_elements(COALESCE(r.rules, '[]'::jsonb)) WITH ORDINALITY AS e(rule, ord)
     WHERE r.is_system) s;

-- ── (2) ЕДИНСТВЕННОЕ МЕСТО ПРЕДИКАТА СНЯТИЯ ──────────────────────────────────
--
-- Осматриваются ВСЕ названные глаголы, а не только снимаемые: перепись и
-- проверка «резолвится для части ресурсов» читают ту же таблицу, что и правка.
-- Якорь `*` глаголом не считается — он называет не имя, а «все».
CREATE TEMP TABLE _seg_scan (
  role_id       text    NOT NULL,
  role_name     text    NOT NULL,
  rule_ord      bigint  NOT NULL,
  module        text,
  res_total     bigint  NOT NULL,
  concrete_lane boolean NOT NULL,
  wildcard_lane boolean NOT NULL,
  authored_verb text    NOT NULL,
  verb          text    NOT NULL,
  res_ok        bigint,
  in_vocabulary boolean,
  drop_it       boolean NOT NULL
) ON COMMIT DROP;

INSERT INTO _seg_scan (role_id, role_name, rule_ord, module, res_total,
                       concrete_lane, wildcard_lane, authored_verb, verb,
                       res_ok, in_vocabulary, drop_it)
SELECT a.role_id, a.role_name, a.rule_ord, a.module, a.res_total,
       a.concrete_lane, a.wildcard_lane, a.authored_verb, a.verb,
       a.res_ok, a.in_vocabulary,
       (a.concrete_lane AND a.res_ok = 0) OR (a.wildcard_lane AND NOT a.in_vocabulary)
  FROM (
    SELECT s.role_id,
           s.role_name,
           s.rule_ord,
           s.module,
           s.res_total,
           s.concrete_lane,
           s.wildcard_lane,
           v.value #>> '{}'               AS authored_verb,
           lower(btrim(v.value #>> '{}')) AS verb,
           -- Сколько ресурсов правила несут живую строку каталога на ЭТОТ глагол.
           -- Приведение — на АВТОРСКОЙ стороне; у каталога приводить нечего
           -- (CONSTRAINT catalog_verb_canonical). Образец: 20260901113757:490.
           CASE WHEN s.concrete_lane THEN (
                  SELECT count(*)
                    FROM jsonb_array_elements(s.rule -> 'resources') res
                   WHERE EXISTS (
                         SELECT 1 FROM kacho_iam.catalog_verb cv
                          WHERE cv.module = s.module
                            AND cv.resource = res.value #>> '{}'
                            AND cv.verb = lower(btrim(v.value #>> '{}'))
                            AND cv.live))
                ELSE NULL END AS res_ok,
           -- Полоса полной подстановки: глагол обязан быть объявлен ХОТЬ ОДНИМ типом.
           CASE WHEN s.wildcard_lane THEN
                  EXISTS (SELECT 1 FROM kacho_iam.catalog_verb cv
                           WHERE cv.verb = lower(btrim(v.value #>> '{}'))
                             AND cv.live)
                ELSE NULL END AS in_vocabulary
      FROM _sys_rule s
      CROSS JOIN LATERAL jsonb_array_elements(s.rule -> 'verbs') v
     WHERE (v.value #>> '{}') <> '*') a;

-- ── (3) МИГРАЦИЯ ОТКАЗЫВАЕТ, А НЕ ДОГАДЫВАЕТСЯ ───────────────────────────────
--
-- Три состояния, при которых снятие означало бы решение, которого никто не
-- принимал. Каждое сегодня даёт НОЛЬ, и это измеряется, а не предполагается.
-- +goose StatementBegin
DO $$
DECLARE
    offender text;
BEGIN
    -- (а) Полуподстановка: ни полосы каталога, ни полосы объединения.
    SELECT string_agg(x, ', ' ORDER BY x) INTO offender
      FROM (SELECT DISTINCT role_name || ' (правило ' || rule_ord || ')' AS x
              FROM _sys_rule
             WHERE NOT concrete_lane AND NOT wildcard_lane) t;
    IF offender IS NOT NULL THEN
        RAISE EXCEPTION
            'полуподстановка среди правил системных ролей: % — у неё нет ни полосы каталога, '
            'ни полосы объединения, и молчаливый выбор одной был бы решением, которого никто '
            'не принимал (kacho#1815, IAM-SV-1-13)', offender;
    END IF;

    -- (б) Глагол резолвится для ЧАСТИ ресурсов правила. Снятие отняло бы
    --     законное право на одном ресурсе ради незаконного на другом.
    SELECT string_agg(x, ', ' ORDER BY x) INTO offender
      FROM (SELECT DISTINCT role_name || ' (правило ' || rule_ord || ', глагол ' || authored_verb || ')' AS x
              FROM _seg_scan
             WHERE concrete_lane AND res_ok > 0 AND res_ok < res_total) t;
    IF offender IS NOT NULL THEN
        RAISE EXCEPTION
            'глагол резолвится для части ресурсов правила: % — снятие отняло бы законное право '
            'на одном ресурсе ради незаконного на другом (kacho#1815, IAM-SV-1-16)', offender;
    END IF;

    -- (в) Снятие опустошило бы правило. Такое правило не даёт ничего целиком, и
    --     его судьбу решает не эта миграция. (Форма CHECK roles_rules_valid
    --     отвергла бы пустой массив кодом 23514 — но безымянно; отказ обязан
    --     называть роль и правило.)
    SELECT string_agg(x, ', ' ORDER BY x) INTO offender
      FROM (SELECT DISTINCT s.role_name || ' (правило ' || s.rule_ord || ')' AS x
              FROM _sys_rule s
             WHERE s.verb_total > 0
               AND s.verb_total = (SELECT count(*) FROM _seg_scan d
                                    WHERE d.role_id = s.role_id AND d.rule_ord = s.rule_ord AND d.drop_it)) t;
    IF offender IS NOT NULL THEN
        RAISE EXCEPTION
            'снятие опустошило бы правило: % — правило без единого глагола не даёт ничего '
            'целиком, и это ДРУГОЙ предмет (kacho#1815, IAM-SV-1-12)', offender;
    END IF;
END;
$$;
-- +goose StatementEnd

-- ── (4) ПРАВКА: СНИМАЕТСЯ ВТОРОЕ ИМЯ ТОГО, ЧТО УЖЕ НАЗВАНО ───────────────────
--
-- Порядок глаголов внутри правила и порядок правил внутри роли сохраняются:
-- `WITH ORDINALITY` + `ORDER BY`. `permissions` не входит в SET ни одним словом.
UPDATE kacho_iam.roles r
   SET rules = nr.rules
  FROM (
    SELECT s.role_id,
           jsonb_agg(
             CASE
               WHEN EXISTS (SELECT 1 FROM _seg_scan d
                             WHERE d.role_id = s.role_id AND d.rule_ord = s.rule_ord AND d.drop_it)
               THEN jsonb_set(s.rule, '{verbs}', (
                      SELECT COALESCE(jsonb_agg(v.value ORDER BY v.ord), '[]'::jsonb)
                        FROM jsonb_array_elements(s.rule -> 'verbs') WITH ORDINALITY AS v(value, ord)
                       WHERE NOT EXISTS (SELECT 1 FROM _seg_scan d2
                                          WHERE d2.role_id = s.role_id
                                            AND d2.rule_ord = s.rule_ord
                                            AND d2.drop_it
                                            AND d2.authored_verb = v.value #>> '{}')))
               ELSE s.rule
             END
             ORDER BY s.rule_ord) AS rules
      FROM _sys_rule s
     WHERE EXISTS (SELECT 1 FROM _seg_scan d WHERE d.role_id = s.role_id AND d.drop_it)
     GROUP BY s.role_id
  ) nr
 WHERE r.id = nr.role_id
   AND r.rules IS DISTINCT FROM nr.rules;

-- ── (5) СЛЕД СНИМАЕТСЯ ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ ─────────────────────────────
--
-- `role_grant_orphan` со `source = 'rule_ref'` — запись о ПЕРЕСЕЛЕНИИ
-- объявления. Запись, которой больше нечего описывать, — находка: она
-- утверждала бы, что объявление живо, при том что его нет.
--
-- Предикат СТРОГО СИММЕТРИЧЕН предикату постановки (20260901113757): снимается
-- строка, чей сегмент больше НЕ ОБЪЯВЛЕН ролью. Форма `DELETE … WHERE source =
-- 'rule_ref'` без условия сняла бы и строку, чей предмет уцелел, — а это ровно
-- то, что она обязана показывать.
CREATE TEMP TABLE _trace_drop (
  role_id     text NOT NULL,
  object_type text NOT NULL,
  verb        text NOT NULL
) ON COMMIT DROP;

INSERT INTO _trace_drop (role_id, object_type, verb)
SELECT o.role_id, o.object_type, o.verb
  FROM kacho_iam.role_grant_orphan o
 WHERE o.source = 'rule_ref'
   AND NOT EXISTS (
         SELECT 1
           FROM kacho_iam.roles r,
                LATERAL jsonb_array_elements(COALESCE(r.rules, '[]'::jsonb)) rule,
                LATERAL jsonb_array_elements(rule -> 'resources') res,
                LATERAL jsonb_array_elements(rule -> 'verbs') vrb
          WHERE r.id = o.role_id
            AND rule ->> 'module' <> '*'
            AND res.value #>> '{}' <> '*'
            AND (rule ->> 'module') || '.' || (res.value #>> '{}') = o.object_type
            AND CASE WHEN EXISTS (
                       SELECT 1 FROM jsonb_array_elements_text(rule -> 'verbs') w WHERE w = '*')
                     THEN ''
                     ELSE lower(btrim(vrb.value #>> '{}'))
                END = o.verb);

DELETE FROM kacho_iam.role_grant_orphan o
 USING _trace_drop d
 WHERE o.source = 'rule_ref'
   AND o.role_id = d.role_id
   AND o.object_type = d.object_type
   AND o.verb = d.verb;

-- ── (6) САМОПРОВЕРКА ИСХОДА И ПЕРЕПИСЬ ───────────────────────────────────────
--
-- Перепись печатается ВСЕГДА, а не при находке: «ноль снятых» обязано быть
-- отличимо от «ноль прочитанных». Повторное применение печатает нули — и это
-- его штатный исход (IAM-SV-1-14).
-- +goose StatementBegin
DO $$
DECLARE
    rules_scanned int;
    verbs_dropped int;
    trace_dropped int;
    still_bad     text;
    empty_rule    text;
BEGIN
    SELECT count(*) INTO rules_scanned FROM _sys_rule;
    SELECT count(*) INTO verbs_dropped FROM _seg_scan WHERE drop_it;
    SELECT count(*) INTO trace_dropped FROM _trace_drop;

    -- Исход по существу: ни один авторский глагол системной роли больше не
    -- остался без референта. Пересчитывается ПО ДЕРЕВУ ПОСЛЕ правки, а не
    -- выводится из числа снятых.
    SELECT string_agg(x, ', ' ORDER BY x) INTO still_bad
      FROM (
    SELECT DISTINCT r.name || ': ' || (rule ->> 'module') || '.' ||
                    (res.value #>> '{}') || '.' || (vrb.value #>> '{}') AS x
      FROM kacho_iam.roles r,
           LATERAL jsonb_array_elements(COALESCE(r.rules, '[]'::jsonb)) rule,
           LATERAL jsonb_array_elements(rule -> 'resources') res,
           LATERAL jsonb_array_elements(rule -> 'verbs') vrb
     WHERE r.is_system
       AND (vrb.value #>> '{}') <> '*'
       AND (
             (rule ->> 'module' <> '*' AND res.value #>> '{}' <> '*'
              AND NOT EXISTS (SELECT 1 FROM kacho_iam.catalog_verb cv
                               WHERE cv.module = rule ->> 'module'
                                 AND cv.resource = res.value #>> '{}'
                                 AND cv.verb = lower(btrim(vrb.value #>> '{}'))
                                 AND cv.live))
          OR (rule ->> 'module' = '*' AND res.value #>> '{}' = '*'
              AND NOT EXISTS (SELECT 1 FROM kacho_iam.catalog_verb cv
                               WHERE cv.verb = lower(btrim(vrb.value #>> '{}'))
                                 AND cv.live))
           )) t;
    IF still_bad IS NOT NULL THEN
        RAISE EXCEPTION
            'после правки остались авторские глаголы без референта: % — предикат снятия '
            'не покрыл свой же предмет (kacho#1815, IAM-SV-1-02/03)', still_bad;
    END IF;

    -- Пустых наборов глаголов не осталось ни одного. Проверка стоит и ПОСЛЕ:
    -- (в) выше судила НАМЕРЕНИЕ, эта — ИСХОД.
    SELECT string_agg(x, ', ' ORDER BY x) INTO empty_rule
      FROM (SELECT DISTINCT r.name || ' (правило ' || e.ord || ')' AS x
              FROM kacho_iam.roles r
              CROSS JOIN LATERAL jsonb_array_elements(COALESCE(r.rules, '[]'::jsonb))
                   WITH ORDINALITY AS e(rule, ord)
             WHERE r.is_system
               AND jsonb_array_length(e.rule -> 'verbs') = 0) t;
    IF empty_rule IS NOT NULL THEN
        RAISE EXCEPTION
            'после правки правило осталось без единого глагола: % (kacho#1815, IAM-SV-1-12)', empty_rule;
    END IF;

    RAISE NOTICE 'правил системных ролей осмотрено % · глаголов снято % · строк следа снято %',
        rules_scanned, verbs_dropped, trace_dropped;
    RAISE NOTICE 'осталось строк следа объявления (source=rule_ref): %',
        (SELECT count(*) FROM kacho_iam.role_grant_orphan WHERE source = 'rule_ref');
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Обратного пути нет, и причина названа, а не умолчана.
--
-- Откат вернул бы объявления, которые не дают НИЧЕГО: ни одно из снятых имён не
-- объявлено типом, на который правило адресовано, поэтому ни один кортеж по ним
-- не эмитился и ни одна строка вердикта не появлялась за всё время их жизни.
-- Восстанавливать состояние, признанное дефектным, значит объявлять его
-- законным — и заново заполнять след сирот записями о переселении, предмета у
-- которых снова не будет.
--
-- Откат, которому и вправду нужен один из этих глаголов, нуждается в имени,
-- которое несёт каталог платформы, — то есть в НОВОМ объявлении со своей
-- приёмкой, а не в обращении этой миграции.
SELECT 1;

-- +goose StatementEnd
