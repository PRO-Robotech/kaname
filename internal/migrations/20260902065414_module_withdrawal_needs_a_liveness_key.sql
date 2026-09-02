-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 20260902065414_module_withdrawal_needs_a_liveness_key — ОТЗЫВ МОДУЛЯ: порядок
-- держит КЛЮЧ, а не память автора.
--
-- Задачи продукта #1823 (обратимость — ядро) и #1859 (сам ключ). Приёмка
-- services/iam/docs/engineering/acceptance/module-withdrawal-is-described.md
-- (APPROVED круга 2), §2.2; сценарии IAM-MW-1-07, IAM-MW-1-08, IAM-MW-1-09.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО НЕВЕРНО СЕГОДНЯ
--
-- Единственный ключ от `catalog_resource` к `catalog_module` идёт на ПЕРВИЧНЫЙ
-- ключ `(module)` — то есть на строку независимо от её живости. Поэтому
-- состояние «модуль снят, а двадцать семь его ресурсов живы и грантуют»
-- ПРЕДСТАВИМО, и отвергнуть его нечем.
--
-- Это не теория: поставка модуля описана данными, а обратной половины у неё нет,
-- и первый же откат оставил бы строки, на которые никто не отвечает. Ровно так
-- заводится класс #1815 — что-то перестало существовать, а ссылки остались.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО ЭТА МИГРАЦИЯ ДЕЛАЕТ
--
-- Даёт `catalog_resource` вторую ссылку — на «этот модуль И он жив». Референт у
-- неё уже был и не использовался ни одним ключом: `catalog_module_live_uk
-- UNIQUE (module, live)` (20260901113757, объявление живости). Уникальный ключ
-- без ссылающегося — признак ребра, которое задумывалось и не доехало.
--
-- Порядок держится в ОБЕ стороны, и обе половины проверены прогоном:
--
--   вниз   снять модуль, пока жив хоть один его ресурс   → 23503
--   вниз   снять модуль, все ресурсы которого сняты      → проходит
--   вверх  оживить ресурс при снятом модуле              → 23503
--   вверх  оживить модуль, затем его ресурсы             → проходит
--
-- Половина «вверх» — не побочный эффект: без неё повторная установка модуля
-- упиралась бы в отказ, и причину искали бы в форме оживления строки, а не в
-- порядке.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ КОЛОНКА ОБРАЩАЕТСЯ В NULL, А НЕ ОБЪЯВЛЕНА КОНСТАНТОЙ `true`
--
-- Это не стиль, а ЕДИНСТВЕННАЯ форма, при которой модуль вообще снимается.
--
-- Форма `module_live boolean NOT NULL DEFAULT true` под `CHECK (module_live)`
-- делает колонку константой `true` у КАЖДОЙ строки `catalog_resource`, включая
-- СНЯТЫЕ. Снятые строки здесь не удаляются и обязаны не удаляться — на этом
-- стоит обратимость (снятая строка занимает первичный ключ, поэтому повторная
-- установка ОЖИВЛЯЕТ строку, а не вставляет новую). Значит ссылка на
-- `(module, true)` жила бы вечно, и снять модуль было бы нельзя НИКОГДА:
-- отрицательный сценарий IAM-MW-1-07 зеленел бы ровно тем исходом, который
-- положительный контроль IAM-MW-1-08 заведён отличать. `ON UPDATE CASCADE` тут
-- не спасает — каскад поставил бы `module_live = false` и уронил бы `CHECK`.
--
-- Довод «константная колонка уже применена дважды в этом дереве» НЕ переносится,
-- и вот чем: у `role_rule_ref.live` и `role_verb.live` она работает потому, что
-- строки проекции УДАЛЯЮТСЯ (`ReplaceRuleRefs` начинается с `DELETE`). Строки
-- каталога не удаляются by construction. Совпадает синтаксис, не ситуация.
--
-- Генерируемая в `NULL` колонка плюс умолчание `MATCH SIMPLE` даёт нужное by
-- construction: у снятой строки составляющая ключа пуста, ключ с пустой
-- составляющей считается выполненным, и снятая строка модуль не удерживает. Тот
-- же приём уже работает у `role_rule_ref_verb_fk`, где `NULL` в глаголе означает
-- якорь.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЦЕНА ФОРМЫ — НАЗВАНА, А НЕ УМОЛЧАНА
--
-- `ADD COLUMN … GENERATED ALWAYS AS … STORED` ПЕРЕПИСЫВАЕТ таблицу и берёт на
-- неё `ACCESS EXCLUSIVE`. На каталоге из тридцати строк это ничто, и потому
-- здесь допустимо; следующий каталог может быть не таким, и тогда цену придётся
-- считать заново. `ADD CONSTRAINT … FOREIGN KEY` вдобавок проверяет каждую
-- существующую строку — на том же объёме это тоже ничто.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕГО ЭТА МИГРАЦИЯ НЕ ДАЁТ
--
-- Уровня ГЛАГОЛОВ она не трогает: `catalog_verb_resource_fk` по-прежнему идёт на
-- первичный ключ ресурса, поэтому состояние «ресурс снят, его глаголы живы»
-- остаётся представимым. Это не дыра — строка глагола под снятым ресурсом
-- недостижима, правило отвергает ключ РЕСУРСА, — но и не порядок, удержанный
-- ключом. Осознанный выбор на этом уровне заведён отдельным предметом, а не
-- сделан здесь молча.
--
-- И она не делает «модуль снят» значимым для приёма правил: членство модуля
-- читается на пути запроса ЛИТЕРАЛОМ (`domain.IsKnownModule`), а не строками.
-- Перевод этого читателя — остаток #1816.

-- +goose Up

-- Перепись ДО — чтобы самопроверка ниже утверждала «эта миграция живости не
-- меняла» замером, а не выписанным числом. Выписанное число устарело бы молча:
-- каталог растёт, и его мощность уже менялась под #1863.
CREATE TEMP TABLE _catalog_before ON COMMIT DROP AS
SELECT (SELECT count(*) FROM kacho_iam.catalog_module   WHERE live) AS modules,
       (SELECT count(*) FROM kacho_iam.catalog_resource WHERE live) AS resources,
       (SELECT count(*) FROM kacho_iam.catalog_verb     WHERE live) AS verbs;

ALTER TABLE kacho_iam.catalog_resource
  ADD COLUMN module_live boolean
    GENERATED ALWAYS AS (CASE WHEN live THEN true END) STORED;

COMMENT ON COLUMN kacho_iam.catalog_resource.module_live IS
  'Составляющая ключа «мой модуль ЖИВ». У живой строки — true, у снятой — NULL, и NULL здесь означает «эта строка модуль не удерживает», а не «значение не задано»: ключ с пустой составляющей считается выполненным (MATCH SIMPLE). Константа true сделала бы модуль неснимаемым — снятые строки каталога не удаляются.';

ALTER TABLE kacho_iam.catalog_resource
  ADD CONSTRAINT catalog_resource_module_live_fk
    FOREIGN KEY (module, module_live)
    REFERENCES kacho_iam.catalog_module (module, live) MATCH SIMPLE
    ON DELETE NO ACTION ON UPDATE NO ACTION;

-- ── САМОПРОВЕРКА ИСХОДА И ПЕРЕПИСЬ ───────────────────────────────────────────
--
-- Утверждается ровно то, что эта миграция обещает: ключ существует, живость ни
-- одной строки не изменилась, и состояние «модуль снят при живом ресурсе» в
-- каталоге отсутствует. Перепись печатается ВСЕГДА — «ноль расхождений» обязано
-- быть отличимо от «ноль прочитанного».

-- +goose StatementBegin
DO $$
DECLARE
    before_mod   int;
    before_res   int;
    before_verb  int;
    after_mod    int;
    after_res    int;
    after_verb   int;
    key_present  int;
    contradicted int;
BEGIN
    SELECT modules, resources, verbs
      INTO before_mod, before_res, before_verb
      FROM _catalog_before;

    SELECT count(*) INTO key_present
      FROM pg_constraint
     WHERE conname = 'catalog_resource_module_live_fk'
       AND conrelid = 'kacho_iam.catalog_resource'::regclass;
    IF key_present <> 1 THEN
        RAISE EXCEPTION
            'ключ catalog_resource_module_live_fk не заведён (найдено %): без него '
            'состояние «модуль снят, его ресурсы живы» остаётся представимым '
            '(kacho#1859)', key_present;
    END IF;

    SELECT count(*) INTO after_mod  FROM kacho_iam.catalog_module   WHERE live;
    SELECT count(*) INTO after_res  FROM kacho_iam.catalog_resource WHERE live;
    SELECT count(*) INTO after_verb FROM kacho_iam.catalog_verb     WHERE live;

    IF (after_mod, after_res, after_verb) IS DISTINCT FROM (before_mod, before_res, before_verb) THEN
        RAISE EXCEPTION
            'миграция изменила живой каталог: было модулей %, ресурсов %, глаголов %; '
            'стало %, %, % — ключ обязан менять ПРЕДСТАВИМОЕ, а не посеянное (kacho#1859)',
            before_mod, before_res, before_verb, after_mod, after_res, after_verb;
    END IF;

    -- Ключ только что провалидировал каждую строку, поэтому противоречие здесь
    -- невозможно. Проверка стоит не ради него, а ради того, чтобы перепись
    -- называла ОБЕ величины: «нарушений 0» при «прочитано 0» неотличимо от
    -- исправной работы.
    SELECT count(*) INTO contradicted
      FROM kacho_iam.catalog_resource cr
      JOIN kacho_iam.catalog_module cm ON cm.module = cr.module
     WHERE cr.live AND NOT cm.live;
    IF contradicted <> 0 THEN
        RAISE EXCEPTION
            'живых ресурсов у снятых модулей: % — ключ не удержал порядок (kacho#1859)',
            contradicted;
    END IF;

    RAISE NOTICE
        'ключ живости модуля: осмотрено живых модулей %, ресурсов %, глаголов %; '
        'живых ресурсов у снятых модулей %',
        after_mod, after_res, after_verb, contradicted;
END;
$$;
-- +goose StatementEnd

-- +goose Down
--
-- Откат снимает ПОРЯДОК, а не данные: ни одна строка каталога не меняется.
-- После него состояние «модуль снят, его ресурсы живы» снова становится
-- представимым — и это надо знать тому, кто откат применяет.
ALTER TABLE kacho_iam.catalog_resource
  DROP CONSTRAINT catalog_resource_module_live_fk;

ALTER TABLE kacho_iam.catalog_resource
  DROP COLUMN module_live;
