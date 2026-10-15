-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- subject_class_fact_is_a_read — класс субъектов (`system_class:…`) в прямом
-- факте допустим только на отношении чтения: сужение приёма класса субъекта
-- (задача PRO-Robotech/kaname#838, эпик PRO-Robotech/kaname#829).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md`,
-- решение Р4 «классу — только чтение». Миграция 20261015120000 исполняет Р4 на
-- выдаче (`access_binding_subjects_system_class_reads_only` судит роль), но
-- прямой факт приходит в `kaname.relation_fact` мимо выдачи — журналом
-- (регистрация ресурса соседом, выпуск кортежей выдачи) либо вставкой. Здесь
-- последнее слово переходит к ограничению самой таблицы фактов, как у
-- `relation_fact_subject_not_wildcard`: ветвь фактов вердикта соединяет
-- говорящего с субъектом факта без разбора типа, и класс на отношении иерархии
-- (`project`, `parent`, `owner`) либо на пишущем отношении раздал бы доступ
-- всякому такому субъекту.
--
-- ПЕРЕЧЕНЬ ЗАКРЫТ И ПОЛОЖИТЕЛЕН. Класс принимается ровно на трёх отношениях —
-- тех, что пишет продукт:
--   * `v_get` — хранимая публикация для чтения без входа
--     (`domain.PublicationSubject`, факт `system_class:anonymous #v_get`);
--   * `viewer` — ярус чтения: системная выдача чтения справочников
--     (`cluster#viewer system_class:authenticated`, Р8) и выдача роли только
--     чтения на области проекта либо аккаунта;
--   * `system_viewer` — тот же ярус чтения на кластере (`mapClusterRelations`).
-- Запрещающий перечень (отношения иерархии) не годится: новое отношение
-- иерархии модели открыло бы класс молча. Имя класса — закрытый словарь из
-- двух (`anonymous`, `authenticated`), форма множества (`…#member`) классом не
-- бывает.
--
-- Отказ — 23514 с именем ограничения при любой записи, в том числе журнальной:
-- проекция журнала в факт идёт той же транзакцией, и запись намерения с классом
-- вне чтения откатывается целиком.
--
-- НОЛЬ — НЕ ТИШИНА. Строка, нарушающая перечень, к накату — уже выданное право,
-- и снять его молча значило бы отозвать без следа: миграция отказывает,
-- называя число строк.

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    v_bad int;
BEGIN
    SELECT count(*) INTO v_bad FROM kaname.relation_fact
     WHERE split_part(subject, ':', 1) = 'system_class'
       AND NOT (subject IN ('system_class:anonymous', 'system_class:authenticated')
                AND relation IN ('v_get', 'viewer', 'system_viewer'));
    IF v_bad > 0 THEN
        RAISE EXCEPTION
            'subject classes: % direct fact(s) name a system class outside a read relation; revoke them before applying', v_bad;
    END IF;
END
$$;
-- +goose StatementEnd

ALTER TABLE kaname.relation_fact DROP CONSTRAINT IF EXISTS relation_fact_subject_class_reads_only;
ALTER TABLE kaname.relation_fact
    ADD CONSTRAINT relation_fact_subject_class_reads_only
        CHECK ((split_part(subject, ':', 1) <> 'system_class'
                OR (subject = ANY (ARRAY['system_class:anonymous'::text, 'system_class:authenticated'::text])
                    AND relation = ANY (ARRAY['v_get'::text, 'viewer'::text, 'system_viewer'::text]))));

COMMENT ON CONSTRAINT relation_fact_subject_class_reads_only ON kaname.relation_fact IS 'Класс субъектов (system_class:anonymous | system_class:authenticated) в прямом факте — только на отношении чтения: v_get (публикация), viewer и system_viewer (ярус чтения). Р4 приёмки системного класса; сужение приёма класса субъекта, kaname#838.';

-- +goose Down
ALTER TABLE kaname.relation_fact DROP CONSTRAINT IF EXISTS relation_fact_subject_class_reads_only;
