-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 754001_subject_change_dictionary_admits_only_what_is_produced — словарь видов
-- события перестаёт допускать то, чего продукт произвести не умеет.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- `subject_change_op_check` допускал семь значений. Производителя в не-тестовом
-- коде не имели два: `jit_revoke` и `bg_revoke`. Это не «ещё не написали» —
-- подсистем, ради которых значения заводились, в дереве нет вовсе (предикат
-- `git grep -rln 'JITAccess\|jit_access\|JustInTime'` на 04e2e523f → ноль файлов).
--
-- Значение словаря без производителя обещает вид события, которого не бывает.
-- По нему пишут ветки читателей и оговорки в комментариях (обе очереди годков
-- перечисляли эти два значения как действующие), а отвечать за них некому.
--
-- Третье значение, `group_member_change`, стояло в этом же ограничении с первого
-- дня схемы и производителя не имело до #754 — смена членства в группе не
-- эмитила ничего, и снятый из группы терял доступ только по истечении срока
-- жизни записи в кеше вердиктов. Теперь производитель есть, и значение остаётся.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОРЯДОК: данные → словарь → объявление
--
-- Сперва проверяются ДАННЫЕ. Строк со снимаемыми значениями существовать не
-- может (их некому было написать), поэтому проверка не «подстраховка», а
-- условие применимости: если такая строка всё же есть, ограничение не
-- применится, и лучше узнать об этом с названным числом, чем отказом посреди
-- перекатки. Направление выбрано ГРОМКОЕ, а не «подчистить»: снимаемое значение
-- в строке означало бы производителя, о котором мы не знаем, — это находка, а не
-- мусор, и придумывать за него намерение нельзя.
--
-- Значения `binding_grant` / `binding_revoke` в словаре ОСТАЮТСЯ, хотя как `op`
-- их тоже никто не пишет: это канонический словарь `event_type`, а
-- `deriveOpFromEventType` пропускает незнакомый вид события в `op` как есть —
-- то есть будущее событие приедет сюда именно в этой форме, и ограничение обязано
-- его принять. Словарь колонки `op` поэтому union двух написаний, и это сказано
-- здесь, чтобы следующий не «дочистил» его до трёх значений.
--
-- Регрессия: internal/repohygiene TestQueueEventValueHasAProducer — обходит
-- живой словарь и требует производителя от каждого значения.

-- +goose Up

-- +goose StatementBegin
DO $$
DECLARE
    stray bigint;
BEGIN
    SELECT count(*) INTO stray
      FROM kacho_iam.subject_change_outbox
     WHERE op IN ('jit_revoke', 'bg_revoke');
    IF stray > 0 THEN
        RAISE EXCEPTION
            'subject_change_outbox: % строк несут снимаемый вид события (jit_revoke/bg_revoke). '
            'Производителя у этих значений в дереве нет — значит он появился вне его. '
            'Разберись, кто их пишет, ПРЕЖДЕ чем сужать словарь.', stray;
    END IF;
END
$$;
-- +goose StatementEnd

ALTER TABLE kacho_iam.subject_change_outbox
    DROP CONSTRAINT IF EXISTS subject_change_op_check;

ALTER TABLE kacho_iam.subject_change_outbox
    ADD CONSTRAINT subject_change_op_check CHECK (op = ANY (ARRAY[
        'binding_upsert'::text,
        'binding_delete'::text,
        'group_member_change'::text,
        'binding_grant'::text,
        'binding_revoke'::text
    ]));

COMMENT ON CONSTRAINT subject_change_op_check ON kacho_iam.subject_change_outbox IS
  'Словарь видов события очереди смены субъекта. Каждое значение обязано иметь производителя в не-тестовом коде iam — это держит гейт internal/repohygiene TestQueueEventValueHasAProducer. Union двух написаний: op-псевдонимы (binding_upsert/binding_delete) и канонические event_type (binding_grant/binding_revoke/group_member_change), потому что deriveOpFromEventType пропускает незнакомый вид в op как есть. Расширяя словарь, заводи производителя тем же изменением: значение без производителя обещает подсистему, которой нет.';

-- +goose Down

ALTER TABLE kacho_iam.subject_change_outbox
    DROP CONSTRAINT IF EXISTS subject_change_op_check;

ALTER TABLE kacho_iam.subject_change_outbox
    ADD CONSTRAINT subject_change_op_check CHECK (op = ANY (ARRAY[
        'binding_upsert'::text,
        'binding_delete'::text,
        'group_member_change'::text,
        'binding_grant'::text,
        'binding_revoke'::text,
        'jit_revoke'::text,
        'bg_revoke'::text
    ]));
