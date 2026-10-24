-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- access_binding_carries_a_subject — у выдачи есть хотя бы одна строка набора
-- субъектов (`access_binding_subjects`), и держит это база, а не писатель
-- (задача PRO-Robotech/kaname#902).
--
-- Санкция: задача #902 (P2, корректность). Публичный контракт не меняется:
-- запрос без субъектов отвергается ещё до записи (`domain.NormalizeSubjects`,
-- «subjects (must be 1..32)»), и каждый путь записи выдачи пишет набор в той
-- же транзакции. Отказ этой проверки — дефект писателя, а не ввод вызывающего.
--
-- ПРИЗНАК. Решение о доступе и чтения видимости берут субъектов выдачи только
-- из набора: выдача без его строк невидима вердикту целиком — право записано,
-- читается списками и не действует, и отличить это от «права не выдавали»
-- нечем. До этой миграции схема такую выдачу пропускала: набор держали девять
-- путей записи (пять сценариев службы, посев модулей, обратное заполнение
-- владельцев, две миграции), а гейт пути записи снят.
--
-- ЧТО ВВОДИТСЯ — функция и два отложенных до коммита ограничения-триггера на
-- ней. Данных не трогает ни одна строка.
--
--   1. `kaname.access_binding_carries_a_subject()` — по выдаче, о которой
--      спрашивает строка события, проверяет, что у живой выдачи есть строка
--      набора. Выдача, снятая той же транзакцией, не судится: её набор снят
--      каскадом внешнего ключа, и снятие выдачи целиком законно.
--   2. `access_bindings_carry_a_subject` — после вставки выдачи. Набор пишется
--      ВТОРЫМ оператором (внешний ключ набора ссылается на выдачу), поэтому
--      проверка отложена до коммита: между операторами транзакции выдача без
--      набора законна, на коммите — нет.
--   3. `access_binding_subjects_keep_one` — после снятия строки набора и после
--      смены её выдачи: последняя строка живой выдачи не снимается.
--
-- КОНКУРЕНЦИЯ. Две транзакции, снимающие РАЗНЫЕ строки набора одной выдачи,
-- каждая видит строку соседки ещё лежащей, и без замка обе прошли бы проверку —
-- выдача осталась бы без набора. Поэтому функция первым делом берёт строку
-- выдачи `FOR NO KEY UPDATE`: проверки одной выдачи идут по очереди, а вторая
-- после ожидания читает набор новым снимком (READ COMMITTED: снимок берётся на
-- каждый оператор функции) и видит снятие первой. Замок не конфликтует с
-- `FOR KEY SHARE`, который берёт внешний ключ при вставке строк набора, —
-- вставку набора он не задерживает. Проба —
-- `access_binding_subject_set_integration_test.go`.
--
-- ОТКАЗ — SQLSTATE 23000 с клаузой `CONSTRAINT` (имя ограничения-триггера):
-- безымянный отказ этого класса попадал бы в общую полосу предусловия. Служба
-- отвечает на него фиксированным INTERNAL (`pgmaperr.go`): вызывающему исправить
-- нечего.
--
-- ЛЕЖАЩИЕ СТРОКИ ограничение-триггер не судит — он срабатывает на событиях.
-- Поэтому накат сам считает выдачи без набора и при ненулевом числе
-- ОТКАЗЫВАЕТ, не заводя проверку. Счёт идёт ПОД замком обеих таблиц
-- (`SHARE ROW EXCLUSIVE` — тот же режим, что берёт заведение триггера): между
-- переписью и заведением проверки новая выдача без набора не зафиксируется.
-- Чтение таблиц замок не останавливает; запись стоит на время переписи —
-- антисоединение по индексу `access_binding_subjects_binding_ordinal_idx`. Обратного заполнения из пары
-- `access_bindings (subject_type, subject_id)` здесь нет намеренно: такая выдача
-- до наката не действовала (вердикт её не видел), и заполнение включило бы
-- доступ одной выкаткой, без решения выдавшего. Перепись на цепи посева — ноль
-- (проба печатает её числом).
--
-- ОТКАТ снимает оба ограничения-триггера и функцию; данных не трогает.

-- +goose Up
SET LOCAL lock_timeout = '5s';

LOCK TABLE kaname.access_bindings, kaname.access_binding_subjects IN SHARE ROW EXCLUSIVE MODE;

-- +goose StatementBegin
DO $$
DECLARE
    v_bare bigint;
BEGIN
    SELECT count(*) INTO v_bare
      FROM kaname.access_bindings b
     WHERE NOT EXISTS (SELECT 1 FROM kaname.access_binding_subjects s WHERE s.binding_id = b.id);
    IF v_bare > 0 THEN
        RAISE EXCEPTION 'access_bindings: выдач без строк набора субъектов — %; проверка не заводится', v_bare
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'access_bindings_carry_a_subject',
                  HINT = 'SELECT b.id FROM kaname.access_bindings b WHERE NOT EXISTS (SELECT 1 FROM kaname.access_binding_subjects s WHERE s.binding_id = b.id)';
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.access_binding_carries_a_subject() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_binding text;
BEGIN
    IF TG_TABLE_NAME = 'access_bindings' THEN
        v_binding := NEW.id;
    ELSE
        v_binding := OLD.binding_id;
    END IF;

    -- Замок строки выдачи — до чтения набора: проверки одной выдачи идут по
    -- очереди, и вторая читает набор после коммита первой.
    PERFORM 1 FROM kaname.access_bindings WHERE id = v_binding FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        -- Выдача снята той же транзакцией (либо её строки уже нет): набор ушёл
        -- каскадом вместе с ней.
        RETURN NULL;
    END IF;

    IF EXISTS (SELECT 1 FROM kaname.access_binding_subjects WHERE binding_id = v_binding) THEN
        RETURN NULL;
    END IF;

    RAISE EXCEPTION 'access binding % carries no subject', v_binding
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'access_bindings_carry_a_subject';
END;
$$;
-- +goose StatementEnd

CREATE CONSTRAINT TRIGGER access_bindings_carry_a_subject
    AFTER INSERT ON kaname.access_bindings
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION kaname.access_binding_carries_a_subject();

CREATE CONSTRAINT TRIGGER access_binding_subjects_keep_one
    AFTER DELETE OR UPDATE OF binding_id ON kaname.access_binding_subjects
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION kaname.access_binding_carries_a_subject();

-- +goose Down
SET LOCAL lock_timeout = '5s';

DROP TRIGGER IF EXISTS access_binding_subjects_keep_one ON kaname.access_binding_subjects;
DROP TRIGGER IF EXISTS access_bindings_carry_a_subject ON kaname.access_bindings;
DROP FUNCTION IF EXISTS kaname.access_binding_carries_a_subject();
