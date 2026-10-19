-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- access_binding_pair_is_in_its_subject_set — пара выдачи (`subject_type`,
-- `subject_id`) есть одна из строк её набора субъектов, и держит это база, а не
-- писатель (задача PRO-Robotech/kaname#907, преемник kaname#902).
--
-- Санкция: задача #907 (P2, корректность). Публичный контракт не меняется:
-- каждый путь записи выдачи выводит пару из `subjects[0]`
-- (`domain.NormalizeSubjects`) и пишет набор в той же транзакции. Отказ этой
-- проверки — дефект писателя, а не ввод вызывающего; служба отвечает на него
-- тем же фиксированным INTERNAL, что на отказ kaname#902 (`pgmaperr.go`).
--
-- ПРИЗНАК. Чтения по субъекту спрашивают обе проекции выдачи — пару и набор
-- (`bindingNamesSubject`), а вердикт берёт субъектов только из набора. Пара вне
-- набора показывает выдачу субъекту, у которого права по ней нет. Проверка
-- kaname#902 судила лишь «у живой выдачи есть строка набора»; путь записи,
-- минующий `NormalizeSubjects`, оставлял пару, которой в наборе нет.
--
-- ЧТО ВВОДИТСЯ. Данных не трогает ни одна строка.
--
--   1. `kaname.access_binding_carries_a_subject()` переопределяется: у живой
--      выдачи в наборе есть строка её пары. Это строго сильнее прежнего
--      утверждения (строка пары — строка набора), поэтому оба отказа идут под
--      ОДНИМ именем ограничения `access_bindings_carry_a_subject`, а текст
--      различает «набор пуст» и «пары в наборе нет».
--   2. `access_bindings_pair_change_carries_a_subject` — после смены пары
--      выдачи. Отложена до коммита, как и прежние: пару и набор вправе менять
--      разные операторы одной транзакции.
--   3. `access_binding_subjects_keep_the_pair` — после смены субъекта строки
--      набора: строка пары не переписывается на другого субъекта.
--   Снятие строки набора и вставку выдачи судят прежние ограничения-триггеры
--   kaname#902 — теперь новым телом функции.
--
-- ПОЧЕМУ НЕ ВНЕШНИЙ КЛЮЧ `(id, subject_type, subject_id)` →
-- `access_binding_subjects (binding_id, subject_type, subject_id)`. Ключ
-- проверяет ссылку замком `FOR KEY SHARE` на строке набора, а проверка
-- kaname#902 берёт строку выдачи `FOR NO KEY UPDATE`. Смена пары и снятие её
-- новой строки в двух транзакциях ждали бы тогда друг друга на разных строках
-- (ключ — снятия строки набора, проверка набора — смены строки выдачи), и пара
-- расходилась бы взаимной блокировкой вместо отказа ограничения — это вывод
-- разбора порядка замков, замером ключа он не подтверждался. Одна функция под
-- одним замком строки выдачи эту пару выстраивает в очередь, и это утверждает
-- проба 4 (отказ ограничением, не 40P01).
--
-- КОНКУРЕНЦИЯ. Функция первым делом берёт строку выдачи `FOR NO KEY UPDATE` и
-- читает пару из взятой версии (READ COMMITTED: после ожидания — уже
-- зафиксированную соседкой), а набор — новым снимком оператора. Проверки одной
-- выдачи идут по очереди, и вторая видит пару и набор после коммита первой.
-- Проба — `access_binding_pair_in_set_integration_test.go`, проба 4.
--
-- ЦЕНА на пути записи: проверка пары — поиск по первичному ключу набора
-- `(binding_id, subject_type, subject_id)` вместо поиска по ведущему столбцу
-- индекса `access_binding_subjects_binding_ordinal_idx`; замер вставки выдачи
-- с набором до и после печатает проба 6 того же файла.
--
-- ЛЕЖАЩИЕ СТРОКИ ограничения-триггеры не судят — они срабатывают на событиях.
-- Поэтому накат сам считает выдачи, чья пара вне набора, и при ненулевом числе
-- ОТКАЗЫВАЕТ, не меняя проверки. Счёт идёт ПОД замком обеих таблиц
-- (`SHARE ROW EXCLUSIVE`): между переписью и заменой проверки новая такая
-- выдача не зафиксируется. Обратного заполнения нет намеренно: дописать пару в
-- набор значило бы включить доступ одной выкаткой, без решения выдавшего.
--
-- ОТКАТ возвращает тело функции kaname#902 и снимает оба новых
-- ограничения-триггера; данных не трогает.

-- +goose Up
SET LOCAL lock_timeout = '5s';

LOCK TABLE kaname.access_bindings, kaname.access_binding_subjects IN SHARE ROW EXCLUSIVE MODE;

-- +goose StatementBegin
DO $$
DECLARE
    v_lying bigint;
BEGIN
    SELECT count(*) INTO v_lying
      FROM kaname.access_bindings b
     WHERE NOT EXISTS (SELECT 1 FROM kaname.access_binding_subjects s
                        WHERE s.binding_id = b.id
                          AND s.subject_type = b.subject_type
                          AND s.subject_id = b.subject_id);
    IF v_lying > 0 THEN
        RAISE EXCEPTION 'access_bindings: выдач, чья пара вне набора субъектов, — %; проверка не меняется', v_lying
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'access_bindings_carry_a_subject',
                  HINT = 'SELECT b.id FROM kaname.access_bindings b WHERE NOT EXISTS (SELECT 1 FROM kaname.access_binding_subjects s WHERE s.binding_id = b.id AND s.subject_type = b.subject_type AND s.subject_id = b.subject_id)';
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.access_binding_carries_a_subject() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_binding text;
    v_type    text;
    v_id      text;
BEGIN
    IF TG_TABLE_NAME = 'access_bindings' THEN
        v_binding := NEW.id;
    ELSE
        v_binding := OLD.binding_id;
    END IF;

    -- Замок строки выдачи — до чтения набора, и пара читается из взятой версии:
    -- проверки одной выдачи идут по очереди, и вторая видит пару и набор после
    -- коммита первой.
    SELECT b.subject_type, b.subject_id INTO v_type, v_id
      FROM kaname.access_bindings b WHERE b.id = v_binding FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        -- Выдача снята той же транзакцией (либо её строки уже нет): набор ушёл
        -- каскадом вместе с ней.
        RETURN NULL;
    END IF;

    IF EXISTS (SELECT 1 FROM kaname.access_binding_subjects
                WHERE binding_id = v_binding AND subject_type = v_type AND subject_id = v_id) THEN
        RETURN NULL;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM kaname.access_binding_subjects WHERE binding_id = v_binding) THEN
        RAISE EXCEPTION 'access binding % carries no subject', v_binding
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'access_bindings_carry_a_subject';
    END IF;

    RAISE EXCEPTION 'access binding % does not carry its subject pair in its subject set', v_binding
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'access_bindings_carry_a_subject';
END;
$$;
-- +goose StatementEnd

CREATE CONSTRAINT TRIGGER access_bindings_pair_change_carries_a_subject
    AFTER UPDATE OF subject_type, subject_id ON kaname.access_bindings
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    WHEN (OLD.subject_type IS DISTINCT FROM NEW.subject_type OR OLD.subject_id IS DISTINCT FROM NEW.subject_id)
    EXECUTE FUNCTION kaname.access_binding_carries_a_subject();

CREATE CONSTRAINT TRIGGER access_binding_subjects_keep_the_pair
    AFTER UPDATE OF subject_type, subject_id ON kaname.access_binding_subjects
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    WHEN (OLD.subject_type IS DISTINCT FROM NEW.subject_type OR OLD.subject_id IS DISTINCT FROM NEW.subject_id)
    EXECUTE FUNCTION kaname.access_binding_carries_a_subject();

-- +goose Down
SET LOCAL lock_timeout = '5s';

DROP TRIGGER IF EXISTS access_binding_subjects_keep_the_pair ON kaname.access_binding_subjects;
DROP TRIGGER IF EXISTS access_bindings_pair_change_carries_a_subject ON kaname.access_bindings;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.access_binding_carries_a_subject() RETURNS trigger
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
