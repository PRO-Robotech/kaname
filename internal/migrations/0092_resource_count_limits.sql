-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0092_resource_count_limits.sql — потолок на число ресурсов арендатора: величина,
-- её область видимости и монотонная ревизия, по которой владельцы типов тянут дельту.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Сколько сетей, подсетей, адресов, интерфейсов, групп правил, таблиц маршрутизации,
-- шлюзов и наборов префиксов заводит один арендатор — не ограничено ничем. Каждая
-- строка тратит общий ресурс, и один проект способен сделать платформу непригодной
-- для остальных, не нарушив ни одного действующего правила.
--
-- Здесь живёт ВЕЛИЧИНА. Учёт и отказ живут у владельца типа ресурса, потому что
-- списание обязано быть атомарным со вставкой строки (ban #10), а «прочитать у
-- соседа → записать у себя» — это check-then-act через сеть.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ССЫЛКА НА ОБЛАСТЬ ВИДИМОСТИ — ТРИГГЕР, А НЕ FK
--
-- `scope_id` полиморфен: он адресует строку `accounts` ЛИБО `projects`, выбор
-- делает `scope`. Единственного REFERENCES-адресата не существует, поэтому FK
-- здесь невыразим — ровно тот случай, для которого в этом сервисе уже принят
-- заменитель: BEFORE INSERT/UPDATE-триггер с БЛОКИРУЮЩИМ чтением референта
-- (`SELECT … FOR KEY SHARE`, миграция 0049) плюс BEFORE DELETE на референтах
-- (0050). Блокирующее чтение — не украшение: снимок без блокировки не закрывает
-- гонку «удаляем проект / назначаем на него предел», и обе транзакции коммитятся.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕГО ЗДЕСЬ НАМЕРЕННО НЕТ: `CHECK (used <= limit_value)`
--
-- Потребления эта таблица не хранит вовсе (оно живёт у владельца типа), но решение
-- назвать стоит здесь, потому что соседний прецедент такой CHECK несёт и он делает
-- ШТАТНУЮ операцию невыразимой: администратор не может понизить предел ниже
-- текущего потребления — запись падает на 23514. «Занято больше, чем разрешено» —
-- законное состояние: новые нельзя, старые живут, удаление работает.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ОТЗЫВ — НАДГРОБИЕ, А НЕ УДАЛЕНИЕ СТРОКИ
--
-- Владелец типа держит ПРОЕКЦИЮ пределов у себя и обновляет её дельтой. Дельта,
-- знающая только о записях, не способна ни понизить, ни СНЯТЬ строку проекции:
-- отозванный предел проекта продолжал бы перекрывать аккаунт вечно, а проекция
-- стала бы записью всего, что когда-либо было верно. Поэтому отзыв — это
-- `withdrawn_at`, ревизия двигается, и дельта несёт запись со снятым признаком.
-- Отсюда же частичность UNIQUE: тройка уникальна СРЕДИ ДЕЙСТВУЮЩИХ, и предел,
-- отозванный вчера, не мешает назначить его заново сегодня.

-- +goose Up
-- +goose StatementBegin

-- Ревизия — источник монотонного порядка дельты.
CREATE SEQUENCE IF NOT EXISTS kacho_iam.limits_revision_seq AS bigint START 1;

-- +goose StatementEnd
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS kacho_iam.limits (
    id           TEXT        PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Три области видимости, от общей к частной. Разрешение перекрытий
    -- (PROJECT > ACCOUNT > DEFAULT) делает сервис — здесь хранится только то,
    -- что сказано, а не то, что из сказанного следует.
    scope        TEXT        NOT NULL,
    -- '' ровно для DEFAULT и никогда иначе (см. CHECK ниже).
    scope_id     TEXT        NOT NULL DEFAULT '',
    kind         TEXT        NOT NULL,
    limit_value  BIGINT      NOT NULL,

    -- Момент отзыва. NULL — предел действует.
    withdrawn_at TIMESTAMPTZ,

    -- Ревизию проставляет ТРИГГЕР, а не вызывающий: правило «двигается на
    -- изменении, стоит на повторе того же значения» обязано быть верным для
    -- КАЖДОГО писателя, а не только для того, который сегодня существует.
    revision     BIGINT      NOT NULL DEFAULT 0,

    -- id: `lim-<17 crockford-base32>`, 21 символ (ids.PrefixLimitHyphen).
    -- Алфавит СТРОЧНЫЙ crockford (0-9 a-h j k m n p-t v-z; без i, l, o, u) —
    -- ровно тот, что эмитит генератор.
    CONSTRAINT limits_id_form_ck
        CHECK (id ~ '^lim-[0-9a-hjkmnp-tv-z]{17}$'),

    CONSTRAINT limits_scope_ck
        CHECK (scope IN ('DEFAULT', 'ACCOUNT', 'PROJECT')),

    -- Область видимости и её предмет — одно утверждение, поэтому состояние
    -- «сказано про аккаунт, но не сказано про какой» невыразимо, а не
    -- отлавливается проверкой в коде.
    CONSTRAINT limits_scope_subject_ck
        CHECK ((scope =  'DEFAULT' AND scope_id =  '')
            OR (scope <> 'DEFAULT' AND scope_id <> '')),

    -- ФОРМА вида проверяется здесь, ЧЛЕНСТВО в закрытом каталоге — доменом.
    -- Разделение осознанное: форма (`domain.resource`) стабильна и переживёт
    -- любой новый домен, а перечень видов растёт — вписанный сюда, он требовал
    -- бы миграции на каждый новый вид, а применённую миграцию править нельзя.
    CONSTRAINT limits_kind_form_ck
        CHECK (kind ~ '^[a-z][a-z0-9]*\.[a-zA-Z][a-zA-Z0-9]*$'),

    -- Ноль — законная величина («ни одного ресурса этого вида»), поэтому
    -- запрещено только отрицательное.
    CONSTRAINT limits_value_nonnegative_ck
        CHECK (limit_value >= 0)
);

-- +goose StatementEnd
-- +goose StatementBegin

-- Тройка уникальна СРЕДИ ДЕЙСТВУЮЩИХ пределов. Частичность — не оптимизация:
-- без неё отзыв навсегда занимал бы слот, и предел, снятый по ошибке, нельзя
-- было бы назначить заново.
CREATE UNIQUE INDEX IF NOT EXISTS limits_scope_kind_uk
    ON kacho_iam.limits (scope, scope_id, kind)
    WHERE withdrawn_at IS NULL;

-- +goose StatementEnd
-- +goose StatementBegin

-- Курсорная страница платформы — (created_at, id).
CREATE INDEX IF NOT EXISTS limits_created_at_id_idx
    ON kacho_iam.limits (created_at, id);

-- +goose StatementEnd
-- +goose StatementBegin

-- Дельта читается по ревизии.
CREATE INDEX IF NOT EXISTS limits_revision_idx
    ON kacho_iam.limits (revision);

-- +goose StatementEnd
-- +goose StatementBegin

-- Разрешение действующих пределов идёт по (scope, scope_id) для одного сервиса.
CREATE INDEX IF NOT EXISTS limits_scope_lookup_idx
    ON kacho_iam.limits (scope, scope_id)
    WHERE withdrawn_at IS NULL;

-- +goose StatementEnd
-- +goose StatementBegin

-- limits_stamp_revision() — ревизия двигается на ИЗМЕНЕНИИ и стоит на повторе.
--
-- ПОЧЕМУ БЛОКИРОВКА ПЕРЕД nextval. Номер из последовательности берётся в момент
-- ВЫЗОВА, а виден читателю — в момент КОММИТА. Без сериализации транзакция с
-- номером 10 может закоммититься ПОЗЖЕ транзакции с номером 11, и тянущий,
-- дочитавший до 11, не увидит 10 НИКОГДА — молча и навсегда. Транзакционная
-- консультативная блокировка держится до коммита, поэтому порядок номеров
-- совпадает с порядком коммитов by construction. Назначение предела —
-- административное действие единичной частоты; цена этой сериализации нулевая,
-- а её отсутствие стоило бы потерянного изменения без единого признака.
CREATE OR REPLACE FUNCTION kacho_iam.limits_stamp_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.limit_value  IS NOT DISTINCT FROM OLD.limit_value
       AND NEW.withdrawn_at IS NOT DISTINCT FROM OLD.withdrawn_at THEN
        -- Ничего наблюдаемого не изменилось: тянущие не обязаны об этом узнать.
        NEW.revision := OLD.revision;
        RETURN NEW;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('kacho_iam.limits_revision'));
    NEW.revision := nextval('kacho_iam.limits_revision_seq');
    RETURN NEW;
END;
$$;

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS limits_stamp_revision_trg ON kacho_iam.limits;
CREATE TRIGGER limits_stamp_revision_trg
    BEFORE INSERT OR UPDATE ON kacho_iam.limits
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.limits_stamp_revision();

-- +goose StatementEnd
-- +goose StatementBegin

-- limits_scope_ref_exists() — заменитель полиморфного FK на стороне ВСТАВКИ.
--
-- Семантика FK на UPDATE: если ссылка (scope, scope_id) не менялась, референт не
-- перепроверяется. Иначе отзыв предела у только что удалённого проекта был бы
-- невозможен — надгробие нельзя было бы поставить именно там, где оно и нужно.
--
-- Отказ помечается CONSTRAINT = 'limits_scope_ref', чтобы адаптер отдал
-- контракт-тон отсутствия («<Resource> <id> not found») своей полосой прямого
-- чтения, а не общим отказом хранилища.
CREATE OR REPLACE FUNCTION kacho_iam.limits_scope_ref_exists() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.scope    = OLD.scope
       AND NEW.scope_id = OLD.scope_id THEN
        RETURN NEW;
    END IF;

    IF NEW.scope = 'DEFAULT' THEN
        RETURN NEW;
    ELSIF NEW.scope = 'ACCOUNT' THEN
        PERFORM 1 FROM kacho_iam.accounts WHERE id = NEW.scope_id FOR KEY SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE    = '23503',
                CONSTRAINT = 'limits_scope_ref',
                MESSAGE    = format('Account %s not found', NEW.scope_id);
        END IF;
    ELSIF NEW.scope = 'PROJECT' THEN
        PERFORM 1 FROM kacho_iam.projects WHERE id = NEW.scope_id FOR KEY SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE    = '23503',
                CONSTRAINT = 'limits_scope_ref',
                MESSAGE    = format('Project %s not found', NEW.scope_id);
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = format('Illegal argument scope %s', NEW.scope);
    END IF;
    RETURN NEW;
END;
$$;

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS limits_scope_ref_exists_trg ON kacho_iam.limits;
CREATE TRIGGER limits_scope_ref_exists_trg
    BEFORE INSERT OR UPDATE ON kacho_iam.limits
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.limits_scope_ref_exists();

-- +goose StatementEnd
-- +goose StatementBegin

-- limits_withdraw_for_scope_object() — сторона УДАЛЕНИЯ той же ссылки, зеркало
-- 0050. Референт уходит — пределы, сказанные про него, отзываются той же
-- транзакцией. Не запрет удаления: предел не есть повод удерживать проект.
--
-- Почему триггер, а не уборка в use-case: удалить проект можно не только тем
-- путём, который сегодня существует, а счётчик обязан быть верным для каждого
-- писателя (в т.ч. для каскада и ручного SQL). Ревизию двигает
-- limits_stamp_revision — отзыв виден дельте как изменение.
CREATE OR REPLACE FUNCTION kacho_iam.limits_withdraw_for_scope_object() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE kacho_iam.limits
       SET withdrawn_at = now()
     WHERE scope        = TG_ARGV[0]
       AND scope_id     = OLD.id
       AND withdrawn_at IS NULL;
    RETURN OLD;
END;
$$;

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS projects_withdraw_limits_trg ON kacho_iam.projects;
CREATE TRIGGER projects_withdraw_limits_trg
    BEFORE DELETE ON kacho_iam.projects
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.limits_withdraw_for_scope_object('PROJECT');

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS accounts_withdraw_limits_trg ON kacho_iam.accounts;
CREATE TRIGGER accounts_withdraw_limits_trg
    BEFORE DELETE ON kacho_iam.accounts
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.limits_withdraw_for_scope_object('ACCOUNT');

-- +goose StatementEnd
-- +goose StatementBegin

-- ── ПОСЕВ УМОЛЧАНИЙ ─────────────────────────────────────────────────────────
--
-- ЭТО ЕДИНСТВЕННОЕ МЕСТО В ПРОДУКТЕ, ГДЕ ЭТИ ЧИСЛА ЗАПИСАНЫ. Величина,
-- назначенная константой кода, конфигурации или чарта владельца типа, —
-- находка, а не реализация: у предела появился бы второй источник, и
-- администратор, поднявший потолок здесь, не понял бы, почему это не подействовало.
--
-- Числа ВЫБРАНЫ, а не измерены, и внутренне согласованы: адресов не меньше двух
-- на интерфейс (v4+v6), подсетей не меньше четырёх на сеть. Сеть — самая дорогая
-- строка домена (невозвращаемая координата изоляции плюс три строки ресурса плюс
-- три записи регистрации в чужом сервисе), поэтому её потолок самый низкий.
-- Пересмотр — когда доля проектов, упирающихся в потолок, перестанет быть
-- пренебрежимой; величина наблюдаема после того, как владельцы начнут считать.
--
-- Идентификаторы посева детерминированы (тело из нулей и порядкового номера) —
-- иначе повторный прогон миграции на уже посеянной базе был бы неотличим от
-- первого только по содержимому, а не по ключу.
INSERT INTO kacho_iam.limits (id, scope, scope_id, kind, limit_value) VALUES
    ('lim-00000000000000001', 'DEFAULT', '', 'vpc.network',           16),
    ('lim-00000000000000002', 'DEFAULT', '', 'vpc.subnet',            64),
    ('lim-00000000000000003', 'DEFAULT', '', 'vpc.address',          256),
    ('lim-00000000000000004', 'DEFAULT', '', 'vpc.networkInterface', 128),
    ('lim-00000000000000005', 'DEFAULT', '', 'vpc.securityGroup',     64),
    ('lim-00000000000000006', 'DEFAULT', '', 'vpc.routeTable',        32),
    ('lim-00000000000000007', 'DEFAULT', '', 'vpc.gateway',           16),
    ('lim-00000000000000008', 'DEFAULT', '', 'vpc.cidrGroup',         64),
    ('lim-00000000000000009', 'DEFAULT', '', 'iam.project',           16)
ON CONFLICT (id) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS accounts_withdraw_limits_trg ON kacho_iam.accounts;

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS projects_withdraw_limits_trg ON kacho_iam.projects;

-- +goose StatementEnd
-- +goose StatementBegin

DROP FUNCTION IF EXISTS kacho_iam.limits_withdraw_for_scope_object();

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS limits_scope_ref_exists_trg ON kacho_iam.limits;

-- +goose StatementEnd
-- +goose StatementBegin

DROP FUNCTION IF EXISTS kacho_iam.limits_scope_ref_exists();

-- +goose StatementEnd
-- +goose StatementBegin

DROP TRIGGER IF EXISTS limits_stamp_revision_trg ON kacho_iam.limits;

-- +goose StatementEnd
-- +goose StatementBegin

DROP FUNCTION IF EXISTS kacho_iam.limits_stamp_revision();

-- +goose StatementEnd
-- +goose StatementBegin

DROP TABLE IF EXISTS kacho_iam.limits;

-- +goose StatementEnd
-- +goose StatementBegin

DROP SEQUENCE IF EXISTS kacho_iam.limits_revision_seq;

-- +goose StatementEnd
