-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- =============================================================================
-- Накопительный журнал ЛИЧНОСТЕЙ: рост платформы становится наблюдаемым.
-- =============================================================================
-- Задача `PRO-Robotech/kacho#619`.
--
-- ЧЕГО НЕ БЫЛО. Потолок на число аккаунтов ОДНОЙ личности заведён (484002) и
-- работает. Обходится он заведением личностей: регистрация самообслуживаемая и
-- стоит подтверждённого адреса. Потолок темпа удорожает автоматизацию, но не
-- ловит МЕДЛЕННОЕ накопление — а его не производила ни одна величина. Рост числа
-- личностей не наблюдался ничем: ни счётчика, ни ряда на витрине, ни порога.
--
-- ЭТО СТРАХОВКА, А НЕ МЕРА, и форма выведена именно отсюда. Отказ по потолку
-- платформы приходит СЛЕДУЮЩЕМУ честному человеку, а не тому, кто исчерпал
-- полку, — поэтому сначала ВИДНО, и только потом, отдельным решением, отказ.
-- Записью каталога потолков это не является и являться не может: у потолка
-- платформы нет носителя, внешнего по отношению к предмету счёта, — кластер и
-- есть предмет.
--
-- ПОЧЕМУ ЖУРНАЛ, А НЕ СЧЁТ ПО СТРОКАМ ПОЛЬЗОВАТЕЛЕЙ. `count(DISTINCT
-- external_id)` мгновенен и НЕ МОНОТОНЕН: строку пользователя удаляют, и
-- величина падает. Три следствия, и каждое само по себе решающее:
--
--   1. «Личностей ноль» перестаёт быть утверждением о всей жизни платформы и
--      становится утверждением о текущем мгновении — тогда как спрошено именно
--      про всю жизнь;
--   2. на падающем ряде РОСТ не определён: `increase()` над ним молчит там, где
--      рост и был, — то есть наблюдение отказывает ровно на своём предмете;
--   3. накопление становится обходимым тем же действием, что и счёт: заводить и
--      снимать.
--
-- Журнал рядов не снимает НИКОГДА, в том числе при уходе человека. Монотонность
-- получается by construction, а не соблюдением.
--
-- ПОЧЕМУ ЭТО ТРИГГЕР, А НЕ ЗАПИСЬ ИЗ КОДА. Личность появляется двумя путями —
-- первым входом и активацией приглашения, — и оба пишут в одну таблицу. Проверка
-- в коде обязана была бы стоять в обоих и разошлась бы на третьем; триггер стоит
-- на ТАБЛИЦЕ и потому верен для каждого писателя, включая будущего.
--
-- ПОЧЕМУ ВСТАВКА И ПРАВКА, А НЕ ОДНА ВСТАВКА. Приглашённый, ещё не вошедший,
-- личности не несёт — схема этого прямо требует
-- (`users_invite_status_consistency`: у `PENDING` внешний идентификатор пуст), —
-- и становится ею в момент активации, то есть на ПРАВКЕ строки. Журнал,
-- слушающий одну вставку, терял бы каждого приглашённого молча.
--
-- ЧЕГО ЗДЕСЬ НАМЕРЕННО НЕТ: снятия рядов. Ни каскада, ни триггера на удаление
-- строки пользователя. Это и есть накопительность; удаление ряда вернуло бы все
-- три следствия выше разом.

-- +goose Up
-- +goose StatementBegin
SET search_path TO kacho_iam, public;

-- -----------------------------------------------------------------------------
-- Журнал.
-- -----------------------------------------------------------------------------
-- Ряд на личность, а не на членство. Личность — внешний идентификатор входа;
-- строка пользователя есть ЧЛЕНСТВО в одном аккаунте, и один человек законно
-- держит по строке на каждый свой аккаунт. Ключом взято именно то, что НЕ
-- размножается вместе с членствами.
CREATE TABLE IF NOT EXISTS kacho_iam.identity_journal (
    identity      text        NOT NULL,

    -- Момент ПЕРВОГО появления. Не обновляется никогда: вторая, третья и всякая
    -- следующая встреча той же личности ряда не трогает — иначе величина «когда
    -- она появилась» означала бы «когда её видели в последний раз».
    first_seen_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT identity_journal_pkey PRIMARY KEY (identity),
    -- Пустая строка личностью не является и в журнал не попадает. Ограничением,
    -- а не соглашением: пустой ряд один раз завёлся бы и навсегда прибавил
    -- платформе несуществующего человека.
    CONSTRAINT identity_journal_identity_ck CHECK (identity <> '')
);

COMMENT ON TABLE kacho_iam.identity_journal IS
    'accumulating ledger of every login identity the platform has ever seen. Rows '
    'are never removed, not even when the person leaves: the question asked of it '
    'is about the whole life of the platform, and an instantaneous count answers a '
    'different one. Monotone by construction, so growth is defined on it';

COMMENT ON COLUMN kacho_iam.identity_journal.identity IS
    'the external login subject (users.external_id), NOT a user row id: a user row '
    'is a membership scoped to one account, and one person holds one per account';

-- Возраст ряда — ось, по которой спрашивают о СКОРОСТИ появления, когда витрина
-- недоступна или когда её ряд надо перепроверить у источника.
CREATE INDEX IF NOT EXISTS identity_journal_first_seen_idx
    ON kacho_iam.identity_journal (first_seen_at);

-- +goose StatementEnd
-- +goose StatementBegin

-- -----------------------------------------------------------------------------
-- Затравка по уже известным личностям.
-- -----------------------------------------------------------------------------
-- Без неё журнал начал бы с нуля на живой платформе, и первая же величина роста
-- показала бы всплеск, которого не было. Момент первого появления берётся у
-- САМОЙ РАННЕЙ строки пользователя этой личности — это лучшее, что о нём знает
-- база; выдумывать `now()` значило бы утверждать, что все они появились сегодня.
INSERT INTO kacho_iam.identity_journal (identity, first_seen_at)
SELECT u.external_id, min(u.created_at)
  FROM kacho_iam.users u
 WHERE u.external_id <> ''
 GROUP BY u.external_id
ON CONFLICT (identity) DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

-- -----------------------------------------------------------------------------
-- Производитель ряда.
-- -----------------------------------------------------------------------------
-- Наблюдаемость не гейт: функция ничего не отвергает и ничем не может уронить
-- вставку пользователя. `ON CONFLICT DO NOTHING` делает её идемпотентной, а
-- значит безопасной при любом числе повторов и при любом порядке писателей.
CREATE OR REPLACE FUNCTION kacho_iam.identity_journal_note()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO kacho_iam.identity_journal (identity, first_seen_at)
    VALUES (NEW.external_id, now())
    ON CONFLICT (identity) DO NOTHING;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION kacho_iam.identity_journal_note() IS
    'notes an identity the first time it appears, on insert and on the update that '
    'activates an invitation. Never refuses and never removes: observability is not '
    'a gate, and the ledger is accumulating on purpose';

DROP TRIGGER IF EXISTS users_identity_journal_insert ON kacho_iam.users;
CREATE TRIGGER users_identity_journal_insert
    AFTER INSERT ON kacho_iam.users
    FOR EACH ROW
    WHEN (NEW.external_id <> '')
    EXECUTE FUNCTION kacho_iam.identity_journal_note();

-- Активация приглашения — ПРАВКА, а не вставка: строка уже существует с пустым
-- внешним идентификатором. Отбор по переходу «было пусто → стало непусто», а не
-- по одному только новому значению: иначе всякая правка активной строки
-- (переименование, смена состояния) стучалась бы в журнал впустую.
DROP TRIGGER IF EXISTS users_identity_journal_activate ON kacho_iam.users;
CREATE TRIGGER users_identity_journal_activate
    AFTER UPDATE OF external_id ON kacho_iam.users
    FOR EACH ROW
    WHEN (OLD.external_id = '' AND NEW.external_id <> '')
    EXECUTE FUNCTION kacho_iam.identity_journal_note();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET search_path TO kacho_iam, public;

DROP TRIGGER IF EXISTS users_identity_journal_activate ON kacho_iam.users;
DROP TRIGGER IF EXISTS users_identity_journal_insert ON kacho_iam.users;
DROP FUNCTION IF EXISTS kacho_iam.identity_journal_note();
DROP TABLE IF EXISTS kacho_iam.identity_journal;
-- +goose StatementEnd
