-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- Ключница подписных ключей платформы (задача #897, приёмка F1 §9.1 п. 1).
--
-- ПРЕДМЕТ. Платформа начинает чеканить свои токены сама, значит ей нужен
-- подписной ключ с публичной половиной, идентификатором, сроком и состоянием.
--
-- ПОЧЕМУ ИМЯ ДРУГОЕ. Хранилище подписных ключей в этом дереве уже было и снято
-- миграцией 0065; его имя стоит записью в ведомости дропов и обязано там
-- остаться (ban #5 — применённая миграция не правится). Совпадение имён сделало
-- бы стража ведомости красным СПРАВЕДЛИВО: он увидел бы воскресшую таблицу,
-- которую сам же считает снятой. Имя новое, и это решение, а не случайность.
--
-- ПОЧЕМУ ЧИТАТЕЛЬ БЫЛ РАНЬШЕ ЭТОЙ СТРОКИ. Предшественник умер не от схемы: его
-- приватную половину не расшифровывал никто, и хранилище выглядело исправным,
-- потому что запись удавалась. Поэтому порядок работ фазы обратный привычному —
-- сперва проба «прочитанный ключ подписывает», и только под неё схема.
--
-- «ПОДПИСЫВАЕТ РОВНО ОДИН» — ИНВАРИАНТ БАЗЫ, А НЕ ПРОВЕРКА В КОДЕ (ban #10).
-- Держит частичный уникальный индекс token_signing_keys_one_active. Программная
-- последовательность «прочитать → убедиться → записать» под конкуренцией даёт
-- двух подписывающих, и это состояние ничем не отличимо от исправного, пока
-- кто-нибудь не спросит.
--
-- СОСТОЯНИЙ ПЯТЬ, и «скомпрометирован» существует ОТДЕЛЬНО от «выведен»:
--   PUBLISHED   — в наборе, ещё не подписывает (этап существует ради порядка
--                 «в наборе → подписывает»);
--   ACTIVE      — подписывает, такой ровно один;
--   RETIRED     — выведен, остаётся в наборе всю отсрочку: подписанные им
--                 токены доживают свой срок;
--   REMOVED     — отсрочка истекла, в наборе его нет;
--   COMPROMISED — покидает набор НЕМЕДЛЕННО; живые токены отвергаются, и это
--                 принятая цена, а не дефект.
-- Слияние двух последних в один глагол лишило бы оператора одного из двух
-- решений: вывести ключ из ротации и объявить его утёкшим — решения разной цены.
--
-- ПРИВАТНАЯ ПОЛОВИНА ЛЕЖИТ ОБЁРНУТОЙ. Ключ обёртки — уже объявленная ручка
-- authn.jwks-encryption-key-hex; второй ручки об этом предмете не заводится.
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS kacho_iam.token_signing_keys (
    kid                   text NOT NULL,
    algorithm             text NOT NULL,
    state                 text NOT NULL,
    public_key_pem        text NOT NULL,
    private_key_wrapped   bytea NOT NULL,
    created_at            timestamp with time zone NOT NULL DEFAULT now(),
    not_after             timestamp with time zone NOT NULL,
    activated_at          timestamp with time zone,
    retired_at            timestamp with time zone,
    removed_at            timestamp with time zone,
    compromised_at        timestamp with time zone,

    CONSTRAINT token_signing_keys_pkey PRIMARY KEY (kid),

    -- Словарь алгоритмов ЗАКРЫТ и здесь, а не только в коде: строка, попавшая
    -- в таблицу мимо прикладного пути, обязана отвергаться тем же словарём.
    CONSTRAINT token_signing_keys_algorithm_ck
        CHECK (algorithm = ANY (ARRAY['RS256'::text, 'ES256'::text, 'EdDSA'::text])),

    CONSTRAINT token_signing_keys_state_ck
        CHECK (state = ANY (ARRAY['PUBLISHED'::text, 'ACTIVE'::text, 'RETIRED'::text,
                                  'REMOVED'::text, 'COMPROMISED'::text])),

    -- Форма идентификатора ограничена ДО всякого использования: значение
    -- попадает в заголовок токена и приходит обратно от предъявителя.
    CONSTRAINT token_signing_keys_kid_ck
        CHECK (kid ~ '^[A-Za-z0-9._:-]{1,128}$'),

    CONSTRAINT token_signing_keys_public_key_ck
        CHECK (length(public_key_pem) BETWEEN 1 AND 16384),

    CONSTRAINT token_signing_keys_private_key_ck
        CHECK (octet_length(private_key_wrapped) BETWEEN 1 AND 32768),

    -- Срок ключа — величина, из которой вычисляется отсрочка снятия; ключ,
    -- истёкший в момент заведения, не заводится.
    CONSTRAINT token_signing_keys_not_after_ck
        CHECK (not_after > created_at),

    -- Отметка состояния стоит тогда и только тогда, когда состояние её
    -- предполагает: строка, объявляющая себя выведенной без отметки вывода,
    -- лишает отсрочку слагаемого.
    CONSTRAINT token_signing_keys_state_stamps_ck CHECK (
        (state = 'PUBLISHED'   AND activated_at IS NULL AND retired_at IS NULL
                               AND removed_at IS NULL   AND compromised_at IS NULL) OR
        (state = 'ACTIVE'      AND activated_at IS NOT NULL AND retired_at IS NULL
                               AND removed_at IS NULL   AND compromised_at IS NULL) OR
        (state = 'RETIRED'     AND retired_at IS NOT NULL
                               AND removed_at IS NULL   AND compromised_at IS NULL) OR
        (state = 'REMOVED'     AND removed_at IS NOT NULL AND compromised_at IS NULL) OR
        (state = 'COMPROMISED' AND compromised_at IS NOT NULL)
    )
);
-- +goose StatementEnd

-- +goose StatementBegin
-- ПОДПИСЫВАЕТ РОВНО ОДИН. Частичный уникальный индекс по константному
-- выражению: строк со state='ACTIVE' в таблице не может быть двух — ни через
-- прикладной путь, ни в обход него.
CREATE UNIQUE INDEX IF NOT EXISTS token_signing_keys_one_active
    ON kacho_iam.token_signing_keys ((state))
    WHERE state = 'ACTIVE';
-- +goose StatementEnd

-- +goose StatementBegin
-- Набор читается по состоянию — запрос публикации ходит именно этим индексом.
CREATE INDEX IF NOT EXISTS token_signing_keys_keyset_idx
    ON kacho_iam.token_signing_keys (created_at, kid)
    WHERE state IN ('PUBLISHED', 'ACTIVE', 'RETIRED');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS kacho_iam.token_signing_keys_keyset_idx;
-- +goose StatementEnd
-- +goose StatementBegin
DROP INDEX IF EXISTS kacho_iam.token_signing_keys_one_active;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS kacho_iam.token_signing_keys;
-- +goose StatementEnd
