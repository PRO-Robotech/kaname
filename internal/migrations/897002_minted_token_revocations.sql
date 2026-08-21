-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- Отзыв токенов, отчеканенных платформой (задача #897, приёмка F1 §2.2).
--
-- ПРЕДМЕТ. Контроль, действующий на ВЫДАЧЕ и не действующий на ПРЕДЪЯВЛЕНИИ,
-- отзывом не является: он лишь не выдаёт нового, а предъявленное продолжает
-- проходить до истечения срока. Это состояние НЕ СХОДИТСЯ САМО — в отличие от
-- задержки распространения, — поэтому окно отзыва равнялось бы сроку токена, а
-- не сроку, который выбрали мы. Контур, где мы чеканим токен и не можем его
-- отозвать, production-complete не является.
--
-- ФОРМА. Одна строка на СУБЪЕКТА: «всё, что выпущено раньше этого момента,
-- недействительно». Отзыв действует ВПЕРЁД — выпущенное после момента снова
-- действительно, иначе отзыв означал бы вечную блокировку принципала, а не
-- снятие выданного.
--
-- ПОЧЕМУ НЕ user_token_revocations. Та таблица связана внешним ключом с
-- пользователями и покрывает пользовательские сессии провайдера. Субъектом
-- нашего токена бывает и служебная учётка; внешний ключ на «любой вид
-- принципала» в этом дереве не выражается, а отзыв, не покрывающий машинного
-- принципала, — это отзыв, которого нет ровно там, где токен и живёт.
--
-- ПОЧЕМУ БЕЗ ВНЕШНЕГО КЛЮЧА. Субъект — идентификатор принципала любого вида;
-- ссылочная целостность здесь означала бы выбор одного вида и молчаливый отказ
-- отзывать остальные. Снятие принципала снимает и осмысленность строки, но
-- строка при этом безвредна: токенов такого субъекта больше не выпускают.
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS kacho_iam.minted_token_revocations (
    subject        text        NOT NULL,
    revoke_before  timestamptz NOT NULL,
    reason         text        NOT NULL DEFAULT '',
    revoked_by     text        NOT NULL DEFAULT '',
    updated_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT minted_token_revocations_pkey PRIMARY KEY (subject),

    CONSTRAINT minted_token_revocations_subject_ck
        CHECK (length(subject) BETWEEN 1 AND 128),

    CONSTRAINT minted_token_revocations_reason_ck
        CHECK (length(reason) <= 256),

    -- Действие такой цены не бывает анонимным: кто принял решение, записано
    -- вместе с решением, а не восстанавливается по журналу.
    CONSTRAINT minted_token_revocations_decider_ck
        CHECK (length(revoked_by) BETWEEN 1 AND 128)
);

COMMENT ON TABLE kacho_iam.minted_token_revocations IS
    'Отзыв токенов, отчеканенных платформой: всё, выпущенное субъекту раньше revoke_before, недействительно. Читается авторитетом отзыва на пути запроса.';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS kacho_iam.minted_token_revocations;
-- +goose StatementEnd
