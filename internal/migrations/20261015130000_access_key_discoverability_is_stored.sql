-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- access_key_discoverability_is_stored — строка ключа доступа несёт ПРИЗНАК
-- ОБНАРУЖИМОСТИ удостоверения, и состояний у него три (задача
-- PRO-Robotech/kaname#786).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/access-keys-are-ours.md`, SHA-256
-- `5ea26ad012add99800a8c185e98b9e2f38910c1c54daec5bdd8a5c4f3ea3efbe`
-- (запись `docs/specs/reviews/access-keys-are-ours/5ea26ad012add99800a8c185e98b9e2f38910c1c54daec5bdd8a5c4f3ea3efbe.yaml`,
-- `APPROVED`, круг 11, событие
-- https://github.com/PRO-Robotech/kaname/issues/269#issuecomment-5972714344;
-- решение Р12, сценарии Ф7-41, Ф7-56, Ф7-57).
--
-- =============================================================================
-- ПОЧЕМУ ТРИ СОСТОЯНИЯ СЛОВОМ, А НЕ NULL
-- =============================================================================
-- Расширение `credProps.rk` аутентификатор сообщает ОДИН раз — в церемонии
-- регистрации; ни одно последующее утверждение его не несёт. «Не сообщено» —
-- состояние факта, а не отсутствие записи, и потому оно названо словом
-- закрытого перечня: пустое значение и «нет» с ним не сливаются (Ф7-57).
--
-- =============================================================================
-- ЛЕЖАЩИЕ СТРОКИ
-- =============================================================================
-- Обратного заполнения не существует (Р12): у ключа, заведённого до этой
-- миграции, признак не был записан, и прочитать его заново негде. Накат кладёт
-- им «не сообщено» — правду о строке. Следствие названо приёмкой: страж
-- последнего способа входа такой ключ годным не считает (консервативно, §10
-- п. 28). Умолчание снимается тем же накатом: новую строку пишет только приём
-- церемонии, и забытый писателем признак — отказ NOT NULL, а не молчаливое
-- «не сообщено».

-- +goose Up

-- +goose StatementBegin
ALTER TABLE kaname.user_access_keys
    ADD COLUMN discoverability text DEFAULT 'unreported'::text NOT NULL;

ALTER TABLE kaname.user_access_keys
    ADD CONSTRAINT user_access_keys_discoverability_check
        CHECK ((discoverability = ANY (ARRAY['discoverable'::text, 'not-discoverable'::text, 'unreported'::text])));

ALTER TABLE kaname.user_access_keys ALTER COLUMN discoverability DROP DEFAULT;

COMMENT ON COLUMN kaname.user_access_keys.discoverability IS
  'Признак обнаружимости удостоверения из расширения credProps.rk церемонии регистрации: discoverable — сообщено «обнаруживаемое»; not-discoverable — сообщено «не обнаруживаемое»; unreported — расширения не было. Пишется один раз, приёмом церемонии. Читатель — страж последнего способа входа: годен только discoverable.';
-- +goose StatementEnd

-- +goose Down

-- Откат снимает столбец: признак после повторного наката у этих строк станет
-- «не сообщено», то есть страж посчитает их негодными — сторона лишнего
-- отказа, а не запирания человека.
-- +goose StatementBegin
ALTER TABLE kaname.user_access_keys DROP CONSTRAINT user_access_keys_discoverability_check;
ALTER TABLE kaname.user_access_keys DROP COLUMN discoverability;
-- +goose StatementEnd
