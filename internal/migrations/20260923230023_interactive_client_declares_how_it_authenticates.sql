-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- interactive_client_declares_how_it_authenticates — СПОСОБ аутентификации
-- интерактивного клиента на токен-эндпоинте выражается схемой (задача
-- PRO-Robotech/kaname#317; санкция — одобренная приёмка LINE-A-1, решение Р3,
-- сценарий LINE-A-1-12).
--
-- =============================================================================
-- ЧТО ИЗМЕРЕНО
-- =============================================================================
-- `git grep -n token_endpoint_auth_method -- 'internal/migrations/*.sql'` на
-- ревизии 860078a96 называет ОДНУ строку — объявление колонки
-- `text DEFAULT ''::text NOT NULL` в `0001_initial.sql`. Ни одно ограничение её
-- не сужало. Колонка проверочного значения секрета уже стоит
-- (`20260920175118_interactive_client_carries_its_secret_verifier.sql`), но со
-- способом она не связана. Схема поэтому принимала и клиента с видом выдачи без
-- объявленного способа, и публичного клиента с материалом секрета, и способ,
-- которого не знает ни один читатель. Пустое значение при этом читается
-- по-разному: для регистрации клиентов по RFC 7591 опущенный способ означает
-- `client_secret_basic`, а для этой службы — «способ не объявлен».
--
-- =============================================================================
-- ТРИ ОГРАНИЧЕНИЯ, ПО ОДНОМУ ФАКТУ НА КАЖДОЕ
-- =============================================================================
-- 1. `interactive_clients_auth_method_ck` — СЛОВАРЬ ЗАКРЫТ. Принимается ровно
--    то, что строка выражает целиком: `none` (публичный клиент, владение
--    доказывает PKCE), `client_secret_basic` и `client_secret_post` (секрет;
--    его проверочное значение — `secret_verifier`), и пустая строка — только в
--    границах ограничения 2. Подписанного утверждения ключом (`private_key_jwt`)
--    в словаре НЕТ, и это решение: колонки ключа у строки нет, а способ без
--    места для своего материала невыразим. Способ входит в словарь только
--    вместе с колонкой своего материала.
--
-- 2. `interactive_clients_auth_method_declared_ck` — СПОСОБ ОБЪЯВЛЕН у каждого
--    клиента с непустым перечнем видов выдачи. Судится класс, а не один
--    `authorization_code`: каждый вид перечня обслуживает токен-эндпоинт, и
--    каждому нужно знать, чем клиент аутентифицируется. Клиент без видов
--    выдачи на токен-эндпоинт не выходит, и пустой способ у него законен.
--
-- 3. `interactive_clients_secret_verifier_method_ck` — МАТЕРИАЛ СЕКРЕТА лежит
--    только у клиента, чей способ секрет предъявляет. Признак публичности
--    поэтому ОДИН — способ `none`, — а не пустота колонки материала: публичный
--    клиент с материалом невыразим, и два источника признака разойтись не
--    могут.
--
-- =============================================================================
-- ЧТО НЕ ВЫРАЖЕНО, И ПОЧЕМУ
-- =============================================================================
-- Обратная связка «способ секретом ⟹ материал лежит в этой строке» НЕ
-- заведена, и это решение. Строка не несёт признака того, где лежит материал
-- клиента: в реестре службы либо у внешнего поставщика, зеркалом которого
-- строка тогда является. Ограничение, требующее материал в строке, сделало бы
-- конфиденциального клиента внешнего поставщика невыразимым. Клиент со
-- способом секретом и без материала в строке не может предъявить ничего, что
-- служба приняла бы, — такой отказ закрыт, а не открыт.
--
-- =============================================================================
-- ЛЕЖАЩИЕ СТРОКИ
-- =============================================================================
-- Обратного заполнения нет. Способ строки кладёт её единственный писатель
-- (`InteractiveClientRepo.Insert`) из ответа производителя, и оба производителя
-- объявляют `none` при перечне видов службы (`grantTypesInteractive`):
-- собственный — константой (`internal/repo/kaname/pg/own_interactive_client_provider.go`),
-- адаптер внешнего поставщика — запросом `none` и эхом ответа
-- (`internal/clients/hydra_interactive_clients.go`). Материала секрета не кладёт
-- ни один прод-писатель. Строка, нарушающая ограничение, делает накат ОТКАЗОМ,
-- и это намеренно: верный способ для неё неизвестен, а выдуманный объявил бы
-- удостоверение, которого клиент не объявлял.

-- +goose Up

-- +goose StatementBegin
ALTER TABLE kaname.interactive_clients
    ADD CONSTRAINT interactive_clients_auth_method_ck CHECK (
        (token_endpoint_auth_method = ANY (ARRAY[''::text, 'none'::text,
                                                 'client_secret_basic'::text, 'client_secret_post'::text]))),
    ADD CONSTRAINT interactive_clients_auth_method_declared_ck CHECK (
        ((cardinality(grant_types) = 0) OR (token_endpoint_auth_method <> ''::text))),
    ADD CONSTRAINT interactive_clients_secret_verifier_method_ck CHECK (
        ((secret_verifier = ''::text)
         OR (token_endpoint_auth_method = ANY (ARRAY['client_secret_basic'::text, 'client_secret_post'::text]))));
-- +goose StatementEnd

COMMENT ON COLUMN kaname.interactive_clients.token_endpoint_auth_method IS
  'Способ аутентификации клиента на токен-эндпоинте: none (публичный, владение доказывает PKCE) | client_secret_basic | client_secret_post (секрет, проверочное значение в secret_verifier). Пустая строка — способ НЕ объявлен; законна только при пустом grant_types. Признак публичности — none, а не пустота secret_verifier. Держат interactive_clients_auth_method_ck, interactive_clients_auth_method_declared_ck, interactive_clients_secret_verifier_method_ck.';

-- +goose Down

-- Откат снимает три ограничения и описание колонки; данных он не трогает:
-- ограничения ничего не записывали, они только отвергали.
ALTER TABLE kaname.interactive_clients
    DROP CONSTRAINT interactive_clients_secret_verifier_method_ck,
    DROP CONSTRAINT interactive_clients_auth_method_declared_ck,
    DROP CONSTRAINT interactive_clients_auth_method_ck;

COMMENT ON COLUMN kaname.interactive_clients.token_endpoint_auth_method IS NULL;
