-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- Разные пространства для PK и частичного UNIQUE( secret_hash ). Совпадение
-- hashtext только сериализует две резервации; коллизию данных решают индексы.
-- Невалидные входы ordinary INSERT по-прежнему судят ограничения таблицы.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_user_token_unique_keys_v1(p_id text,p_kind text,p_hash bytea)
RETURNS TABLE(space integer,key_value text)
LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
    SELECT 1262569307,p_id WHERE octet_length(p_id) BETWEEN 1 AND 64
    UNION ALL
    SELECT 1262569308,encode(p_hash,'hex')
    WHERE p_kind='SECRET' AND octet_length(p_hash)=32
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname._authority_user_token_unique_keys_v1(text,text,bytea) FROM PUBLIC;

-- Обычные писатели имеют совместимые shared locks: исход параллельных
-- INSERT по-прежнему решает PostgreSQL. UPDATE захватывает только входящие
-- ключи. DELETE и TouchLastUsed не создают новой записи в уникальном индексе.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_user_token_unique_guard_v1() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE wanted_id text; wanted_hash bytea; k record;
BEGIN
    IF TG_RELID<>'kaname.user_oauth_clients'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW'
       OR TG_OP NOT IN ('INSERT','UPDATE') THEN
        RAISE EXCEPTION 'invalid credential key guard context' USING ERRCODE='42501';
    END IF;
    wanted_id:=NEW.id;
    wanted_hash:=NEW.secret_hash;
    IF TG_OP='UPDATE' THEN
        IF OLD.id IS NOT DISTINCT FROM NEW.id THEN wanted_id:=NULL; END IF;
        IF OLD.credential_kind='SECRET' AND OLD.secret_hash IS NOT DISTINCT FROM NEW.secret_hash THEN
            wanted_hash:=NULL;
        END IF;
    END IF;
    FOR k IN SELECT * FROM kaname._authority_user_token_unique_keys_v1(wanted_id,NEW.credential_kind,wanted_hash) ORDER BY space LOOP
        PERFORM pg_advisory_xact_lock_shared(k.space,hashtext(k.key_value COLLATE "C"));
    END LOOP;
    RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname._authority_user_token_unique_guard_v1() FROM PUBLIC;
CREATE TRIGGER authority_user_token_unique BEFORE INSERT OR UPDATE OF id,credential_kind,secret_hash
ON kaname.user_oauth_clients FOR EACH ROW EXECUTE FUNCTION kaname._authority_user_token_unique_guard_v1();

-- Последний физический шаг ПОСЛЕ блокирующих ожиданий источников, квоты и
-- аудита. SELECT FOR UPDATE NOWAIT различает свободный ключ, занятый ключ
-- и ещё не завершённый перенос/удаление. Последний случай повторяет ВСЮ TX.
-- Ни значение ключа, ни хеш удостоверения не попадают в сообщение ошибки.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_user_token_unique_reserve_v1(p_id text,p_kind text,p_hash bytea) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE k record;
BEGIN
    IF current_setting('transaction_isolation')<>'read committed'
       OR p_id IS NULL OR octet_length(p_id) NOT BETWEEN 20 AND 21 OR p_id !~ '^uoc_?[0-9a-hjkmnp-tv-z]{17}$'
       OR p_kind IS NULL OR p_kind NOT IN ('KEYPAIR','SECRET')
       OR (p_kind='KEYPAIR' AND coalesce(octet_length(p_hash),0)<>0)
       OR (p_kind='SECRET' AND octet_length(p_hash) IS DISTINCT FROM 32) THEN
        RAISE EXCEPTION 'invalid credential reservation' USING ERRCODE='22023';
    END IF;
    LOCK TABLE ONLY kaname.user_oauth_clients IN ROW EXCLUSIVE MODE NOWAIT;
    FOR k IN SELECT * FROM kaname._authority_user_token_unique_keys_v1(p_id,p_kind,p_hash) ORDER BY space LOOP
        IF NOT pg_try_advisory_xact_lock(k.space,hashtext(k.key_value COLLATE "C")) THEN
            RAISE EXCEPTION 'credential key in use; restart writer' USING ERRCODE='40001';
        END IF;
    END LOOP;
    PERFORM 1 FROM ONLY kaname.user_oauth_clients WHERE id=p_id FOR UPDATE NOWAIT;
    IF FOUND THEN
        RAISE EXCEPTION 'credential already exists' USING ERRCODE='23505',CONSTRAINT='user_oauth_clients_pkey';
    END IF;
    IF p_kind='SECRET' THEN
        PERFORM 1 FROM ONLY kaname.user_oauth_clients WHERE credential_kind='SECRET' AND secret_hash=p_hash FOR UPDATE NOWAIT;
        IF FOUND THEN
            RAISE EXCEPTION 'credential already exists' USING ERRCODE='23505',CONSTRAINT='user_oauth_clients_secret_hash_unique';
        END IF;
    END IF;
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'credential row or relation in use; restart writer' USING ERRCODE='40001';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname._authority_user_token_unique_reserve_v1(text,text,bytea) FROM PUBLIC;

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP TRIGGER authority_user_token_unique ON kaname.user_oauth_clients;
DROP FUNCTION kaname._authority_user_token_unique_reserve_v1(text,text,bytea);
DROP FUNCTION kaname._authority_user_token_unique_guard_v1();
DROP FUNCTION kaname._authority_user_token_unique_keys_v1(text,text,bytea);
