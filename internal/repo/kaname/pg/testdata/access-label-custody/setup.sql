CREATE SCHEMA kaname;
CREATE FUNCTION kaname.access_labels_valid_v1(p jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE
AS 'SELECT jsonb_typeof(p) = ''object''';
CREATE TABLE kaname.accounts(
 id text PRIMARY KEY,name text NOT NULL DEFAULT 'initial',description text NOT NULL DEFAULT '',
 labels jsonb NOT NULL DEFAULT '{}',access_labels jsonb NOT NULL);
CREATE TABLE kaname.projects(LIKE kaname.accounts INCLUDING ALL);
CREATE TABLE kaname.relation_fact(object_type text,object_id text,relation text,subject text);
-- В фикстуре владелец базы сам задаёт образы до и после правки, а также
-- запись программы. Штатную проверку полномочий здесь не запускаем.
CREATE FUNCTION kaname.authority_protocol_require_owner() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 IF current_user <> session_user THEN RAISE EXCEPTION 'fixture owner required' USING ERRCODE='42501'; END IF;
END $$;
CREATE TEMP TABLE kaname_authority_sequence_program(
 singleton boolean PRIMARY KEY CHECK(singleton),nonce uuid NOT NULL,family text NOT NULL,frozen jsonb NOT NULL);
CREATE FUNCTION kaname._authority_metadata_access_label_origin_v1(p_table text,p_id text)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE f jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 SELECT frozen INTO STRICT f FROM pg_temp.kaname_authority_sequence_program WHERE singleton;
 IF f->>'table' IS DISTINCT FROM p_table OR f#>>'{command,old,id}' IS DISTINCT FROM p_id THEN
  RAISE EXCEPTION 'fixture origin mismatch'; END IF;
 RETURN f->'command';
END $$;
CREATE FUNCTION kaname._authority_sequence_store_v3() RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE result jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 SELECT to_jsonb(p)||jsonb_build_object('invoker_oid',to_regrole(session_user)::oid)
 INTO STRICT result FROM pg_temp.kaname_authority_sequence_program p WHERE singleton;
 RETURN result;
END $$;
INSERT INTO kaname.accounts(id,access_labels) VALUES ('account-1','{"env":"A"}');
INSERT INTO kaname.projects(id,access_labels) VALUES ('project-1','{"env":"A"}');
