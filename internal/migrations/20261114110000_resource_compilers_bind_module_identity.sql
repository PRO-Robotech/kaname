-- Приёмка: docs/engineering/acceptance/grant-authority-matches-the-whole-effect.md
-- Основание: §8.1–8.2: compiler управляющего и полного эффекта; §8.4: единая identity модуля и каталога.
-- +goose Up
-- +goose StatementBegin
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_drain();
-- Source fragment: resource-module-identity.sql
-- Соответствие повторяет platformmodules.CatalogModuleOfService и fallback
-- moduleidentity.parseRoster. Это проверка написаний, а не mTLS admission:
-- принадлежность peer установленному roster проверяет настоящий RelationWriteGate.
-- Источник генерации и его SHA закреплены в module-mapping-source.json.
CREATE FUNCTION kaname._authority_resource_module_identity_v2(p_service text,p_actor text,p_catalog_module text)
RETURNS void LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE expected_module text;
BEGIN
 IF p_service IS NULL OR p_service='' OR octet_length(p_service)>253
 OR p_actor IS NULL OR p_catalog_module IS NULL OR p_catalog_module='' THEN
  RAISE EXCEPTION 'invalid resource module identity' USING ERRCODE='42501';
 END IF;
 expected_module:=CASE p_service
  WHEN 'nlb' THEN 'loadbalancer'
  ELSE p_service END;
 IF p_catalog_module IS DISTINCT FROM expected_module
 OR p_actor IS DISTINCT FROM ('sva'||substr(md5('kacho-'||p_service),1,17)) THEN
  RAISE EXCEPTION 'resource module identity mismatch' USING ERRCODE='42501';
 END IF;
END $$;
DO $$ DECLARE r record;BEGIN
 REVOKE ALL ON FUNCTION kaname._authority_resource_module_identity_v2(text,text,text) FROM PUBLIC;
 FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc p
 CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
 WHERE p.oid='kaname._authority_resource_module_identity_v2(text,text,text)'::regprocedure AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_resource_module_identity_v2(text,text,text) FROM %I',r.rolname);
 END LOOP;
END $$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_drain();
DROP FUNCTION kaname._authority_resource_module_identity_v2(text,text,text);
-- +goose StatementEnd
