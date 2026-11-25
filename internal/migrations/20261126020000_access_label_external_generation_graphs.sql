-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Дополняем граф пересчёта источниками внешнего корня даже без выходных фактов.
-- Постоянная привязка и ребро входят в граф чтения; завершение отдельно проверяет их удержания.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_access_label_generation_graphs_v1(jsonb,jsonb,jsonb,jsonb)','acc5b813a6461a380609c5bf5d70e0b60a4b62ac280974c828e17a876a49db4a','a2a2707d6974b9526d199e5963fd96588db85f97d0bd0f6f9e7821c2f3d5c003',
  $changes$[
 [
  " carriers jsonb;scopes jsonb;binding_ids text[];full_bindings text[];work integer;",
  " carriers jsonb;scopes jsonb;binding_ids text[];full_bindings text[];work integer;\n lifecycle_required jsonb:='{}';lifecycle_source jsonb;source_kind integer;"
 ],
 [
  " -- Замкнутый набор выходов берём от owner census, а не из RR proposal.\n -- Стоимость учитывает и повторные выходы разных получателей/поколений.\n WITH census AS MATERIALIZED (\n  SELECT f->>'object_type' AS model,f->>'object_id' AS id\n  FROM jsonb_array_elements(p_capture->'roots') r\n  CROSS JOIN LATERAL jsonb_array_elements(r->'facts') f\n ), model_dictionary AS MATERIALIZED (\n  SELECT r->>'ObjectType' AS model,min((r->>'Module')||'.'||(r->>'Resource')) AS dotted\n  FROM jsonb_array_elements(coalesce(nullif(p_catalog#>'{Live,Resources}','null'::jsonb),'[]'::jsonb)||\n     coalesce(nullif(p_catalog#>'{Retired,Resources}','null'::jsonb),'[]'::jsonb)) r\n  GROUP BY r->>'ObjectType'\n  HAVING count(DISTINCT (r->>'Module')||'.'||(r->>'Resource'))=1\n ), coordinates AS MATERIALIZED (\n  SELECT DISTINCT c.model,c.id FROM census c\n ), mapped AS MATERIALIZED (\n  SELECT c.model,c.id,d.dotted,jsonb_build_array(d.dotted,c.id)::text AS key\n  FROM coordinates c LEFT JOIN model_dictionary d ON d.model=c.model\n )\n SELECT (SELECT count(*)::integer FROM census),\n  count(*) FILTER(WHERE dotted IS NULL OR coalesce(id,'')='')::integer,\n  coalesce(jsonb_agg(jsonb_build_object('model',model,'id',id,'dotted',dotted,'key',key)\n   ORDER BY key COLLATE \"C\") FILTER(WHERE dotted IS NOT NULL),'[]'::jsonb)\n INTO work,missing,targets FROM mapped;\n IF missing<>0 THEN RAISE EXCEPTION 'generation output lacks canonical catalog identity' USING ERRCODE='42501';END IF;\n",
  " -- Факты хранят координату модели; внешний корень хранит точечное\n -- имя из каталога. Снятый тип нельзя заменять живым типом той же модели.\n WITH fact_census AS MATERIALIZED (\n  SELECT (f->>'object_type') COLLATE \"C\" AS model,(f->>'object_id') COLLATE \"C\" AS id\n  FROM jsonb_array_elements(p_capture->'roots') r\n  CROSS JOIN LATERAL jsonb_array_elements(r->'facts') f\n ), lifecycle_census AS MATERIALIZED (\n  SELECT (r#>>'{state,2,root_type}') COLLATE \"C\" AS dotted,(r#>>'{state,2,root_id}') COLLATE \"C\" AS id\n  FROM jsonb_array_elements(p_capture->'roots') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')\n ), catalog AS MATERIALIZED (\n  SELECT (r->>'ObjectType') COLLATE \"C\" AS model,\n   ((r->>'Module')||'.'||(r->>'Resource')) COLLATE \"C\" AS dotted\n  FROM jsonb_array_elements(coalesce(nullif(p_catalog#>'{Live,Resources}','null'::jsonb),'[]'::jsonb)||\n     coalesce(nullif(p_catalog#>'{Retired,Resources}','null'::jsonb),'[]'::jsonb)) r\n ), model_dictionary AS MATERIALIZED (\n  SELECT model,min(dotted) AS dotted FROM catalog GROUP BY model HAVING count(DISTINCT dotted)=1\n ), dotted_dictionary AS MATERIALIZED (\n  SELECT dotted,min(model) AS model FROM catalog GROUP BY dotted HAVING count(DISTINCT model)=1\n ), fact_coordinates AS MATERIALIZED (\n  SELECT DISTINCT c.model,c.id FROM fact_census c\n ), lifecycle_coordinates AS MATERIALIZED (\n  SELECT DISTINCT c.dotted,c.id FROM lifecycle_census c\n ), mapped AS MATERIALIZED (\n  SELECT c.model,c.id,d.dotted,false AS lifecycle FROM fact_coordinates c\n   LEFT JOIN model_dictionary d ON d.model=c.model\n  UNION ALL\n  SELECT d.model,c.id,c.dotted,true FROM lifecycle_coordinates c\n   LEFT JOIN dotted_dictionary d ON d.dotted=c.dotted\n ), grouped AS MATERIALIZED (\n  SELECT dotted,id,min(model) AS model,bool_or(lifecycle) AS lifecycle,\n   count(DISTINCT model) AS models,bool_or(model IS NULL) AS unmapped,\n   jsonb_build_array(dotted,id)::text AS key\n  FROM mapped GROUP BY dotted,id\n )\n SELECT (SELECT count(*)::integer FROM fact_census)+(SELECT count(*)::integer FROM lifecycle_census),\n  count(*) FILTER(WHERE unmapped OR models<>1 OR coalesce(dotted,'')='' OR coalesce(id,'')=''\n   OR (lifecycle AND (model !~ '^[a-z][a-z0-9_]*$' OR split_part(dotted,'.',1)='iam'\n    OR kaname._authority_access_label_dirty_root_type_valid_v1(dotted) IS DISTINCT FROM true)))::integer,\n  coalesce(jsonb_agg(jsonb_build_object('model',model,'id',id,'dotted',dotted,'key',key,'lifecycle',lifecycle)\n   ORDER BY key COLLATE \"C\") FILTER(WHERE dotted IS NOT NULL),'[]'::jsonb)\n INTO work,missing,targets FROM grouped;\n IF missing<>0 THEN RAISE EXCEPTION 'generation graph lacks exact catalog identity' USING ERRCODE='42501';END IF;\n"
 ],
 [
  "  value->>'dotted' AS dotted,value->>'id' AS id FROM jsonb_array_elements(targets) LOOP\n",
  "  value->>'dotted' AS dotted,value->>'id' AS id,(value->>'lifecycle')::boolean AS lifecycle\n  FROM jsonb_array_elements(targets) LOOP\n  IF entry.lifecycle THEN\n   -- Даже существующий в сертификате граф должен предъявить точные\n   -- предикаты ребра и постоянной привязки. Пустой набор тоже обязателен.\n   FOREACH source_kind IN ARRAY ARRAY[3,5] LOOP\n    lifecycle_source:=kaname._authority_resource_require_capture_v2(p_index,source_kind,entry.model,entry.id);\n    IF source_kind=5 AND jsonb_array_length(lifecycle_source->'states')>1 THEN\n     RAISE EXCEPTION 'generation permanent binding census is ambiguous' USING ERRCODE='42501';END IF;\n    lifecycle_required:=lifecycle_required||jsonb_build_object(\n     jsonb_build_array(source_kind,entry.model,entry.id,'')::text,true);\n    work:=work+1;\n   END LOOP;\n  END IF;\n"
 ],
 [
  "  RETURN jsonb_set(p_certificate,'{work}',to_jsonb(work));",
  "  new_required:=(p_certificate->'required')||lifecycle_required;\n  IF work>100000 OR (SELECT count(*) FROM jsonb_object_keys(new_required))>4096 THEN\n   RAISE EXCEPTION 'generation lifecycle source budget exceeded' USING ERRCODE='54000';END IF;\n  RETURN p_certificate||jsonb_build_object('required',new_required,'work',work);"
 ],
 [
  " new_required:=(p_certificate->'required')||new_required||(carriers->'required')||(scopes->'required');",
  " new_required:=(p_certificate->'required')||new_required||lifecycle_required||(carriers->'required')||(scopes->'required');"
 ]
]$changes$::jsonb),
 ('_authority_crud_storage_v3()','8f74405db20549c6d05bc115b4cbabe476ff6fb43eadc2b5d4f2678b8f589981','758c9c0009b779ac40b834b0ed906a61142c1ee450dab6ed1be7d3c0432f9952',
  $changes$[
 [
  "acc5b813a6461a380609c5bf5d70e0b60a4b62ac280974c828e17a876a49db4a",
  "a2a2707d6974b9526d199e5963fd96588db85f97d0bd0f6f9e7821c2f3d5c003"
 ]
]$changes$::jsonb),
 ('_authority_full_contract_storage_v3()','b9402d9d61a06d324893798f483ef5f4aba3786ee7a4d45d1c22d5b6219b7364','eaba8c4bde5ed93f75a75ad4a18486dbf108bc59ea986ca34586b3e23efc0818',
  $changes$[
 [
  "8f74405db20549c6d05bc115b4cbabe476ff6fb43eadc2b5d4f2678b8f589981",
  "758c9c0009b779ac40b834b0ed906a61142c1ee450dab6ed1be7d3c0432f9952"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','7cb001a7cd5dcaea693d88de1a7ee947a1f768224ff566b54e66ffe1070b0fc5','58a0264a26a5e0f4cf1fe047801ec51f7475a5a1b97819ba0eb253849618d654',
  $changes$[
 [
  "8f74405db20549c6d05bc115b4cbabe476ff6fb43eadc2b5d4f2678b8f589981",
  "758c9c0009b779ac40b834b0ed906a61142c1ee450dab6ed1be7d3c0432f9952"
 ],
 [
  "b9402d9d61a06d324893798f483ef5f4aba3786ee7a4d45d1c22d5b6219b7364",
  "eaba8c4bde5ed93f75a75ad4a18486dbf108bc59ea986ca34586b3e23efc0818"
 ]
]$changes$::jsonb)
 ) AS expected(signature,old_digest,new_digest,changes) LOOP
  found_oid:=pg_catalog.to_regprocedure('kaname.'||step.signature);
  SELECT pg_catalog.pg_get_functiondef(p.oid),p.prosrc INTO STRICT definition,original
  FROM pg_catalog.pg_proc p WHERE p.oid=found_oid;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.old_digest THEN
   RAISE EXCEPTION 'metadata carrier predecessor differs: %',step.signature;END IF;
  FOR pair IN SELECT value FROM jsonb_array_elements(step.changes) LOOP
   IF octet_length(original)-octet_length(replace(original,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'metadata carrier patch does not match once: %',step.signature;END IF;
   original:=replace(original,pair->>0,pair->>1);
   definition:=replace(definition,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata carrier expected body differs: %',step.signature;END IF;
  EXECUTE definition;
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=found_oid)
   IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata carrier installed body differs: %',step.signature;END IF;
 END LOOP;
END;
$install$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('authority_metadata_service_account_access_label_ready_v1()','58a0264a26a5e0f4cf1fe047801ec51f7475a5a1b97819ba0eb253849618d654','7cb001a7cd5dcaea693d88de1a7ee947a1f768224ff566b54e66ffe1070b0fc5',
  $changes$[
 [
  "eaba8c4bde5ed93f75a75ad4a18486dbf108bc59ea986ca34586b3e23efc0818",
  "b9402d9d61a06d324893798f483ef5f4aba3786ee7a4d45d1c22d5b6219b7364"
 ],
 [
  "758c9c0009b779ac40b834b0ed906a61142c1ee450dab6ed1be7d3c0432f9952",
  "8f74405db20549c6d05bc115b4cbabe476ff6fb43eadc2b5d4f2678b8f589981"
 ]
]$changes$::jsonb),
 ('_authority_full_contract_storage_v3()','eaba8c4bde5ed93f75a75ad4a18486dbf108bc59ea986ca34586b3e23efc0818','b9402d9d61a06d324893798f483ef5f4aba3786ee7a4d45d1c22d5b6219b7364',
  $changes$[
 [
  "758c9c0009b779ac40b834b0ed906a61142c1ee450dab6ed1be7d3c0432f9952",
  "8f74405db20549c6d05bc115b4cbabe476ff6fb43eadc2b5d4f2678b8f589981"
 ]
]$changes$::jsonb),
 ('_authority_crud_storage_v3()','758c9c0009b779ac40b834b0ed906a61142c1ee450dab6ed1be7d3c0432f9952','8f74405db20549c6d05bc115b4cbabe476ff6fb43eadc2b5d4f2678b8f589981',
  $changes$[
 [
  "a2a2707d6974b9526d199e5963fd96588db85f97d0bd0f6f9e7821c2f3d5c003",
  "acc5b813a6461a380609c5bf5d70e0b60a4b62ac280974c828e17a876a49db4a"
 ]
]$changes$::jsonb),
 ('_authority_access_label_generation_graphs_v1(jsonb,jsonb,jsonb,jsonb)','a2a2707d6974b9526d199e5963fd96588db85f97d0bd0f6f9e7821c2f3d5c003','acc5b813a6461a380609c5bf5d70e0b60a4b62ac280974c828e17a876a49db4a',
  $changes$[
 [
  " new_required:=(p_certificate->'required')||new_required||lifecycle_required||(carriers->'required')||(scopes->'required');",
  " new_required:=(p_certificate->'required')||new_required||(carriers->'required')||(scopes->'required');"
 ],
 [
  "  new_required:=(p_certificate->'required')||lifecycle_required;\n  IF work>100000 OR (SELECT count(*) FROM jsonb_object_keys(new_required))>4096 THEN\n   RAISE EXCEPTION 'generation lifecycle source budget exceeded' USING ERRCODE='54000';END IF;\n  RETURN p_certificate||jsonb_build_object('required',new_required,'work',work);",
  "  RETURN jsonb_set(p_certificate,'{work}',to_jsonb(work));"
 ],
 [
  "  value->>'dotted' AS dotted,value->>'id' AS id,(value->>'lifecycle')::boolean AS lifecycle\n  FROM jsonb_array_elements(targets) LOOP\n  IF entry.lifecycle THEN\n   -- Даже существующий в сертификате граф должен предъявить точные\n   -- предикаты ребра и постоянной привязки. Пустой набор тоже обязателен.\n   FOREACH source_kind IN ARRAY ARRAY[3,5] LOOP\n    lifecycle_source:=kaname._authority_resource_require_capture_v2(p_index,source_kind,entry.model,entry.id);\n    IF source_kind=5 AND jsonb_array_length(lifecycle_source->'states')>1 THEN\n     RAISE EXCEPTION 'generation permanent binding census is ambiguous' USING ERRCODE='42501';END IF;\n    lifecycle_required:=lifecycle_required||jsonb_build_object(\n     jsonb_build_array(source_kind,entry.model,entry.id,'')::text,true);\n    work:=work+1;\n   END LOOP;\n  END IF;\n",
  "  value->>'dotted' AS dotted,value->>'id' AS id FROM jsonb_array_elements(targets) LOOP\n"
 ],
 [
  " -- Факты хранят координату модели; внешний корень хранит точечное\n -- имя из каталога. Снятый тип нельзя заменять живым типом той же модели.\n WITH fact_census AS MATERIALIZED (\n  SELECT (f->>'object_type') COLLATE \"C\" AS model,(f->>'object_id') COLLATE \"C\" AS id\n  FROM jsonb_array_elements(p_capture->'roots') r\n  CROSS JOIN LATERAL jsonb_array_elements(r->'facts') f\n ), lifecycle_census AS MATERIALIZED (\n  SELECT (r#>>'{state,2,root_type}') COLLATE \"C\" AS dotted,(r#>>'{state,2,root_id}') COLLATE \"C\" AS id\n  FROM jsonb_array_elements(p_capture->'roots') r\n  WHERE r#>>'{state,2,root_type}' NOT IN ('iam.account','iam.project','iam.serviceAccount')\n ), catalog AS MATERIALIZED (\n  SELECT (r->>'ObjectType') COLLATE \"C\" AS model,\n   ((r->>'Module')||'.'||(r->>'Resource')) COLLATE \"C\" AS dotted\n  FROM jsonb_array_elements(coalesce(nullif(p_catalog#>'{Live,Resources}','null'::jsonb),'[]'::jsonb)||\n     coalesce(nullif(p_catalog#>'{Retired,Resources}','null'::jsonb),'[]'::jsonb)) r\n ), model_dictionary AS MATERIALIZED (\n  SELECT model,min(dotted) AS dotted FROM catalog GROUP BY model HAVING count(DISTINCT dotted)=1\n ), dotted_dictionary AS MATERIALIZED (\n  SELECT dotted,min(model) AS model FROM catalog GROUP BY dotted HAVING count(DISTINCT model)=1\n ), fact_coordinates AS MATERIALIZED (\n  SELECT DISTINCT c.model,c.id FROM fact_census c\n ), lifecycle_coordinates AS MATERIALIZED (\n  SELECT DISTINCT c.dotted,c.id FROM lifecycle_census c\n ), mapped AS MATERIALIZED (\n  SELECT c.model,c.id,d.dotted,false AS lifecycle FROM fact_coordinates c\n   LEFT JOIN model_dictionary d ON d.model=c.model\n  UNION ALL\n  SELECT d.model,c.id,c.dotted,true FROM lifecycle_coordinates c\n   LEFT JOIN dotted_dictionary d ON d.dotted=c.dotted\n ), grouped AS MATERIALIZED (\n  SELECT dotted,id,min(model) AS model,bool_or(lifecycle) AS lifecycle,\n   count(DISTINCT model) AS models,bool_or(model IS NULL) AS unmapped,\n   jsonb_build_array(dotted,id)::text AS key\n  FROM mapped GROUP BY dotted,id\n )\n SELECT (SELECT count(*)::integer FROM fact_census)+(SELECT count(*)::integer FROM lifecycle_census),\n  count(*) FILTER(WHERE unmapped OR models<>1 OR coalesce(dotted,'')='' OR coalesce(id,'')=''\n   OR (lifecycle AND (model !~ '^[a-z][a-z0-9_]*$' OR split_part(dotted,'.',1)='iam'\n    OR kaname._authority_access_label_dirty_root_type_valid_v1(dotted) IS DISTINCT FROM true)))::integer,\n  coalesce(jsonb_agg(jsonb_build_object('model',model,'id',id,'dotted',dotted,'key',key,'lifecycle',lifecycle)\n   ORDER BY key COLLATE \"C\") FILTER(WHERE dotted IS NOT NULL),'[]'::jsonb)\n INTO work,missing,targets FROM grouped;\n IF missing<>0 THEN RAISE EXCEPTION 'generation graph lacks exact catalog identity' USING ERRCODE='42501';END IF;\n",
  " -- Замкнутый набор выходов берём от owner census, а не из RR proposal.\n -- Стоимость учитывает и повторные выходы разных получателей/поколений.\n WITH census AS MATERIALIZED (\n  SELECT f->>'object_type' AS model,f->>'object_id' AS id\n  FROM jsonb_array_elements(p_capture->'roots') r\n  CROSS JOIN LATERAL jsonb_array_elements(r->'facts') f\n ), model_dictionary AS MATERIALIZED (\n  SELECT r->>'ObjectType' AS model,min((r->>'Module')||'.'||(r->>'Resource')) AS dotted\n  FROM jsonb_array_elements(coalesce(nullif(p_catalog#>'{Live,Resources}','null'::jsonb),'[]'::jsonb)||\n     coalesce(nullif(p_catalog#>'{Retired,Resources}','null'::jsonb),'[]'::jsonb)) r\n  GROUP BY r->>'ObjectType'\n  HAVING count(DISTINCT (r->>'Module')||'.'||(r->>'Resource'))=1\n ), coordinates AS MATERIALIZED (\n  SELECT DISTINCT c.model,c.id FROM census c\n ), mapped AS MATERIALIZED (\n  SELECT c.model,c.id,d.dotted,jsonb_build_array(d.dotted,c.id)::text AS key\n  FROM coordinates c LEFT JOIN model_dictionary d ON d.model=c.model\n )\n SELECT (SELECT count(*)::integer FROM census),\n  count(*) FILTER(WHERE dotted IS NULL OR coalesce(id,'')='')::integer,\n  coalesce(jsonb_agg(jsonb_build_object('model',model,'id',id,'dotted',dotted,'key',key)\n   ORDER BY key COLLATE \"C\") FILTER(WHERE dotted IS NOT NULL),'[]'::jsonb)\n INTO work,missing,targets FROM mapped;\n IF missing<>0 THEN RAISE EXCEPTION 'generation output lacks canonical catalog identity' USING ERRCODE='42501';END IF;\n"
 ],
 [
  " carriers jsonb;scopes jsonb;binding_ids text[];full_bindings text[];work integer;\n lifecycle_required jsonb:='{}';lifecycle_source jsonb;source_kind integer;",
  " carriers jsonb;scopes jsonb;binding_ids text[];full_bindings text[];work integer;"
 ]
]$changes$::jsonb)
 ) AS expected(signature,old_digest,new_digest,changes) LOOP
  found_oid:=pg_catalog.to_regprocedure('kaname.'||step.signature);
  SELECT pg_catalog.pg_get_functiondef(p.oid),p.prosrc INTO STRICT definition,original
  FROM pg_catalog.pg_proc p WHERE p.oid=found_oid;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.old_digest THEN
   RAISE EXCEPTION 'metadata carrier predecessor differs: %',step.signature;END IF;
  FOR pair IN SELECT value FROM jsonb_array_elements(step.changes) LOOP
   IF octet_length(original)-octet_length(replace(original,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'metadata carrier patch does not match once: %',step.signature;END IF;
   original:=replace(original,pair->>0,pair->>1);
   definition:=replace(definition,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata carrier expected body differs: %',step.signature;END IF;
  EXECUTE definition;
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=found_oid)
   IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata carrier installed body differs: %',step.signature;END IF;
 END LOOP;
END;
$install$;
-- +goose StatementEnd
