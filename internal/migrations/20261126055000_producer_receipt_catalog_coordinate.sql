-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Поиск policy epoch использует каталожный тип. Существующий индекс
-- (object_type,object_id,kind) обслуживает тип модели.
-- +goose NO TRANSACTION
-- +goose Up
-- Goose фиксирует версию только после последней инструкции. Прерванный
-- CREATE INDEX CONCURRENTLY может оставить невалидный индекс. Удаляем лишь
-- наш незавершённый индекс под блокировкой таблицы, до установки writer.
-- При активном построении оставляем выбор повторной попытке мигратора.
-- +goose StatementBegin
DO $recover$
DECLARE target oid; rel oid:='kaname.producer_source_receipt'::regclass;
BEGIN
 target:=to_regclass('kaname.producer_source_receipt_catalog_coordinate');
 IF target IS NULL OR EXISTS(SELECT FROM pg_catalog.pg_index i WHERE i.indexrelid=target AND i.indisvalid) THEN
  RETURN;
 END IF;
 LOCK TABLE ONLY kaname.producer_source_receipt IN SHARE UPDATE EXCLUSIVE MODE NOWAIT;
 IF target IS DISTINCT FROM to_regclass('kaname.producer_source_receipt_catalog_coordinate')
  OR to_regprocedure('kaname._authority_metadata_mirror_epoch_hold_v1()') IS NOT NULL
  OR EXISTS(SELECT FROM pg_catalog.pg_stat_progress_create_index v WHERE v.relid=rel)
  OR NOT EXISTS(SELECT FROM pg_catalog.pg_index i
   JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
   JOIN pg_catalog.pg_class t ON t.oid=i.indrelid
   JOIN pg_catalog.pg_am am ON am.oid=c.relam
   WHERE c.oid=target AND i.indrelid=rel AND c.relkind='i' AND c.relowner=t.relowner
    AND t.relowner=current_user::regrole AND i.indislive AND NOT i.indisvalid
    AND NOT (i.indisunique OR i.indisprimary OR i.indisexclusion OR i.indisreplident OR i.indisclustered)
    AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnatts=2 AND i.indnkeyatts=2
    AND am.amname='btree' AND pg_get_indexdef(target,1,true)='catalog_type'
    AND pg_get_indexdef(target,2,true)='object_id'
    AND NOT EXISTS(SELECT FROM pg_catalog.pg_constraint k WHERE k.conindid=target)) THEN
  RAISE EXCEPTION 'refusing removal of foreign, active or in-use receipt index';
 END IF;
 -- Не ждём вытеснения нагрузки ради очистки. Повтор проверяет всё заново.
 LOCK TABLE ONLY kaname.producer_source_receipt IN ACCESS EXCLUSIVE MODE NOWAIT;
 DROP INDEX kaname.producer_source_receipt_catalog_coordinate;
END;
$recover$;
-- +goose StatementEnd
CREATE INDEX CONCURRENTLY IF NOT EXISTS producer_source_receipt_catalog_coordinate
 ON kaname.producer_source_receipt USING btree (catalog_type,object_id);
-- +goose StatementBegin
DO $verify$
BEGIN
 IF NOT EXISTS(SELECT FROM pg_catalog.pg_index i
  JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
  JOIN pg_catalog.pg_am am ON am.oid=c.relam
  WHERE i.indexrelid='kaname.producer_source_receipt_catalog_coordinate'::regclass
  AND i.indrelid='kaname.producer_source_receipt'::regclass
  AND i.indisready AND i.indisvalid AND i.indislive AND NOT i.indisunique
  AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnatts=2 AND i.indnkeyatts=2
  AND am.amname='btree' AND pg_get_indexdef(i.indexrelid,1,true)='catalog_type'
  AND pg_get_indexdef(i.indexrelid,2,true)='object_id') THEN
  RAISE EXCEPTION 'producer receipt catalog coordinate index incomplete or changed';
 END IF;
END;
$verify$;
-- +goose StatementEnd
-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS kaname.producer_source_receipt_catalog_coordinate;
