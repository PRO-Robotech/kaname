// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import "github.com/PRO-Robotech/kaname/internal/catalog"

// catalog_consequence_sql.go — ОТБОР СНИМАЕМОГО и ПРЕДИКАТЫ ПОСЛЕДСТВИЙ,
// объявленные ОДИН РАЗ на обе стороны (задача продукта kacho#1034, объём О6).
//
// # Зачем это отдельным объявлением, а не текстом внутри операторов
//
// Стороны две, и они разные по природе: ПРИМЕНЕНИЕ снимает строки
// (`catalog_writer.go`), ПЛАН считает, сколько снялось бы (`catalog_plan_reader.go`).
// Обещание плана осмысленно ровно постольку, поскольку он считает ТО ЖЕ
// множество, которое применение и тронет. Выписанная у плана копия предиката
// разошлась бы с применением МОЛЧА — и разошлась бы именно там, где расхождение
// не видно: на манифесте, ничего не снимающем, обе копии отвечают «ноль», и
// заметить это стало бы нечем до боевой базы.
//
// Поэтому предикат объявлен здесь, а операторы обеих сторон его ВСТАВЛЯЮТ. Копий
// в дереве не заводится — тот же довод, что у `ModuleStateExpr` и `CatalogLockKey`.
//
// # Контракт входа: отношения `stale_res`, `stale_verb`, `stale_dotted`
//
// Всякий оператор, вставляющий предикаты ниже, обязан открываться
// `catalogStaleInputCTE`: он объявляет три отношения из ПЯТИ массивов
// (`$1`…`$5`), и предикаты читают только их. Нумерация у обеих сторон одна —
// иначе вставка предиката в оператор с другими номерами дала бы верный на вид
// текст и неверный смысл.
//
// Точечное имя (`модуль.ресурс`) выводится ОДИН раз и в SQL: выведенное вторично
// на языке Go, оно стало бы вторым правилом склейки, и разошлись бы они на первом
// же ресурсе с необычным именем.
//
// # Почему у прунинга те же пять массивов, хотя действий он не читает
//
// Ради ЕДИНСТВЕННОСТИ входного объявления. Отдельный вход «только ресурсы» был бы
// вторым местом, где выводится точечное имя, — то есть ровно тем, чего этот файл
// и не допускает. Незачитанные массивы стоят одну связку параметров и ничего не
// стоят плану: отношение `stale_verb` его предикатами не читается и потому не
// материализуется.

// catalogStaleInputCTE — ВХОД отбора: три отношения из пяти массивов.
//
//	stale_res(module, resource)          снимаемые ресурсы
//	stale_verb(module, resource, verb)   снимаемые действия
//	stale_dotted(dotted)                 точечные имена снимаемых ресурсов
//
// Открывает `WITH` обеих сторон, поэтому пишется без ведущего `WITH` и без
// завершающей запятой — их ставит вставляющий оператор.
const catalogStaleInputCTE = `stale_res AS (
		  SELECT * FROM unnest($1::text[], $2::text[]) AS t(module, resource)
		), stale_verb AS (
		  SELECT * FROM unnest($3::text[], $4::text[], $5::text[]) AS t(module, resource, verb)
		), stale_dotted AS (
		  SELECT module || '.' || resource AS dotted FROM stale_res
		)`

// catalogStaleRuleRefPredicate — ПЕРВАЯ популяция: объявления правил
// арендаторских ролей, теряющие референт.
//
// Псевдоним таблицы фиксирован (`rr`): предикат вставляется и в `DELETE FROM …
// role_rule_ref rr`, и в `SELECT count(*) FROM … role_rule_ref rr`, и чужой
// псевдоним сделал бы одну из сторон неразбираемой — то есть отказ был бы громким,
// а не молчаливым. Это и есть цель.
//
// Обе ветви входа нужны: `role_rule_ref` ссылается и на ресурс, и на действие
// (`role_rule_ref_res_fk`, `role_rule_ref_verb_fk`), значит её строку роняет и
// снятие ресурса, и снятие одного действия.
//
// `is_system = false` — роль системного яруса объявлена манифестом; манифест,
// снимающий ресурс, который его же роль называет, противоречит сам себе, и это
// обязано быть отвергнуто ключом, а не улажено молчаливым отбором права.
const catalogStaleRuleRefPredicate = `EXISTS (SELECT 1 FROM kaname.roles r
		                  WHERE r.id = rr.role_id AND r.is_system = false)
		     AND (EXISTS (SELECT 1 FROM stale_res s
		                   WHERE s.module = rr.module AND s.resource = rr.resource)
		       OR EXISTS (SELECT 1 FROM stale_verb s
		                   WHERE s.module = rr.module AND s.resource = rr.resource
		                     AND s.verb = rr.verb))`

// catalogStaleRoleVerbPredicate — ВТОРАЯ популяция: выдачи глаголов
// арендаторских ролей, теряющие референт.
//
// Псевдоним фиксирован (`rv`), по тому же доводу.
//
// Ветвь действий здесь НЕ читается, и это не пропуск: `role_verb` ссылается
// ТОЛЬКО на ресурс (`role_verb_type_fk` → `catalog_resource(dotted, live)`),
// поэтому снятие действия её ключом не задевает, и переселять её на этом входе
// значило бы отбирать у арендатора право, которого база не отбирает.
const catalogStaleRoleVerbPredicate = `EXISTS (SELECT 1 FROM kaname.roles r
		                  WHERE r.id = rv.role_id AND r.is_system = false)
		     AND rv.object_type IN (SELECT dotted FROM stale_dotted)`

// catalogSelectorPruneCTE — ТРЕТЬЯ популяция: приведение массива точечных типов
// в `role_rule_selectors` к каталожному факту.
//
// Объявляет два отношения, и оба читают обе стороны:
//
//	touched(role_id, rule_fp, was, container, alive)   строки, пересекающиеся со снимаемым
//	changed                                            из них те, у которых состав изменился
//
// Из `changed` обе стороны производят ТРИ величины одинаково: `cardinality(alive)
// > 0` — строка укорачивается, `= 0` — снимается целиком (пустой массив запрещён
// ограничением `role_rule_selectors_types_nonempty`), а разность длин суммируется
// в число вырезанных элементов.
//
// # `alive` НЕ ЗАВИСИТ ОТ МОМЕНТА, и это несущее
//
// Применение зовёт вырезание ПОСЛЕ снятия строк каталога (`apply.go`, шаг 8), а
// план — до какого бы то ни было снятия. Читай `alive` одну лишь живость
// (`cr.live`), обе стороны давали бы РАЗНЫЕ ответы на одном и том же входе: у
// применения снимаемая строка уже неживая и элемент выпадает, у плана она ещё
// жива и элемент уцелевает — то есть план обещал бы ноль там, где применение
// вырежет.
//
// Второй конъюнкт (`NOT EXISTS … stale_dotted`) убирает эту зависимость: у
// применения он не меняет НИЧЕГО (снимаемые строки уже `live = false`, и первый
// конъюнкт их отверг), у плана — делает всю работу. Один предикат, один ответ, в
// обоих моментах.
//
// # Почему фильтр «оставить живое», а не «вырезать снятое»
//
// Вход триггера `role_rule_selectors_types_live` судит КАЖДЫЙ элемент массива, а
// не изменённые. Вырежи применение лишь снятое собой — строка с ранее повисшим
// элементом была бы отвергнута триггером, и применитель отказал бы по причине,
// которой в манифесте нет и которую оператору нечем починить.
//
// # Почему трогаются только пересекающиеся строки
//
// Предмет вырезания есть СНЯТИЕ, а не таблица целиком. Отбери мы строки по одному
// признаку «есть неживой элемент» — всякий подъём службы правил бы селекторы всех
// арендаторов, и цена применения перестала бы зависеть от размера снятого.
//
// Пересечение считается по агрегату `stale_dotted`, свёрнутому в массив: на
// пустом снятии он даёт пустой массив, `&&` ложно, и `touched` пусто — то есть
// вход «снимать нечего» даёт нули без отдельной ветви в коде.
//
// # Ссылок на каталог у строки ДВЕ — и снятие судит обе (kaname#874)
//
// Вложенный селектор называет каталог ещё и типом КОНТЕЙНЕРА (`container_type`),
// и страж живости судит его наравне с `object_types`. Читай вырезание один
// `object_types`, снятие типа-контейнера давало бы два исхода, и оба неверны:
// при живых `object_types` строка оставалась бы называть снятый контейнер
// (повисший, и всякая её правка отвергалась бы стражем), а при снятии рядом и
// одного из `object_types` укорачивающее обновление судил бы страж — 23514, и
// применение каталога откатывалось бы целиком.
//
// Вложенный селектор без живого контейнера не укорачивается, а СНИМАЕТСЯ:
// без контейнера он стал бы селектором верхнего уровня — правом на все объекты
// типа вместо потомков названного контейнера. Поэтому `alive` у такой строки
// пуст, и обе стороны разводят её в «снята целиком» тем же признаком, что и
// строку без живых типов. Мёртвый контейнер судится тем же двухконъюнктным
// правилом, что и элемент, — по той же причине независимости от момента.
//
// Строка попадает в `touched` по любой из двух ссылок; вторая ветвь идёт
// частичным индексом `role_rule_selectors_container_type_idx`, поэтому цена
// по-прежнему зависит от размера снятого, а не от таблицы.
const catalogSelectorPruneCTE = `touched AS (
		  SELECT s.role_id, s.rule_fp, s.object_types AS was, s.container_type AS container,
		         CASE WHEN s.container_type IS NOT NULL
		               AND (NOT EXISTS (SELECT 1 FROM kaname.catalog_resource cr
		                                 WHERE cr.dotted = s.container_type AND cr.live)
		                    OR EXISTS (SELECT 1 FROM stale_dotted d WHERE d.dotted = s.container_type))
		              THEN ARRAY[]::text[]
		              ELSE (SELECT coalesce(array_agg(t ORDER BY t), ARRAY[]::text[])
		                      FROM unnest(s.object_types) AS t
		                     WHERE EXISTS (SELECT 1 FROM kaname.catalog_resource cr
		                                    WHERE cr.dotted = t AND cr.live)
		                       AND NOT EXISTS (SELECT 1 FROM stale_dotted d WHERE d.dotted = t))
		         END AS alive
		    FROM kaname.role_rule_selectors s
		    JOIN kaname.roles r ON r.id = s.role_id
		   WHERE r.is_system = false
		     AND (s.object_types && coalesce(
		            (SELECT array_agg(d.dotted) FROM stale_dotted d), ARRAY[]::text[])
		       OR s.container_type = ANY (coalesce(
		            (SELECT array_agg(d.dotted) FROM stale_dotted d), ARRAY[]::text[])))
		), changed AS (
		  SELECT * FROM touched WHERE alive IS DISTINCT FROM was
		)`

// ─────────────────────────────────────────────────────────────────────────────
// ОПЕРАТОРЫ ПИСАТЕЛЯ — ОДНИМ ЛИТЕРАЛОМ ОТ СНЯТИЯ ДО ПЕРЕСЕЛЕНИЯ
//
// Здесь предикат стоит НЕ ссылкой, а дословным вложением, и это вынужденно —
// назову ограничение прямо, иначе следующий «почистит» его обратно и уронит
// гейт дерева.
//
// `internal/repohygiene` `TestIAMRV112_RoleVerbProjectionHasASoleWriter` требует,
// чтобы СТРОКОВЫЙ ЛИТЕРАЛ, содержащий `DELETE FROM` проекции роли, содержал и
// `INSERT INTO kaname.role_grant_orphan`. Признак читается по литералу
// намеренно: снятие и переселение неделимы ровно тогда, когда стоят в одном
// операторе, и отобранное право иначе неотличимо от никогда не выданного.
//
// Предикат лежит в тексте МЕЖДУ снятием и переселением. Значит вставить его
// ссылкой — значит разрезать литерал ровно там, где гейт требует целости:
// требования взаимно исключают друг друга by construction, и уступает то, чьё
// существо мельче. Существо гейта — необратимое право арендатора; существо
// ссылки — форма записи.
//
// Поэтому вложение ДОСЛОВНОЕ, а единственность держит проба
// `catalog_consequence_sql_test.go`: она требует, чтобы каждый оператор писателя
// содержал авторитетное объявление предиката побайтово. Дрейф перестаёт быть
// молчаливым — он перестаёт садиться.
//
// Третьей популяции это не касается: `role_rule_selectors` в наборе гейта нет
// (переселять её нечем — у строки селектора нет пары «тип + глагол», которой
// адресуются сироты), и её предикат вставляется ссылкой.

// resettleRuleRefSQL — ПЕРВАЯ популяция: снятие объявлений правил арендаторских
// ролей и переселение снятого в сироты ОДНИМ оператором.
//
// Отдаёт ДВЕ величины: сколько снято и КАКИЕ роли тронуты. Второе — вход события
// роли (kaname#76), и берётся оно из ВЫХОДА снятия, а не из ведомости: вставка в
// сироты на повторной паре гасится ключом, и роль, отзываемая второй раз, из
// ведомости пропала бы.
const resettleRuleRefSQL = `
		WITH ` + catalogStaleInputCTE + `, dropped AS (
		  DELETE FROM kaname.role_rule_ref rr
		   WHERE EXISTS (SELECT 1 FROM kaname.roles r
		                  WHERE r.id = rr.role_id AND r.is_system = false)
		     AND (EXISTS (SELECT 1 FROM stale_res s
		                   WHERE s.module = rr.module AND s.resource = rr.resource)
		       OR EXISTS (SELECT 1 FROM stale_verb s
		                   WHERE s.module = rr.module AND s.resource = rr.resource
		                     AND s.verb = rr.verb))
		  RETURNING rr.role_id, rr.module, rr.resource, rr.verb
		), moved AS (
		  INSERT INTO kaname.role_grant_orphan (role_id, object_type, verb, source, reason, applied_by)
		  SELECT d.role_id, d.module || '.' || d.resource, COALESCE(d.verb, ''), 'rule_ref', $6, $7
		    FROM dropped d
		  ON CONFLICT (role_id, object_type, verb, source, cause) DO NOTHING
		)
		SELECT (SELECT count(*) FROM dropped),
		       (SELECT coalesce(array_agg(DISTINCT role_id ORDER BY role_id), ARRAY[]::text[]) FROM dropped)`

// resettleRoleVerbSQL — ВТОРАЯ популяция: снятие выдач глаголов и переселение
// снятого в сироты ОДНИМ оператором.
//
// Отдаёт те же две величины и по тому же доводу, что сосед выше.
const resettleRoleVerbSQL = `
		WITH ` + catalogStaleInputCTE + `, dropped AS (
		  DELETE FROM kaname.role_verb rv
		   WHERE EXISTS (SELECT 1 FROM kaname.roles r
		                  WHERE r.id = rv.role_id AND r.is_system = false)
		     AND rv.object_type IN (SELECT dotted FROM stale_dotted)
		  RETURNING rv.role_id, rv.object_type, rv.verb
		), moved AS (
		  INSERT INTO kaname.role_grant_orphan (role_id, object_type, verb, source, reason, applied_by)
		  SELECT d.role_id, d.object_type, d.verb, 'role_verb', $6, $7 FROM dropped d
		  ON CONFLICT (role_id, object_type, verb, source, cause) DO NOTHING
		)
		SELECT (SELECT count(*) FROM dropped),
		       (SELECT coalesce(array_agg(DISTINCT role_id ORDER BY role_id), ARRAY[]::text[]) FROM dropped)`

// staleRowArrays — вход отбора в форме, которую читает `catalogStaleInputCTE`.
//
// Один разбор на обе стороны: выписанный у каждой, он разошёлся бы порядком
// массивов, и оператор принял бы имя ресурса за имя модуля — молча, потому что
// обе величины суть строки.
func staleRowArrays(resources []catalog.ResourceRow, verbs []catalog.VerbRow) (
	resModules, resNames, verbModules, verbResources, verbNames []string,
) {
	resModules = make([]string, 0, len(resources))
	resNames = make([]string, 0, len(resources))
	for _, r := range resources {
		resModules = append(resModules, r.Module)
		resNames = append(resNames, r.Resource)
	}
	verbModules = make([]string, 0, len(verbs))
	verbResources = make([]string, 0, len(verbs))
	verbNames = make([]string, 0, len(verbs))
	for _, v := range verbs {
		verbModules = append(verbModules, v.Module)
		verbResources = append(verbResources, v.Resource)
		verbNames = append(verbNames, v.Verb)
	}
	return resModules, resNames, verbModules, verbResources, verbNames
}
