// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// catalog_writer.go — ЕДИНСТВЕННЫЙ писатель строк каталога модуля в прод-коде
// (`kacho_iam.catalog_module` / `catalog_resource` / `catalog_verb`), задача
// продукта #1034.
//
// # Почему писатель живёт РЯДОМ С ЧИТАТЕЛЕМ, а не на `kacho.Writer`
//
// Каталог — данные ПЛАТФОРМЫ, а `kacho.Writer` — писательская транзакция
// арендаторских ресурсов: аккаунты, проекты, роли, выдачи. Каталог там был бы
// методом, который ни один арендаторский use-case не вправе позвать, — и он был
// бы у всех. Читатель каталога (`catalog_repo.go`) по этой же причине живёт над
// пулом, а не за `kacho.Reader`; писатель следует за ним.
//
// Транзакцию открывает `pkg/db.Transactor` — ЕДИНСТВЕННОЕ платформенное
// объявление этого паттерна над пулом. Своя последовательность
// begin→commit→rollback была бы вторым местом об одном предмете и разошлась бы
// с первым молча.
//
// # Отказы приходят СЫРЫМИ, и это решение
//
// Приведение к статусу (`mapErr`) здесь НЕ делается: оно сворачивает
// `*pgconn.PgError` в sentinel и теряет ИМЯ НАРУШЕННОГО ОГРАНИЧЕНИЯ, а именно оно
// и есть предмет разбора для оператора установки — «порядок держит ключ» без
// имени ключа проверить нечем. Приведение принадлежит транспорту, который у
// этого глагола появится вместе со своим потребителем.
//
// # Идемпотентность выражена ОПЕРАТОРОМ, а не сравнением в коде
//
// `ON CONFLICT … DO UPDATE … WHERE <строка отличается>` меняет строку ровно
// тогда, когда объявленное состояние в ней не стоит, и `RETURNING` пуст, когда не
// меняет. «Прочитать и сравнить» дало бы то же число и окно между чтением и
// записью (запрет #10): под конкуренцией два применения увидели бы одну и ту же
// строку неизменной.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// CatalogLockKey — ключ ГЛОБАЛЬНОГО консультативного замка каталога.
//
// Один на весь каталог, а не на модуль: переселение проекций трогает роли, а роль
// одного модуля вправе называть ресурс другого. Замок по модулю сериализовал бы
// то, что и так безопасно, и пропустил бы ровно тот случай, ради которого берётся.
//
// Экспортирован ради пробы замка: она обязана состязаться за ТОТ ЖЕ ключ, а
// выписанный у неё второй литерал разошёлся бы с этим молча — и разошёлся бы
// незаметно, потому что проба на чужом ключе просто не дождалась бы блокировки и
// зеленела бы, ничего не проверив.
const CatalogLockKey = "kacho_iam.module_catalog"

// ModuleStateExpr — ВЫРАЖЕНИЕ отпечатка состояния каталога одного модуля.
//
// Скалярное подвыражение SQL, читающее `$1` как имя модуля и отдающее
// непрозрачную строку. Контракт для вызывающего — ТОЛЬКО равенство: строка не
// разбирается никем, её состав есть деталь реализации.
//
// # Состав ВЫВЕДЕН из `WHERE` писателя, а не выбран
//
//	`catalog_module`    `live` — оживление модуля есть изменение
//	`catalog_resource`  `resource`, `object_type`, `live` — ровно то, что читает
//	                    условие изменения `UpsertResource`, плюс ключ снятия
//	`catalog_verb`      `resource`, `verb`, `per_object`, `live` — ровно условие
//	                    изменения `UpsertVerb`, плюс ключ снятия
//
// Причина снятия (`retired_reason` / `retired_at` / `superseded_by`) НЕ входит:
// исхода применения она не меняет — ни один `WHERE` писателя её не читает, — а
// войдя, обесценивала бы подтверждение на правке, ничего не решающей.
//
// Проекции правил ролей (`role_rule_ref`, `role_verb`, `role_rule_selectors`) НЕ
// входят: их двигает любой арендатор циклом создания и удаления роли, а их
// арендаторский писатель замка каталога не берёт вовсе — «CAS» по ним был бы
// формой без содержания. Довод целиком — `modulecatalog/confirm.go`.
//
// # Имя модуля входит БЕЗУСЛОВНО
//
// Первая строка агрегата — само имя, а не строка таблицы: модуль, которого в
// каталоге нет ни одной строкой, иначе давал бы отпечаток пустого агрегата,
// ОДИН И ТОТ ЖЕ для всех таких модулей, и подтверждение одного пустого модуля
// проходило бы для другого.
//
// # Экспортировано РАДИ ПРОБЫ, и это тот же довод, что у `CatalogLockKey`
//
// Проба подтверждения обязана читать состояние ТЕМ ЖЕ выражением, каким его
// читает CAS: выписанная у неё копия разошлась бы с этой молча — и разошлась бы
// именно там, где расхождение не видно, потому что на несдвинутом каталоге обе
// копии отвечают «совпало». Второго объявления состава в дереве не заводится.
const ModuleStateExpr = `(SELECT md5(coalesce(string_agg(x, '|' ORDER BY x), ''))
	  FROM (
	    SELECT 'module:' || $1::text AS x
	    UNION ALL
	    SELECT 'm:' || module || ':' || live::text
	      FROM kacho_iam.catalog_module WHERE module = $1
	    UNION ALL
	    SELECT 'r:' || resource || ':' || object_type || ':' || live::text
	      FROM kacho_iam.catalog_resource WHERE module = $1
	    UNION ALL
	    SELECT 'v:' || resource || '.' || verb || ':' || live::text || ':' || per_object::text
	      FROM kacho_iam.catalog_verb WHERE module = $1
	  ) s)`

// CatalogWriteRepo — исполнитель транзакций применителя каталога над пулом.
type CatalogWriteRepo struct {
	tx *coredb.Transactor
}

// NewCatalogWriteRepo собирает исполнителя транзакций поверх пула.
func NewCatalogWriteRepo(pool *pgxpool.Pool) *CatalogWriteRepo {
	return &CatalogWriteRepo{tx: coredb.NewTransactor(pool)}
}

// RunInWriteTx исполняет fn под ОДНОЙ писательской транзакцией: все шаги
// применения ложатся вместе либо не ложатся вовсе.
func (r *CatalogWriteRepo) RunInWriteTx(
	ctx context.Context,
	fn func(context.Context, modulecatalog.CatalogWriter) error,
) error {
	return r.tx.InTx(ctx, func(tx pgx.Tx) error { return fn(ctx, catalogWriter{tx: tx}) })
}

// catalogWriter — `modulecatalog.CatalogWriter` над одной транзакцией.
type catalogWriter struct{ tx pgx.Tx }

// LockCatalog берёт транзакционный консультативный замок: он снимается коммитом
// И откатом, поэтому оборванный применитель не оставляет каталог запертым.
func (w catalogWriter) LockCatalog(ctx context.Context) error {
	_, err := w.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, CatalogLockKey)
	return err
}

// LockModuleResources берёт замки на ВСЕ строки ресурсов модуля ОДНИМ
// оператором, в порядке, который назначает БАЗА (задача продукта #2012).
//
// # Почему это отдельный оператор, а не порядок в коде
//
// Применитель трогает строки каталога ДВАЖДЫ и разными проходами: объявленные —
// на upsert'е (шаг 4 применения), снимаемые — на retire (шаг 7). Обе
// последовательности возрастающие сами по себе, но их КОНКАТЕНАЦИЯ возрастающей
// не является: снимаемое имя, сортирующееся раньше сохраняемого, достаётся
// применителю последним. Писатель роли берёт те же строки одним оператором и по
// `ORDER BY dotted` — порядки расходятся, и пара даёт взаимную блокировку.
//
// Замер, из-за которого оператор заведён (проба
// `catalog_applier_lock_order_integration_test.go`): модуль с живыми `aaa` и
// `zzz`, манифест оставляет `zzz` — применитель получал
// `deadlock detected (SQLSTATE 40P01)` на снятии `aaa`. Цену платил ОПЕРАТОР
// установки, а не арендатор: выкатка отвергалась, а правка роли доходила.
//
// # Порядок назначает БАЗА, а не сортировка в Go
//
// Писатель роли упорядочивает свой набор `ORDER BY dotted`; здесь стоит тот же
// `ORDER BY dotted`. Отсортируй мы вход в Go — на лок-порядок работали бы ДВА
// сортировщика с разными правилами (байтовый порядок Go против сравнения строк
// СУБД), и совпадение их приходилось бы предполагать. Один оператор, одна
// сортирующая власть — расхождение перестаёт быть представимым.
//
// # Почему `WHERE module = $1` без сужения, и почему это НЕ пере-блокировка
//
// Множество строк, которые транзакция применения тронет, есть в точности строки
// этого модуля: объявленные (upsert держит замок на конфликтующей строке ДАЖЕ
// когда `WHERE` ветви `DO UPDATE` ложен и строка не меняется) плюс снимаемые
// (`live` минус объявленные) плюс оживляемые (снятые с тем же ключом). Ни одной
// лишней строки оператор не берёт — он берёт ТЕ ЖЕ и раньше.
//
// `FOR UPDATE`, а не `FOR NO KEY UPDATE`: снятие и оживление меняют `live`,
// входящий в уникальные ограничения — цели внешних ключей, — то есть обновляют
// КЛЮЧ и берут именно `FOR UPDATE`. Более слабый предварительный замок пришлось
// бы повышать, и повышение снова стояло бы в неупорядоченном месте.
//
// Ноль строк — законный исход (модуль устанавливается впервые): замок берётся на
// то, что есть, а строки, которых ещё нет, конкурента иметь не могут — второго
// применителя не пускает консультативный замок каталога.
func (w catalogWriter) LockModuleResources(ctx context.Context, module string) error {
	_, err := w.tx.Exec(ctx, `
		SELECT 1 FROM kacho_iam.catalog_resource
		 WHERE module = $1
		 ORDER BY dotted
		   FOR UPDATE`, module)
	return err
}

// ReadModule читает живые строки одного модуля.
//
// Три оператора под ОДНОЙ транзакцией — то есть один снимок: собранный из разных
// моментов, он показал бы «ресурс снят, его глаголы живы», а такого состояния в
// базе не бывает ни при каком порядке применения.
func (w catalogWriter) ReadModule(ctx context.Context, module string) (catalog.Rows, error) {
	var out catalog.Rows

	var present bool
	if err := w.tx.QueryRow(ctx,
		`SELECT true FROM kacho_iam.catalog_module WHERE module = $1 AND live`, module,
	).Scan(&present); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, fmt.Errorf("прочитать строку модуля %s: %w", module, err)
	}
	if present {
		out.Modules = append(out.Modules, module)
	}

	resRows, err := w.tx.Query(ctx,
		`SELECT module, resource, object_type FROM kacho_iam.catalog_resource
		  WHERE module = $1 AND live
		  ORDER BY resource`, module)
	if err != nil {
		return out, fmt.Errorf("прочитать ресурсы модуля %s: %w", module, err)
	}
	out.Resources, err = pgx.CollectRows(resRows, func(row pgx.CollectableRow) (catalog.ResourceRow, error) {
		var r catalog.ResourceRow
		return r, row.Scan(&r.Module, &r.Resource, &r.ObjectType)
	})
	if err != nil {
		return out, fmt.Errorf("прочитать ресурсы модуля %s: %w", module, err)
	}

	verbRows, err := w.tx.Query(ctx,
		`SELECT module, resource, verb, per_object FROM kacho_iam.catalog_verb
		  WHERE module = $1 AND live ORDER BY resource, verb`, module)
	if err != nil {
		return out, fmt.Errorf("прочитать действия модуля %s: %w", module, err)
	}
	out.Verbs, err = pgx.CollectRows(verbRows, func(row pgx.CollectableRow) (catalog.VerbRow, error) {
		var v catalog.VerbRow
		return v, row.Scan(&v.Module, &v.Resource, &v.Verb, &v.PerObject)
	})
	if err != nil {
		return out, fmt.Errorf("прочитать действия модуля %s: %w", module, err)
	}
	return out, nil
}

// ReadCatalog читает ВЕСЬ каталог ОБЕИМИ половинами — живой и снятой — под ТОЙ
// ЖЕ транзакцией, в которой применитель уже писал.
//
// # Почему транзакцией, а не пулом
//
// Сверка опоры судит состояние, которое применение ПРОИЗВЕЛО, а из пула этих
// строк не видно: они ещё не закоммичены. Прочитанное пулом дало бы вердикт о
// состоянии ДО применения — то есть проверку, которая на своём предмете молчит
// всегда.
//
// # Почему ВЕСЬ каталог, а не один модуль
//
// Опора — литерал ПЛАТФОРМЫ целиком, и «нет в литерале» с «нет строкой»
// считаются по всем модулям сразу. Подай сверке один модуль — строки остальных
// приехали бы недостающими, и всякое применение отвергалось бы by construction.
//
// # Почему ОБЕ половины одним методом
//
// Порт стража двухметодный, и подавший ему одно живое множество получит законное
// снятие недостающей строкой. Один метод, отдающий обе половины, делает пропуск
// невыразимым: `modulecatalog.NewCatalogState` требует их позиционно, и
// «забыть» снятую сторону здесь нечем.
//
// Шесть операторов под одной транзакцией — то есть ОДИН снимок: собранный из
// разных моментов, он показал бы состояние, которого в базе не бывает.
func (w catalogWriter) ReadCatalog(ctx context.Context) (modulecatalog.CatalogState, error) {
	live, err := readCatalogHalf(ctx, w.tx, liveCatalogHalf)
	if err != nil {
		return modulecatalog.CatalogState{}, err
	}
	retired, err := readCatalogHalf(ctx, w.tx, retiredCatalogHalf)
	if err != nil {
		return modulecatalog.CatalogState{}, err
	}
	return modulecatalog.NewCatalogState(live, retired), nil
}

// UpsertModule заводит либо ОЖИВЛЯЕТ строку модуля.
//
// Оживление, а не вставка новой строки: снятая строка занимает первичный ключ, и
// на этом стоит обратимость установки — повторная установка возвращает ТУ ЖЕ
// строку, а не заводит вторую с той же парой.
func (w catalogWriter) UpsertModule(ctx context.Context, module string) (bool, error) {
	return w.changed(ctx, `
		INSERT INTO kacho_iam.catalog_module (module) VALUES ($1)
		ON CONFLICT (module) DO UPDATE
		   SET retired_at = NULL, live = true, retired_reason = NULL
		 WHERE catalog_module.live IS DISTINCT FROM true
		RETURNING 1`, module)
}

// UpsertResource заводит либо оживляет строку ресурса.
//
// `superseded_by` снимается вместе с оживлением: преемник объявлен ровно у снятой
// строки (`catalog_resource_successor_only_when_retired`), и оставить его на живой
// нельзя ни при каком порядке.
//
// `object_type` входит в условие изменения наравне со снятостью: строка, лежащая
// с ЧУЖИМ именем типа, живёт и по паре (модуль, ресурс) сверку прошла бы молча —
// а расходилась бы при этом ровно та величина, ради которой колонка заведена
// (какое отношение `v_*` адресует ресурс). Правка манифеста, меняющая
// `objectType`, обязана доезжать до строки; иначе она была бы принята и
// проигнорирована.
func (w catalogWriter) UpsertResource(ctx context.Context, r catalog.ResourceRow) (bool, error) {
	return w.changed(ctx, `
		INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, object_type)
		VALUES ($1, $2, $1 || '.' || $2, $3)
		ON CONFLICT (module, resource) DO UPDATE
		   SET retired_at = NULL, live = true, retired_reason = NULL, superseded_by = NULL,
		       object_type = EXCLUDED.object_type
		 WHERE catalog_resource.live IS DISTINCT FROM true
		    OR catalog_resource.object_type IS DISTINCT FROM EXCLUDED.object_type
		RETURNING 1`, r.Module, r.Resource, r.ObjectType)
}

// UpsertVerb заводит, оживляет либо приводит признак словаря.
//
// Признак входит в условие изменения намеренно: строка, лежащая с неверным
// признаком, существует и по тройке сверку прошла бы молча — а разошлись бы ровно
// те две величины, ради которых словари разделены (что ключ пропускает и что
// материализуется).
func (w catalogWriter) UpsertVerb(ctx context.Context, v catalog.VerbRow) (bool, error) {
	return w.changed(ctx, `
		INSERT INTO kacho_iam.catalog_verb (module, resource, verb, per_object)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (module, resource, verb) DO UPDATE
		   SET retired_at = NULL, live = true, retired_reason = NULL,
		       per_object = EXCLUDED.per_object
		 WHERE catalog_verb.live IS DISTINCT FROM true
		    OR catalog_verb.per_object IS DISTINCT FROM EXCLUDED.per_object
		RETURNING 1`, v.Module, v.Resource, v.Verb, v.PerObject)
}

// RetireVerb помечает строку действия снятой. Повторное снятие — ноль строк.
func (w catalogWriter) RetireVerb(ctx context.Context, v catalog.VerbRow, reason string) (bool, error) {
	return w.changed(ctx, `
		UPDATE kacho_iam.catalog_verb
		   SET retired_at = now(), live = false, retired_reason = $4
		 WHERE module = $1 AND resource = $2 AND verb = $3 AND live
		RETURNING 1`, v.Module, v.Resource, v.Verb, reason)
}

// RetireResource помечает строку ресурса снятой. Повторное снятие — ноль строк.
func (w catalogWriter) RetireResource(ctx context.Context, r catalog.ResourceRow, reason string) (bool, error) {
	return w.changed(ctx, `
		UPDATE kacho_iam.catalog_resource
		   SET retired_at = now(), live = false, retired_reason = $3
		 WHERE module = $1 AND resource = $2 AND live
		RETURNING 1`, r.Module, r.Resource, reason)
}

// ResettleTenantProjections переселяет проекции АРЕНДАТОРСКИХ ролей, теряющие
// референт вместе со снимаемыми строками.
//
// # Почему две популяции переселяются по РАЗНЫМ входам
//
// `role_rule_ref` ссылается и на ресурс, и на действие (`role_rule_ref_res_fk`,
// `role_rule_ref_verb_fk`) — значит её строку роняет и снятие ресурса, и снятие
// одного действия. `role_verb` ссылается ТОЛЬКО на ресурс
// (`role_verb_type_fk` → `catalog_resource(dotted, live)`), поэтому снятие
// действия её ключом не задевает, и переселять её на этом входе значило бы
// отбирать у арендатора право, которого база не отбирает. Снятое действие при
// живом ресурсе — предмет `deprecatedVerbs`, а не этого писателя.
//
// # Почему только `is_system = false`
//
// Роль системного яруса объявлена манифестом. Если манифест снимает ресурс,
// который его же роль называет, манифест противоречит сам себе — и это обязано
// быть отвергнуто ключом, а не улажено молчаливым отбором права у роли, которую
// применитель не объявлял.
//
// # Почему СНЯТИЕ производит переселяемое, а не отбирает его второй раз
//
// # Строка, оставшаяся без единого живого типа, СНИМАЕТСЯ целиком
//
// Пустой массив запрещён ограничением `role_rule_selectors_types_nonempty`
// (миграция `0026`): селектор, которому нечего выбирать, строкой быть не вправе.
// Оба исхода — «вырезать элементы» и «снять строку» — не изобретены здесь: их
// ВЫПОЛНИЛ ЧЕЛОВЕК двумя отдельными шагами миграции `0074`, ровно по этому
// признаку. Применитель делает то же самое глаголом, а не рукой.
//
// # Почему оператор отдаёт ТРИ величины, а не одну
//
// Этот писатель — НЕ автор строки: он её только снимает. Автор один
// (`roleWriter.ReplaceRoleVerbs` / `ReplaceRuleRefs`), и форму строки знает он.
// Остаток, который такое разделение оставляло, ровно один: ключ строки был
// ПОВТОРЁН — сначала в отборе (`doomed`), потом в предикате снятия
// (`USING … WHERE`). Ключ изменят, предикат разойдётся с отбором, и разойдётся
// МОЛЧА, — поэтому оператор отдавал обе величины, а писатель их сверял.
//
// Повтора больше нет: снятие само СТАЛО отбором. `DELETE … RETURNING` — и
// единственное место, где сказано, что уходит, и производитель того, что
// переселяется; вставка в сироты читает его выход. Расхождение отбора со снятием
// перестало быть представимым — не «не производится ни одним входом», а
// невыразимо by construction, — и вместе с предметом снята сверка кардинальности
// (`resettleExactly`) и её проба. Оставлять отрицание, чей вход больше не
// производится, значило бы держать вечно молчащую проверку, неотличимую от
// исправной (`testing.md` §«Гейт на класс», п. 9).
//
// # Цена повтора была измерена, а не предположена (задача продукта #1959)
//
// Повтор ключа стоил не строки кода, а ИСПОЛНИМОСТИ операции. Ключ проекции
// правила несёт `verb`, допускающий NULL, поэтому предикат снятия сравнивал его
// через `IS NOT DISTINCT FROM`, а этот оператор не хешируется и не мержится:
// планировщик сводил соединение к паре `(module, resource)` и отправлял
// `role_id`/`verb` в фильтр. На тысяче ролей это давало merge join с
// `Rows Removed by Join Filter: 99 980 000` — то есть сто миллионов пар ради
// двадцати тысяч снятий, квадратично по числу ролей.
//
// Замер на PostgreSQL 16.15 (shared_buffers 128MB, work_mem 4MB), 1000 ролей,
// 20 000 строк в популяции, `EXPLAIN (ANALYZE, BUFFERS)`:
//
//	повтор ключа, свежая статистика	17 054 мс	merge join, 99 980 000 пар
//	повтор ключа, ПОСЛЕ `ANALYZE`	   824 мс	hash join, 80 000 пар
//	снятие-производитель		   834 мс	соединения нет вовсе
//
// Средняя строка объясняет, почему дефект дожил до порога незамеченным: та же
// SQL на той же машине быстрее в двадцать раз, если статистика собрана. Разбор,
// снятый на собранной статистике, называл дорогим не то звено; применитель на
// свежей установке встречает первый план, а не второй. Соединения в новой форме
// нет вовсе — значит выбирать планировщику нечего, и разброса нет.
//
// Что осталось дорогим и почему это не чинится здесь: 96 % нового оператора —
// вставка в сироты (420 мс) и пооперационный триггер ключа на `roles` (385 мс).
// Ключ снимает `FOR KEY SHARE` со строки роли, и это единственная гонко-безопасная
// конструкция: заменив его проверкой по множеству, мы отдали бы блокировку и
// пустили гонку «сирота записана — роль удалена» (запрет #10). Замер потолка:
// та же вставка без ключа — 414 мс против 818 мс, то есть весь возможный выигрыш
// вдвое, ценой инварианта. Не берём.
// Автор снятия — ОБЯЗАТЕЛЬНЫЙ параметр, а не поле писателя и не значение по
// умолчанию (#2005): применение разрешает актора первым действием, до открытия
// транзакции, и передать его сюда значением — единственный способ, при котором
// «строка переселена без автора» невыразимо.
func (w catalogWriter) ResettleTenantProjections(
	ctx context.Context,
	resources []catalog.ResourceRow,
	verbs []catalog.VerbRow,
	reason string,
	appliedBy string,
) (modulecatalog.Resettled, error) {
	var out modulecatalog.Resettled

	// Разбор входа — ОБЩИЙ с планом (`catalog_consequence_sql.go`): выписанный
	// здесь второй раз, он разошёлся бы порядком массивов молча.
	resModules, resNames, verbModules, verbResources, verbNames := staleRowArrays(resources, verbs)

	// Один оператор на популяцию: перенос и снятие обязаны быть неделимы, иначе
	// между ними помещается состояние «право отобрано и нигде не записано».
	// Порядок внутри оператора задан ПОТОКОМ ДАННЫХ, а не порядком записи веток:
	// `moved` читает выход `dropped`, поэтому вставка не может опередить снятие.
	if err := w.tx.QueryRow(ctx, resettleRuleRefSQL,
		resModules, resNames, verbModules, verbResources, verbNames, reason, appliedBy,
	).Scan(&out.RuleRefs); err != nil {
		return out, fmt.Errorf("переселить объявления правил: %w", err)
	}

	if err := w.tx.QueryRow(ctx, resettleRoleVerbSQL,
		resModules, resNames, verbModules, verbResources, verbNames, reason, appliedBy,
	).Scan(&out.RoleVerbs); err != nil {
		return out, fmt.Errorf("переселить выдачи глаголов: %w", err)
	}
	return out, nil
}

// ConfirmModuleState сверяет состояние каталога модуля с подтверждением
// вызывающего ОДНИМ оператором, кардинальность которого есть вердикт.
//
// # Почему это CAS конструкцией базы, а не software check-then-act
//
// Сериализует ЗАМОК, взятый первым оператором ЭТОЙ ЖЕ транзакции
// (`LockCatalog`), а не сравнение: между замком и сверкой второго писателя быть
// не может — он ждёт на замке, — поэтому состояние, которое сверка признала
// совпавшим, доживает до коммита by construction. Классический check-then-act
// оставляет окно между чтением и записью; здесь окна нет, потому что читающий и
// пишущий — один держатель замка, и оба шага лежат в одной транзакции.
//
// Форма — та, которую требует `data-integrity.md` от атомарного сравнения,
// перенесённая на чтение: не «прочитать, сравнить в коде и записать», а ОДИН
// оператор, чья кардинальность и есть решение. Ноль строк ⇒ состояние
// сдвинулось; строка ⇒ то самое.
//
// Значение отпечатка наружу НЕ отдаётся намеренно: контракт подтверждения —
// только равенство, а выдача значения завела бы вход, на котором вызывающий
// сверяет его сам, вне замка и по частям.
func (w catalogWriter) ConfirmModuleState(ctx context.Context, module, expected string) (bool, error) {
	var one int
	err := w.tx.QueryRow(ctx, `SELECT 1 WHERE `+ModuleStateExpr+` = $2`, module, expected).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("сверить состояние каталога модуля %s: %w", module, err)
	}
	return true, nil
}

// EmitApplied записывает след применения В ТОЙ ЖЕ транзакции.
//
// # Шва здесь нет by construction, и второй копии не заводится
//
// Путь записи в чужую транзакцию в дереве ОДИН — `insertAuditEventTx`, вход
// которого есть `pgx.Tx`; транзакция применителя — тот же `pgx.Tx` того же
// пакета. Значит атомарность следа с применением не требует ни переходника, ни
// второго объявления формы записи: откат уносит запись вместе с применением,
// коммит кладёт их вместе.
//
// Тело записи собирает USE-CASE (`modulecatalog.AppliedEvent.Payload`), а не
// этот адаптер: имена ключей — решение того, кто знает предмет события, и
// `outboxtypes.AuditEvent` говорит это дословно. Адаптер только заворачивает.
//
// Арендаторского аккаунта у записи нет и быть не может: каталог — данные
// ПЛАТФОРМЫ, и приписать применение одному арендатору значило бы утверждать
// неверное.
func (w catalogWriter) EmitApplied(ctx context.Context, ev modulecatalog.AppliedEvent) error {
	return insertAuditEventTx(ctx, w.tx, service.AuditEvent{
		EventType: modulecatalog.AppliedEventType,
		Payload:   ev.Payload(),
	})
}

// changed исполняет оператор, меняющий не более одной строки, и отвечает,
// изменилась ли она. Пустой `RETURNING` — это «объявленное уже стоит», а не отказ.
func (w catalogWriter) changed(ctx context.Context, sql string, args ...any) (bool, error) {
	var one int
	err := w.tx.QueryRow(ctx, sql, args...).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Проверка соответствия портам — на этапе сборки, а не в рантайме.
var (
	_ modulecatalog.TxRunner      = (*CatalogWriteRepo)(nil)
	_ modulecatalog.CatalogWriter = catalogWriter{}
)

// PruneRetiredSelectorTypes приводит ТРЕТЬЮ проекцию правила к каталожному факту:
// вырезает из `role_rule_selectors.object_types` арендаторских ролей элементы, не
// называющие ЖИВОЙ строки каталога (задача продукта #1942).
//
// # Почему фильтр «оставить живое», а не «вырезать снятое»
//
// Вход триггера `role_rule_selectors_types_live` судит КАЖДЫЙ элемент массива, а
// не изменённые. Вырежи мы лишь снятое ЭТИМ применением — строка с ранее
// повисшим элементом была бы отвергнута триггером, и применитель отказал бы по
// причине, которой в манифесте нет и которую оператору нечем починить. Фильтр
// «оставить живое» делает правку приемлемой для триггера by construction.
//
// # Почему трогаются только пересекающиеся строки
//
// Предмет вырезания есть СНЯТИЕ, а не таблица целиком. Отбери мы строки по одному
// признаку «есть неживой элемент» — всякий подъём службы правил бы селекторы всех
// арендаторов, и цена применения перестала бы зависеть от размера снятого.
//
// # Почему только `is_system = false`
//
// Тот же довод, что у переселения: роль системного яруса объявлена манифестом, и
// манифест, снимающий ресурс, который его же роль называет, противоречит сам
// себе — это обязано быть отвергнуто ключом, а не улажено молчаливой правкой
// роли, которую применитель не объявлял.
//
// # Почему оператор отдаёт ДВЕ величины
//
// «Тронута одна строка» не говорит, вырезан из неё один элемент или пять, а
// «вырезано пять» не говорит, у одной роли или у пяти; а строка, СНЯТАЯ целиком,
// есть событие иного рода, чем строка укороченная, и сумма их не различает. Все
// три приходят из ОДНОГО оператора, то есть из одного снимка.
//
// # Вырезанное ЗАПИСЫВАЕТСЯ — ТЕМ ЖЕ оператором (#1988)
//
// Каждый вырезанный элемент ложится в `kacho_iam.role_selector_prune`: роль,
// отпечаток правила, тип, исход строки (укорочена либо снята целиком), причина
// снятия строки каталога и момент. До этого вырезание было НЕОБРАТИМО и не
// записано нигде — объём был виден только в плане применения.
//
// Запись стоит В ТОМ ЖЕ операторе по тому же доводу, что и у переселения:
// иначе между вырезанием и записью помещается состояние «вырезано и нигде не
// записано», а восстановить его потом не из чего. Порядок внутри оператора задан
// ПОТОКОМ ДАННЫХ, а не порядком веток: `cut` читает выход `emptied`/`stripped`,
// поэтому запись не может опередить вырезание.
//
// Ветвь `recorded` ИСПОЛНЯЕТСЯ, хотя итоговый SELECT её не читает: изменяющая
// ветвь `WITH` исполняется ровно один раз и до конца независимо от того, читает
// ли её основной запрос. Свойство держит проба на живой базе
// (`selector_pruning_leaves_a_ledger_integration_test.go`), а не эта строка.
//
// Четвёртой величины наружу оператор не отдаёт НАМЕРЕННО: перепись применения
// уже несёт число вырезанных элементов, а число записанных строк от него
// отличается лишь на повторы, которых у необратимого вырезания не бывает.
//
// ВЕДОМОСТЬ НЕ ВВОДИТ ПОТОЛКА и не подразумевает его. Решение не ставить потолок
// на эту популяцию остаётся: потолок запрещал бы ПОЧИНКУ — висячий элемент
// делает строку неприемлемой для стража живости, и арендатор не может её
// править, пока висяк не вырезан.
// Автор вырезания — обязательный параметр по тому же доводу, что у соседа
// (#2005): вопрос «кто снял» у обеих ведомостей общий, и арендатор не различает,
// какой из проекций правила он лишился.
func (w catalogWriter) PruneRetiredSelectorTypes(
	ctx context.Context,
	resources []catalog.ResourceRow,
	appliedBy string,
) (modulecatalog.Pruned, error) {
	var out modulecatalog.Pruned
	if len(resources) == 0 {
		return out, nil
	}
	// Вход — ТОТ ЖЕ, что у переселения и у плана. Действий вырезание не читает,
	// но берёт их массивы: единственность входного объявления важнее трёх
	// незачитанных параметров (довод — `catalog_consequence_sql.go`).
	resModules, resNames, verbModules, verbResources, verbNames := staleRowArrays(resources, nil)

	if err := w.tx.QueryRow(ctx, `
		WITH `+catalogStaleInputCTE+`, `+catalogSelectorPruneCTE+`, emptied AS (
		  DELETE FROM kacho_iam.role_rule_selectors s
		   USING changed c
		   WHERE s.role_id = c.role_id AND s.rule_fp = c.rule_fp
		     AND cardinality(c.alive) = 0
		  RETURNING s.role_id, s.rule_fp
		), stripped AS (
		  UPDATE kacho_iam.role_rule_selectors s
		     SET object_types = c.alive
		    FROM changed c
		   WHERE s.role_id = c.role_id AND s.rule_fp = c.rule_fp
		     AND cardinality(c.alive) > 0
		  RETURNING s.role_id, s.rule_fp
		), cut AS (
		  SELECT role_id, rule_fp, 'dropped'::text   AS outcome FROM emptied
		  UNION ALL
		  SELECT role_id, rule_fp, 'shortened'::text AS outcome FROM stripped
		), recorded AS (
		  INSERT INTO kacho_iam.role_selector_prune
		         (role_id, rule_fp, object_type, outcome, retired_reason, applied_by)
		  SELECT k.role_id, k.rule_fp, t, k.outcome, cr.retired_reason, $6
		    FROM cut k
		    JOIN changed c ON c.role_id = k.role_id AND c.rule_fp = k.rule_fp
		    CROSS JOIN LATERAL unnest(c.was) AS t
		    LEFT JOIN kacho_iam.catalog_resource cr ON cr.dotted = t
		   WHERE NOT (t = ANY (c.alive))
		  ON CONFLICT (role_id, rule_fp, object_type) DO NOTHING
		  RETURNING 1
		)
		SELECT (SELECT count(*) FROM stripped),
		       (SELECT count(*) FROM emptied),
		       (SELECT coalesce(sum(cardinality(was) - cardinality(alive)), 0) FROM changed)`,
		resModules, resNames, verbModules, verbResources, verbNames, appliedBy,
	).Scan(&out.Rows, &out.Dropped, &out.Elements); err != nil {
		return out, fmt.Errorf("вырезать снятые типы из селекторов: %w", err)
	}
	return out, nil
}
