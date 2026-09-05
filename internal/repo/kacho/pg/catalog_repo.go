// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// catalog_repo.go — ЕДИНСТВЕННЫЙ читатель живых строк каталога модуля
// (`kacho_iam.catalog_module` / `catalog_resource` / `catalog_verb`).
//
// # Почему читатель ОДИН
//
// Живое множество спрашивают трое: страж старта, сверяющий его с литералом
// (`seed.AssertCatalogParity`); снимок каталога, которым отвечают читатели на
// пути запроса (`internal/catalog`); и ПРИМЕНИТЕЛЬ каталога, сверяющий опору
// внутри своей транзакции (`catalog_writer.go`). Дай каждому свой запрос —
// получишь три места об одном предмете, и разойдутся они молча: у стража
// множество одно, у снимка другое, а согласие между ними никто не проверяет.
// Поэтому запрос здесь один, а вызывающих у него трое.
//
// Третий вызывающий читает не пулом, а СВОЕЙ ТРАНЗАКЦИЕЙ — ему нужно увидеть
// собственные ещё не закоммиченные строки, а из пула их не видно by
// construction. Поэтому запрос параметризован соединением (`catalogQuerier`), а
// не привязан к пулу: разные соединения, один текст.
//
// Отсюда и величина, которую утверждает проба `IAM-CT-2-01`: за время старта к
// таблицам каталога уходит РОВНО СТОЛЬКО операторов, сколько шлёт сам страж, —
// своего чтения снимок не заводит.
//
// # Почему ПУЛ, а не читающая сторона
//
// Читающая сторона предпочитает реплику, а страж исполняется на старте, когда
// отставание реплики наиболее вероятно. Прочитанный оттуда пустой каталог дал бы
// отказ старта на исправной службе — то есть контроль отказал бы по причине,
// которой в предмете контроля нет.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
)

// CatalogRepo — реализация порта `catalog.RowSource` поверх пула.
type CatalogRepo struct {
	pool *pgxpool.Pool
}

// NewCatalogRepo — конструктор порта чтения каталога.
func NewCatalogRepo(pool *pgxpool.Pool) *CatalogRepo { return &CatalogRepo{pool: pool} }

// ReadRetiredCatalog читает СНЯТОЕ множество каталога — строки, у которых
// `retired_at` проставлен, а `live` ложен.
//
// # Почему снятое читается ОТДЕЛЬНЫМ методом, а не флагом в живом чтении
//
// У живого множества один потребитель на пути запроса — снимок каталога, и ему
// снятые строки не нужны ни для чего: отношение `v_*` на снятом типе не
// резолвится, кортежа он не производит, а ключ проекции (`role_verb_type_fk` →
// `catalog_resource(dotted, live)`) такую строку не пропускает. Отдай их снимку
// вместе с живыми — он обязан был бы их отсеивать сам, то есть завести второе
// место, где решается, что значит «живо».
//
// Спрашивают снятое ДВОЕ — страж старта и применитель каталога, — и оба ради
// одного вопроса: строка, которую называет литерал, а живой нет, — СНЯТА
// решением или НЕ ДОЕХАЛА вовсе? Эти два состояния снаружи выглядят одинаково
// («прав не выдали»), а чинятся противоположно: первое не чинится вовсе, второе
// — применением миграций. Различает их наличие строки, и больше ничего.
//
// # Форма та же, что у живого множества
//
// `catalog.Rows` — не совпадение: обе стороны сверки обязаны быть выражены
// одинаково, иначе сравнение начинает зависеть от того, кто как разложил свою
// сторону.
func (r *CatalogRepo) ReadRetiredCatalog(ctx context.Context) (catalog.Rows, error) {
	return readCatalogHalf(ctx, r.pool, retiredCatalogHalf)
}

// ReadLiveCatalog читает ЖИВОЕ множество каталога.
//
// Три оператора — по одному на таблицу, — и это величина, а не константа кода:
// проба `-01` её ИЗМЕРЯЕТ и сверяет с тем, сколько уходит за время старта.
// Свернут их когда-нибудь в один — утверждение пробы останется верным без
// правки.
//
// Отбор `WHERE live` — тот же, каким живое множество определено в схеме: `live`
// есть производная `retired_at IS NULL`, и согласие этих двух держит проверка
// колонки, а не читатель.
func (r *CatalogRepo) ReadLiveCatalog(ctx context.Context) (catalog.Rows, error) {
	return readCatalogHalf(ctx, r.pool, liveCatalogHalf)
}

// catalogQuerier — то, что чтению каталога нужно от соединения.
//
// Пул и ТРАНЗАКЦИЯ годны одинаково, и это ровно то, ради чего порт объявлен: у
// чтения каталога появился второй вызывающий — применитель, которому нужно
// увидеть СВОИ ещё не закоммиченные строки, а из пула их не видно by
// construction. Написав ему свои три запроса, мы завели бы два места об одном
// предмете; так у запроса по-прежнему одно место и два соединения.
type catalogQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// catalogHalf — ПОЛОВИНА каталога: три запроса, по одному на таблицу.
//
// Половины две, и они не выражаются флагом: `live` и `NOT live` есть отбор, а
// отбор принадлежит тексту запроса. Собери мы его подстановкой — получили бы
// строимую SQL там, где вариантов ровно два и оба известны на этапе сборки.
type catalogHalf struct {
	// what — как называть половину в отказе: тексты «прочитать каталог …» и
	// «прочитать снятые строки каталога …» ведут оператора к РАЗНЫМ предметам.
	what string
	// modules / resources / verbs — по запросу на таблицу.
	modules   string
	resources string
	verbs     string
}

var (
	// liveCatalogHalf — ЖИВОЕ множество. Отбор `WHERE live` — тот же, каким живое
	// множество определено в схеме: `live` есть производная `retired_at IS NULL`,
	// и согласие этих двух держит проверка колонки, а не читатель.
	liveCatalogHalf = catalogHalf{
		what:      "каталог",
		modules:   `SELECT module FROM kacho_iam.catalog_module WHERE live`,
		resources: `SELECT module, resource, object_type FROM kacho_iam.catalog_resource WHERE live`,
		verbs:     `SELECT module, resource, verb, per_object FROM kacho_iam.catalog_verb WHERE live`,
	}
	// retiredCatalogHalf — СНЯТОЕ множество: `retired_at` проставлен, `live`
	// ложен. Спрашивает его тот, кому нужно отличить снятую решением строку от
	// непроехавшей вовсе.
	retiredCatalogHalf = catalogHalf{
		what:      "снятые строки каталога",
		modules:   `SELECT module FROM kacho_iam.catalog_module WHERE NOT live`,
		resources: `SELECT module, resource, object_type FROM kacho_iam.catalog_resource WHERE NOT live`,
		verbs:     `SELECT module, resource, verb, per_object FROM kacho_iam.catalog_verb WHERE NOT live`,
	}
)

// readCatalogHalf читает одну половину каталога ТРЕМЯ операторами.
//
// Три, а не один — и это величина, а не константа кода: проба `-01` её ИЗМЕРЯЕТ
// и сверяет с тем, сколько уходит за время старта. Свернут их когда-нибудь в
// один — утверждение пробы останется верным без правки.
//
// `object_type` и `per_object` читаются ВМЕСТЕ со строкой, а не спрашиваются у
// словаря, порождённого сборкой. Иначе ресурс, заведённый применением манифеста
// в работающем процессе, оставался бы для читателя безымянным и пропускался
// молча (#1816, IAM-CT-2-14), а набору типа доставались бы глаголы, которые
// кортежа не производят (#1863).
func readCatalogHalf(ctx context.Context, q catalogQuerier, h catalogHalf) (catalog.Rows, error) {
	var out catalog.Rows

	modRows, err := q.Query(ctx, h.modules)
	if err != nil {
		return out, fmt.Errorf("прочитать %s: модули: %w", h.what, err)
	}
	out.Modules, err = pgx.CollectRows(modRows, pgx.RowTo[string])
	if err != nil {
		return out, fmt.Errorf("прочитать %s: модули: %w", h.what, err)
	}

	resRows, err := q.Query(ctx, h.resources)
	if err != nil {
		return out, fmt.Errorf("прочитать %s: ресурсы: %w", h.what, err)
	}
	out.Resources, err = pgx.CollectRows(resRows, func(row pgx.CollectableRow) (catalog.ResourceRow, error) {
		var r catalog.ResourceRow
		return r, row.Scan(&r.Module, &r.Resource, &r.ObjectType)
	})
	if err != nil {
		return out, fmt.Errorf("прочитать %s: ресурсы: %w", h.what, err)
	}

	verbRows, err := q.Query(ctx, h.verbs)
	if err != nil {
		return out, fmt.Errorf("прочитать %s: действия: %w", h.what, err)
	}
	out.Verbs, err = pgx.CollectRows(verbRows, func(row pgx.CollectableRow) (catalog.VerbRow, error) {
		var v catalog.VerbRow
		return v, row.Scan(&v.Module, &v.Resource, &v.Verb, &v.PerObject)
	})
	if err != nil {
		return out, fmt.Errorf("прочитать %s: действия: %w", h.what, err)
	}
	return out, nil
}
